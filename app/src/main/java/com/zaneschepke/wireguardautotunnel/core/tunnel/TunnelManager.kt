package com.zaneschepke.wireguardautotunnel.core.tunnel

import android.os.PowerManager
import com.zaneschepke.logcatter.LogReader
import com.zaneschepke.networkmonitor.NetworkMonitor
import com.zaneschepke.wireguardautotunnel.core.service.ServiceManager
import com.zaneschepke.wireguardautotunnel.core.tunnel.backend.TunnelBackend
import com.zaneschepke.wireguardautotunnel.core.tunnel.handler.DynamicDnsHandler
import com.zaneschepke.wireguardautotunnel.core.tunnel.handler.TunnelActiveStatePersister
import com.zaneschepke.wireguardautotunnel.core.tunnel.handler.TunnelMonitorHandler
import com.zaneschepke.wireguardautotunnel.core.tunnel.handler.TunnelServiceHandler
import com.zaneschepke.wireguardautotunnel.data.model.AppMode
import com.zaneschepke.wireguardautotunnel.domain.enums.BackendMode
import com.zaneschepke.wireguardautotunnel.domain.enums.TunnelStatus
import com.zaneschepke.wireguardautotunnel.domain.events.BackendCoreException
import com.zaneschepke.wireguardautotunnel.domain.events.BackendMessage
import com.zaneschepke.wireguardautotunnel.domain.events.NotAuthorized
import com.zaneschepke.wireguardautotunnel.domain.model.AutoTunnelSettings
import com.zaneschepke.wireguardautotunnel.domain.model.GeneralSettings
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig
import com.zaneschepke.wireguardautotunnel.domain.repository.AutoTunnelSettingsRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.GeneralSettingRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.LockdownSettingsRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.MonitoringSettingsRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.domain.state.LogHealthState
import com.zaneschepke.wireguardautotunnel.domain.state.PingState
import com.zaneschepke.wireguardautotunnel.domain.state.ActiveNetwork
import com.zaneschepke.wireguardautotunnel.domain.state.TunnelState
import com.zaneschepke.wireguardautotunnel.domain.state.TunnelStatistics
import com.zaneschepke.wireguardautotunnel.util.network.NetworkUtils
import com.zaneschepke.wireguardautotunnel.util.extensions.isValidIpv4orIpv6Address
import com.zaneschepke.wireguardautotunnel.domain.state.toDomain
import org.amnezia.awg.config.InetEndpoint
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.flow.filterNot
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.plus
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap
import timber.log.Timber

@OptIn(ExperimentalCoroutinesApi::class, ExperimentalAtomicApi::class)
class TunnelManager(
    kernelBackend: TunnelBackend,
    userspaceBackend: TunnelBackend,
    proxyUserspaceBackend: TunnelBackend,
    private val networkMonitor: NetworkMonitor,
    networkUtils: NetworkUtils,
    powerManager: PowerManager,
    logReader: LogReader,
    monitoringSettingsRepository: MonitoringSettingsRepository,
    private val serviceManager: ServiceManager,
    private val settingsRepository: GeneralSettingRepository,
    private val autoTunnelSettingsRepository: AutoTunnelSettingsRepository,
    private val lockdownSettingsRepository: LockdownSettingsRepository,
    private val tunnelsRepository: TunnelRepository,
    private val applicationScope: CoroutineScope,
    private val ioDispatcher: CoroutineDispatcher,
) : TunnelProvider {

    private val _activeTunnels = MutableStateFlow<Map<Int, TunnelState>>(emptyMap())
    override val activeTunnels: StateFlow<Map<Int, TunnelState>> = _activeTunnels.asStateFlow()

    @OptIn(ExperimentalAtomicApi::class) val currentAppMode = AtomicReference(AppMode.VPN)

    private val defaultManager =
        TunnelLifecycleManager(userspaceBackend, applicationScope, ioDispatcher, _activeTunnels)

    private val lifecycleManagers: Map<AppMode, TunnelLifecycleManager> =
        mapOf(
            AppMode.KERNEL to
                TunnelLifecycleManager(
                    kernelBackend,
                    applicationScope,
                    ioDispatcher,
                    _activeTunnels,
                ),
            AppMode.VPN to defaultManager,
            AppMode.PROXY to
                TunnelLifecycleManager(
                    proxyUserspaceBackend,
                    applicationScope,
                    ioDispatcher,
                    _activeTunnels,
                ),
            AppMode.LOCK_DOWN to
                TunnelLifecycleManager(
                    proxyUserspaceBackend,
                    applicationScope,
                    ioDispatcher,
                    _activeTunnels,
                ),
        )

    @OptIn(ExperimentalAtomicApi::class)
    private fun getProvider(): TunnelProvider {
        return lifecycleManagers[currentAppMode.load()] ?: defaultManager
    }

    override suspend fun startTunnel(tunnelConfig: TunnelConfig): Result<Unit> {
        seedCachedDnsEndpoints(tunnelConfig)
        return getProvider().startTunnel(tunnelConfig)
    }

    override suspend fun stopTunnel(tunnelId: Int) {
        getProvider().stopTunnel(tunnelId)
        cachedResolvedEndpoints.remove(tunnelId)
    }

    override suspend fun forceStopTunnel(tunnelId: Int) {
        getProvider().forceStopTunnel(tunnelId)
        cachedResolvedEndpoints.remove(tunnelId)
    }

    override suspend fun stopActiveTunnels() {
        val activeIds = activeTunnels.value.keys.toSet()
        getProvider().stopActiveTunnels()
        activeIds.forEach { cachedResolvedEndpoints.remove(it) }
    }

    override fun setBackendMode(backendMode: BackendMode) =
        getProvider().setBackendMode(backendMode)

    override fun getBackendMode(): BackendMode = getProvider().getBackendMode()

    override suspend fun runningTunnelNames(): Set<String> = getProvider().runningTunnelNames()

    override fun handleDnsReresolve(tunnelConfig: TunnelConfig): Boolean =
        getProvider().handleDnsReresolve(tunnelConfig)

    override fun getStatistics(tunnelId: Int): TunnelStatistics? =
        getProvider().getStatistics(tunnelId)

    override suspend fun updateTunnelStatus(
        tunnelId: Int,
        status: TunnelStatus?,
        stats: TunnelStatistics?,
        pingStates: Map<String, PingState>?,
        logHealthState: LogHealthState?,
    ) = getProvider().updateTunnelStatus(tunnelId, status, stats, pingStates, logHealthState)

    @OptIn(ExperimentalCoroutinesApi::class)
    private val localErrorEvents = MutableSharedFlow<Pair<String?, BackendCoreException>>()

    @OptIn(ExperimentalCoroutinesApi::class)
    private val localMessageEvents = MutableSharedFlow<Pair<String?, BackendMessage>>()

    override val errorEvents: SharedFlow<Pair<String?, BackendCoreException>> =
        merge(localErrorEvents, *lifecycleManagers.values.map { it.errorEvents }.toTypedArray())
            .shareIn(
                scope = applicationScope + ioDispatcher,
                started = SharingStarted.Eagerly,
                replay = 0,
            )

    override val messageEvents: SharedFlow<Pair<String?, BackendMessage>> =
        merge(localMessageEvents, *lifecycleManagers.values.map { it.messageEvents }.toTypedArray())
            .shareIn(
                scope = applicationScope.plus(ioDispatcher),
                started = SharingStarted.Eagerly,
                replay = 0,
            )

    private val tunnelServiceHandler =
        TunnelServiceHandler(
            activeTunnels = activeTunnels,
            settingsRepository = settingsRepository,
            serviceManager = serviceManager,
            applicationScope = applicationScope,
            ioDispatcher = ioDispatcher,
        )

    private val tunnelActiveStatePersister =
        TunnelActiveStatePersister(
            activeTunnels = activeTunnels,
            tunnelsRepository = tunnelsRepository,
            applicationScope = applicationScope,
            ioDispatcher = ioDispatcher,
        )

    // Function to check if roaming is active (will be set by roaming handler)
    @Volatile
    private var isRoamingActive: () -> Boolean = { false }

    private val dynamicDnsHandler =
        DynamicDnsHandler(
            activeTunnels = activeTunnels,
            tunnelsRepository = tunnelsRepository,
            settingsRepository = settingsRepository,
            localMessageEvents = localMessageEvents,
            handleDnsReresolve = { config -> handleDnsReresolve(config) },
            isRoamingActive = { isRoamingActive() },
            applicationScope = applicationScope,
            ioDispatcher = ioDispatcher,
        )

    fun setRoamingStateProvider(provider: () -> Boolean) {
        isRoamingActive = provider
    }

    fun getDnsHandler(): DynamicDnsHandler = dynamicDnsHandler

    private val fullTunnelMonitorHandler =
        TunnelMonitorHandler(
            activeTunnels = activeTunnels,
            tunnelsRepository = tunnelsRepository,
            settingsRepository = settingsRepository,
            monitoringSettingsRepository = monitoringSettingsRepository,
            networkMonitor = networkMonitor,
            networkUtils = networkUtils,
            powerManager = powerManager,
            logReader = logReader,
            getStatistics = { id -> getStatistics(id) },
            updateResolvedEndpoints = { id, stats -> updateCachedDnsEndpoints(id, stats) },
            updateTunnelStatus = { id, status, stats, pings, logHealth ->
                updateTunnelStatus(id, status, stats, pings, logHealth)
            },
            applicationScope = applicationScope,
            ioDispatcher = ioDispatcher,
        )

    private val cachedResolvedEndpoints =
        ConcurrentHashMap<Int, ConcurrentHashMap<String, String>>()

    init {
        applicationScope.launch(ioDispatcher) {
            var lastSsid: String? = null
            networkMonitor.connectivityStateFlow.collect { state ->
                when (val activeNetwork = state.toDomain().activeNetwork) {
                    is ActiveNetwork.Wifi -> {
                        if (lastSsid != null && activeNetwork.ssid != lastSsid) {
                            clearCachedDnsEndpoints()
                        }
                        lastSsid = activeNetwork.ssid
                    }
                    else -> {
                        clearCachedDnsEndpoints()
                        lastSsid = null
                    }
                }
            }
        }
        applicationScope.launch(ioDispatcher) {
            var previousActiveIds = emptySet<Int>()
            activeTunnels.collect { active ->
                val currentIds = active.keys.toSet()
                val removedIds = previousActiveIds - currentIds
                removedIds.forEach { cachedResolvedEndpoints.remove(it) }
                previousActiveIds = currentIds
            }
        }
        applicationScope.launch(ioDispatcher) {
            val initialEmit = AtomicBoolean(true)
            settingsRepository.flow
                .filterNotNull()
                .filterNot { it == GeneralSettings() }
                .distinctUntilChangedBy { it.appMode }
                .collect { settings ->
                    val isInitialEmit = initialEmit.exchange(false)
                    val previousMode = currentAppMode.exchange(settings.appMode)

                    if (isInitialEmit) {
                        return@collect handleRestore(settings)
                    }

                    if (previousMode != settings.appMode) {
                        handleModeChangeCleanup(previousMode)
                    }
                    if (settings.appMode == AppMode.LOCK_DOWN) {
                        handleLockDownModeInit()
                    }
                }
        }
    }

    fun applyCachedDnsForRoaming(tunnelConfig: TunnelConfig): TunnelConfig {
        val cachedByPeer = cachedResolvedEndpoints[tunnelConfig.id] ?: return tunnelConfig
        if (cachedByPeer.isEmpty()) return tunnelConfig

        val amConfig = tunnelConfig.toAmConfig()
        var wasUpdated = false

        val updatedPeers =
            amConfig.peers.map { peer ->
                val key = peer.publicKey.toBase64()
                val cachedEndpoint = cachedByPeer[key] ?: return@map peer

                val parsed =
                    runCatching { InetEndpoint.parse(cachedEndpoint) }.getOrNull()
                        ?: return@map peer

                if (!parsed.host.isValidIpv4orIpv6Address()) return@map peer

                if (peer.endpoint.isPresent) {
                    val existingHost = peer.endpoint.get().host
                    if (existingHost.isValidIpv4orIpv6Address()) return@map peer
                }

                wasUpdated = true
                copyPeerWithEndpoint(peer, cachedEndpoint)
            }

        if (!wasUpdated) return tunnelConfig

        val updatedConfig =
            org.amnezia.awg.config.Config.Builder()
                .setInterface(amConfig.`interface`)
                .addPeers(updatedPeers)
                .build()

        return tunnelConfig.copy(
            wgQuick = updatedConfig.toWgQuickString(true),
            amQuick = updatedConfig.toAwgQuickString(true, false),
        )
    }

    fun clearCachedDnsEndpoints() {
        cachedResolvedEndpoints.clear()
    }

    private fun updateCachedDnsEndpoints(tunnelId: Int, stats: TunnelStatistics?) {
        if (stats == null) return
        val peers = stats.getPeers()
        if (peers.isEmpty()) return

        val cache = cachedResolvedEndpoints.getOrPut(tunnelId) { ConcurrentHashMap() }
        peers.forEach { peerKey ->
            val resolvedEndpoint = stats.peerStats(peerKey)?.resolvedEndpoint?.trim().orEmpty()
            if (resolvedEndpoint.isBlank()) return@forEach

            val parsed = runCatching { InetEndpoint.parse(resolvedEndpoint) }.getOrNull()
            if (parsed == null || !parsed.host.isValidIpv4orIpv6Address()) return@forEach

            cache[peerKey] = resolvedEndpoint
        }
    }

    private fun seedCachedDnsEndpoints(tunnelConfig: TunnelConfig) {
        val amConfig = tunnelConfig.toAmConfig()
        val cache = cachedResolvedEndpoints.getOrPut(tunnelConfig.id) { ConcurrentHashMap() }

        amConfig.peers.forEach { peer ->
            val key = peer.publicKey.toBase64()
            if (!peer.endpoint.isPresent) return@forEach
            val endpoint = peer.endpoint.get()
            if (!endpoint.host.isValidIpv4orIpv6Address()) return@forEach
            cache[key] = endpoint.toString()
        }
    }

    private fun copyPeerWithEndpoint(
        peer: org.amnezia.awg.config.Peer,
        endpoint: String,
    ): org.amnezia.awg.config.Peer {
        return org.amnezia.awg.config.Peer.Builder()
            .apply {
                parsePublicKey(peer.publicKey.toBase64())
                if (peer.preSharedKey.isPresent) {
                    parsePreSharedKey(peer.preSharedKey.get().toBase64().trim())
                }
                if (peer.persistentKeepalive.isPresent) {
                    parsePersistentKeepalive(peer.persistentKeepalive.get().toString().trim())
                }
                if (endpoint.isNotBlank()) parseEndpoint(endpoint.trim())
                val allowedIps = peer.allowedIps.joinToString(", ").trim()
                if (allowedIps.isNotBlank()) parseAllowedIPs(allowedIps)
            }
            .build()
    }

    // TODO this can crash if we haven't started foreground service yet, especially for
    // workerManager
    private suspend fun handleLockDownModeInit() {
        val lockdownSettings = lockdownSettingsRepository.getLockdownSettings()
        val allowedIps =
            if (lockdownSettings.bypassLan) TunnelConfig.IPV4_PUBLIC_NETWORKS else emptySet()
        try {
            if (serviceManager.hasVpnPermission()) {
                setBackendMode(
                    BackendMode.KillSwitch(
                        allowedIps,
                        lockdownSettings.metered,
                        lockdownSettings.dualStack,
                    )
                )
            } else {
                throw NotAuthorized()
            }
        } catch (e: BackendCoreException) {
            localErrorEvents.tryEmit(null to e)
        }
    }

    private suspend fun handleModeChangeCleanup(previousAppMode: AppMode) {
        val previousManager = lifecycleManagers[previousAppMode]
        previousManager?.stopActiveTunnels()

        // Wait for all tunnels to actually stop before switching modes
        withTimeoutOrNull(3000L) {
            activeTunnels.first { it.isEmpty() }
        } ?: run {
            Timber.w("Mode change cleanup timed out waiting for tunnels to stop")
        }

        if (previousAppMode == AppMode.LOCK_DOWN) {
            previousManager?.setBackendMode(BackendMode.Inactive)
        }
    }

    suspend fun handleRestore(settings: GeneralSettings? = null) =
        withContext(ioDispatcher) {
            val currentSettings = settings ?: settingsRepository.getGeneralSettings()
            val autoTunnelSettings = autoTunnelSettingsRepository.getAutoTunnelSettings()
            val tunnels = tunnelsRepository.userTunnelsFlow.firstOrNull()
            if (autoTunnelSettings.isAutoTunnelEnabled)
                return@withContext restoreAutoTunnel(autoTunnelSettings)
            if (currentSettings.appMode == AppMode.LOCK_DOWN) handleLockDownModeInit()
            if (tunnels?.any { it.isActive } == true) {
                if (currentSettings.appMode == AppMode.VPN && !serviceManager.hasVpnPermission())
                    return@withContext localErrorEvents.emit(null to NotAuthorized())
                when (currentSettings.appMode) {
                    AppMode.VPN,
                    AppMode.PROXY,
                    AppMode.LOCK_DOWN -> {
                        tunnels.firstOrNull { it.isActive }?.let { startTunnel(it) }
                    }
                    AppMode.KERNEL ->
                        tunnels.filter { it.isActive }.forEach { conf -> startTunnel(conf) }
                }
            }
        }

    private suspend fun restoreAutoTunnel(autoTunnelSettings: AutoTunnelSettings) {
        autoTunnelSettingsRepository.upsert(autoTunnelSettings.copy(isAutoTunnelEnabled = true))
        serviceManager.startAutoTunnelService()
    }

    suspend fun handleReboot() =
        withContext(ioDispatcher) {
            val settings = settingsRepository.getGeneralSettings()
            val autoTunnelSettings = autoTunnelSettingsRepository.getAutoTunnelSettings()
            val defaultTunnel = tunnelsRepository.getDefaultTunnel()
            if (autoTunnelSettings.startOnBoot)
                return@withContext restoreAutoTunnel(autoTunnelSettings)
            if (settings.isRestoreOnBootEnabled) {
                tunnelsRepository.resetActiveTunnels()
                when (settings.appMode) {
                    AppMode.LOCK_DOWN -> handleLockDownModeInit()
                    AppMode.VPN ->
                        if (!serviceManager.hasVpnPermission())
                            return@withContext localErrorEvents.emit(null to NotAuthorized())
                    AppMode.KERNEL,
                    AppMode.PROXY -> Unit
                }
                defaultTunnel?.let { startTunnel(it) }
            }
        }

    suspend fun restartActiveTunnel(id: Int) =
        withContext(ioDispatcher) {
            val activeIds = activeTunnels.value.keys.toList()
            if (activeIds.isEmpty()) return@withContext
            if (!activeIds.contains(id)) return@withContext
            val tunnel = tunnelsRepository.getById(id) ?: return@withContext
            restartTunnel(tunnel)
        }

    suspend fun restartActiveTunnels() =
        withContext(ioDispatcher) {
            val activeIds = activeTunnels.value.keys.toList()
            if (activeIds.isEmpty()) return@withContext

            val tunnels = tunnelsRepository.getAll()
            if (tunnels.isEmpty()) return@withContext

            supervisorScope {
                activeIds.forEach { id ->
                    val tunnel =
                        tunnels.find { it.id == id }
                            ?: run {
                                Timber.w("Tunnel config $id not found; skipping restart")
                                return@forEach
                            }
                    restartTunnel(tunnel)
                }
            }
        }

    private suspend fun restartTunnel(tunnel: TunnelConfig) {
        runCatching { stopTunnel(tunnel.id) }
            .onFailure { e -> Timber.e(e, "Failed to stop tunnel ${tunnel.id} during restart") }

        delay(RESTART_TUNNEL_DELAY)

        runCatching { startTunnel(tunnel) }
            .onFailure { e -> Timber.e(e, "Failed to restart tunnel ${tunnel.id}") }
    }

    companion object {
        const val RESTART_TUNNEL_DELAY = 300L
    }
}
