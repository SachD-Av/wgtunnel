package com.zaneschepke.wireguardautotunnel.core.tunnel.handler

import android.os.PowerManager
import com.zaneschepke.networkmonitor.ActiveNetwork
import com.zaneschepke.networkmonitor.NetworkMonitor
import com.zaneschepke.wireguardautotunnel.data.model.AppMode
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig
import com.zaneschepke.wireguardautotunnel.domain.repository.GeneralSettingRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.domain.state.TunnelState
import com.zaneschepke.wireguardautotunnel.domain.state.TunnelStatistics
import com.zaneschepke.wireguardautotunnel.util.extensions.isValidIpv4orIpv6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/**
 * Handles WiFi roaming events (BSSID change on the same SSID).
 *
 * When roaming is detected:
 * 1. The active tunnel stays UP to prevent traffic leaks.
 * 2. A partial wakelock is acquired so the recovery runs even when
 *    the phone is locked / in Doze.
 * 3. For DDNS endpoints, a cached IP is used first for instant recovery
 *    (avoids DNS lookup failure during the transition).
 * 4. After a stabilization delay, a force socket rebind is performed.
 *    This re-applies the tunnel config to rebind the UDP socket to the
 *    new network path without stopping the tunnel (zero leak window).
 * 5. If force rebind fails, a fast restart is performed as last resort.
 */
class WifiRoamingHandler(
    private val activeTunnels: StateFlow<Map<Int, TunnelState>>,
    private val tunnelsRepository: TunnelRepository,
    private val settingsRepository: GeneralSettingRepository,
    private val networkMonitor: NetworkMonitor,
    private val powerManager: PowerManager,
    private val forceSocketRebind: suspend (TunnelConfig) -> Boolean,
    private val ensureTunnelUp: suspend (Int) -> Unit,
    private val getStatistics: (Int) -> TunnelStatistics?,
    private val restartTunnel: suspend (Int) -> Unit,
    private val applicationScope: CoroutineScope,
    private val ioDispatcher: CoroutineDispatcher,
) {
    // Cache: tunnel ID -> (hostname -> resolved IP)
    private val endpointIpCache = ConcurrentHashMap<Int, Map<String, String>>()

    // Debounce: pending recovery job (cancelled on new roaming event)
    private var pendingRecoveryJob: Job? = null
    private val recoveryMutex = Mutex()

    init {
        applicationScope.launch(ioDispatcher) {
            monitorBssidChanges()
        }
        applicationScope.launch(ioDispatcher) {
            maintainEndpointCache()
        }
    }

    /**
     * Monitors for WiFi BSSID changes on the same SSID (roaming events).
     * Uses the raw [ConnectivityState] from the network monitor so we see
     * BSSID updates even when the phone is locked (the monitor callback
     * is registered as a system service callback, independent of UI).
     */
    private suspend fun monitorBssidChanges() {
        var lastBssid: String? = null
        var lastSsid: String? = null

        networkMonitor.connectivityStateFlow
            .map { state ->
                val network = state.activeNetwork
                if (network is ActiveNetwork.Wifi) {
                    WifiSnapshot(network.ssid, network.bssid)
                } else {
                    null
                }
            }
            .distinctUntilChanged()
            .collect { snapshot ->
                if (snapshot == null) {
                    // Not on WiFi: reset tracking and cancel any pending recovery
                    lastBssid = null
                    lastSsid = null
                    cancelPendingRecovery()
                    return@collect
                }

                val currentBssid = snapshot.bssid
                val currentSsid = snapshot.ssid

                if (currentBssid != null &&
                    lastBssid != null &&
                    lastSsid == currentSsid &&
                    lastBssid != currentBssid
                ) {
                    Timber.i(
                        "WiFi roaming detected: SSID=%s, BSSID %s -> %s",
                        currentSsid,
                        lastBssid,
                        currentBssid,
                    )
                    onRoamingDetected()
                }

                lastBssid = currentBssid
                lastSsid = currentSsid
            }
    }

    /**
     * Keeps the endpoint IP cache up-to-date for active tunnels that use
     * DDNS hostnames. Resolves endpoint hostnames when a tunnel becomes
     * active and clears the cache when it goes down.
     */
    private suspend fun maintainEndpointCache() {
        activeTunnels.collect { tunnelMap ->
            // Remove cache entries for tunnels that are no longer active
            val staleIds = endpointIpCache.keys.toList().filter { it !in tunnelMap }
            staleIds.forEach { endpointIpCache.remove(it) }

            // Resolve and cache endpoints for active tunnels
            for ((id, state) in tunnelMap) {
                if (!state.status.isUp()) continue
                if (endpointIpCache.containsKey(id)) continue

                val config = tunnelsRepository.getById(id) ?: continue
                if (config.isStaticallyConfigured()) continue

                resolveAndCacheEndpoints(config)
            }
        }
    }

    private fun resolveAndCacheEndpoints(tunnelConfig: TunnelConfig) {
        val amConfig = tunnelConfig.toAmConfig()
        val cache = mutableMapOf<String, String>()
        for (peer in amConfig.peers) {
            val endpoint = peer.endpoint.orElse(null) ?: continue
            val host = endpoint.host
            if (host.isValidIpv4orIpv6Address()) continue

            try {
                val resolved = InetAddress.getByName(host).hostAddress
                if (resolved != null) {
                    cache[host] = resolved
                    Timber.d("Cached endpoint IP for %s: %s -> %s", tunnelConfig.name, host, resolved)
                }
            } catch (e: Exception) {
                Timber.w(e, "Failed to resolve endpoint %s for caching", host)
            }
        }
        if (cache.isNotEmpty()) {
            endpointIpCache[tunnelConfig.id] = cache
        }
    }

    /**
     * Cancels any pending roaming recovery. Called when WiFi is lost
     * to let AutoTunnel handle the network transition instead.
     */
    private fun cancelPendingRecovery() {
        pendingRecoveryJob?.let { job ->
            if (job.isActive) {
                Timber.d("Roaming: WiFi lost, cancelling pending recovery")
                job.cancel()
            }
        }
        pendingRecoveryJob = null
    }

    @Suppress("DEPRECATION")
    private fun acquireWakeLock(): PowerManager.WakeLock {
        return powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            WAKELOCK_TAG,
        ).apply {
            acquire(WAKELOCK_TIMEOUT_MS)
        }
    }

    private suspend fun onRoamingDetected() {
        val settings = settingsRepository.flow.filterNotNull().first()
        // Kernel backend handles socket rebinding natively via the kernel networking stack
        if (settings.appMode == AppMode.KERNEL) {
            Timber.d("Skipping roaming handler: kernel mode handles rebinding natively")
            return
        }

        val activeTunnelIds = activeTunnels.value.filter { it.value.status.isUp() }.keys
        if (activeTunnelIds.isEmpty()) return

        // Debounce: first roaming = immediate, subsequent = wait for stabilization
        // This ensures rapid BSSID changes (A→B→C→D) only trigger ONE recovery
        // after the BSSID stabilizes, while single roaming recovers instantly
        recoveryMutex.withLock {
            val hasPendingRecovery = pendingRecoveryJob?.isActive == true
            pendingRecoveryJob?.cancel()

            pendingRecoveryJob = applicationScope.launch(ioDispatcher) {
                // First roaming = immediate recovery (might be the only one)
                // Subsequent roaming = debounce to wait for BSSID stability
                if (hasPendingRecovery) {
                    Timber.d("Roaming: rapid BSSID changes, debouncing %dms", DEBOUNCE_DELAY_MS)
                    delay(DEBOUNCE_DELAY_MS)
                }

                // Verify still on WiFi (network may have changed during debounce)
                val currentNetwork = networkMonitor.connectivityStateFlow.value.activeNetwork
                if (currentNetwork !is ActiveNetwork.Wifi) {
                    Timber.d("Roaming: no longer on WiFi, skipping recovery")
                    return@launch
                }

                Timber.d("Roaming: starting recovery")
                val wakeLock = acquireWakeLock()
                try {
                    // Re-check active tunnels (state may have changed during debounce)
                    val currentActiveTunnels = activeTunnels.value
                        .filter { it.value.status.isUp() }
                        .keys

                    for (id in currentActiveTunnels) {
                        val config = tunnelsRepository.getById(id) ?: continue
                        recoverTunnel(id, config)
                    }
                } finally {
                    if (wakeLock.isHeld) wakeLock.release()
                }
            }
        }
    }

    /**
     * Returns the most recent handshake epoch (millis) across all peers,
     * or 0 if stats are unavailable.
     */
    private fun latestHandshakeEpoch(tunnelId: Int): Long {
        val stats = getStatistics(tunnelId) ?: return 0L
        return stats.getPeers().maxOfOrNull { key ->
            stats.peerStats(key)?.latestHandshakeEpochMillis ?: 0L
        } ?: 0L
    }

    /**
     * Two-phase recovery:
     *
     * Phase 1 – force socket rebind (zero leak, keeps tunnel UP).
     * Phase 2 – tunnel restart as last resort if rebind fails.
     *
     * Uses cached IPs for DDNS endpoints to avoid DNS resolution through
     * the broken VPN. For static IP endpoints, uses config directly.
     */
    private suspend fun recoverTunnel(id: Int, config: TunnelConfig) {
        val handshakeBefore = latestHandshakeEpoch(id)

        // Use cached IPs for DDNS (avoids DNS through broken VPN), or original config for static IP
        val cachedIps = endpointIpCache[id]
        val rebindConfig = if (cachedIps != null && cachedIps.isNotEmpty()) {
            Timber.d("Roaming: using cached endpoint IPs for %s", config.name)
            configWithCachedIps(config, cachedIps)
        } else {
            config
        }

        // Phase 1: force socket rebind - keeps tunnel UP (zero leak)
        Timber.i("Roaming: forcing socket rebind for %s", config.name)
        val rebindSuccess = runCatching { forceSocketRebind(rebindConfig) }
            .onFailure { Timber.w(it, "Roaming: force rebind failed for %s", config.name) }
            .getOrDefault(false)

        if (rebindSuccess) {
            delay(HANDSHAKE_CHECK_DELAY_MS)
            runCatching { ensureTunnelUp(id) }

            val handshakeAfterRebind = latestHandshakeEpoch(id)
            if (handshakeAfterRebind > handshakeBefore) {
                Timber.i("Roaming: tunnel %s recovered", config.name)
                resolveAndCacheEndpoints(config)
                return
            }
        }

        // Phase 2: restart tunnel as last resort
        Timber.w("Roaming: rebind insufficient, restarting tunnel %s", config.name)
        runCatching { restartTunnel(id) }
            .onSuccess {
                Timber.i("Roaming: tunnel %s restarted", config.name)
                resolveAndCacheEndpoints(config)
            }
            .onFailure { Timber.e(it, "Roaming: tunnel %s restart failed", config.name) }

        // Final state restoration
        delay(STATE_RESTORE_DELAY_MS)
        runCatching { ensureTunnelUp(id) }
    }

    /**
     * Creates a copy of [tunnelConfig] where DDNS hostnames in peer
     * Endpoint lines are replaced with cached IP addresses. This allows
     * [handleDnsReresolve] to "resolve" instantly using the known-good
     * IP from before roaming.
     *
     * Only replaces hostnames in "Endpoint = host:port" lines to avoid
     * accidentally modifying DNS settings or comments.
     */
    private fun configWithCachedIps(
        tunnelConfig: TunnelConfig,
        cachedIps: Map<String, String>,
    ): TunnelConfig {
        fun replaceEndpointHostnames(config: String): String {
            return config.lines().joinToString("\n") { line ->
                if (line.trim().startsWith("Endpoint", ignoreCase = true)) {
                    var modifiedLine = line
                    for ((hostname, ip) in cachedIps) {
                        modifiedLine = modifiedLine.replace(hostname, ip)
                    }
                    modifiedLine
                } else {
                    line
                }
            }
        }

        val amQuick = tunnelConfig.amQuick.ifBlank { tunnelConfig.wgQuick }
        return tunnelConfig.copy(
            amQuick = replaceEndpointHostnames(amQuick),
            wgQuick = replaceEndpointHostnames(tunnelConfig.wgQuick),
        )
    }

    private data class WifiSnapshot(val ssid: String, val bssid: String?)

    companion object {
        const val WAKELOCK_TAG = "wgtunnel:wifi-roaming"
        const val WAKELOCK_TIMEOUT_MS = 60_000L // auto-release after 60 s
        const val DEBOUNCE_DELAY_MS = 2_000L // wait for BSSID to stabilize (rapid roaming only)
        const val HANDSHAKE_CHECK_DELAY_MS = 1_500L // check if handshake succeeded
        const val STATE_RESTORE_DELAY_MS = 500L // wait for backend callbacks to settle
    }
}
