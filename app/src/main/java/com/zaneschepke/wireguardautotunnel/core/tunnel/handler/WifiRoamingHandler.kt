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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
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
    private val handleDnsReresolve: (TunnelConfig) -> Boolean,
    private val forceSocketRebind: (TunnelConfig) -> Boolean,
    private val getStatistics: (Int) -> TunnelStatistics?,
    private val restartTunnel: suspend (Int) -> Unit,
    private val applicationScope: CoroutineScope,
    private val ioDispatcher: CoroutineDispatcher,
) {
    // Cache: tunnel ID -> (hostname -> resolved IP)
    private val endpointIpCache = ConcurrentHashMap<Int, Map<String, String>>()

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
                    // Not on WiFi: reset tracking
                    lastBssid = null
                    lastSsid = null
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

        for (id in activeTunnelIds) {
            val config = tunnelsRepository.getById(id) ?: continue

            applicationScope.launch(ioDispatcher) {
                val wakeLock = acquireWakeLock()
                try {
                    recoverTunnel(id, config)
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
     * Three-phase recovery:
     *
     * Phase 1 – cached IP re-resolve (instant, no DNS needed).
     * Phase 2 – force socket rebind (re-applies config without restart, zero leak).
     * Phase 3 – tunnel restart as last resort if rebind fails.
     *
     * DNS re-resolution is skipped because after roaming:
     * - DNS likely goes through the broken VPN → timeout
     * - Even if DNS works, resolveDDNS won't rebind if IP is unchanged
     */
    private suspend fun recoverTunnel(id: Int, config: TunnelConfig) {
        val handshakeBefore = latestHandshakeEpoch(id)

        // Phase 1: cached IP → attempt instant socket rebind without DNS
        val cachedIps = endpointIpCache[id]
        if (cachedIps != null && cachedIps.isNotEmpty()) {
            Timber.d("Roaming: using cached endpoint IPs for %s", config.name)
            val cachedConfig = configWithCachedIps(config, cachedIps)
            runCatching { handleDnsReresolve(cachedConfig) }
                .onSuccess { Timber.d("Roaming: cached IP re-resolve for %s, updated=%s", config.name, it) }
                .onFailure { Timber.w(it, "Roaming: cached IP re-resolve failed for %s", config.name) }

            // Brief wait to check if cached IP recovery worked
            delay(HANDSHAKE_CHECK_DELAY_MS)
            val handshakeAfterCache = latestHandshakeEpoch(id)
            if (handshakeAfterCache > handshakeBefore) {
                Timber.i("Roaming: tunnel %s recovered with cached IP", config.name)
                return
            }
        }

        // Wait for network to stabilize after roaming (debounce)
        Timber.d("Roaming: waiting for network stabilization")
        delay(STABILIZATION_DELAY_MS)

        // Check if tunnel recovered naturally during stabilization
        val handshakeAfterStabilization = latestHandshakeEpoch(id)
        if (handshakeAfterStabilization > handshakeBefore) {
            Timber.i("Roaming: tunnel %s recovered during stabilization", config.name)
            resolveAndCacheEndpoints(config)
            return
        }

        // Phase 2: force socket rebind (re-applies config, no tunnel restart)
        // This keeps the tunnel UP the entire time → zero leak window
        Timber.i("Roaming: forcing socket rebind for %s", config.name)
        val rebindSuccess = runCatching { forceSocketRebind(config) }
            .onFailure { Timber.w(it, "Roaming: force rebind threw for %s", config.name) }
            .getOrDefault(false)

        if (rebindSuccess) {
            delay(HANDSHAKE_CHECK_DELAY_MS)
            val handshakeAfterRebind = latestHandshakeEpoch(id)
            if (handshakeAfterRebind > handshakeBefore) {
                Timber.i("Roaming: tunnel %s recovered after force rebind", config.name)
                resolveAndCacheEndpoints(config)
                return
            }
        }

        // Phase 3: restart tunnel as last resort
        // Only reached if force rebind failed or didn't restore connectivity
        Timber.w("Roaming: force rebind insufficient, restarting tunnel %s", config.name)
        runCatching { restartTunnel(id) }
            .onSuccess {
                Timber.i("Roaming: tunnel %s restarted successfully", config.name)
                resolveAndCacheEndpoints(config)
            }
            .onFailure { Timber.e(it, "Roaming: tunnel %s restart failed", config.name) }
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
        const val HANDSHAKE_CHECK_DELAY_MS = 2_000L
        const val STABILIZATION_DELAY_MS = 3_000L // debounce for network to settle
    }
}
