package com.zaneschepke.wireguardautotunnel.core.tunnel.handler

import com.zaneschepke.wireguardautotunnel.data.model.AppMode
import com.zaneschepke.wireguardautotunnel.domain.events.BackendMessage
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConfig
import com.zaneschepke.wireguardautotunnel.domain.repository.GeneralSettingRepository
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.domain.state.TunnelState
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.plus
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

class DynamicDnsHandler(
    private val activeTunnels: StateFlow<Map<Int, TunnelState>>,
    private val tunnelsRepository: TunnelRepository,
    private val settingsRepository: GeneralSettingRepository,
    private val localMessageEvents: MutableSharedFlow<Pair<String?, BackendMessage>>,
    private val handleDnsReresolve: (TunnelConfig) -> Boolean,
    private val isRoamingActive: () -> Boolean,
    private val applicationScope: CoroutineScope,
    private val ioDispatcher: CoroutineDispatcher,
) {
    private val mutex = Mutex()
    private val jobs = ConcurrentHashMap<Int, Job>()

    // Trigger to force immediate DNS check after roaming
    private val recheckTrigger = MutableSharedFlow<Int>(extraBufferCapacity = 10)

    init {
        applicationScope.launch(ioDispatcher) {
            combine(activeTunnels, settingsRepository.flow.filterNotNull()) { active, settings ->
                    active to settings
                }
                .collect { (activeTuns, settings) ->
                    mutex.withLock {
                        val activeIds =
                            activeTuns.keys
                                .filter { id ->
                                    val config =
                                        tunnelsRepository.getById(id) ?: return@filter false
                                    config.restartOnPingFailure &&
                                        settings.appMode != AppMode.KERNEL
                                }
                                .toSet()

                        (jobs.keys - activeIds).forEach { id ->
                            Timber.d("Shutting down Dynamic DNS monitoring job for tunnelId: $id")
                            jobs.remove(id)?.cancel()
                        }

                        activeIds.forEach { id ->
                            if (jobs.containsKey(id)) return@forEach
                            val config = tunnelsRepository.getById(id) ?: return@forEach
                            val tunStateFlow =
                                activeTunnels
                                    .map { it[id] }
                                    .stateIn(applicationScope + ioDispatcher)
                            Timber.d("Starting Dynamic DNS monitoring job for tunnelId: $id")
                            jobs[id] =
                                applicationScope.launch(ioDispatcher) {
                                    monitorDynamicDns(config, tunStateFlow)
                                }
                        }
                    }
                }
        }
    }

    private suspend fun monitorDynamicDns(
        config: TunnelConfig,
        tunStateFlow: StateFlow<TunnelState?>,
    ) {
        var backoff = BASE_BACKOFF

        // Launch recheck trigger listener
        val recheckJob = applicationScope.launch(ioDispatcher) {
            recheckTrigger.collect { triggeredId ->
                if (triggeredId == config.id && tunStateFlow.value?.health() == TunnelState.Health.UNHEALTHY) {
                    Timber.d("Immediate DNS recheck triggered for ${config.name} after roaming")
                    runCatching {
                        val updated = handleDnsReresolve(config)
                        if (updated) {
                            localMessageEvents.emit(config.name to BackendMessage.DynamicDnsSuccess)
                            backoff = BASE_BACKOFF
                        }
                    }.onFailure { Timber.e(it, "Failed DNS recheck after roaming for ${config.name}") }
                }
            }
        }

        try {
            while (true) {
                val state = tunStateFlow.value ?: break
                if (state.health() != TunnelState.Health.UNHEALTHY) {
                    backoff = BASE_BACKOFF
                    tunStateFlow.first { it?.health() == TunnelState.Health.UNHEALTHY || it == null }
                    continue
                }

                // Skip DNS resolution if roaming is active to avoid race conditions
                if (isRoamingActive()) {
                    Timber.d("Skipping DNS resolution for ${config.name} - roaming in progress")
                    delay(1000) // Wait 1s and recheck
                    continue
                }

                runCatching {
                        val updated = handleDnsReresolve(config)
                        if (updated) {
                            localMessageEvents.emit(config.name to BackendMessage.DynamicDnsSuccess)
                            backoff = BASE_BACKOFF
                        } else {
                            Timber.i(
                                "Dynamic DNS check completed, current endpoint address is already up to date."
                            )
                        }
                    }
                    .onFailure { Timber.e(it, "Failed to handle dns re-resolution for ${config.name}") }

                delay(backoff)
                backoff = (backoff * 1.5).toLong().coerceAtMost(MAX_BACKOFF_TIME)
            }
        } finally {
            recheckJob.cancel()
        }
    }

    /**
     * Trigger immediate DNS recheck for a tunnel (called after roaming completes)
     */
    fun triggerRecheck(tunnelId: Int) {
        recheckTrigger.tryEmit(tunnelId)
    }

    companion object {
        const val BASE_BACKOFF = 30_000L
        const val MAX_BACKOFF_TIME = 300_000L
    }
}
