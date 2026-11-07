package org.amnezia.vpn

import android.net.VpnService
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.SystemClock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.suspendCancellableCoroutine
import org.amnezia.vpn.protocol.NativeIdleObservation
import org.amnezia.vpn.protocol.NativeIdleState
import org.amnezia.vpn.protocol.NativeSessionBinding
import org.amnezia.vpn.protocol.NativeSessionIdentity
import org.amnezia.vpn.protocol.NativeSessionDescriptor
import org.amnezia.vpn.protocol.DnsSessionOwner
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolState
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.xray.Xray
import org.amnezia.vpn.util.Log
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.resume

/** Keeps the admitted AWG/Wireguard service/session owner while selecting its effective transport. */
internal class DnsFallbackProtocol(
    private val primary: Protocol, private val fallback: DnsFallbackConfig,
    private val builder: () -> VpnService.Builder
) : Protocol() {
    private val policy = DnsFallbackPolicy(fallback.failureThreshold)
    private val primaryState = MutableStateFlow(ProtocolState.UNKNOWN)
    private val dnsState = MutableStateFlow(ProtocolState.UNKNOWN)
    private val dnsOwner = DnsSessionOwner()
    private val lifecycle = Any()
    private val ownedTransports = java.util.concurrent.ConcurrentHashMap.newKeySet<DnsFallbackTransport>()
    private var workers: CoroutineScope? = null
    private var monitor: Job? = null
    @Volatile private var ticket = 0L
    @Volatile private var active = false
    @Volatile private var transport: DnsFallbackTransport? = null
    @Volatile private var pendingTransport: DnsFallbackTransport? = null
    @Volatile private var primaryProbe: HttpsURLConnection? = null
    @Volatile private var dnsStarted = false
    @Volatile private var primaryRetired = false
    @Volatile private var cleanupConfirmed = false
    @Volatile private var identity: NativeSessionIdentity? = null
    @Volatile private var reason = "primary"
    @Volatile private var nextDnsAttemptMs = 0L
    private var dnsRetryDelayMs = 30_000L
    private var nextDnsHealthMs = 0L
    private var dnsUnhealthy = false
    private var dnsHealthFailures = 0
    private var observedPhysicalKey: String? = null
    private var originalConfig: JSONObject? = null
    private var protectSocket: ((Int) -> Boolean)? = null
    private val xray get() = Xray.instance

    private fun closeTransport(value: DnsFallbackTransport?) {
        value?.close()
        if (value?.isStopped == true) ownedTransports.remove(value)
    }

    override val statistics: Statistics get() = if (dnsStarted) xray.statistics else primary.statistics
    override val migrationObservation: String? get() = if (primaryRetired) null else primary.migrationObservation
    override val migrationCleanupObservation: String? get() {
        if (!primaryRetired) return primary.migrationCleanupObservation
        val id = identity ?: return null
        if (!cleanupConfirmed || active) return null
        return JSONObject().put("connectionNonce", id.connectionNonce).put("serviceInstanceId", id.serviceInstanceId)
            .put("serviceActivationId", id.serviceActivationId).put("nativeCleanupConfirmed", true).toString()
    }
    override fun readRestoredSessionBinding(): NativeSessionBinding? {
        if (!primaryRetired) return primary.readRestoredSessionBinding()
        if (!dnsRestoreResourcesLive()) return null
        val nowMs = SystemClock.elapsedRealtime()
        return if (state.value == ProtocolState.CONNECTED && transport?.isAlive == true) dnsOwner.binding(nowMs)
        else dnsOwner.binding(nowMs, "RECONNECTING", resourcesLive = true)
    }
    override fun isRestoredSessionBindingCurrent(binding: NativeSessionBinding): Boolean =
        if (binding.effectiveTransport == "dns") active && primaryRetired && dnsStarted &&
            dnsState.value == ProtocolState.CONNECTED &&
            (binding.sessionState != "CONNECTED" || transport?.isAlive == true) &&
            (binding.sessionState == "CONNECTED") == (state.value == ProtocolState.CONNECTED) &&
            dnsOwner.isCurrent(binding, SystemClock.elapsedRealtime(), resourcesLive = true)
        else !primaryRetired && primary.isRestoredSessionBindingCurrent(binding)

    /** Called only on IO; Main commit checks the already-bound lease without binder/network reads. */
    private fun dnsRestoreResourcesLive(): Boolean {
        if (!active || !dnsStarted || dnsState.value != ProtocolState.CONNECTED) return false
        // Even with no physical network, the actual DNS TUN/child/backend owner may
        // be restored for stop/reconnect control; its wire state remains RECONNECTING.
        return ownedVpnNetwork() != null
    }
    override fun readNativeIdleObservation(): NativeIdleObservation {
        if (!primaryRetired) return primary.readNativeIdleObservation()
        return NativeIdleObservation(when {
            active -> NativeIdleState.ACTIVE
            cleanupConfirmed -> NativeIdleState.VERIFIED_RETIRED
            else -> NativeIdleState.UNKNOWN
        }, dnsOwner.currentGeneration(), identity.takeIf { cleanupConfirmed })
    }
    override fun retireUnstartedSession(descriptor: NativeSessionDescriptor): Boolean = synchronized(lifecycle) {
        if (identity != null || active || dnsStarted || primaryRetired || transport != null || pendingTransport != null
            || ownedTransports.isNotEmpty() || monitor != null || workers != null || originalConfig != null || primaryProbe != null)
            return@synchronized false
        primary.retireUnstartedSession(descriptor)
    }
    override fun stopVpnIfBound(expected: NativeSessionIdentity): Boolean {
        if (!expected.valid() || identity != expected) return false
        stopVpn()
        return cleanupConfirmed && identity == expected
    }
    fun status(): String = JSONObject().put("transport", if (primaryRetired) "dns" else "primary")
        .put("reason", reason).put("restoredBindingSupported", true)
        .put("nativeGeneration", dnsOwner.currentGeneration().toString()).toString()
    fun protocolLabel(primaryLabel: String?): String? = if (dnsStarted) "${primaryLabel ?: "VPN"} + DNS" else primaryLabel

    override fun internalInit() {
        primary.initialize(context, primaryState, onError)
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: VpnService.Builder, protect: (Int) -> Boolean) {
        synchronized(lifecycle) {
            if (active) throw VpnStartException("DNS fallback session already active")
            identity = NativeSessionIdentity(config.optString("nativeServiceInstanceId"), config.optString("nativeServiceActivationId"), config.optString("migrationConnectionNonce"))
            require(identity?.valid() == true)
            originalConfig = JSONObject(config.toString()); protectSocket = protect
            cleanupConfirmed = false; primaryRetired = false; dnsStarted = false; dnsHealthFailures = 0
            dnsOwner.activate(NativeSessionDescriptor(identity!!, config.optString("nativeSessionServerId"),
                config.optString("protocol").uppercase(java.util.Locale.ROOT)), fallback.profileDigest())
            ticket = policy.begin(SystemClock.elapsedRealtime()); active = true
        }
        val ownedTicket = ticket
        primaryState.value = ProtocolState.CONNECTING
        try { primary.startVpn(config, vpnBuilder, protect) }
        catch (e: Exception) { active = false; policy.stop(); throw e }
        if (!policy.current(ownedTicket)) return
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        workers = scope
        scope.launch {
            primaryState.collect { current ->
                if (policy.current(ownedTicket) && !primaryRetired) state.value = current
            }
        }
        monitor = scope.launch {
            while (policy.current(ownedTicket)) {
                delay(5000)
                val mobile = dnsFallbackPhysicalNetwork(context, mobileOnly = !primaryRetired, profileResolvers = fallback.profileResolvers)
                if (dnsStarted || primaryRetired) {
                    if (primaryRetired && !primary.readNativeIdleObservation().isAbsent) {
                        state.value = ProtocolState.UNKNOWN
                        reason = "primary_native_cleanup_unconfirmed"
                        continue
                    }
                    val currentTransport = transport
                    if (mobile == null) {
                        observedPhysicalKey = null
                        dnsOwner.revokeProof()
                        state.value = ProtocolState.RECONNECTING
                        reason = "dns_underlying_network_unavailable"
                        continue
                    }
                    if (observedPhysicalKey != mobile.key) {
                        // A new physical path must not inherit the old path's retry cooldown.
                        observedPhysicalKey = mobile.key; nextDnsAttemptMs = 0L; dnsHealthFailures = 0
                    }
                    val nowMs = SystemClock.elapsedRealtime()
                    if (pendingTransport == null && dnsStarted && currentTransport != null && mobile.network == currentTransport.network && nowMs >= nextDnsHealthMs) {
                        val healthy = currentTransport.verify(fallback, protect) &&
                            dnsState.value == ProtocolState.CONNECTED && vpnReachable()
                        if (!policy.current(ownedTicket)) break
                        val confirmedHealthy = healthy && dnsOwner.confirm(dnsOwner.currentGeneration(), SystemClock.elapsedRealtime(),
                            currentTransport.isAlive, dnsState.value == ProtocolState.CONNECTED, ownedVpnNetwork() != null)
                        dnsHealthFailures = if (confirmedHealthy) 0 else (dnsHealthFailures + 1).coerceAtMost(2)
                        nextDnsHealthMs = SystemClock.elapsedRealtime() + if (confirmedHealthy) 20_000 else 5_000
                        dnsUnhealthy = !confirmedHealthy && (dnsHealthFailures >= 2 || !currentTransport.isAlive ||
                            dnsState.value != ProtocolState.CONNECTED || ownedVpnNetwork() == null)
                        if (!confirmedHealthy) dnsOwner.revokeProof()
                        state.value = if (confirmedHealthy) ProtocolState.CONNECTED else ProtocolState.RECONNECTING
                        reason = if (confirmedHealthy) "dns_active" else "dns_authenticated_probe_failed"
                    }
                    if (SystemClock.elapsedRealtime() >= nextDnsAttemptMs &&
                        (!dnsStarted || dnsUnhealthy || dnsState.value != ProtocolState.CONNECTED || currentTransport == null || !currentTransport.isAlive ||
                            mobile.network != currentTransport.network || currentTransport.resolver !in mobile.resolvers)) {
                        state.value = ProtocolState.RECONNECTING
                        prepareDns(ownedTicket, mobile)
                    }
                    continue
                }
                val success = vpnReachable()
                if (policy.primarySample(ownedTicket, success, mobile != null, SystemClock.elapsedRealtime()) && mobile != null) {
                    prepareDns(ownedTicket, mobile)
                }
            }
        }
    }

    /** Bind the health request to our VPN network, never mistake direct cellular HTTPS for tunnel health. */
    private fun ownedVpnNetworks(): List<android.net.Network> {
        val manager = context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return manager.allNetworks.filter { network ->
            val capabilities = manager.getNetworkCapabilities(network)
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                (Build.VERSION.SDK_INT < Build.VERSION_CODES.R || capabilities.ownerUid == context.applicationInfo.uid)
        }
    }
    private fun ownedVpnNetwork(): android.net.Network? = ownedVpnNetworks().singleOrNull()

    private fun vpnReachable(): Boolean {
        val vpn = ownedVpnNetwork() ?: return false
        val connection = runCatching { vpn.openConnection(URL(fallback.probeUrl)) as HttpsURLConnection }.getOrNull() ?: return false
        primaryProbe = connection
        return try {
            connection.connectTimeout = 4000; connection.readTimeout = 4000
            connection.instanceFollowRedirects = false; connection.requestMethod = "HEAD"
            connection.responseCode in 200..399
        } catch (_: Exception) { false } finally { connection.disconnect(); if (primaryProbe === connection) primaryProbe = null }
    }

    /** Cancel/timeout closes this exact network-bound request; no direct physical HTTPS fallback. */
    private suspend fun vpnReachableWithin(vpn: android.net.Network, budgetMs: Long, report: (String) -> Unit): Boolean {
        val scope = workers ?: return false
        return withTimeoutOrNull(budgetMs.coerceAtMost(8000).coerceAtLeast(1)) {
            suspendCancellableCoroutine<Boolean> { continuation ->
                val connection = runCatching { vpn.openConnection(URL(fallback.probeUrl)) as HttpsURLConnection }
                    .onFailure { report("open_connection:${dnsTlsFailureSummary(it)}") }.getOrNull()
                if (connection == null) {
                    continuation.resume(false)
                    return@suspendCancellableCoroutine
                }
                primaryProbe = connection
                continuation.invokeOnCancellation {
                    runCatching { connection.disconnect() }
                    if (primaryProbe === connection) primaryProbe = null
                }
                scope.launch(Dispatchers.IO) {
                    val result = try {
                        if (!continuation.isActive) false else {
                            val ioTimeout = (budgetMs / 2).coerceIn(1, 4000).toInt()
                            connection.connectTimeout = ioTimeout; connection.readTimeout = ioTimeout
                            connection.instanceFollowRedirects = false; connection.requestMethod = "HEAD"
                            val code = connection.responseCode
                            if (code !in 200..399) report("http_status_${code.coerceIn(-1, 999)}")
                            code in 200..399
                        }
                    } catch (e: Exception) { report("request:${dnsTlsFailureSummary(e)}"); false } finally {
                        runCatching { connection.disconnect() }
                        if (primaryProbe === connection) primaryProbe = null
                    }
                    continuation.resume(result)
                }
            }
        } ?: false
    }

    /** A failed replacement must release its native consumer before its relay. */
    private fun retireFailedDnsReplacement(candidate: DnsFallbackTransport): Boolean {
        if (dnsStarted && !runCatching { xray.stopVpnVerified() }.getOrDefault(false)) {
            pendingTransport = candidate
            dnsOwner.revokeProof()
            state.value = ProtocolState.UNKNOWN
            reason = "dns_native_cleanup_unconfirmed"
            return false
        }
        dnsStarted = false
        closeTransport(candidate)
        if (pendingTransport === candidate) pendingTransport = null
        return true
    }

    private suspend fun prepareDns(ownedTicket: Long, mobile: DnsFallbackNetwork) {
        val protect = protectSocket ?: return
        var candidate: DnsFallbackTransport? = null
        var nativeReplacementStarted = false
        var stage = "start_transport"
        try {
            // An earlier failed stop retains its exact consumer/relay ownership.
            // Do not overwrite pendingTransport or start another native owner.
            val retained = pendingTransport
            if (retained != null) {
                stage = "cleanup_failed_replacement"
                if (!retireFailedDnsReplacement(retained))
                    throw VpnStartException("dns_native_cleanup_unconfirmed")
            }
            for (resolver in mobile.resolvers) {
                if (!policy.current(ownedTicket)) return
                try {
                    stage = "start_transport"
                    candidate = DnsFallbackTransport.start(context, mobile, resolver, fallback, protect)
                    ownedTransports.add(candidate)
                    pendingTransport = candidate
                    // Native process/listener startup can block while this owner
                    // is stopped. Retire the newly registered candidate in finally
                    // instead of starting another bounded network probe after stop.
                    kotlinx.coroutines.currentCoroutineContext().ensureActive()
                    if (!policy.current(ownedTicket)) return
                    stage = "verify_transport"
                    if (candidate.verify(fallback, protect)) break
                } catch (e: CancellationException) { throw e } catch (e: Exception) {
                    Log.w("DnsFallback", "Transport unavailable stage=$stage failure=${dnsTlsFailureSummary(e)}")
                }
                closeTransport(candidate); candidate = null; pendingTransport = null
            }
            val verified = candidate ?: throw VpnStartException("dns_authenticated_probe_failed")
            kotlinx.coroutines.currentCoroutineContext().ensureActive()
            if (!policy.current(ownedTicket)) return
            reason = "dns_authenticated_probe_passed"
            stage = "publish_replacement"
            val previousVpnNetworks = ownedVpnNetworks().toSet()
            Log.i("DnsFallback", "Switch requested reason=primary_unreachable authenticatedDns=true")
            // No pre-handover binding may commit after native TUN replacement begins.
            // Publish the effective mode before the state event can reach the Activity/Qt queue.
            if (!dnsStarted) primaryRetired = true
            nativeReplacementStarted = true
            val replacementGeneration = dnsOwner.invalidateNative()
            state.value = ProtocolState.RECONNECTING
            if (dnsStarted) {
                stage = "stop_previous_dns"
                if (!xray.stopVpnVerified()) throw VpnStartException("dns_native_cleanup_unconfirmed")
                dnsStarted = false
            } else {
                stage = "stop_primary"
                primary.stopVpn()
                stage = "verify_primary_idle"
                if (!primary.readNativeIdleObservation().isAbsent) throw VpnStartException("primary_native_cleanup_unconfirmed")
            }
            if (!policy.current(ownedTicket)) return
            stage = "build_xray_config"
            val xrayConfig = verified.xrayConfig(originalConfig ?: throw VpnStartException("dns_config_missing"), fallback)
            stage = "initialize_xray"
            xray.initialize(context, dnsState) { Log.w("DnsFallback", "Xray DNS backend reported an error") }
            // Track partial native starts too: their cleanup must be confirmed before another activation.
            dnsStarted = true
            stage = "start_xray"
            xray.startVpn(xrayConfig, builder(), protect)
            kotlinx.coroutines.currentCoroutineContext().ensureActive()
            if (!policy.current(ownedTicket)) return
            // The protected loopback preflight alone cannot validate tun2socks or UDP DNS routing.
            stage = "verify_tun"
            val readinessStarted = SystemClock.elapsedRealtime()
            val readinessFailure = java.util.concurrent.atomic.AtomicReference("network_pending")
            val readyVpn = awaitDnsTunnelReady(
                isCurrent = { active && policy.current(ownedTicket) && dnsStarted &&
                    dnsOwner.currentGeneration() == replacementGeneration },
                selectNetwork = {
                    if (dnsState.value != ProtocolState.CONNECTED) {
                        readinessFailure.set("native_state_not_connected"); null
                    } else {
                        val networks = ownedVpnNetworks()
                        val selected = dnsReplacementNetwork(previousVpnNetworks, networks)
                        if (selected == null) readinessFailure.set(when {
                            networks.isEmpty() -> "owned_network_missing"
                            networks.size != 1 -> "owned_network_ambiguous"
                            else -> "previous_network_still_visible"
                        })
                        selected
                    }
                },
                verify = { network, remainingMs -> vpnReachableWithin(network, remainingMs) { readinessFailure.set(it) } }
            )
            if (readyVpn == null) {
                Log.w("DnsFallback", "TUN readiness unavailable elapsedMs=${SystemClock.elapsedRealtime() - readinessStarted} reason=${readinessFailure.get()}")
                throw VpnStartException("dns_tun_probe_failed")
            }
            stage = "confirm_owner"
            if (!dnsOwner.confirm(replacementGeneration, SystemClock.elapsedRealtime(), verified.isAlive,
                    dnsState.value == ProtocolState.CONNECTED, ownedVpnNetwork() == readyVpn))
                throw VpnStartException("dns_owner_generation_changed")
            val previous = transport; transport = verified; candidate = null; closeTransport(previous)
            pendingTransport = null; nextDnsAttemptMs = 0L; dnsRetryDelayMs = 30_000L
            nextDnsHealthMs = SystemClock.elapsedRealtime() + 20_000; dnsUnhealthy = false; dnsHealthFailures = 0
            check(policy.dnsVerified(ownedTicket))
            stage = "publish_dns_active"
            reason = "dns_active"
            state.value = ProtocolState.CONNECTED
            Log.i("DnsFallback", "Transport active transport=dns authenticated=true")
        } catch (e: CancellationException) { throw e }
        catch (e: Exception) {
            reason = if (primaryRetired) "dns_start_or_cleanup_failed" else "dns_probe_failed_primary_retained"
            Log.w("DnsFallback", "Fallback unavailable reason=$reason stage=$stage failure=${dnsTlsFailureSummary(e)}")
            if (primaryRetired) {
                nextDnsAttemptMs = SystemClock.elapsedRealtime() + dnsRetryDelayMs
                dnsRetryDelayMs = (dnsRetryDelayMs * 2).coerceAtMost(300_000)
                val previous = transport
                val retainedHealthy = pendingTransport == null && !nativeReplacementStarted && previous != null && dnsStarted && dnsState.value == ProtocolState.CONNECTED &&
                    previous.isAlive && previous.verify(fallback, protect) && vpnReachable()
                if (policy.current(ownedTicket) && retainedHealthy && dnsOwner.confirm(dnsOwner.currentGeneration(),
                        SystemClock.elapsedRealtime(), true, true, ownedVpnNetwork() != null)) {
                    // A new network's resolver may reject tunneling while the prior physical path still works.
                    dnsHealthFailures = 0; dnsUnhealthy = false
                    nextDnsHealthMs = SystemClock.elapsedRealtime() + 20_000
                    reason = "dns_active_previous_network"; state.value = ProtocolState.CONNECTED
                } else {
                    dnsOwner.revokeProof()
                    // Never pretend that an AWG binding describes this Xray TUN or admit a second session.
                    state.value = ProtocolState.UNKNOWN
                }
            } else policy.retryPrimary(ownedTicket, SystemClock.elapsedRealtime())
        } finally {
            val failed = candidate
            if (failed != null && nativeReplacementStarted) retireFailedDnsReplacement(failed)
            else { closeTransport(failed); if (pendingTransport === failed) pendingTransport = null }
        }
    }

    override fun reconnectVpn(vpnBuilder: VpnService.Builder, protect: (Int) -> Boolean) {
        if (dnsStarted) {
            // The monitor recreates the relay on the newly selected physical network.
            reason = "dns_network_change"
        } else {
            // Service reconnect changes the outer state only. Reset the private
            // StateFlow so the backend's next CONNECTED is a fresh observation.
            val reconnectTicket = ticket
            primaryState.value = ProtocolState.RECONNECTING
            primary.reconnectVpn(vpnBuilder, protect)
            // A fast backend may complete before the collector runs and conflate
            // both values. Publish its current observation, never assume success.
            if (policy.current(reconnectTicket) && !primaryRetired) state.value = primaryState.value
        }
    }

    override fun stopVpn() {
        synchronized(lifecycle) { active = false; policy.stop(); dnsOwner.retire() }
        primaryProbe?.disconnect(); primaryProbe = null
        // Uncommitted relay preparation can be interrupted immediately. A relay
        // consumed by native Xray stays owned until its native stop is confirmed.
        if (!dnsStarted && !primaryRetired) ownedTransports.toList().forEach(::closeTransport)
        val job = monitor; job?.cancel()
        val joined = runBlocking { withTimeoutOrNull(12_000) { job?.join(); true } ?: false }
        // A timed-out monitor may still be in a native start/cleanup. Keep its
        // exact scope/job and relay references so the next stop can join it.
        if (joined) { workers?.cancel(); workers = null; monitor = null }
        val dnsClosed = joined && (!dnsStarted || runCatching { xray.stopVpnVerified() }.getOrDefault(false))
        if (dnsClosed) dnsStarted = false
        val primaryClosed = joined && runCatching {
            primary.stopVpn()
            // A cancelled wrapper may never have reached its primary start. Only
            // the primary's pristine guard can author the exact retirement receipt.
            originalConfig?.let { config ->
                identity?.let { id -> primary.retireUnstartedSession(NativeSessionDescriptor(id,
                    config.optString("nativeSessionServerId"), config.optString("protocol").uppercase(java.util.Locale.ROOT))) }
            }
            primary.readNativeIdleObservation().isAbsent
        }.getOrDefault(false)
        if (joined && dnsClosed) {
            ownedTransports.toList().forEach(::closeTransport)
            if (ownedTransports.isEmpty()) { transport = null; pendingTransport = null }
        }
        cleanupConfirmed = joined && dnsClosed && ownedTransports.isEmpty() && primaryClosed
        reason = if (cleanupConfirmed) "stopped" else "native_cleanup_unconfirmed"
        state.value = if (cleanupConfirmed) ProtocolState.DISCONNECTED else ProtocolState.UNKNOWN
    }

    companion object {
        fun wrap(primary: Protocol, config: JSONObject, context: android.content.Context,
            builder: () -> VpnService.Builder): Protocol {
            if (config.optString("protocol").uppercase(java.util.Locale.ROOT) !in setOf("AWG", "WIREGUARD")) return primary
            if (config.optString("dnsFallbackUnavailableReason") == "owner_excluded_by_app_split") {
                Log.w("DnsFallback", "Fallback unavailable reason=owner_excluded_by_app_split")
                return primary
            }
            val fallback = DnsFallbackConfig.parse(config) ?: return primary
            if (dnsFallbackExecutable(context) == null) {
                Log.w("DnsFallback", "Fallback unavailable reason=dns_binary_unavailable")
                return primary
            }
            return DnsFallbackProtocol(primary, fallback, builder)
        }
    }
}
