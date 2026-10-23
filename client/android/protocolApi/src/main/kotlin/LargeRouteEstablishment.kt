package org.amnezia.vpn.protocol

import android.content.Context
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import android.provider.Settings
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.Log

/** Only exact final default routes may survive the first establishment. */
fun bootstrapRouteSubset(routes: Collection<Route>): List<Route>? {
    val defaults = routes.filter { it.include && it.inetNetwork.mask == 0 }
    if (defaults.isEmpty() || routes.any { route -> defaults.none {
            it.inetNetwork.isIpv4 == route.inetNetwork.isIpv4 } }) return null
    return defaults
}

/** A measured contained component of RouteInfo, not an estimate of its whole parcel.
 * Android 15 RouteInfo.writeToParcel writes exactly this nested Parcelable first.
 * The recommendation is a conservative scheduling criterion, not a Binder limit.
 */
fun routeDestinationParcelExceedsRecommendation(routes: Collection<Route>): Boolean {
    if (Build.VERSION.SDK_INT < 33) return false
    val parcel = Parcel.obtain()
    return try {
        routes.forEach { parcel.writeParcelable(IpPrefix(it.inetNetwork.address, it.inetNetwork.mask), 0) }
        val bytes = parcel.dataSize()
        val recommendation = IBinder.getSuggestedMaxIpcSizeBytes()
        Log.i("LargeRouteEstablishment", "routeDestinationParcelBytes=$bytes recommendationBytes=$recommendation routes=${routes.size}")
        bytes > recommendation
    } finally { parcel.recycle() }
}

/** Holds an unconsumed small TUN until its new, owned network is validated, then
 * replaces its interface on the same agent. No descriptor is passed to native
 * here. Retained VALIDATED is NOT an acknowledgement of final NetworkMonitor LP
 * delivery: final system errors and actual traffic remain acceptance evidence.
 */
class LargeRouteEstablishment(private val context: Context) {
    var cleanupConfirmed: Boolean = true
        private set
    suspend fun establish(
        builder: VpnService.Builder,
        addresses: Set<InetNetwork>,
        finalRoutes: Collection<Route>,
        configureSmall: () -> Unit,
        appendFinal: () -> Unit,
        ensureOwner: () -> Unit = {}
    ): ParcelFileDescriptor? {
        fun legacy(reason: String): ParcelFileDescriptor? {
            Log.i("LargeRouteEstablishment", "legacyFallback=$reason")
            return null
        }
        if (Build.VERSION.SDK_INT < 33) return legacy("platform")
        if (Looper.myLooper() == Looper.getMainLooper()) return legacy("main_thread")
        // Strict/unknown private DNS retains the legacy exact path: without a
        // native tunnel the bootstrap cannot resolve a strict provider through it.
        val dnsMode = try { Settings.Global.getString(context.contentResolver, "private_dns_mode") }
            catch (_: SecurityException) { return legacy("private_dns_unreadable") }
        if (dnsMode != "off" && dnsMode != "opportunistic") return legacy("strict_or_unknown_private_dns")
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return legacy("connectivity_unavailable")
        val before = cm.allNetworks.toSet()
        fun ownVpn(network: Network): Boolean = cm.getNetworkCapabilities(network)?.let {
            it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && it.ownerUid == Process.myUid()
        } == true
        // A recently retired agent can linger after close. Observe its loss for
        // a bounded period, otherwise preserve the established legacy behavior.
        val changed = MutableStateFlow(0L)
        val lock = Any()
        val caps = mutableMapOf<Network, NetworkCapabilities>()
        val links = mutableMapOf<Network, LinkProperties>()
        val lost = mutableSetOf<Network>()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(n: Network, c: NetworkCapabilities) = synchronized(lock) {
                caps[n] = NetworkCapabilities(c); changed.value++; Unit
            }
            override fun onLinkPropertiesChanged(n: Network, p: LinkProperties) = synchronized(lock) {
                // Framework callback snapshots are retained read-only. The
                // LinkProperties copy constructor is not in the public SDK.
                links[n] = p; changed.value++; Unit
            }
            override fun onLost(n: Network) = synchronized(lock) {
                lost += n; caps.remove(n); links.remove(n); changed.value++; Unit
            }
        }
        val request = NetworkRequest.Builder().removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN).build()
        cm.registerNetworkCallback(request, callback)
        var small: ParcelFileDescriptor? = null
        var final: ParcelFileDescriptor? = null
        var failure: Throwable? = null
        var registered = true
        try {
            val oldOwn = before.filter(::ownVpn).toSet()
            if (oldOwn.isNotEmpty() && withTimeoutOrNull(2000) {
                    changed.first { synchronized(lock) { lost.containsAll(oldOwn) } }
                } == null) return legacy("prior_own_agent_retained")
            if (cm.allNetworks.any(::ownVpn)) return legacy("own_agent_present")
            withTimeout(10_000) {
                currentCoroutineContext().ensureActive()
                ensureOwner()
                configureSmall()
                currentCoroutineContext().ensureActive()
                ensureOwner()
                Log.i("LargeRouteEstablishment", "bootstrap establish routes=default-only nativeActive=false")
                small = builder.establish() ?: throw VpnStartException("Create bootstrap VPN interface: permission revoked")
                cleanupConfirmed = false
                fun matching(n: Network, finalPolicy: Boolean): Boolean {
                    val c = caps[n] ?: return false
                    val p = links[n] ?: return false
                    if (n in before || n in lost || c.ownerUid != Process.myUid() ||
                        !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                        !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ||
                        p.interfaceName.isNullOrEmpty() ||
                        !p.linkAddresses.map { InetNetwork(it.address, it.prefixLength) }.toSet().containsAll(addresses)) return false
                    return !finalPolicy || finalRoutes.all { r -> p.routes.any {
                        it.destination == IpPrefix(r.inetNetwork.address, r.inetNetwork.mask) &&
                            it.type == (if (r.include) 1 else 9)
                    } }
                }
                changed.first { synchronized(lock) { caps.keys.any { matching(it, false) } } }
                val network = synchronized(lock) { caps.keys.singleOrNull { matching(it, false) }
                    ?: throw VpnStartException("Ambiguous bootstrap VPN network") }
                val initialInterface = synchronized(lock) { links.getValue(network).interfaceName }
                Log.i("LargeRouteEstablishment", "bootstrap owned new network validated; finalRoutes=${finalRoutes.size}")
                currentCoroutineContext().ensureActive()
                ensureOwner()
                appendFinal()
                currentCoroutineContext().ensureActive()
                ensureOwner()
                final = builder.establish() ?: throw VpnStartException("Create final VPN interface: permission revoked")
                small?.close(); small = null
                changed.first { synchronized(lock) {
                    if (network in lost) throw VpnStartException("Bootstrap VPN agent was replaced")
                    matching(network, true) && links[network]?.interfaceName != initialInterface
                } }
                currentCoroutineContext().ensureActive()
                ensureOwner()
            }
            // Keep ownership across withTimeout's cancellable return boundary
            // and callback cleanup; either can fail after establishment.
            cm.unregisterNetworkCallback(callback)
            registered = false
            currentCoroutineContext().ensureActive()
            ensureOwner()
            val result = final
            final = null
            cleanupConfirmed = true // Descriptor ownership is transferred to caller.
            Log.i("LargeRouteEstablishment", "final exact routes observed on same agent; networkMonitorFinalDelivery=unconfirmed")
            return result
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            var cleanupFailure: Throwable? = null
            var descriptorsClosed = true
            for ((index, cleanup) in listOf<() -> Unit>({ final?.close(); Unit }, { small?.close(); Unit },
                    { if (registered) cm.unregisterNetworkCallback(callback) }).withIndex()) {
                try { cleanup() } catch (error: Throwable) {
                    if (index < 2) descriptorsClosed = false
                    if (cleanupFailure == null) cleanupFailure = error else cleanupFailure.addSuppressed(error)
                }
            }
            if (descriptorsClosed) cleanupConfirmed = true
            cleanupFailure?.let { if (failure != null) failure.addSuppressed(it) else throw it }
        }
    }
}
