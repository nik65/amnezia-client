package org.amnezia.vpn.protocol

import android.content.Context
import android.net.IpPrefix
import android.net.VpnService
import android.net.VpnService.Builder
import android.os.Build
import android.system.OsConstants
import androidx.annotation.RequiresApi
import kotlinx.coroutines.flow.MutableStateFlow
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.InetNetwork
import org.json.JSONObject

private const val TAG = "Protocol"

const val VPN_SESSION_NAME = "AmneziaVPN"

private const val SPLIT_TUNNEL_DISABLE = 0
private const val SPLIT_TUNNEL_INCLUDE = 1
private const val SPLIT_TUNNEL_EXCLUDE = 2

abstract class Protocol {

    abstract val statistics: Statistics
    open val migrationObservation: String? get() = null
    open val migrationCleanupObservation: String? get() = null
    open fun readRestoredSessionBinding(): NativeSessionBinding? = null
    open fun readNativeIdleObservation(): NativeIdleObservation = NativeIdleObservation(NativeIdleState.UNKNOWN, 0)
    open fun stopVpnIfBound(expected: NativeSessionIdentity): Boolean = false
    protected lateinit var context: Context
    protected lateinit var state: MutableStateFlow<ProtocolState>
    protected lateinit var onError: (String) -> Unit
    protected var isInitialized: Boolean = false

    fun initialize(context: Context, state: MutableStateFlow<ProtocolState>, onError: (String) -> Unit) {
        this.context = context
        this.state = state
        this.onError = onError
        internalInit()
        isInitialized = true
    }

    protected abstract fun internalInit()

    abstract suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean)

    abstract fun stopVpn()

    abstract fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean)

    protected fun ProtocolConfig.Builder.configSplitTunneling(config: JSONObject) {
        setAllowIpv6Routes(config.optBoolean("serverIpv6Available", true))

        if (!allowSplitTunneling) {
            Log.i(TAG, "Global address split tunneling is prohibited, " +
                "only tunneling from the protocol config is used")
            return
        }

        val splitTunnelType = config.optInt("splitTunnelType")
        if (splitTunnelType == SPLIT_TUNNEL_DISABLE) return
        val splitTunnelSites = config.getJSONArray("splitTunnelSites")
        val addressHandlerFunc = when (splitTunnelType) {
            SPLIT_TUNNEL_INCLUDE -> ::includeAddress
            SPLIT_TUNNEL_EXCLUDE -> ::excludeAddress

            else -> throw BadConfigException("Unexpected value of the 'splitTunnelType' parameter: $splitTunnelType")
        }

        for (i in 0 until splitTunnelSites.length()) {
            val address = InetNetwork.parse(splitTunnelSites.getString(i))
            addressHandlerFunc(address)
        }
    }

    protected fun ProtocolConfig.Builder.configAppSplitTunneling(config: JSONObject) {
        val splitTunnelType = config.optInt("appSplitTunnelType")
        if (splitTunnelType == SPLIT_TUNNEL_DISABLE) return
        val splitTunnelApps = config.getJSONArray("splitTunnelApps")
        val appHandlerFunc = when (splitTunnelType) {
            SPLIT_TUNNEL_INCLUDE -> ::includeApplication
            SPLIT_TUNNEL_EXCLUDE -> ::excludeApplication

            else -> throw BadConfigException("Unexpected value of the 'appSplitTunnelType' parameter: $splitTunnelType")
        }

        for (i in 0 until splitTunnelApps.length()) {
            appHandlerFunc(splitTunnelApps.getString(i))
        }
    }

    protected fun interfaceRoutes(config: ProtocolConfig): Set<Route> {
        val ordered = mutableListOf<Route>()
        if (Build.BRAND == "samsung") config.dnsServers.forEach { ordered += Route(InetNetwork(it), true) }
        ordered.addAll(config.routes)
        return compactRoutes(if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU)
            ordered.filter { it.include } else ordered)
    }

    protected fun applyInterfaceRoutes(routes: Collection<Route>, vpnBuilder: Builder) {
        for ((inetNetwork, include) in routes) {
            if (include) vpnBuilder.addRoute(inetNetwork)
            else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) vpnBuilder.excludeRoute(inetNetwork)
        }
    }

    protected open fun buildVpnInterface(config: ProtocolConfig, vpnBuilder: Builder) =
        buildVpnInterfaceWithRoutes(config, vpnBuilder, interfaceRoutes(config))

    /** Metadata is configured once; a bootstrap may only append the exact final route projection. */
    protected fun buildVpnInterfaceWithRoutes(config: ProtocolConfig, vpnBuilder: Builder, routes: Collection<Route>) {
        vpnBuilder.setSession(VPN_SESSION_NAME)

        for (addr in config.addresses) {
            Log.d(TAG, "addAddress: $addr")
            vpnBuilder.addAddress(addr)
        }

        for (addr in config.dnsServers) {
            Log.d(TAG, "addDnsServer: $addr")
            vpnBuilder.addDnsServer(addr)
        }

        config.searchDomain?.let {
            Log.d(TAG, "addSearchDomain: $it")
            vpnBuilder.addSearchDomain(it)
        }

        applyInterfaceRoutes(routes, vpnBuilder)

        if (!config.useIncludedUnion) {
            for (app in config.includedApplications) {
                Log.d(TAG, "addAllowedApplication")
                vpnBuilder.addAllowedApplication(app)
            }
        }

        for (app in config.excludedApplications) {
            Log.d(TAG, "addDisallowedApplication")
            vpnBuilder.addDisallowedApplication(app)
        }

        Log.d(TAG, "setMtu: ${config.mtu}")
        vpnBuilder.setMtu(config.mtu)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            config.httpProxy?.let {
                Log.d(TAG, "setHttpProxy: $it")
                vpnBuilder.setHttpProxy(it)
            }
        }

        if (config.allowAllAF) {
            Log.d(TAG, "allowFamily")
            vpnBuilder.allowFamily(OsConstants.AF_INET)
            vpnBuilder.allowFamily(OsConstants.AF_INET6)
        }

        Log.d(TAG, "setBlocking: ${config.blockingMode}")
        vpnBuilder.setBlocking(config.blockingMode)
        vpnBuilder.setUnderlyingNetworks(null)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
            vpnBuilder.setMetered(false)
    }
}

private fun VpnService.Builder.addAddress(addr: InetNetwork) = addAddress(addr.address, addr.mask)
private fun VpnService.Builder.addRoute(addr: InetNetwork) = addRoute(addr.address, addr.mask)

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
private fun VpnService.Builder.excludeRoute(addr: InetNetwork) = excludeRoute(IpPrefix(addr.address, addr.mask))
