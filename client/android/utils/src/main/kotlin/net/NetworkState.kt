package org.amnezia.vpn.util.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.ConnectivityManager.NetworkCallback
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET
import android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import androidx.core.content.getSystemService
import kotlin.LazyThreadSafetyMode.NONE
import kotlinx.coroutines.delay
import org.amnezia.vpn.util.Log

private const val TAG = "NetworkState"

class NetworkState(
    private val context: Context,
    private val onNetworkChange: (Long) -> Unit
) {
    private var currentNetwork: Network? = null
    private var validated: Boolean = false
    private var isListenerBound = false
    private var decisionEpoch = 0L
    private var previousNetworkHandle = 0L

    private val handler: Handler by lazy(NONE) {
        Handler(context.mainLooper)
    }

    private val connectivityManager: ConnectivityManager by lazy(NONE) {
        context.getSystemService<ConnectivityManager>()!!
    }

    private val networkRequest: NetworkRequest by lazy(NONE) {
        NetworkRequest.Builder()
            .addCapability(NET_CAPABILITY_INTERNET)
            .build()
    }

    private val networkCallback: NetworkCallback by lazy(NONE) {
        object : NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.v(TAG, "onAvailable: $network")
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                Log.v(TAG, "onCapabilitiesChanged: $network, $networkCapabilities")
                checkNetworkState(network, networkCapabilities)
            }

            private fun checkNetworkState(network: Network, networkCapabilities: NetworkCapabilities) {
                if (currentNetwork == null) {
                    currentNetwork = network
                    validated = networkCapabilities.hasCapability(NET_CAPABILITY_VALIDATED)
                } else {
                    val networkChanged = currentNetwork != network
                    if (networkChanged) {
                        previousNetworkHandle = currentNetwork!!.networkHandle
                        decisionEpoch++
                        currentNetwork = network
                        validated = false
                    }
                    if (!validated) {
                        validated = networkCapabilities.hasCapability(NET_CAPABILITY_VALIDATED)
                        if (networkChanged || validated) {
                            // Persist only bounded metadata: never capabilities.toString(),
                            // SSID, addresses, subscriptions, or other network identifiers.
                            val outcome = if (validated) "requested" else "deferred_unvalidated"
                            Log.d(TAG, "ReconnectDecision cause=validated_new_network epoch=$decisionEpoch " +
                                "oldHandle=$previousNetworkHandle newHandle=${network.networkHandle} " +
                                "wifi=${networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)} " +
                                "cellular=${networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)} " +
                                "ethernet=${networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)} " +
                                "vpn=${networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)} " +
                                "validated=$validated outcome=$outcome")
                        }
                        if (validated) onNetworkChange(decisionEpoch)
                    }
                }
            }

            override fun onBlockedStatusChanged(network: Network, blocked: Boolean) {
                Log.v(TAG, "onBlockedStatusChanged: $network, $blocked")
            }

            override fun onLost(network: Network) {
                Log.v(TAG, "onLost: $network")
            }
        }
    }

    suspend fun bindNetworkListener() {
        if (isListenerBound) return
        Log.d(TAG, "Bind network listener")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            connectivityManager.registerBestMatchingNetworkCallback(networkRequest, networkCallback, handler)
        } else {
            val numberAttempts = 300
            var attemptCount = 0
            while(true) {
                try {
                    connectivityManager.requestNetwork(networkRequest, networkCallback, handler)
                    break
                } catch (e: SecurityException) {
                    Log.e(TAG, "Failed to bind network listener: $e")
                    // Android 11 bug: https://issuetracker.google.com/issues/175055271
                    if (e.message?.startsWith("Package android does not belong to") == true) {
                        if (++attemptCount > numberAttempts) {
                            throw e
                        }
                        delay(1000)
                        continue
                    } else {
                        throw e
                    }
                }
            }
        }
        isListenerBound = true
    }

    fun unbindNetworkListener() {
        if (!isListenerBound) return
        Log.d(TAG, "Unbind network listener")
        connectivityManager.unregisterNetworkCallback(networkCallback)
        isListenerBound = false
        currentNetwork = null
        validated = false
    }
}
