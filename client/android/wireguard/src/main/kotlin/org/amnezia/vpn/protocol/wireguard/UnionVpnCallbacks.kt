package org.amnezia.vpn.protocol.wireguard

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import androidx.annotation.Keep
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.ProtocolErrorReason
import org.amnezia.vpn.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

/** One native tunnel owns this object; callbacks are released after native cleanup. */
@Keep
class UnionVpnCallbacks private constructor(
    private val connectivity: ConnectivityManager,
    private val includedUids: Set<Int>,
    private val protect: (Int) -> Boolean
) {
    private val ownerWarning = AtomicBoolean(false)

    fun protectSocket(fd: Int): Boolean = fd >= 0 && protect(fd)

    // JNI uses these numeric addresses without parsing/resolving hostnames.
    fun ownerSelected(protocol: Int, source: ByteArray, sourcePort: Int,
                      destination: ByteArray, destinationPort: Int): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1
        return try {
            val uid = connectivity.getConnectionOwnerUid(protocol,
                InetSocketAddress(InetAddress.getByAddress(source), sourcePort),
                InetSocketAddress(InetAddress.getByAddress(destination), destinationPort))
            when {
                uid < 0 -> { warnOwnerUnavailable(); -1 }
                uid in includedUids -> 1
                else -> 0
            }
        } catch (error: Exception) {
            warnOwnerUnavailable()
            -1
        }
    }

    private fun warnOwnerUnavailable() {
        if (ownerWarning.compareAndSet(false, true))
            Log.w("Wireguard", "Connection owner lookup unavailable; unidentified flows stay in VPN")
    }

    companion object {
        fun create(context: Context, applications: Set<String>, protect: (Int) -> Boolean): UnionVpnCallbacks {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q)
                throw BadConfigException("Combining included sites and apps requires Android 10 or newer",
                    reasonCode = ProtocolErrorReason.COMBINED_ROUTING_REQUIRES_ANDROID_10)
            val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: throw BadConfigException("Connection owner service is unavailable")
            val uids = applications.map { application ->
                try {
                    context.packageManager.getApplicationInfo(application, 0).uid
                } catch (error: android.content.pm.PackageManager.NameNotFoundException) {
                    throw BadConfigException("An included application is no longer installed")
                }
            }.toSet()
            return UnionVpnCallbacks(connectivity, uids, protect)
        }
    }
}
