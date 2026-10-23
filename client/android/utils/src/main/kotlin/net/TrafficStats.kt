package org.amnezia.vpn.util.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.os.Build
import android.os.Process
import android.os.SystemClock
import kotlin.math.roundToLong

private const val BYTE = 1L
private const val KiB = BYTE shl 10
private const val MiB = KiB shl 10
private const val GiB = MiB shl 10
private const val TiB = GiB shl 10

internal data class TrafficCounterSample(val source: String, val rx: Long, val tx: Long)

class TrafficStats internal constructor(
    private val readSample: () -> TrafficCounterSample?,
    private val elapsedRealtime: () -> Long
) {
    constructor(context: Context) : this({ readOwnedTraffic(context) }, { SystemClock.elapsedRealtime() })
    private var lastSample: TrafficCounterSample? = null
    private var lastTimestamp = 0L

    @Synchronized
    fun reset() {
        lastSample = readSample()?.takeIf { it.rx >= 0 && it.tx >= 0 }
        lastTimestamp = elapsedRealtime()
    }

    @Synchronized
    fun isSupported(): Boolean = lastSample != null

    @Synchronized
    fun getSpeed(): TrafficData {
        val now = elapsedRealtime()
        val sample = readSample()?.takeIf { it.rx >= 0 && it.tx >= 0 }
        val previous = lastSample
        val elapsed = now - lastTimestamp
        lastSample = sample
        lastTimestamp = now
        if (sample == null || previous == null || sample.source != previous.source || elapsed <= 0 ||
            sample.rx < previous.rx || sample.tx < previous.tx) return TrafficData.ZERO
        return TrafficData(sample.rx, sample.tx).diff(TrafficData(previous.rx, previous.tx), elapsed / 1000.0)
    }

    companion object {
        private fun readOwnedTraffic(context: Context): TrafficCounterSample? {
            val uid = Process.myUid()
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S)
                return TrafficCounterSample("uid:$uid", TrafficStats.getUidRxBytes(uid), TrafficStats.getUidTxBytes(uid))
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
            fun source(): Pair<Long, String>? {
                val owned = cm.allNetworks.mapNotNull { network ->
                    val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
                    if (caps.ownerUid != uid || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
                    val iface = cm.getLinkProperties(network)?.interfaceName?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                    network.networkHandle to iface
                }
                return owned.singleOrNull()
            }
            return try {
                val selected = source() ?: return null
                val rx = TrafficStats.getRxBytes(selected.second)
                val tx = TrafficStats.getTxBytes(selected.second)
                if (source() != selected) null
                else TrafficCounterSample("vpn:$uid:${selected.first}:${selected.second}", rx, tx)
            } catch (_: SecurityException) { null }
        }
    }

    class TrafficData(val rx: Long, val tx: Long) {

        private var _rxString: String? = null
        val rxString: String
            get() {
                if (_rxString == null) _rxString = rx.speedToString()
                return _rxString ?: throw AssertionError("Set to null by another thread")
            }

        private var _txString: String? = null
        val txString: String
            get() {
                if (_txString == null) _txString = tx.speedToString()
                return _txString ?: throw AssertionError("Set to null by another thread")
            }

        fun diff(other: TrafficData, elapsedSeconds: Double): TrafficData {
            val rx = ((this.rx - other.rx) / elapsedSeconds).round()
            val tx = ((this.tx - other.tx) / elapsedSeconds).round()
            return if (rx == 0L && tx == 0L) ZERO else TrafficData(rx, tx)
        }

        private fun Double.round() = if (isNaN()) 0L else roundToLong()

        private fun Long.speedToString() =
            when {
                this < KiB -> formatSize(this, BYTE, "B/s")
                this < MiB -> formatSize(this, KiB, "KiB/s")
                this < GiB -> formatSize(this, MiB, "MiB/s")
                this < TiB -> formatSize(this, GiB, "GiB/s")
                else -> formatSize(this, TiB, "TiB/s")
            }

        private fun formatSize(bytes: Long, divider: Long, unit: String): String {
            val s = (bytes.toDouble() / divider * 100).roundToLong() / 100.0
            return "${s.toString().removeSuffix(".0")} $unit"
        }

        companion object {
            val ZERO: TrafficData = TrafficData(0L, 0L)
        }
    }
}
