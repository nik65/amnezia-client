package org.amnezia.vpn

internal const val REMOTE_LOG_HEARTBEAT_INTERVAL_MS = 60_000L
internal const val REMOTE_LOG_SAMPLE_MAX_AGE_MS = 15_000L

// Protocols use zero/zero as EMPTY_STATISTICS when native counters are absent.
// A genuinely idle zero/zero is ambiguous too, so never call it an observed sample.
internal fun remoteLogSampleCountersAvailable(rxBytes: Long?, txBytes: Long?): Boolean =
    rxBytes != null && txBytes != null && rxBytes >= 0 && txBytes >= 0 &&
        (rxBytes > 0 || txBytes > 0)

/** Monotonic service liveness; never claims Internet or collector health. */
internal fun remoteLogHeartbeatDue(lastElapsedMs: Long?, nowElapsedMs: Long): Boolean =
    nowElapsedMs >= 0 && (lastElapsedMs == null || nowElapsedMs < lastElapsedMs ||
        nowElapsedMs - lastElapsedMs >= REMOTE_LOG_HEARTBEAT_INTERVAL_MS)

/** Only already sampled aggregate counters are emitted; no addresses or identities. */
internal fun remoteLogServiceHeartbeatLine(nowElapsedMs: Long, sampleElapsedMs: Long?,
                                         rxBytes: Long?, txBytes: Long?): String {
    val age = sampleElapsedMs?.let { nowElapsedMs - it }
    val fresh = age != null && age in 0..REMOTE_LOG_SAMPLE_MAX_AGE_MS &&
        remoteLogSampleCountersAvailable(rxBytes, txBytes)
    return if (fresh) {
        "RemoteLogServiceSample connected=true counters=fresh rxBytes=$rxBytes txBytes=$txBytes sampleAgeMs=$age"
    } else {
        "RemoteLogServiceSample connected=true counters=unknown"
    }
}
