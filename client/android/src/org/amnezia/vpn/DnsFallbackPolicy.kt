package org.amnezia.vpn

/** No network or Android dependencies: one generation owns every asynchronous decision. */
internal class DnsFallbackPolicy(private val threshold: Int, private val graceMs: Long = 20_000) {
    enum class Phase { PRIMARY, PREPARING, DNS, STOPPED }
    private var generation = 0L
    private var startedMs = 0L
    private var failures = 0
    private var retryAtMs = 0L
    private var retryDelayMs = 30_000L
    @Volatile var phase = Phase.STOPPED
        private set

    init { require(threshold in 2..8 && graceMs >= 0) }
    @Synchronized fun begin(nowMs: Long): Long {
        generation++; startedMs = nowMs; failures = 0; retryAtMs = nowMs
        retryDelayMs = 30_000; phase = Phase.PRIMARY
        return generation
    }
    @Synchronized fun current(ticket: Long) = ticket == generation && phase != Phase.STOPPED
    @Synchronized fun primarySample(ticket: Long, success: Boolean, mobileAvailable: Boolean, nowMs: Long): Boolean {
        if (!current(ticket) || phase != Phase.PRIMARY || nowMs < startedMs) return false
        if (success) { failures = 0; retryDelayMs = 30_000; return false }
        failures = (failures + 1).coerceAtMost(threshold)
        if (!mobileAvailable || failures < threshold || nowMs - startedMs < graceMs || nowMs < retryAtMs) return false
        phase = Phase.PREPARING
        return true
    }
    @Synchronized fun dnsVerified(ticket: Long): Boolean {
        if (!current(ticket) || phase !in setOf(Phase.PREPARING, Phase.DNS)) return false
        phase = Phase.DNS; failures = 0
        return true
    }
    @Synchronized fun retryPrimary(ticket: Long, nowMs: Long): Boolean {
        if (!current(ticket)) return false
        phase = Phase.PRIMARY; failures = 0; retryAtMs = nowMs + retryDelayMs
        retryDelayMs = (retryDelayMs * 2).coerceAtMost(300_000)
        return true
    }
    @Synchronized fun stop() { generation++; failures = 0; phase = Phase.STOPPED }
}
