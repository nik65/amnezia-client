package org.amnezia.vpn

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeoutOrNull

/** A replacement cannot borrow an old VPN handle or select through ambiguous ownership. */
internal fun <T> dnsReplacementNetwork(previous: Set<T>, owned: List<T>): T? =
    owned.singleOrNull()?.takeUnless { it in previous }

/** A native start is not a published Android network, nor proof of traffic through its TUN. */
internal suspend fun <T> awaitDnsTunnelReady(
    timeoutMs: Long = 12_000, pollMs: Long = 100,
    isCurrent: () -> Boolean, selectNetwork: () -> T?,
    verify: suspend (T, remainingMs: Long) -> Boolean
): T? {
    require(timeoutMs in 1..30_000 && pollMs in 1..1000)
    return withTimeoutOrNull(timeoutMs) {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (isCurrent()) {
            currentCoroutineContext().ensureActive()
            val remainingMs = ((deadline - System.nanoTime()) / 1_000_000).coerceAtLeast(0)
            if (remainingMs == 0L) return@withTimeoutOrNull null
            val network = selectNetwork()
            if (network != null && verify(network, remainingMs)) {
                currentCoroutineContext().ensureActive()
                if (isCurrent() && selectNetwork() == network) return@withTimeoutOrNull network
            }
            delay(pollMs.coerceAtMost(remainingMs))
        }
        null
    }
}
