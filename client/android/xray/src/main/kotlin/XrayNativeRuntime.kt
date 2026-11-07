package org.amnezia.vpn.protocol.xray

import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext

/**
 * One process-wide native lane. A thread that entered the AWG Go runtime must never
 * enter this independent gomobile Go runtime (confirmed Android cgo TLS corruption).
 * Do not share this executor with AWG or pass its dispatcher to another backend.
 */
internal object XrayNativeRuntime {
    @Volatile private var owner: Thread? = null
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread({ owner = Thread.currentThread(); runnable.run() }, "amnezia-xray-native").apply { isDaemon = true }
    }
    private val dispatcher = executor.asCoroutineDispatcher()

    fun requireOwner() { check(Thread.currentThread() === owner) { "Xray native entry outside exclusive lane" } }

    /** Suspend startup instead of blocking Android Main while native initialization runs. */
    suspend fun <T> await(block: () -> T): T = withContext(dispatcher) { requireOwner(); block() }

    /** Cleanup callers already execute on IO. Reentry on our own lane must not submit-and-wait. */
    fun <T> call(block: () -> T): T {
        if (Thread.currentThread() === owner) return block()
        try { return executor.submit(Callable { requireOwner(); block() }).get() }
        catch (error: ExecutionException) { throw (error.cause ?: error) }
        catch (error: InterruptedException) { Thread.currentThread().interrupt(); throw error }
    }
}
