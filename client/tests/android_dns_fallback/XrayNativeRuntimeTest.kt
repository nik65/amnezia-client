package org.amnezia.vpn.protocol.xray

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.*

fun runXrayNativeRuntimeTests(): Int {
    var checks = 0
    fun verify(value: Boolean) { checks++; check(value) { "Xray native lane test $checks" } }
    val caller = Thread.currentThread()
    val owner = XrayNativeRuntime.call { XrayNativeRuntime.requireOwner(); Thread.currentThread() }
    verify(owner !== caller)
    verify(runCatching { XrayNativeRuntime.requireOwner() }.isFailure)
    verify(XrayNativeRuntime.call { XrayNativeRuntime.call { Thread.currentThread() === owner } })
    val marker = IllegalArgumentException("inert native failure")
    verify(runCatching { XrayNativeRuntime.call<Int> { throw marker } }.exceptionOrNull() === marker)
    verify(XrayNativeRuntime.call { Thread.currentThread() === owner })
    val running = AtomicInteger(); val entries = AtomicInteger()
    val callers = Executors.newFixedThreadPool(8)
    try {
        val jobs = (0 until 32).map { callers.submit<Boolean> {
            XrayNativeRuntime.call {
                check(Thread.currentThread() === owner)
                check(running.incrementAndGet() == 1)
                Thread.sleep(2)
                entries.incrementAndGet(); running.decrementAndGet(); true
            }
        } }
        verify(jobs.all { it.get(5, TimeUnit.SECONDS) })
        verify(entries.get() == 32 && running.get() == 0)
    } finally { callers.shutdownNow() }
    val ui = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    try {
        runBlocking(ui) {
            val uiThread = Thread.currentThread()
            var heartbeat = false
            val entry = async {
                XrayNativeRuntime.await { Thread.sleep(40); Thread.currentThread() }
            }
            launch { heartbeat = true }.join()
            verify(heartbeat && !entry.isCompleted) // Startup suspends the caller instead of blocking its lane.
            verify(entry.await() === owner && Thread.currentThread() === uiThread)
            verify(XrayNativeRuntime.await { XrayNativeRuntime.call { Thread.currentThread() === owner } })
            verify(runCatching { XrayNativeRuntime.await<Int> { throw marker } }.exceptionOrNull() === marker)
        }
    } finally { ui.close() }
    return checks
}
