package org.amnezia.vpn

import kotlinx.coroutines.*
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

fun runDnsTunnelReadinessTests(): Int = runBlocking {
    var checks=0
    fun verify(value:Boolean) { checks++;check(value) { "DNS TUN readiness test $checks" } }
    verify(dnsReplacementNetwork(setOf(1), listOf(1))==null)
    verify(dnsReplacementNetwork(setOf(1), listOf(1,2))==null)
    verify(dnsReplacementNetwork(setOf(1), listOf(2))==2)
    verify(dnsReplacementNetwork(setOf(1), emptyList<Int>())==null)
    val started=System.nanoTime();var probes=0
    val late=awaitDnsTunnelReady(timeoutMs=1600, pollMs=25, isCurrent={true}, selectNetwork={
        if ((System.nanoTime()-started)/1_000_000 >= 600) 2 else null
    }, verify={network,budget -> probes++;verify(network==2 && budget in 1..1600);true})
    verify(late==2 && probes==1)
    verify((System.nanoTime()-started)/1_000_000 >= 600)
    val missing=awaitDnsTunnelReady<Int>(timeoutMs=150, pollMs=20, isCurrent={true}, selectNetwork={null}, verify={_,_ -> error("No network must never probe")})
    verify(missing==null)
    val failed=awaitDnsTunnelReady(timeoutMs=150, pollMs=20, isCurrent={true}, selectNetwork={2}, verify={_,_ -> false})
    verify(failed==null)
    var current=true
    val stale=awaitDnsTunnelReady(timeoutMs=100, pollMs=10, isCurrent={current}, selectNetwork={2}, verify={_,_ -> current=false;true})
    verify(stale==null)
    var selected:Int?=2
    val replaced=awaitDnsTunnelReady(timeoutMs=100, pollMs=10, isCurrent={true}, selectNetwork={selected}, verify={_,_ -> selected=null;true})
    verify(replaced==null)
    val cancelledProbe=AtomicBoolean(false);val entered=CompletableDeferred<Unit>()
    val job=launch {
        awaitDnsTunnelReady(timeoutMs=2000, pollMs=10, isCurrent={true}, selectNetwork={2}, verify={_,_ ->
            suspendCancellableCoroutine<Boolean> { continuation ->
                continuation.invokeOnCancellation { cancelledProbe.set(true) }
                entered.complete(Unit)
            }
        })
        error("Cancelled readiness must not publish a result")
    }
    entered.await();job.cancelAndJoin();verify(cancelledProbe.get() && job.isCancelled)
    val timedOutProbe=AtomicBoolean(false)
    val bounded=awaitDnsTunnelReady(timeoutMs=100, pollMs=10, isCurrent={true}, selectNetwork={2}, verify={_,_ ->
        suspendCancellableCoroutine<Boolean> { continuation -> continuation.invokeOnCancellation { timedOutProbe.set(true) } }
    })
    verify(bounded==null && timedOutProbe.get())
    checks
}
