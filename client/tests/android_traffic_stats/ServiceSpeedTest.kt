package org.amnezia.vpn.util.net
import kotlinx.coroutines.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
fun main()=runBlocking {
 var checks=0
 suspend fun scenario(mode:String)=supervisorScope {
  val entered=CountDownLatch(1);val release=CountDownLatch(1)
  val stats=TrafficStats({entered.countDown();check(release.await(2,TimeUnit.SECONDS));TrafficCounterSample("own",1,1)},{1})
  val service=ActualServiceSpeed(stats)
  val task=async {service.tick()}
  withContext(Dispatchers.IO){check(entered.await(2,TimeUnit.SECONDS))}
  when(mode){"session"->service.activeNativeSession=Any();"protocol"->service.vpnProto=VpnProto(Any());"cancel"->task.cancel()}
  release.countDown();try{task.await()}catch(_:CancellationException){}
  checks++;check(service.serviceNotification.updates==if(mode=="normal")1 else 0)
 }
 scenario("normal");scenario("session");scenario("protocol");scenario("cancel")
 println("actual service-speed checks=$checks")
}
