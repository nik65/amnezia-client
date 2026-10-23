package org.amnezia.vpn.util.net
import android.net.*
import android.os.SystemClock
import android.content.Context
private var checks=0
private fun verify(v:Boolean){checks++;check(v)}
fun main(){
 var now=0L;var sample:TrafficCounterSample?=TrafficCounterSample("tun0",100,200)
 val stats=TrafficStats({sample},{now});stats.reset();now=1000;sample=TrafficCounterSample("tun0",200,400)
 verify(stats.getSpeed().rx==100L);now=2000;sample=TrafficCounterSample("tun1",9000,9000);verify(stats.getSpeed().rx==0L)
 now=3000;sample=TrafficCounterSample("tun1",9100,9200);verify(stats.getSpeed().tx==200L)
 now=4000;sample=TrafficCounterSample("tun1",-1,9300);verify(stats.getSpeed().rx==0L&&!stats.isSupported())
 now=5000;sample=TrafficCounterSample("tun1",9400,9400);verify(stats.getSpeed().rx==0L&&stats.isSupported())
 now=6000;sample=TrafficCounterSample("tun1",10,20);verify(stats.getSpeed().rx==0L)
 sample=TrafficCounterSample("tun1",30,40);verify(stats.getSpeed().rx==0L)
 now=7000;sample=null;verify(stats.getSpeed().rx==0L&&!stats.isSupported())
 val cm=ConnectivityManager();val n=Network(1);cm.networks+=n;cm.caps[n]=NetworkCapabilities(1000);cm.lp[n]=LinkProperties("tun1")
 val actual=TrafficStats(Context(cm));SystemClock.now=0;actual.reset();SystemClock.now=1000
 android.net.TrafficStats.rx=200;android.net.TrafficStats.tx=400
 verify(actual.getSpeed().rx==100L&&android.net.TrafficStats.readIface=="tun1")
 cm.caps[n]=NetworkCapabilities(2000);SystemClock.now=2000;verify(actual.getSpeed().rx==0L&&!actual.isSupported())
 verify(android.net.TrafficStats.uidReads==0)
 cm.caps[n]=NetworkCapabilities(1000);val other=Network(2);cm.networks+=other;cm.caps[other]=NetworkCapabilities(1000);cm.lp[other]=LinkProperties("tun2")
 actual.reset();verify(!actual.isSupported());cm.networks.remove(other)
 actual.reset();android.net.TrafficStats.hook={cm.lp[n]=LinkProperties("tun3")};SystemClock.now=3000
 verify(actual.getSpeed().rx==0L&&!actual.isSupported());android.net.TrafficStats.hook={}
 val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
 val running=java.util.concurrent.atomic.AtomicInteger();val max=java.util.concurrent.atomic.AtomicInteger()
 val serial=TrafficStats({val count=running.incrementAndGet();max.updateAndGet{it.coerceAtLeast(count)}
   entered.countDown();check(release.await(2,java.util.concurrent.TimeUnit.SECONDS));running.decrementAndGet();TrafficCounterSample("own",1,1)},{1L})
 val one=Thread{serial.reset()};val two=Thread{serial.getSpeed()};one.start();check(entered.await(2,java.util.concurrent.TimeUnit.SECONDS));two.start()
 Thread.sleep(30);verify(running.get()==1);release.countDown();one.join(2000);two.join(2000)
 verify(!one.isAlive&&!two.isAlive&&max.get()==1)
 println("staged actual TrafficStats checks=$checks")
}
