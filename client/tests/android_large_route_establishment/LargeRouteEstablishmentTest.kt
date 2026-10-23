package org.amnezia.vpn.protocol

import android.content.Context
import android.net.*
import android.os.ParcelFileDescriptor
import android.provider.Settings
import kotlinx.coroutines.*
import org.amnezia.vpn.util.net.InetNetwork
import java.io.File

private var checks=0
private fun verify(value:Boolean){checks++;check(value)}
private val address=InetNetwork("10.1.1.2",32)
private val policyRoutes=listOf(Route(InetNetwork("0.0.0.0",0),true),Route(InetNetwork("77.88.0.0",16),false))
private fun lp(final:Boolean)=LinkProperties().apply {
    interfaceName=if(final)"tun2" else "tun1"
    linkAddresses=listOf(LinkAddress(address.address,address.mask))
    this.routes=(if(final)policyRoutes else policyRoutes.take(1)).map { RouteInfo(IpPrefix(it.inetNetwork.address,it.inetNetwork.mask),if(it.include)1 else 9) }
}
private suspend fun scenario(mode:String) = supervisorScope {
    Settings.Global.mode="off"
    val cm=ConnectivityManager();val small=ParcelFileDescriptor(1);val full=ParcelFileDescriptor(2)
    val n=Network(2);var configured=0;var appended=0
    val builder=VpnService.Builder { call ->
        if(call==1) {
            cm.emit(n,NetworkCapabilities(ownerUid=if(mode=="foreign")2000 else 1000),lp(false))
            small
        } else {
            if(mode=="lost") cm.lose(n)
            else cm.emit(if(mode=="replacement")Network(3) else n,NetworkCapabilities(),lp(true).apply {
                if(mode=="missing-route")this.routes=emptyList()
            })
            if(mode=="null-final")null else full
        }
    }
    val task=async { LargeRouteEstablishment(Context(cm)).establish(builder,setOf(address),policyRoutes,
        {configured++},{appended++}) }
    if(mode in listOf("foreign","replacement","missing-route")) {
        delay(50);task.cancel();try{task.await()}catch(_:CancellationException){}
        verify(small.closes==1);verify(full.closes==if(builder.calls==2)1 else 0)
    } else if(mode in listOf("lost","null-final")) {
        try{task.await();error("expected failure")}catch(_:VpnStartException){}
        verify(small.closes==1);verify(full.closes==if(mode=="lost")1 else 0)
    } else {
        val result=task.await();verify(result===full);verify(small.closes==1);verify(full.closes==0)
        verify(configured==1&&appended==1&&builder.calls==2);result!!.close()
    }
    verify(cm.unregisters==1)
}
fun main(args:Array<String>)=runBlocking {
    val actual=compactRoutes(File(args[0]).readLines().filter{it.isNotBlank()}.map{Route(InetNetwork.parse(it),false)}+
        Route(InetNetwork("0.0.0.0",0),true))
    verify(actual.size==2421)
    verify(routeDestinationParcelExceedsRecommendation(actual))
    verify(!routeDestinationParcelExceedsRecommendation(policyRoutes))
    verify(bootstrapRouteSubset(policyRoutes)==policyRoutes.take(1))
    verify(bootstrapRouteSubset(policyRoutes.drop(1))==null)
    verify(bootstrapRouteSubset(policyRoutes+Route(InetNetwork("::",0),true))!!.size==2)
    scenario("success");scenario("foreign");scenario("replacement");scenario("missing-route")
    scenario("lost");scenario("null-final")
    for(mode in listOf("hostname",null)) {
        Settings.Global.mode=mode
        val cm=ConnectivityManager();val b=VpnService.Builder{error("must retain legacy path")}
        verify(LargeRouteEstablishment(Context(cm)).establish(b,setOf(address),policyRoutes,{error("configured")},{})==null)
        verify(b.calls==0&&cm.callback==null)
    }
    Settings.Global.mode="off"
    val cm=ConnectivityManager();val old=Network(1);cm.existing[old]=NetworkCapabilities()
    val b=VpnService.Builder{error("old agent must not be bootstrapped")}
    verify(LargeRouteEstablishment(Context(cm)).establish(b,setOf(address),policyRoutes,{},{})==null)
    verify(b.calls==0&&cm.unregisters==1)
    for (mode in listOf("unregister","close","handoff-cancel")) supervisorScope {
        val manager=ConnectivityManager();val first=ParcelFileDescriptor(1);val last=ParcelFileDescriptor(2)
        val network=Network(9)
        manager.unregisterFailures=if(mode=="unregister")1 else 0
        first.failClose=mode=="close"
        val builder=VpnService.Builder { call ->manager.emit(network,NetworkCapabilities(),lp(call==2));if(call==1)first else last}
        val helper=LargeRouteEstablishment(Context(manager))
        val task=async { helper.establish(builder,setOf(address),policyRoutes,{},{}) }
        if(mode=="handoff-cancel")manager.unregisterHook={task.cancel()}
        try{task.await();error("expected failure")}catch(_:Exception){}
        verify(first.closes>=1&&last.closes==1)
        verify(helper.cleanupConfirmed==(mode!="close"))
        verify(manager.callback==null)
        if(mode=="unregister")verify(manager.unregisters==2)
    }
    supervisorScope {
        val manager=ConnectivityManager();val first=ParcelFileDescriptor(1)
        val builder=VpnService.Builder {first}
        try { LargeRouteEstablishment(Context(manager)).establish(builder,setOf(address),policyRoutes,{},{})
            error("expected real bounded timeout") } catch(_:TimeoutCancellationException){}
        verify(first.closes==1&&builder.calls==1&&manager.unregisters==1)
    }
    supervisorScope {
        val manager=ConnectivityManager();val oldNetwork=Network(40);val fresh=Network(41)
        manager.existing[oldNetwork]=NetworkCapabilities()
        val first=ParcelFileDescriptor(1);val last=ParcelFileDescriptor(2)
        val builder=VpnService.Builder{call->manager.emit(fresh,NetworkCapabilities(),lp(call==2));if(call==1)first else last}
        launch {delay(30);manager.lose(oldNetwork)}
        val result=LargeRouteEstablishment(Context(manager)).establish(builder,setOf(address),policyRoutes,{},{})
        verify(result===last&&builder.calls==2&&first.closes==1);result!!.close()
    }
    supervisorScope {
        val manager=ConnectivityManager();val first=ParcelFileDescriptor(1);var allowed=true
        val builder=VpnService.Builder{manager.emit(Network(50),NetworkCapabilities(),lp(false));first}
        try{LargeRouteEstablishment(Context(manager)).establish(builder,setOf(address),policyRoutes,{},
            {allowed=false},{if(!allowed)throw CancellationException("owner")});error("expected owner cancel")}
        catch(_:CancellationException){}
        verify(builder.calls==1&&first.closes==1&&manager.unregisters==1)
    }
    println("actual-helper checks=$checks; actual-fixture nested-prefix parcel recommendation exceeded=true")
}


