import org.amnezia.vpn.protocol.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import java.io.File

private const val instance="11111111-1111-4111-8111-111111111111"
private const val activation="22222222-2222-4222-8222-222222222222"
private const val nonce="33333333-3333-4333-8333-333333333333"
private const val request="44444444-4444-4444-8444-444444444444"
private fun descriptor(id: String=activation)=NativeSessionDescriptor(NativeSessionIdentity(instance,id,nonce),"server-local-id","AWG")
private val peer=java.util.Base64.getEncoder().encodeToString(ByteArray(32))
private var checks=0
private fun verify(ok:Boolean){checks++;check(ok){"native session check $checks"}}
fun main(args:Array<String>){
 val threadFailure=java.util.concurrent.atomic.AtomicReference<Throwable?>()
 val mainThread=Thread.currentThread()
 Thread.setDefaultUncaughtExceptionHandler {thread,failure->if(thread===mainThread)failure.printStackTrace() else threadFailure.compareAndSet(null,failure)}
 val firstGeneration=NativeSessionWire.nextBindingGeneration();verify(NativeSessionWire.nextBindingGeneration()>firstGeneration)
 val d=descriptor();verify(NativeSessionIdentity.parseExpected(d.identity.toJson())==d.identity)
 for(bad in listOf("{}",d.identity.toJson().dropLast(1)+",\"connectionNonce\":\"$nonce\"}",d.identity.toJson().replace("connectionNonce","unknown"),d.identity.toJson().replace(nonce,"bad"),d.identity.toJson().dropLast(1)+",}","\u00a0"+d.identity.toJson()))verify(NativeSessionIdentity.parseExpected(bad)==null)
 for(control in listOf('\u000b','\u000c'))verify(NativeSessionIdentity.parseExpected(d.identity.toJson().replace(":",control+":"))==null)
 verify(!NativeSessionWire.serverId("\ud800")&&!NativeSessionWire.serverId("\udc00"));verify(NativeSessionWire.serverId("\ud83d\ude00"))
 val receiverGate=ServiceEventBindingGate();val oldReceiver=receiverGate.bind();verify(receiverGate.accepts(oldReceiver));val newReceiver=receiverGate.bind();verify(!receiverGate.accepts(oldReceiver)&&receiverGate.accepts(newReceiver));receiverGate.invalidate();verify(!receiverGate.accepts(newReceiver))
 val guard=NativeSessionGuard();guard.activate(d)
 val binding=guard.binding(peer,"10.0.0.2")!!;val snapshot=binding.snapshot(request,"7")!!
 verify(binding.snapshot(request,"07")==null);verify(binding.copy(deviceIpv4Address="010.0.0.2").snapshot(request,"7")==null)
 verify(binding.copy(peerPublicKey="bad").snapshot(request,"7")==null)
 val unicodeSnapshot=requireNotNull(binding.copy(descriptor=d.copy(serverId="\u0441\u0435\u0440\u0432\u0435\u0440-\"\u0442\u0435\u0441\u0442\"" )).snapshot(request,"7"))
 File(args[0]).writeText(snapshot+"\n"+unicodeSnapshot+"\n",Charsets.UTF_8)
 val entered=CountDownLatch(1);val release=CountDownLatch(1);val readerDone=CountDownLatch(1);val writerDone=CountDownLatch(1);var first=0;var second=0
 val one=thread {guard.locked {first=1;entered.countDown();check(release.await(5,TimeUnit.SECONDS));second=1}}
 check(entered.await(5,TimeUnit.SECONDS))
 val reader=thread {guard.locked {verify(first==second)};readerDone.countDown()}
 val two=thread {guard.locked {first=2;second=2};writerDone.countDown()}
 verify(!readerDone.await(30,TimeUnit.MILLISECONDS)&&!writerDone.await(30,TimeUnit.MILLISECONDS));release.countDown();one.join();reader.join();two.join()
 var stops=0;val newer=descriptor("55555555-5555-4555-8555-555555555555");guard.activate(newer)
 verify(!guard.stopIfBound(d.identity){stops++;guard.confirmedCleanup()});verify(stops==0)
 verify(guard.stopIfBound(newer.identity){stops++;guard.confirmedCleanup()});verify(stops==1&&guard.cleanupIdentity()==newer.identity)
 guard.activate(d);guard.confirmedCleanup();guard.replacedNativeHandle();verify(guard.binding(peer,"10.0.0.2")?.descriptor==d&&guard.cleanupIdentity()==null)
 val cachedProtocol=Any();data class Owner(val protocol:Any,val activation:String)
 val old=Owner(cachedProtocol,activation);val next=Owner(cachedProtocol,newer.identity.serviceActivationId)
 val fence=RestoreStatusGate<Owner>();fence.activate(old);val ticket=fence.begin("requester",request,"7")!!
 fence.activate(next);var sends=0;verify(!fence.commit(ticket,{true}){sends++});verify(sends==0)
 val current=fence.begin("requester",request,"7")!!;verify(fence.commit(current,{true}){sends++});verify(!fence.commit(current,{true}){sends++}&&sends==1)
 val stale=fence.begin("requester",request,"7")!!;fence.invalidate();verify(!fence.commit(stale,{true}){sends++})
 val unregister=fence.begin("requester",request,"7")!!;fence.removeRequester("requester");verify(!fence.commit(unregister,{true}){sends++})
 val reused=fence.begin("requester",request,"7")!!;fence.begin("requester",request,"7");verify(!fence.commit(reused,{true}){sends++})
 runActualNativeFixture()
 runActualServiceFixture()
 runActualActivityFixture()
 threadFailure.get()?.let {throw it}
 println("NativeSessionBinding actual-helper checks:$checks PASS")
}
