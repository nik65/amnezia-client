"""Execute the exact production start() body with deterministic host JVM stubs.

No Android, sockets, child process or native binary runs. The stubs exercise
deadline/readiness/cleanup control flow; this is not DNSTT/network acceptance.
"""
import argparse, hashlib, json, os, subprocess
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
p.add_argument('--source',type=Path);p.add_argument('--compiler-classpath',required=True)
a=p.parse_args();root=Path(__file__).resolve().parents[3]
source=a.source or root/'client/android/src/org/amnezia/vpn/DnsFallbackTransport.kt'
s=source.read_text(encoding='utf-8');begin=s.index('        fun start(context: Context, mobile: DnsFallbackNetwork, resolver: InetAddress,')
brace=s.index('{',begin);depth=1;end=brace+1
while depth:
    if s[end]=='{':depth+=1
    elif s[end]=='}':depth-=1
    end+=1
body=s[begin:end];out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
text=r'''
package org.amnezia.vpn
import java.io.IOException
import java.util.concurrent.TimeUnit
private class Context
private class InetAddress { companion object { fun getByName(value:String)=InetAddress() } }
private class InetSocketAddress { constructor(port:Int);constructor(address:InetAddress,port:Int) }
private class File(val absolutePath:String)
private object Fixture {
 var readyAt:Long?=null;var exitAt:Long?=null;var interrupted=false;var protect=true
 var clock=0L;var sockets=mutableListOf<DatagramSocket>();var starts=0;var kills=0;var constructed=0
 fun reset(){readyAt=null;exitAt=null;interrupted=false;protect=true;clock=0;sockets.clear();starts=0;kills=0;constructed=0}
}
private object Thread { fun sleep(ms:Long){if(Fixture.interrupted)throw InterruptedException("fixture");Fixture.clock+=ms} }
private class DatagramSocket {
 constructor(port:Int,address:InetAddress){Fixture.sockets.add(this)}
 constructor(address:Any?){Fixture.sockets.add(this)}
 var soTimeout=0;val localPort=12000;var closed=false
 fun bind(address:InetSocketAddress){}
 fun connect(address:InetAddress,port:Int){}
 fun close(){closed=true}
}
private class Socket:java.io.Closeable {
 fun connect(address:InetSocketAddress,timeout:Int){
  if(Fixture.readyAt?.let{Fixture.clock>=it}==true)return
  Fixture.clock+=timeout;throw IOException("no listener")
 }
 override fun close(){}
}
private class ServerSocket(port:Int,backlog:Int,address:InetAddress):java.io.Closeable {
 val localPort=12001;override fun close(){}
}
private class ParcelFileDescriptor:java.io.Closeable {
 val fd=7;override fun close(){}
 companion object {fun fromDatagramSocket(socket:DatagramSocket)=ParcelFileDescriptor()}
}
private class Network { fun bindSocket(socket:DatagramSocket){} }
private data class DnsFallbackNetwork(val network:Network)
private data class DnsFallbackConfig(val publicKey:String="SYNTHETIC",val domain:String="fixture.invalid")
private fun dnsFallbackExecutable(context:Context):File?=File("/owned-fixture/libdnstt.so")
private class Process {
 val isAlive:Boolean get()=Fixture.exitAt?.let{Fixture.clock<it}?:true
 fun destroyForcibly(){Fixture.kills++}
 fun waitFor(timeout:Long,unit:TimeUnit)=true
}
private class ProcessBuilder(vararg values:String) {
 fun redirectError(file:File)=this;fun redirectOutput(file:File)=this
 fun environment()=mutableMapOf<String,String>()
 fun start():Process{Fixture.starts++;return Process()}
}
private class DnsFallbackTransport(network:Network,resolver:InetAddress,port:Int,local:DatagramSocket,remote:DatagramSocket,process:Process) {
 init{Fixture.constructed++}
 companion object {
'''+body+r'''
 }
}
fun main(){
 var checks=0
 fun test(name:String,readyAt:Long?,exitAt:Long?=null,interrupt:Boolean=false,protect:Boolean=true,success:Boolean){
  Fixture.reset();Fixture.readyAt=readyAt;Fixture.exitAt=exitAt;Fixture.interrupted=interrupt
  val result=runCatching{DnsFallbackTransport.start(Context(),DnsFallbackNetwork(Network()),InetAddress(),DnsFallbackConfig()){protect}}
  check(result.isSuccess==success){"$name success=${result.isSuccess} clock=${Fixture.clock} constructed=${Fixture.constructed}"}
  if(success){check(Fixture.constructed==1&&Fixture.kills==0&&Fixture.sockets.none{it.closed})}
  else{
   check(Fixture.constructed==0&&Fixture.sockets.all{it.closed}){"$name resource leak"}
   check(Fixture.kills==if(Fixture.starts==1)1 else 0){"$name process cleanup missing"}
  }
  if(name=="alive_child_without_listener")check(Fixture.clock in 3000..3200)
  if(interrupt)check(result.exceptionOrNull() is InterruptedException)
  checks++
 }
 test("alive_child_without_listener",null,success=false)
 test("immediate_listener",0,success=true)
 test("delayed_listener",240,success=true)
 test("child_exits_before_listener",null,exitAt=180,success=false)
 test("interrupted_poll_cleanup",null,interrupt=true,success=false)
 test("protect_rejected_cleanup",null,protect=false,success=false)
 println("transportReadinessChecks=$checks passed=true noActualSocketsOrProcess=true")
}
'''
kt=out/'ActualTransportStartContract.kt';kt.write_text(text,encoding='utf-8')
clock=out/'SystemClock.kt';clock.write_text('package android.os\nobject SystemClock {fun elapsedRealtime():Long=org.amnezia.vpn.fixtureClock()}\n',encoding='utf-8')
kt.write_text(kt.read_text(encoding='utf-8')+'\nfun fixtureClock()=Fixture.clock\n',encoding='utf-8')
cp=a.compiler_classpath;classes=out/'classes'
c=subprocess.run(['java','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect',
                  '-classpath',cp,'-d',str(classes),str(kt),str(clock)],capture_output=True,text=True)
(out/'compile.txt').write_text(c.stdout+c.stderr,encoding='utf-8')
if c.returncode:raise SystemExit('Transport contract compilation failed; see '+str(out/'compile.txt'))
r=subprocess.run(['java','-cp',str(classes)+os.pathsep+cp,'org.amnezia.vpn.ActualTransportStartContractKt'],capture_output=True,text=True,timeout=10)
(out/'run.txt').write_text(r.stdout+r.stderr,encoding='utf-8')
receipt={'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'extractedBodySha256':hashlib.sha256(body.encode()).hexdigest(),
         'compileExit':c.returncode,'runExit':r.returncode,'passed':r.returncode==0,
         'deviceOrApplicationOrActualNetworkOrProcessStarted':False}
(out/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8');print(json.dumps(receipt))
raise SystemExit(r.returncode)
