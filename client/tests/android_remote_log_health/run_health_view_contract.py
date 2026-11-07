"""Run actual Kotlin health-reader/writer functions on a host JVM, no app/device.

Disk/Android/Messenger operations are controlled stubs. The target monitor,
snapshot publication, redaction producer and generation checks are production
source, extracted with source hashes in the output receipt.
"""
import argparse, hashlib, json, os, subprocess
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--compiler-classpath',required=True)
p.add_argument('--output',required=True)
p.add_argument('--source',type=Path)
a=p.parse_args()
root=Path(__file__).resolve().parents[3]
source=a.source or root/'client/android/src/org/amnezia/vpn/AmneziaVpnService.kt'
s=source.read_text(encoding='utf-8');out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)

def part(start,end):
    begin=s.index(start)
    return s[begin:s.index(end,begin)]

types=part('private data class RemoteLogTarget(', 'private data class RemoteLogExplicitSecretSet(')
types+=part('private data class RemoteLogHealthView(', 'private enum class RemoteLogUploadResult')
fields=part('    private var remoteLogUploadJob: Job?', '    private val remoteLogOriginLock')
functions=part('    private fun configureRemoteLogUploader(', '    private fun remoteLogHealthSuccessKey(')
functions+=part('    private fun updateRemoteLogHealthViewLocked(', '    private fun publishRemoteLogHealth(')
functions+=part('    private fun recordRemoteLogRedaction(', '    private fun launchRemoteLogUploadJobIfNeeded(')
functions+=part('    private fun stopRemoteLogUploader(', '    private fun isRemoteLogAttemptActive(')
functions+=part('    private fun saveRemoteLogCursorForAttempt(', '    private fun saveRemoteLogCursor(')

text=r'''
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
private const val TAG="AmneziaVpnService"
private const val CONNECTED=1
private const val DISCONNECTED=0
private class State(@Volatile var value:Int)
private class Job { var cancelled=false;fun cancel(){cancelled=true} }
private class HttpURLConnection { fun disconnect(){} }
private class JSONObject(val target:RemoteLogTarget?=null) {
 private val fields=linkedMapOf<String,Any>()
 fun put(key:String,value:Any):JSONObject {fields[key]=value;return this}
 override fun toString()=fields.entries.joinToString("|"){"${it.key}=${it.value}"}
}
private object Log { fun i(tag:String,text:String){} }
private object Prefs {
 @Volatile var loadEntered:CountDownLatch?=null
 @Volatile var loadRelease:CountDownLatch?=null
 @Volatile var saveEntered:CountDownLatch?=null
 @Volatile var saveRelease:CountDownLatch?=null
 @Volatile var lastSuccess=0L
 @Suppress("UNCHECKED_CAST") fun <T> load(key:String):T {
  loadEntered?.countDown();loadRelease?.let {check(it.await(5,TimeUnit.SECONDS))}
  return lastSuccess as T
 }
 fun save(key:String,value:Long) {
  saveEntered?.countDown();saveRelease?.let {check(it.await(5,TimeUnit.SECONDS))}
 }
 fun reset(){loadEntered=null;loadRelease=null;saveEntered=null;saveRelease=null;lastSuccess=0}
}
'''+types+r'''
private class Subject {
 private val protocolState=State(CONNECTED)
 private var remoteLogHeartbeatAtElapsedMs:Long?=null
 private var cursorEntered:CountDownLatch?=null
 private var cursorRelease:CountDownLatch?=null
 var cursorWrites=0
'''+fields+functions+r'''
 private fun parseRemoteLogTarget(config:JSONObject?)=config?.target
 private fun remoteLogHealthSuccessKey(target:RemoteLogTarget)=target.clientId
 private fun publishRemoteLogHealth(){}
 private fun writeRemoteLogOriginCheckpoint():String?="owned-test-checkpoint"
 private fun launchRemoteLogUploadJobIfNeeded(){}
 private fun saveRemoteLogCursor(target:RemoteLogTarget,cursor:RemoteLogCursor):Boolean {
  check(Thread.holdsLock(remoteLogTargetLock)) {"cursor durability lost target lock"}
  cursorEntered?.countDown();cursorRelease?.let{check(it.await(5,TimeUnit.SECONDS))}
  cursorWrites++;return true
 }
 fun configure(target:RemoteLogTarget?)=configureRemoteLogUploader(target?.let{JSONObject(it)})
 fun snapshot():Map<String,String> = remoteLogHealthSnapshot().split('|').associate{ val p=it.split('=',limit=2);p[0] to p[1] }
 fun attempt()=currentRemoteLogAttempt()!!
 fun record(attempt:RemoteLogAttempt,state:Int,http:Int=0)=recordRemoteLogHealth(attempt,state,http=http)
 fun stop()=stopRemoteLogUploader()
 fun redaction(reason:Int)=recordRemoteLogRedaction(reason)
 fun save(attempt:RemoteLogAttempt)=saveRemoteLogCursorForAttempt(attempt,RemoteLogCursor())
 fun blockCursor(entered:CountDownLatch,release:CountDownLatch){cursorEntered=entered;cursorRelease=release}
 fun expire(){synchronized(remoteLogTargetLock){remoteLogHealthSuccess=1;remoteLogHealthState=3;updateRemoteLogHealthViewLocked()}}
 fun disconnect(){protocolState.value=DISCONNECTED}
}

private fun target(name:String)=RemoteLogTarget("http://example.invalid/logs",name,"synthetic-token",false,name)
private fun expectFastSnapshot(subject:Subject):Map<String,String> {
 val reader=Executors.newSingleThreadExecutor()
 return try {reader.submit<Map<String,String>>{subject.snapshot()}.get(700,TimeUnit.MILLISECONDS)}
 finally {reader.shutdownNow()}
}

fun main(){
 var checks=0
 fun test(body:()->Unit){Prefs.reset();body();checks++}
 test {
  val subject=Subject();subject.configure(target("old"));val attempt=subject.attempt()
  subject.record(attempt,3,204)
  val entered=CountDownLatch(1);val release=CountDownLatch(1);subject.blockCursor(entered,release)
  val result=AtomicReference<Boolean>();val writer=Thread{result.set(subject.save(attempt))};writer.start()
  check(entered.await(2,TimeUnit.SECONDS))
  try {val snapshot=expectFastSnapshot(subject);check(snapshot["state"]=="3");check(snapshot["httpStatus"]=="204")}
  finally {release.countDown();writer.join(2000)}
  check(result.get()==true && subject.cursorWrites==1)
 }
 test {
  val subject=Subject();subject.configure(target("old"));val attempt=subject.attempt()
  val entered=CountDownLatch(1);val release=CountDownLatch(1)
  Prefs.saveEntered=entered;Prefs.saveRelease=release
  val writer=Thread{subject.record(attempt,3,204)};writer.start();check(entered.await(2,TimeUnit.SECONDS))
  try {check(expectFastSnapshot(subject)["state"]=="3")}
  finally {release.countDown();writer.join(2000)}
 }
 test {
  val subject=Subject();subject.configure(target("old"));val old=subject.attempt();subject.record(old,3,204)
  val entered=CountDownLatch(1);val release=CountDownLatch(1)
  Prefs.loadEntered=entered;Prefs.loadRelease=release
  val changer=Thread{subject.configure(target("new"))};changer.start();check(entered.await(2,TimeUnit.SECONDS))
  try {val view=expectFastSnapshot(subject);check(view["state"]=="4" && view["lastSuccessMs"]=="0" && view["httpStatus"]=="0")}
  finally {release.countDown();changer.join(2000)}
  subject.record(old,3,204);check(subject.snapshot()["state"]=="4")
  check(!subject.save(old) && subject.cursorWrites==0) {"obsolete cursor crossed target generation"}
 }
 test {
  val subject=Subject();subject.configure(target("old"));subject.record(subject.attempt(),3,204)
  subject.stop();val view=subject.snapshot();check(view["state"]=="1" && view["lastSuccessMs"]=="0")
  subject.configure(target("new"));check(subject.snapshot()["state"]=="4")
 }
 test {
  val subject=Subject();subject.configure(target("valid"));subject.record(subject.attempt(),3,204)
  subject.expire();check(subject.snapshot()["state"]=="4")
  subject.disconnect();check(subject.snapshot()["state"]=="0")
 }
 test {
  val subject=Subject();subject.configure(target("valid"));val failures=AtomicReference<Throwable?>()
  val writer=Thread{try{for(i in 1..50000) subject.redaction(if(i%2==1)1 else 2)}catch(t:Throwable){failures.set(t)}}
  writer.start()
  while(writer.isAlive){val view=subject.snapshot();val count=view.getValue("redactionCount").toLong();val reason=view.getValue("redactionReason").toInt();check(reason==if(count==0L)0 else if(count%2==1L)1 else 2){"torn redaction pair"}}
  writer.join();failures.get()?.let{throw it};check(subject.snapshot()["redactionCount"]=="50000")
 }
 test {
  val subject=Subject();val a=Thread{repeat(20000){subject.redaction(1)}};val b=Thread{repeat(20000){subject.redaction(2)}}
  a.start();b.start();a.join();b.join();check(subject.snapshot()["redactionCount"]=="40000"){"redaction increments lost"}
  subject.redaction(0);val view=subject.snapshot();check(view["redactionReason"]=="0" && view["redactionCount"]=="40000")
 }
 println("healthViewChecks=$checks passed=true heldCursorLockReaderNonblocking=true staleTargetRejected=true redactionPairAtomic=true")
}
'''
k=out/'ActualHealthViewContract.kt';k.write_text(text,encoding='utf-8')
cp=a.compiler_classpath;classes=out/'classes'
c=subprocess.run(['java','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect',
                  '-classpath',cp,'-d',str(classes),str(k)],capture_output=True,text=True)
(out/'compile.txt').write_text(c.stdout+c.stderr,encoding='utf-8')
if c.returncode:raise SystemExit('Kotlin health-view compilation failed; see '+str(out/'compile.txt'))
r=subprocess.run(['java','-cp',str(classes)+os.pathsep+cp,'ActualHealthViewContractKt'],capture_output=True,text=True,timeout=25)
(out/'run.txt').write_text(r.stdout+r.stderr,encoding='utf-8')
receipt={'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'extractedSha256':hashlib.sha256(k.read_bytes()).hexdigest(),
         'compileExit':c.returncode,'runExit':r.returncode,'passed':r.returncode==0,'applicationOrDeviceStarted':False}
(out/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8');print(json.dumps(receipt))
if r.returncode:raise SystemExit('Kotlin health-view behavior failed; see '+str(out/'run.txt'))
