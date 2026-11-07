"""Execute real service IPC branches with nullable Java Message platform fields.

No Android service, VPN or application is built/launched. Java stubs preserve
Kotlin's actual platform-type null check at the boundary. The delayed-statistics
case also recycles the incoming Message before the IO callback completes.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
SOURCE = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "client/android/src/org/amnezia/vpn/AmneziaVpnService.kt"
source = SOURCE.read_text(encoding="utf-8")


def branch(action):
    begin = source.index("Action." + action + " -> {")
    opening = source.index("{", begin)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[opening + 1:end - 1].replace("this@AmneziaVpnService", "this@Fixture")


java_sources = {
    "Messenger": "public class Messenger {}",
    "Message": "public class Message { public Messenger replyTo; public Bundle data = new Bundle(); }",
    "Bundle": """public class Bundle {
 public java.util.Map<String,Object> values = new java.util.HashMap<>();
 public Object get(String key) { return values.get(key); }
 public String getString(String key) { return (String) values.get(key); }
 public boolean containsKey(String key) { return values.containsKey(key); }
 public boolean getBoolean(String key, boolean fallback) {
  Object v=values.get(key);return v instanceof Boolean ? (Boolean)v : fallback;
 }
 public void putString(String key,String value) { values.put(key,value); }
 }""",
}
for name, text in java_sources.items():
    (OUT / (name + ".java")).write_text(text, encoding="utf-8")

fixture = r'''
import kotlinx.coroutines.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
const val TAG="test"
const val MSG_CLIENT_NAME="clientName"
object Log { fun d(tag:String,message:String) {} }
class Statistics { companion object { val EMPTY_STATISTICS=Statistics() } }
class Protocol {
 val entered=CountDownLatch(1);val release=CountDownLatch(1)
 val statistics:Statistics get() {entered.countDown();check(release.await(5,TimeUnit.SECONDS));return Statistics()}
 val migrationObservation:String="safe"
}
class Session(val protocol:Protocol)
class IpcMessenger(val receiver:Messenger,val name:String?) {
 val sent=java.util.Collections.synchronizedList(mutableListOf<Bundle>())
 fun send(body:()->Bundle) {sent.add(body())}
}
enum class ServiceEvent {STATUS,STATISTICS_UPDATE;fun packToMessage(body:Bundle.()->Unit)=Bundle().apply(body)}
fun Bundle.putStatus(status:String) {putString("status",status)}
fun Bundle.putStatistics(statistics:Statistics) {putString("statistics","present")}
class Gate { fun removeRequester(requester:Messenger) {} }
class State {val value="CONNECTED"}
class Fixture {
 val failures=java.util.Collections.synchronizedList(mutableListOf<Throwable>())
 val mainScope=CoroutineScope(SupervisorJob()+Dispatchers.Unconfined+CoroutineExceptionHandler{_,e->failures.add(e)})
 val clientMessengers=java.util.concurrent.ConcurrentHashMap<Messenger,IpcMessenger>()
 val observationClients=mutableSetOf<Messenger>()
 val discoveryGrants=mutableMapOf<Messenger,Any>();val admissionRequests=mutableMapOf<Messenger,Any>()
 val restoreStatusGate=Gate();val protocolState=State()
 var isServiceBound=false;var stops=0;var activeNativeSession:Session?=null;val vpnProto:Nothing?=null
 var restoreQueries=0;var discoveryQueries=0
 fun updateControlBinding() {};fun invalidateDiscoveryGrants() {};fun discoveryStateIdle()=true
 fun stopService() {stops++};fun remoteLogHealthSnapshot()="{}"
 fun requestDiscoveryStatus(requester:Messenger,id:String?,generation:String?) {discoveryQueries++}
 fun requestBoundRestoreStatus(requester:Messenger,id:String,generation:String) {restoreQueries++}
'''.replace("val vpnProto:Nothing?=null", "class Vpn(val protocol:Protocol);val vpnProto:Vpn?=null")
for action, name in [("REGISTER_CLIENT", "register"), ("UNREGISTER_CLIENT", "unregister"), ("REQUEST_STATUS", "status")]:
    fixture += "\n fun " + name + "(msg:Message) {\n" + branch(action) + "\n }\n"
fixture += r'''
}
fun main()=runBlocking {
 val failures=mutableListOf<String>()
 fun case(name:String,body:()->Unit) {try{body();println("PASS $name")}catch(e:Throwable){failures.add("$name: ${e.javaClass.simpleName}");println("FAIL ${failures.last()}")}}
 val f=Fixture()
 case("null reply registration") {f.register(Message());check(f.clientMessengers.isEmpty())}
 case("null reply unregister") {f.unregister(Message());check(f.stops==0)}
 case("null reply legacy status") {f.status(Message())}
 case("null reply restore status") {f.status(Message().apply{data.putString("restoreRequestId","id");data.putString("restoreBindingGeneration","1")});check(f.restoreQueries==0)}
 case("null reply discovery status") {f.status(Message().apply{data.putString("discoveryRequestId","id")});check(f.discoveryQueries==0)}
 val receiver=Messenger();val registered=Message().apply{replyTo=receiver}
 f.register(registered);check(f.clientMessengers.size==1)
 f.status(Message().apply{replyTo=receiver;data.putString("restoreRequestId","id");data.putString("restoreBindingGeneration","1")});check(f.restoreQueries==1)
 f.status(Message().apply{replyTo=receiver;data.putString("discoveryRequestId","id")});check(f.discoveryQueries==1)
 val protocol=Protocol();f.activeNativeSession=Session(protocol)
 val request=Message().apply{replyTo=receiver};f.status(request)
 check(protocol.entered.await(5,TimeUnit.SECONDS));request.replyTo=null;request.data=Bundle();protocol.release.countDown()
 val client=f.clientMessengers[receiver]!!
 repeat(100){if(client.sent.size<2 && f.failures.isEmpty()) delay(10)}
 case("recycled Message retains captured receiver") {check(f.failures.isEmpty());check(client.sent.size==2)}
 f.unregister(registered);check(f.clientMessengers.isEmpty()&&f.stops==1)
 f.mainScope.cancel()
 check(failures.isEmpty()){failures.joinToString()}
 println("PASS real IPC branches: nullable platform fields, live replies, recycled message")
}
'''
(OUT / "StatusMessageContract.kt").write_text(fixture, encoding="utf-8")

cache = Path.home() / ".gradle/caches/modules-2/files-2.1"


def jar(group, name, version):
    hits = list((cache / group / name / version).glob("*/*.jar"))
    assert len(hits) == 1, (group, name, version)
    return hits[0]


jdk = Path.home() / "devtools/jdk-17/bin"
stdlib = jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.1.0")
co = jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.6.4")
ann = jar("org.jetbrains", "annotations", "13.0")
compiler = [jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.1.0"), stdlib,
            jar("org.jetbrains.kotlin", "kotlin-script-runtime", "2.1.0"),
            jar("org.jetbrains.kotlin", "kotlin-reflect", "1.6.10"),
            jar("org.jetbrains.intellij.deps", "trove4j", "1.0.20200330"), ann, co]
classes = OUT / "java-classes"
classes.mkdir(exist_ok=True)
receipt = {"source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
           "extracted_fixture_sha256": hashlib.sha256(fixture.encode()).hexdigest()}


def run(name, command):
    with (OUT / (name + ".log")).open("w", encoding="utf-8") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=60)
    receipt[name + "_exit"] = result.returncode
    (OUT / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(name, result.returncode)
    if result.returncode:
        sys.exit(result.returncode)


run("javac", [str(jdk / "javac.exe"), "-d", str(classes)] + [str(OUT / (n + ".java")) for n in java_sources])
cp = os.pathsep.join(map(str, [classes, stdlib, ann, co]))
target = OUT / "tests.jar"
run("compile", [str(jdk / "java.exe"), "-cp", os.pathsep.join(map(str, compiler)),
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect",
                "-classpath", cp, "-d", str(target), str(OUT / "StatusMessageContract.kt")])
run("tests", [str(jdk / "java.exe"), "-cp", str(target) + os.pathsep + cp, "StatusMessageContractKt"])
