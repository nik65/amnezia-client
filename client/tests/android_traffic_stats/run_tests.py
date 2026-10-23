from pathlib import Path
import argparse,os,subprocess,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
root=Path(__file__).resolve().parents[3];tests=Path(__file__).resolve().parent
source=root/'client/android/utils/src/main/kotlin/net/TrafficStats.kt'
service=root/'client/android/src/org/amnezia/vpn/AmneziaVpnService.kt'
text=service.read_text();assert 'trafficStats = TrafficStats(this)' in text
assert 'withContext(Dispatchers.IO) { trafficStats.reset() }' in text
start=text.index('                    val speedSession = activeNativeSession')
end=text.index('                    delay(TRAFFIC_STATS_UPDATE_TIMEOUT)',start)
fragment=text[start:end]
(out/'ServiceSpeed.kt').write_text('package org.amnezia.vpn.util.net\nimport kotlinx.coroutines.*\nclass VpnProto(val protocol:Any)\nclass Notification {var updates=0;fun updateSpeed(s:TrafficStats.TrafficData){updates++}}\nclass ActualServiceSpeed(val trafficStats:TrafficStats) {var activeNativeSession:Any?=Any();var vpnProto:VpnProto?=VpnProto(Any());var isConnected=true;val serviceNotification=Notification();suspend fun tick(){\n'+fragment+'\n}}')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(g,n,v):return next((cache/g/n/v).glob('*/*.jar'))
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0');coro=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4');ann=jar('org.jetbrains','annotations','13.0')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),ann,coro]
cp=os.pathsep.join(map(str,[stdlib,coro,ann]));java=Path.home()/'devtools/jdk-17/bin/java.exe';target=out/'tests.jar'
sources=[source,*tests.glob('*.kt'),out/'ServiceSpeed.kt']
subprocess.run([str(java),'-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-jvm-target','17','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),*map(str,sources)],check=True,timeout=60)
subprocess.run([str(java),'-cp',str(target)+os.pathsep+cp,'org.amnezia.vpn.util.net.TestKt'],check=True,timeout=30)
subprocess.run([str(java),'-cp',str(target)+os.pathsep+cp,'org.amnezia.vpn.util.net.ServiceSpeedTestKt'],check=True,timeout=30)
sdk=Path.home()/'Android/Sdk/platforms/android-36/android.jar'
subprocess.run([str(java),'-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-jvm-target','17','-no-stdlib','-no-reflect','-classpath',os.pathsep.join(map(str,[stdlib,sdk])),'-d',str(out/'sdk36.jar'),str(source)],check=True,timeout=60)
(out/'INPUTS.json').write_text(json.dumps([{'path':str(x),'sha256':hashlib.sha256(x.read_bytes()).hexdigest()}for x in [source,service,*tests.glob('*.*')]],indent=2))
print('actual TrafficStats SDK36 and service-constructor contract PASS')
