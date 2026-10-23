"""Compile only the production pure Kotlin compactor; no Gradle/APK/device."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[3]
a.output.mkdir(parents=True, exist_ok=True)
cache = Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(group, name, version):
    hits = list((cache/group/name/version).glob('*/*.jar'))
    assert len(hits) == 1, (group, name, version)
    return hits[0]
stdlib = jar('org.jetbrains.kotlin', 'kotlin-stdlib', '2.1.0')
compiler = [jar('org.jetbrains.kotlin', 'kotlin-compiler-embeddable', '2.1.0'), stdlib,
            jar('org.jetbrains.kotlin', 'kotlin-script-runtime', '2.1.0'),
            jar('org.jetbrains.kotlin', 'kotlin-reflect', '1.6.10'),
            jar('org.jetbrains.intellij.deps', 'trove4j', '1.0.20200330'),
            jar('org.jetbrains', 'annotations', '13.0'),
            jar('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm', '1.6.4')]
java = Path.home()/'devtools/jdk-17/bin/java.exe'
protocol = root/'client/android/protocolApi/src/main/kotlin'
# Compile the actual Route data declaration and actual InetNetwork; only its
# Android-independent address parsing/formatting utilities are supplied here.
route = next(x for x in (protocol/'ProtocolConfig.kt').read_text().splitlines() if x.startswith('data class Route('))
(a.output/'Route.kt').write_text('package org.amnezia.vpn.protocol\nimport org.amnezia.vpn.util.net.InetNetwork\n'+route+'\n')
(a.output/'NetworkUtils.kt').write_text('package org.amnezia.vpn.util.net\nimport java.net.InetAddress\nfun parseInetAddress(value:String):InetAddress=InetAddress.getByName(value)\nval InetAddress.ip:String get()=hostAddress!!\n')
source = (protocol/'Protocol.kt').read_text()
start = source.index('    protected fun interfaceRoutes(')
brace = source.index('{', source.index('    protected fun buildVpnInterfaceWithRoutes('))
depth = 1
end = brace + 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
method = source[start:end].replace('protected open fun', 'fun').replace('protected fun', 'fun')
stubs = '''package org.amnezia.vpn.protocol
import java.net.InetAddress
import org.amnezia.vpn.util.net.InetNetwork
private const val TAG="Protocol"
const val VPN_SESSION_NAME="AmneziaVPN"
object Build { var BRAND="other"; object VERSION {var SDK_INT=35}; object VERSION_CODES {const val Q=29;const val TIRAMISU=33} }
object OsConstants {const val AF_INET=2;const val AF_INET6=10}
object Log {fun d(tag:String,message:String){};fun e(tag:String,message:String){}}
data class ProtocolConfig(val routes:Collection<Route>,val dnsServers:Set<InetAddress>,
val addresses:Set<InetNetwork> = emptySet(), val searchDomain:String?=null,
val includedApplications:Set<String> = emptySet(),val excludedApplications:Set<String> = emptySet(),
val useIncludedUnion:Boolean=false,val mtu:Int=1280,val httpProxy:Any?=null,
val allowAllAF:Boolean=false,val blockingMode:Boolean=false)
class Builder {
 val recorded=linkedMapOf<InetNetwork,Route>();val allowed=mutableSetOf<String>();val disallowed=mutableSetOf<String>();val dns=mutableSetOf<InetAddress>()
 fun addRoute(route:InetNetwork){recorded[route]=Route(route,true)}
 fun excludeRoute(route:InetNetwork){recorded[route]=Route(route,false)}
 fun addAddress(route:InetNetwork){};fun addDnsServer(address:InetAddress){dns+=address}
 fun setSession(value:String){};fun addSearchDomain(value:String){}
 fun addAllowedApplication(value:String){allowed+=value};fun addDisallowedApplication(value:String){disallowed+=value}
 fun setMtu(value:Int){};fun setHttpProxy(value:Any){};fun allowFamily(value:Int){}
 fun setBlocking(value:Boolean){};fun setUnderlyingNetworks(value:Any?){};fun setMetered(value:Boolean){}
}
class ActualProtocol {
'''
(a.output/'ActualBuilder.kt').write_text(stubs + method + '\n}\n')
fixture = root/'client/tests/route_rule_matcher/fixtures/android-policy17-installed-route-keys.json'
(a.output/'fixture.txt').write_text('\n'.join(json.loads(fixture.read_text())))
sources = [protocol/'RouteCompaction.kt', root/'client/android/utils/src/main/kotlin/net/InetNetwork.kt',
           a.output/'Route.kt', a.output/'NetworkUtils.kt', a.output/'ActualBuilder.kt', Path(__file__).with_name('RouteCompactionTest.kt')]
cp = os.pathsep.join(map(str, [stdlib, compiler[-2], compiler[-1]]))
target = a.output/'route-tests.jar'
subprocess.run([str(java), '-cp', os.pathsep.join(map(str, compiler)),
                'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
                '-classpath', cp, '-d', str(target), *map(str, sources)], check=True, timeout=60)
subprocess.run([str(java), '-cp', str(target)+os.pathsep+cp,
                'org.amnezia.vpn.protocol.RouteCompactionTestKt', str(a.output/'fixture.txt')], check=True, timeout=60)
print(json.dumps({'source_sha256': hashlib.sha256(sources[0].read_bytes()).hexdigest(),
                  'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest()}))
