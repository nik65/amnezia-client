"""Execute production NetworkState on JVM with deterministic Android API doubles.

No device, emulator, ADB, network request, VPN or Android runtime is used.
Requires the cached Kotlin 2.1 compiler and JDK; writes only to a temporary folder.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class NetworkDecisionTest(unittest.TestCase):
    def test_production_callback_decisions_and_private_metadata(self):
        cache = Path.home() / '.gradle/caches/modules-2/files-2.1'
        def jar(group, module, version='*'):
            found = sorted((cache / group / module).glob(f'{version}/*/*.jar'))
            if not found:
                self.fail(f'Missing cached JVM dependency: {group}/{module}/{version}')
            return found[-1]
        compiler = [jar('org.jetbrains.kotlin', 'kotlin-compiler-embeddable', '2.1.0'),
                    jar('org.jetbrains.kotlin', 'kotlin-stdlib', '2.1.0'),
                    jar('org.jetbrains.kotlin', 'kotlin-script-runtime', '2.1.0'),
                    jar('org.jetbrains.kotlin', 'kotlin-reflect', '1.6.10'),
                    jar('org.jetbrains.intellij.deps', 'trove4j'),
                    jar('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm'),
                    jar('org.jetbrains', 'annotations')]
        stubs = {
            'Context.kt': '''package android.content
class Context { val mainLooper = Any() }
''',
            'Os.kt': '''package android.os
class Handler(looper: Any)
object Build { object VERSION { const val SDK_INT = 31 }; object VERSION_CODES { const val S = 31 } }
''',
            'NetworkCapabilities.java': '''package android.net;
public class NetworkCapabilities {
    private final boolean valid;
    private final java.util.Set<Integer> transports;
    public NetworkCapabilities(boolean v, java.util.Set<Integer> t) { valid = v; transports = t; }
    public boolean hasCapability(int v) { return v == NET_CAPABILITY_VALIDATED && valid; }
    public boolean hasTransport(int v) { return transports.contains(v); }
    public String toString() { throw new AssertionError("Private capabilities must never be formatted"); }
    public static final int NET_CAPABILITY_INTERNET = 12, NET_CAPABILITY_VALIDATED = 16;
    public static final int TRANSPORT_WIFI = 1, TRANSPORT_CELLULAR = 0, TRANSPORT_ETHERNET = 3, TRANSPORT_VPN = 4;
}
''',
            'Net.kt': '''package android.net
import android.os.Handler
data class Network(val networkHandle: Long)
class NetworkRequest { class Builder {
    fun addCapability(value: Int) = this
    fun build() = NetworkRequest()
} }
class ConnectivityManager {
    open class NetworkCallback {
        open fun onAvailable(network: Network) {}
        open fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {}
        open fun onBlockedStatusChanged(network: Network, blocked: Boolean) {}
        open fun onLost(network: Network) {}
    }
    fun registerBestMatchingNetworkCallback(r: NetworkRequest, cb: NetworkCallback, h: Handler) {}
    fun requestNetwork(r: NetworkRequest, cb: NetworkCallback, h: Handler) {}
    fun unregisterNetworkCallback(cb: NetworkCallback) {}
}
''',
            'Core.kt': '''package androidx.core.content
inline fun <reified T> android.content.Context.getSystemService(): T? = null
''',
            'Log.kt': '''package org.amnezia.vpn.util
object Log {
    val saved = mutableListOf<String>()
    fun d(tag: String, msg: String) { saved.add(msg) }
    fun e(tag: String, msg: String) { saved.add(msg) }
    fun v(tag: String, msg: String) {}
}
''',
            'Main.kt': '''import android.content.Context
import android.net.Network
import android.net.NetworkCapabilities
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.NetworkState

fun main() {
    val calls = mutableListOf<Long>()
    val state = NetworkState(Context()) { calls.add(it) }
    val lazyField = state.javaClass.getDeclaredField("networkCallback" + "$" + "delegate")
    lazyField.isAccessible = true
    val callback = (lazyField.get(state) as Lazy<*>).value!!
    val method = callback.javaClass.getDeclaredMethod("checkNetworkState", Network::class.java, NetworkCapabilities::class.java)
    method.isAccessible = true
    fun update(handle: Long, valid: Boolean, vpn: Boolean = false) {
        method.invoke(callback, Network(handle), NetworkCapabilities(valid, setOf(if (vpn) 4 else 1)))
    }
    update(100, true) // Baseline must not recreate a working tunnel.
    update(100, true)
    check(calls.isEmpty() && Log.saved.isEmpty())
    update(200, false)
    update(200, false) // Repeated pending capability callbacks do not flood the log.
    check(calls.isEmpty() && Log.saved.size == 1)
    check(Log.saved.single().contains("oldHandle=100 newHandle=200"))
    check(Log.saved.single().endsWith("validated=false outcome=deferred_unvalidated"))
    update(200, true)
    update(200, true) // No duplicate callback or requested event.
    check(calls == listOf(1L) && Log.saved.size == 2)
    check(Log.saved.last().contains("epoch=1 oldHandle=100 newHandle=200"))
    update(300, true, true)
    check(calls == listOf(1L, 2L))
    check(Log.saved.last().contains("wifi=false cellular=false ethernet=false vpn=true validated=true outcome=requested"))
    val allowed = Regex("ReconnectDecision cause=validated_new_network epoch=[0-9]+ oldHandle=[0-9]+ newHandle=[0-9]+ wifi=(true|false) cellular=(true|false) ethernet=(true|false) vpn=(true|false) validated=(true|false) outcome=(requested|deferred_unvalidated)")
    check(Log.saved.all { allowed.matches(it) })
    println("production NetworkState decision, no duplicate reconnect, metadata privacy PASS")
}
''',
        }
        source = Path(__file__).resolve().parents[2] / 'android/utils/src/main/kotlin/net/NetworkState.kt'
        with tempfile.TemporaryDirectory(prefix='amnezia-network-decision-') as folder:
            work = Path(folder)
            for name, content in stubs.items():
                (work / name).write_text(content, encoding='utf8')
            java_result = subprocess.run(['javac', '-d', str(work / 'classes'), str(work / 'NetworkCapabilities.java')],
                                         capture_output=True, text=True)
            self.assertEqual(java_result.returncode, 0, java_result.stdout + java_result.stderr)
            cp = os.pathsep.join([str(work / 'classes'), *map(str, compiler)])
            command = ['java', '-cp', cp, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
                       '-no-stdlib', '-no-reflect', '-classpath', cp, '-d', str(work / 'classes'),
                       str(source), *map(str, work.glob('*.kt'))]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(['java', '-cp', str(work / 'classes') + os.pathsep + cp, 'MainKt'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('metadata privacy PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
