package org.amnezia.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import org.amnezia.vpn.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

internal data class DnsFallbackConfig(val domain: String, val publicKey: String, val vlessId: UUID,
    val probeUrl: String, val failureThreshold: Int, val profileResolvers: List<InetAddress> = emptyList()) {
    fun profileDigest(): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest((domain + "\n" + publicKey + "\n" + vlessId.toString()).toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    companion object {
        fun parse(config: JSONObject): DnsFallbackConfig? = runCatching {
            val o = config.optJSONObject("dnsFallback") ?: return null
            require(o.toString().toByteArray(Charsets.UTF_8).size <= 2048)
            if (o.opt("enabled") != true) return null
            require(listOf("domain", "publicKey", "vlessId").all { o.opt(it) is String })
            require(!o.has("probeUrl") || o.opt("probeUrl") is String)
            val domain = o.getString("domain").trim().removeSuffix(".").lowercase(java.util.Locale.ROOT)
            require(validDomain(domain))
            val key = o.getString("publicKey").lowercase(java.util.Locale.ROOT)
            require(key.matches(Regex("[0-9a-f]{64}")) && key.any { it != '0' })
            val uuidText = o.getString("vlessId").lowercase(java.util.Locale.ROOT)
            val id = UUID.fromString(uuidText)
            require(id.toString() == uuidText && id != UUID(0, 0))
            val url = o.optString("probeUrl", "https://example.com/")
            val uri = URI(url)
            require(url.length <= 512 && uri.scheme == "https" && uri.userInfo == null && uri.fragment == null &&
                uri.port in setOf(-1, 443) && uri.host != null && validDomain(uri.host.lowercase(java.util.Locale.ROOT)))
            val value = o.opt("failureThreshold") ?: 3
            require(value is Number && value.toDouble() == value.toInt().toDouble() && value.toInt() in 2..8)
            DnsFallbackConfig(domain, key, id, url, value.toInt(),
                dnsProfileResolverCandidates(listOf(config.opt("dns1"), config.opt("dns2"))))
        }.getOrNull()
        private fun validDomain(value: String) = value.length in 1..128 && value.split('.').size >= 2 &&
            !value.matches(Regex("[0-9.]+")) && !value.endsWith(".local") && !value.endsWith(".localhost") &&
            value.split('.').all { it.length in 1..63 && it.matches(Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) }
    }
}

/** Only app-owned packaged code may run; downloaded or writable-cache executables are rejected. */
internal fun dnsFallbackExecutable(context: Context): File? = runCatching {
    val directory = File(context.applicationInfo.nativeLibraryDir).canonicalFile
    File(directory, "libdnstt.so").canonicalFile.takeIf {
        it.parentFile == directory && it.isFile && it.canExecute()
    }
}.getOrNull()

internal data class DnsFallbackNetwork(val network: Network, val resolvers: List<InetAddress>) {
    val key: String get() = network.networkHandle.toString() + ":" + dnsResolverOrderKey(resolvers)
}
internal fun dnsFallbackPhysicalNetwork(context: Context, mobileOnly: Boolean, profileResolvers: List<InetAddress> = emptyList()): DnsFallbackNetwork? {
    val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    return manager.allNetworks.asSequence().mapNotNull { n ->
        val capabilities = manager.getNetworkCapabilities(n) ?: return@mapNotNull null
        if ((mobileOnly && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) ||
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
        val systemResolvers = manager.getLinkProperties(n)?.dnsServers.orEmpty()
        val resolvers = dnsTransportResolverCandidates(systemResolvers, profileResolvers,
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
        if (resolvers.isEmpty()) null else Pair(DnsFallbackNetwork(n, resolvers), when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 0
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 1
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
            else -> 3
        })
    }.sortedBy { it.second }.firstOrNull()?.first
}

/** A TCP DNSTT endpoint and a two-thread relay whose upstream socket belongs to one physical network. */
internal class DnsFallbackTransport private constructor(
    val network: Network, val resolver: InetAddress, val localPort: Int, private val local: DatagramSocket,
    private val remote: DatagramSocket, private val process: Process
) : AutoCloseable {
    private val stopped = AtomicBoolean(false)
    private val workers = Executors.newFixedThreadPool(2) { r -> Thread(r, "dns-fallback-relay").apply { isDaemon = true } }
    @Volatile private var peer: InetSocketAddress? = null
    val isAlive: Boolean get() = !stopped.get() && process.isAlive && !local.isClosed && !remote.isClosed
    val isStopped: Boolean get() = stopped.get() && !process.isAlive && local.isClosed && remote.isClosed

    init {
        workers.execute {
            val bytes = ByteArray(4096)
            while (!stopped.get()) try {
                val packet = DatagramPacket(bytes, bytes.size); local.receive(packet)
                val sender = packet.socketAddress as? InetSocketAddress ?: continue
                if (!sender.address.isLoopbackAddress || packet.length !in 12..4096) continue
                val expected = peer
                if (expected != null && sender != expected) continue
                peer = sender
                remote.send(DatagramPacket(packet.data, packet.offset, packet.length))
            } catch (_: SocketTimeoutException) { } catch (_: IOException) { if (!stopped.get()) close() }
        }
        workers.execute {
            val bytes = ByteArray(4096)
            while (!stopped.get()) try {
                val packet = DatagramPacket(bytes, bytes.size); remote.receive(packet)
                val target = peer ?: continue
                if (packet.length in 12..4096) local.send(DatagramPacket(packet.data, packet.offset, packet.length, target))
            } catch (_: SocketTimeoutException) { } catch (_: IOException) { if (!stopped.get()) close() }
        }
    }

    override fun close() {
        if (stopped.compareAndSet(false, true)) {
            local.close(); remote.close(); process.destroy(); workers.shutdown()
        }
        try {
            if (!process.waitFor(800, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly(); process.waitFor(1200, TimeUnit.MILLISECONDS)
            }
        } catch (_: InterruptedException) { process.destroyForcibly(); Thread.currentThread().interrupt() }
        finally { workers.shutdownNow() }
    }

    /** Verify Noise pinned transport plus VLESS authentication plus actual TLS before switching any TUN. */
    fun verify(config: DnsFallbackConfig, protect: (Int) -> Boolean): Boolean {
        var stage = "transport_alive"
        val started = android.os.SystemClock.elapsedRealtime()
        return runCatching {
        require(isAlive)
        val uri = URI(config.probeUrl)
        val host = uri.host
        Socket().use { socket ->
            stage = "loopback_bind"
            socket.bind(InetSocketAddress("127.0.0.1", 0))
            stage = "loopback_protect"
            ParcelFileDescriptor.fromSocket(socket).use { require(protect(it.fd)) }
            stage = "loopback_connect"
            socket.connect(InetSocketAddress("127.0.0.1", localPort), 3000)
            socket.soTimeout = 10_000
            stage = "vless_request"
            val output = socket.getOutputStream()
            val hostBytes = host.toByteArray(Charsets.US_ASCII)
            require(hostBytes.size in 1..253)
            val id = java.nio.ByteBuffer.allocate(16).putLong(config.vlessId.mostSignificantBits).putLong(config.vlessId.leastSignificantBits).array()
            output.write(byteArrayOf(0)); output.write(id); output.write(byteArrayOf(0, 1, 1, -69, 2, hostBytes.size.toByte()))
            output.write(hostBytes); output.flush()
            stage = "tls_initialize"
            DnsVlessTls(socket, host).use { tls ->
                stage = "tls_handshake"
                tls.startHandshake()
                val path = uri.rawPath.takeUnless { it.isNullOrEmpty() } ?: "/"
                val query = uri.rawQuery?.let { "?$it" } ?: ""
                stage = "https_request"
                tls.write(("HEAD $path$query HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
                stage = "https_response"
                require(dnsHttpsSuccess { tls.read() })
            }
        }
        true
        }.onFailure {
            // Bounded classes/frames and fixed reason codes only; never raw exception messages.
            Log.w("DnsFallback", "Preflight failed stage=$stage failure=${dnsTlsFailureSummary(it)} elapsedMs=${android.os.SystemClock.elapsedRealtime() - started}")
        }.getOrDefault(false)
    }

    fun xrayConfig(original: JSONObject, config: DnsFallbackConfig): JSONObject = JSONObject(original.toString()).apply {
        put("protocol", "xray"); put("hostName", "127.0.0.1")
        // The DNS gateway intentionally denies private destinations. Do not carry an AWG-only
        // private DNS address into this effective transport; these queries travel inside VLESS.
        put("dns1", "1.1.1.1"); put("dns2", "1.0.0.1")
        val outbound = JSONObject().put("protocol", "vless").put("tag", "dns-fallback")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "127.0.0.1")
                .put("port", localPort).put("users", JSONArray().put(JSONObject().put("id", config.vlessId.toString()).put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "tcp").put("security", "none"))
        val inbound = JSONObject().put("listen", "127.0.0.1").put("port", 1080).put("protocol", "socks")
            .put("settings", JSONObject().put("auth", "password").put("udp", true))
        val xray = JSONObject().put("log", JSONObject().put("loglevel", "warning"))
            .put("inbounds", JSONArray().put(inbound)).put("outbounds", JSONArray().put(outbound))
        put("xray_config_data", JSONObject().put("config", xray.toString()))
    }

    companion object {
        fun start(context: Context, mobile: DnsFallbackNetwork, resolver: InetAddress,
            config: DnsFallbackConfig, protect: (Int) -> Boolean): DnsFallbackTransport {
            val executable = dnsFallbackExecutable(context) ?: throw IOException("dns_binary_unavailable")
            val loopback = InetAddress.getByName("127.0.0.1")
            val local = DatagramSocket(0, loopback)
            val remote = DatagramSocket(null)
            var process: Process? = null
            try {
                remote.bind(InetSocketAddress(0)); remote.soTimeout = 500; local.soTimeout = 500
                ParcelFileDescriptor.fromDatagramSocket(remote).use { require(protect(it.fd)) }
                mobile.network.bindSocket(remote); remote.connect(resolver, 53)
                val port = ServerSocket(0, 1, loopback).use { it.localPort }
                process = ProcessBuilder(executable.absolutePath, "-udp", "127.0.0.1:${local.localPort}",
                    "-pubkey", config.publicKey, config.domain, "127.0.0.1:$port")
                    .redirectError(File("/dev/null")).redirectOutput(File("/dev/null"))
                    .apply { environment()["GOMAXPROCS"] = "2"; environment()["GOMEMLIMIT"] = "64MiB" }.start()
                val deadline = android.os.SystemClock.elapsedRealtime() + 3000
                var listenerReady = false
                while (process.isAlive && android.os.SystemClock.elapsedRealtime() < deadline) {
                    try {
                        Socket().use { it.connect(InetSocketAddress(loopback, port), 100) }
                        listenerReady = true
                        break
                    } catch (_: IOException) { Thread.sleep(40) }
                }
                require(process.isAlive && listenerReady) { "dns_local_listener_unavailable" }
                return DnsFallbackTransport(mobile.network, resolver, port, local, remote, process)
            } catch (e: Exception) {
                local.close(); remote.close(); process?.destroyForcibly()
                runCatching { process?.waitFor(1200, TimeUnit.MILLISECONDS) }
                throw e
            }
        }
    }
}
