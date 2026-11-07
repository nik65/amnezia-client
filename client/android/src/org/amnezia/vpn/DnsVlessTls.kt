package org.amnezia.vpn

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.nio.ByteBuffer
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngineResult

private object DnsProbeEngineTls {
    // Some Android Conscrypt versions create an engine in a native server context before
    // setUseClientMode(true). Mixing its tickets with SSLSocket tickets then fails with
    // ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT. Keep an engine-only session cache.
    // Null managers retain the platform/app Network Security Config trust policy.
    val context: SSLContext by lazy { SSLContext.getInstance("TLS").apply { init(null, null, null) } }
}

/** Engine-only context. Never use its socket factory for HttpsURLConnection or SSLSocket. */
internal fun dnsProbeTlsContext(): SSLContext = DnsProbeEngineTls.context

/** Bounded diagnostic metadata. Exception messages may contain credentials and are never emitted. */
internal fun dnsTlsFailureSummary(error: Throwable): String {
    val trustedPrefixes = listOf("javax.net.ssl.", "java.security.cert.", "java.lang.",
        "java.net.", "android.security.net.config.", "com.android.org.conscrypt.", "org.amnezia.vpn.")
    fun safeClass(name: String): String = if (name.length <= 160 &&
        name.matches(Regex("[A-Za-z0-9_.$]+")) && trustedPrefixes.any { name.startsWith(it) }) name else "other"
    val seen = java.util.IdentityHashMap<Throwable, Boolean>()
    val causes = ArrayList<String>()
    var current: Throwable? = error
    while (current != null && causes.size < 6 && seen.put(current, true) == null) {
        val failure = current
        val message = runCatching { failure.message.orEmpty() }.getOrDefault("").take(4096)
        // Public numeric BoringSSL error codes identify unclassified native failures.
        // Never copy the accompanying reason/function text, which could carry arbitrary data.
        val nativeCodes = if (failure is javax.net.ssl.SSLException)
            Regex("error:([0-9A-Fa-f]{8}):SSL routines:").findAll(message).take(2)
                .joinToString(",") { it.groupValues[1].lowercase(java.util.Locale.ROOT) }
            else ""
        val reason = when {
            message in setOf("dns_native_cleanup_unconfirmed", "primary_native_cleanup_unconfirmed",
                "dns_config_missing", "dns_tun_probe_failed", "dns_owner_generation_changed",
                "dns_authenticated_probe_failed") -> message
            message == "Bad address" -> "invalid_vpn_builder_address"
            message.contains("Domain specific configurations require") -> "domain_config_requires_hostname"
            message.contains("Not in handshake; no session available") -> "handshake_session_missing"
            message.contains("Trust anchor for certification path not found") -> "trust_anchor_missing"
            message.contains("Pin verification failed") -> "certificate_pin_failed"
            message.contains("Certificate expired") || message.contains("NotAfter") -> "certificate_expired"
            message.contains("Certificate not yet valid") || message.contains("NotBefore") -> "certificate_not_yet_valid"
            message.contains("No subject alternative") || message.contains("No name matching") ||
                message.contains("Hostname") || message.contains("hostname") -> "hostname_check_failed"
            message.contains("CERTIFICATE_VERIFY_FAILED") -> "certificate_verify_failed"
            message.contains("ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT") -> "tls_session_context_mismatch"
            message.contains("BAD_RECORD_MAC") -> "bad_record_mac"
            message.contains("DECRYPTION_FAILED") -> "decryption_failed"
            message.contains("DECRYPT_ERROR") -> "decrypt_error"
            message.contains("HANDSHAKE_FAILURE") -> "handshake_failure"
            message.contains("WRONG_VERSION_NUMBER") -> "wrong_tls_version"
            else -> "unclassified"
        }
        val frames = runCatching { failure.stackTrace.toList() }.getOrDefault(emptyList()).asSequence()
            .filter { safeClass(it.className) != "other" && it.methodName.length <= 80 &&
                it.methodName.matches(Regex("[A-Za-z0-9_$<>-]+")) }
            .take(2).joinToString(",") { "${safeClass(it.className)}.${it.methodName}:${it.lineNumber.coerceIn(-2, 999999)}" }
        val nativeDetail = if (nativeCodes.isEmpty()) "" else "(ssl_codes=$nativeCodes)"
        causes.add("${safeClass(failure.javaClass.name)}:$reason$nativeDetail[$frames]")
        current = runCatching { failure.cause }.getOrNull()
    }
    return (causes.joinToString(";") + if (current != null) ";truncated" else "").take(2400)
}

/** VLESS responses may arrive only with the first TLS server bytes. Never read before ClientHello. */
internal class DnsVlessResponseInput(private val upstream: InputStream, private val beforeRead: () -> Unit = {}) : InputStream() {
    private var headerRead = false
    private fun header() {
        if (headerRead) return
        beforeRead()
        if (upstream.read() != 0) throw IOException("vless_response_version")
        beforeRead()
        val count = upstream.read()
        if (count < 0) throw EOFException("vless_response_addons_length")
        repeat(count) { beforeRead(); if (upstream.read() < 0) throw EOFException("vless_response_addons") }
        headerRead = true
    }
    override fun read(): Int { header(); beforeRead(); return upstream.read() }
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
        if (length == 0) return 0
        header(); beforeRead(); return upstream.read(bytes, offset, length)
    }
}

/** Provider-independent TLS over the VLESS stream; no native FD can bypass its response framing. */
internal class DnsVlessTls(
    private val socket: Socket, host: String,
    context: SSLContext = dnsProbeTlsContext(), private val timeoutMs: Int = 10_000
) : AutoCloseable {
    private val engine = context.createSSLEngine(host, 443).apply {
        useClientMode = true
        sslParameters = sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
    }
    private val input = DnsVlessResponseInput(socket.getInputStream(), ::bound)
    private val output: OutputStream = socket.getOutputStream()
    private var incoming = ByteBuffer.allocate(engine.session.packetBufferSize * 2).apply { limit(0) }
    private var outgoing = ByteBuffer.allocate(engine.session.packetBufferSize * 2)
    private var plaintext = ByteBuffer.allocate(engine.session.applicationBufferSize * 2).apply { limit(0) }
    private val deadline = System.nanoTime() + timeoutMs.toLong() * 1_000_000
    private var operations = 0
    private fun bound() {
        if (++operations > 10000) throw IOException("tls_operation_budget")
        val remaining = (deadline - System.nanoTime()) / 1_000_000
        if (remaining <= 0) throw java.net.SocketTimeoutException("tls_probe_deadline")
        socket.soTimeout = remaining.coerceAtMost(timeoutMs.toLong()).coerceAtLeast(1).toInt()
    }
    private fun grow(buffer: ByteBuffer): ByteBuffer {
        if (buffer.capacity() >= 256 * 1024) throw IOException("tls_buffer_budget")
        return ByteBuffer.allocate((buffer.capacity() * 2).coerceAtMost(256 * 1024))
    }
    private fun wrap(bytes: ByteBuffer) {
        while (true) {
            bound(); outgoing.clear()
            val result = engine.wrap(bytes, outgoing)
            if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) { outgoing = grow(outgoing); continue }
            if (result.status != SSLEngineResult.Status.OK) throw IOException("tls_wrap_closed")
            outgoing.flip()
            if (outgoing.hasRemaining()) output.write(outgoing.array(), outgoing.position(), outgoing.remaining())
            output.flush(); return
        }
    }
    private fun unwrap() {
        while (true) {
            bound(); plaintext.compact()
            val result = engine.unwrap(incoming, plaintext)
            plaintext.flip()
            when (result.status) {
                SSLEngineResult.Status.OK -> return
                SSLEngineResult.Status.CLOSED -> throw EOFException("tls_peer_closed")
                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    val replacement = grow(plaintext); replacement.put(plaintext); replacement.flip(); plaintext = replacement
                }
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    if (incoming.remaining() == incoming.capacity()) {
                        val replacement = grow(incoming); replacement.put(incoming); replacement.flip(); incoming = replacement
                    }
                    incoming.compact()
                    val count = input.read(incoming.array(), incoming.position(), incoming.remaining())
                    if (count < 0) throw EOFException("tls_record_truncated")
                    incoming.position(incoming.position() + count); incoming.flip()
                }
                else -> throw IOException("tls_unwrap_status")
            }
        }
    }
    private fun handshake() {
        while (true) {
            bound()
            when (engine.handshakeStatus.name) {
                "NEED_TASK" -> { while (true) { val task = engine.delegatedTask ?: break; task.run(); bound() } }
                "NEED_WRAP" -> wrap(ByteBuffer.allocate(0))
                "NEED_UNWRAP", "NEED_UNWRAP_AGAIN" -> unwrap()
                "FINISHED", "NOT_HANDSHAKING" -> return
                else -> throw IOException("tls_handshake_status")
            }
        }
    }
    fun startHandshake() { engine.beginHandshake(); handshake() }
    fun write(bytes: ByteArray) {
        val source = ByteBuffer.wrap(bytes)
        while (source.hasRemaining()) { handshake(); wrap(source) }
        handshake()
    }
    fun read(): Int {
        while (!plaintext.hasRemaining()) { handshake(); unwrap() }
        return plaintext.get().toInt() and 255
    }
    override fun close() { engine.closeOutbound() /* The caller owns/closes the bounded physical socket. */ }
}

/** Parse one strict, bounded HTTP/1.x status line; CRLF is framing, never part of the reason. */
internal fun dnsHttpsSuccess(read: () -> Int): Boolean {
    val line = StringBuilder()
    repeat(256) {
        val next = read()
        if (next == 13) return read() == 10 &&
            line.toString().matches(Regex("HTTP/1\\.[01] [23][0-9]{2} [\\x20-\\x7e\\t]*"))
        if (next < 0 || (next !in 32..126 && next != 9)) return false
        line.append(next.toChar())
    }
    return false
}
