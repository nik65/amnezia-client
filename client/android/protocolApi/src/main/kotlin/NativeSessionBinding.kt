package org.amnezia.vpn.protocol

/** Pure JVM session contract. Identity values must never enter logs. */
object NativeSessionWire {
    const val maximumSnapshotBytes = 8192
    private val bindingGenerations = java.util.concurrent.atomic.AtomicLong(1)
    fun nextBindingGeneration(): Long {
        while (true) {
            val previous = bindingGenerations.get()
            if (previous == Long.MAX_VALUE) return 0
            if (bindingGenerations.compareAndSet(previous, previous + 1)) return previous + 1
        }
    }
    fun jsonSpace(value: Char) = value == ' ' || value == '\t' || value == '\n' || value == '\r'

    private val uuidPattern = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    fun uuid(value: String) = uuidPattern.matches(value)
    fun generation(value: String) = value.matches(Regex("[1-9][0-9]{0,18}")) && value.toLongOrNull()?.let { it > 0 } == true
    fun serverId(value: String): Boolean {
        if (value.isEmpty() || value.toByteArray(Charsets.UTF_8).size > 256 || value.any { it.code < 32 }) return false
        var position = 0
        while (position < value.length) {
            val current = value[position++]
            if (current.isHighSurrogate()) {
                if (position == value.length || !value[position++].isLowSurrogate()) return false
            } else if (current.isLowSurrogate()) return false
        }
        return true
    }
    fun ipv4(value: String): Boolean {
        val parts = value.split('.')
        return parts.size == 4 && parts.all { it.isNotEmpty() && it.length <= 3 && (it == "0" || !it.startsWith('0')) && it.all { c -> c in '0'..'9' } && (it.toIntOrNull() ?: -1) in 0..255 }
    }
    fun peer(value: String): Boolean = try {
        val bytes = java.util.Base64.getDecoder().decode(value)
        bytes.size == 32 && java.util.Base64.getEncoder().encodeToString(bytes) == value
    } catch (_: IllegalArgumentException) { false }
    fun quote(value: String): String = buildString {
        append('"')
        for (c in value) when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            else -> if (c.code < 32) append("\\u%04x".format(c.code)) else append(c)
        }
        append('"')
    }
}

data class NativeSessionIdentity(val serviceInstanceId: String, val serviceActivationId: String, val connectionNonce: String) {
    fun valid() = NativeSessionWire.uuid(serviceInstanceId) && NativeSessionWire.uuid(serviceActivationId) && NativeSessionWire.uuid(connectionNonce)
    fun toJson() = "{\"serviceInstanceId\":${NativeSessionWire.quote(serviceInstanceId)},\"serviceActivationId\":${NativeSessionWire.quote(serviceActivationId)},\"connectionNonce\":${NativeSessionWire.quote(connectionNonce)}}"
    companion object {
        /** The canonical identity alphabet needs no JSON escapes. Reject coercion, duplicates and unknown keys. */
        fun parseExpected(json: String): NativeSessionIdentity? {
            if (json.toByteArray(Charsets.UTF_8).size > 512) return null
            val text = json.trim(NativeSessionWire::jsonSpace)
            if (!text.startsWith('{') || !text.endsWith('}')) return null
            val inner = text.substring(1, text.length - 1)
            val fields = mutableMapOf<String, String>()
            val field = Regex("\"([A-Za-z]+)\"[ \t\r\n]*:[ \t\r\n]*\"([0-9a-f-]+)\"")
            var position = 0
            while (position < inner.length) {
                while (position < inner.length && NativeSessionWire.jsonSpace(inner[position])) position++
                val match = field.find(inner, position) ?: return null
                if (match.range.first != position) return null
                val key = match.groupValues[1]
                if (key !in setOf("serviceInstanceId", "serviceActivationId", "connectionNonce") || fields.put(key, match.groupValues[2]) != null) return null
                position = match.range.last + 1
                while (position < inner.length && NativeSessionWire.jsonSpace(inner[position])) position++
                if (position == inner.length) break
                if (inner[position++] != ',') return null
                if (inner.substring(position).isBlank()) return null
            }
            if (fields.size != 3) return null
            return NativeSessionIdentity(fields.getValue("serviceInstanceId"), fields.getValue("serviceActivationId"), fields.getValue("connectionNonce")).takeIf { it.valid() }
        }
    }
}

data class NativeSessionDescriptor(val identity: NativeSessionIdentity, val serverId: String, val protocol: String) {
    fun valid() = identity.valid() && NativeSessionWire.serverId(serverId) && protocol in setOf("AWG", "WIREGUARD")
}

data class NativeSessionBinding(val descriptor: NativeSessionDescriptor, val peerPublicKey: String, val deviceIpv4Address: String, val nativeGeneration: Long) {
    fun snapshot(requestId: String, bindingGeneration: String): String? {
        if (!descriptor.valid() || !NativeSessionWire.uuid(requestId) || !NativeSessionWire.generation(bindingGeneration)
            || !NativeSessionWire.peer(peerPublicKey) || !NativeSessionWire.ipv4(deviceIpv4Address) || nativeGeneration <= 0) return null
        val i = descriptor.identity
        val values = linkedMapOf("requestId" to requestId, "bindingGeneration" to bindingGeneration, "state" to "CONNECTED",
            "serverId" to descriptor.serverId, "protocol" to descriptor.protocol, "serviceInstanceId" to i.serviceInstanceId,
            "serviceActivationId" to i.serviceActivationId, "connectionNonce" to i.connectionNonce, "peerPublicKey" to peerPublicKey,
            "deviceIpv4Address" to deviceIpv4Address, "nativeGeneration" to nativeGeneration.toString())
        val result = "{\"schema\":1," + values.entries.joinToString(",") { NativeSessionWire.quote(it.key) + ":" + NativeSessionWire.quote(it.value) } + "}"
        return result.takeIf { it.toByteArray(Charsets.UTF_8).size <= NativeSessionWire.maximumSnapshotBytes }
    }
}

enum class NativeIdleState { NEVER_STARTED, VERIFIED_RETIRED, ACTIVE, UNKNOWN }

data class NativeIdleObservation(val state: NativeIdleState, val generation: Long, val retiredIdentity: NativeSessionIdentity? = null) {
    val isAbsent: Boolean get() = state == NativeIdleState.NEVER_STARTED || state == NativeIdleState.VERIFIED_RETIRED
}

/** The production Wireguard lifecycle and all native readers use this same reentrant monitor. */
class NativeSessionGuard {
    @PublishedApi internal val monitor = Any()
    private var descriptor: NativeSessionDescriptor? = null
    private var generation = 0L
    private var cleaned: NativeSessionIdentity? = null
    private var idleState = NativeIdleState.NEVER_STARTED
    private fun advanceGeneration() { generation = if (generation == Long.MAX_VALUE) 1 else generation + 1 }
    inline fun <T> locked(block: () -> T): T = synchronized(monitor) { block() }
    fun activate(value: NativeSessionDescriptor?) = locked { descriptor = value?.takeIf { it.valid() }; advanceGeneration(); cleaned = null; idleState = NativeIdleState.ACTIVE }
    fun replacedNativeHandle() = locked { advanceGeneration(); cleaned = null; idleState = NativeIdleState.UNKNOWN }
    fun beginCleanup() = locked { advanceGeneration(); cleaned = null; idleState = NativeIdleState.UNKNOWN }
    fun idleObservation(handleActive: Boolean): NativeIdleObservation = locked {
        NativeIdleObservation(if (handleActive) NativeIdleState.ACTIVE else idleState, generation, cleaned)
    }
    fun binding(peer: String, address: String): NativeSessionBinding? = locked { descriptor?.let { NativeSessionBinding(it, peer, address, generation) } }
    fun confirmedCleanup() = locked { advanceGeneration(); cleaned = descriptor?.identity; idleState = NativeIdleState.VERIFIED_RETIRED }
    fun cleanupIdentity(): NativeSessionIdentity? = locked { cleaned }
    fun stopIfBound(expected: NativeSessionIdentity, stop: () -> Unit): Boolean = locked {
        if (!expected.valid() || descriptor?.identity != expected) return@locked false
        stop()
        cleaned == expected
    }
}


/** A final commit fence; owner reference is combined with a per-activation descriptor, never a cached protocol alone. */
class RestoreStatusGate<Owner : Any> {
    class Ticket<Owner : Any>(val requester: Any, val requestId: String, val bindingGeneration: String, val owner: Owner, internal val version: Long)
    private val monitor = Any()
    private var owner: Owner? = null
    private var version = 0L
    private val pending = mutableMapOf<Any, Ticket<Owner>>()
    fun activate(value: Owner?) = synchronized(monitor) { owner = value; version++; pending.clear() }
    fun invalidate() = synchronized(monitor) { version++; pending.clear() }
    fun removeRequester(requester: Any) = synchronized(monitor) { pending.remove(requester); Unit }
    fun begin(requester: Any, requestId: String, bindingGeneration: String): Ticket<Owner>? = synchronized(monitor) {
        val captured = owner ?: return@synchronized null
        if (!NativeSessionWire.uuid(requestId) || !NativeSessionWire.generation(bindingGeneration) || (requester !in pending && pending.size >= 64)) return@synchronized null
        Ticket(requester, requestId, bindingGeneration, captured, version).also { pending[requester] = it }
    }
    fun commit(ticket: Ticket<Owner>, valid: () -> Boolean, send: () -> Unit): Boolean = synchronized(monitor) {
        if (version != ticket.version || owner !== ticket.owner || pending[ticket.requester] !== ticket) return@synchronized false
        pending.remove(ticket.requester)
        if (!valid()) return@synchronized false
        send()
        true
    }
}


/** Reject messages from a previous Binder receiver even after the same Activity rebinds. */
class ServiceEventBindingGate {
    private val monitor = Any()
    private var token: Any? = null
    fun bind(): Any = synchronized(monitor) { Any().also { token = it } }
    fun invalidate() = synchronized(monitor) { token = null }
    fun accepts(captured: Any): Boolean = synchronized(monitor) { token === captured }
}
