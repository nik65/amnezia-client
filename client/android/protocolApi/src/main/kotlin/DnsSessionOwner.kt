package org.amnezia.vpn.protocol

/** A process-owned lease, never persisted or reconstructed from a saved connected flag. */
class DnsSessionOwner(private val maximumProofAgeMs: Long = 35_000) {
    private var descriptor: NativeSessionDescriptor? = null
    private var digest = ""
    private var generation = NativeSessionWire.nextBindingGeneration()
    private var verifiedAtMs = -1L

    @Synchronized fun activate(value: NativeSessionDescriptor, profileDigest: String): Long {
        require(value.valid() && profileDigest.matches(Regex("[0-9a-f]{64}")))
        descriptor = value; digest = profileDigest
        return invalidateNative()
    }
    @Synchronized fun invalidateNative(): Long {
        generation = NativeSessionWire.nextBindingGeneration()
        check(generation > 0)
        verifiedAtMs = -1L
        return generation
    }
    @Synchronized fun currentGeneration() = generation
    @Synchronized fun revokeProof() { verifiedAtMs = -1L }
    @Synchronized fun confirm(expectedGeneration: Long, nowMs: Long, transportAlive: Boolean, backendAlive: Boolean, vpnNetworkLive: Boolean): Boolean {
        if (descriptor == null || generation != expectedGeneration || nowMs < 0 || !transportAlive || !backendAlive || !vpnNetworkLive) return false
        verifiedAtMs = nowMs
        return true
    }
    @Synchronized fun binding(nowMs: Long, state: String = "CONNECTED", resourcesLive: Boolean = false): NativeSessionBinding? {
        val owner = descriptor ?: return null
        if (nowMs < 0) return null
        if (state == "CONNECTED") {
            if (verifiedAtMs < 0 || nowMs < verifiedAtMs || nowMs - verifiedAtMs > maximumProofAgeMs) return null
        } else if (state != "RECONNECTING" || !resourcesLive) return null
        return NativeSessionBinding(owner, "", "", generation, "dns", digest, state)
    }
    @Synchronized fun isCurrent(value: NativeSessionBinding, nowMs: Long, resourcesLive: Boolean = false): Boolean =
        binding(nowMs, value.sessionState, resourcesLive) == value
    @Synchronized fun retire() { invalidateNative(); descriptor = null; digest = "" }
}
