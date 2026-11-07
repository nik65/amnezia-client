package org.amnezia.vpn.protocol

/** Metadata only requests a fresh authenticated snapshot; it never proves a native connection. */
class DnsTransportNoticeGate {
    private var lastGeneration = ""
    private var lastReady = false
    fun needsRefresh(generation: String, ready: Boolean): Boolean =
        NativeSessionWire.generation(generation) && (generation != lastGeneration || ready != lastReady)
    fun remember(generation: String, ready: Boolean) { lastGeneration = generation; lastReady = ready }
    fun reset() { lastGeneration = ""; lastReady = false }
}
