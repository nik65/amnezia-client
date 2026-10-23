package org.amnezia.vpn

import org.amnezia.vpn.protocol.NativeSessionWire

/** Finite metadata only. This wire conveys no native identity or cleanup authority. */
internal object ServiceDiscoveryWire {
    fun snapshot(requestId: String, generation: Long, phase: String, component: String, reason: String): String {
        require(generation > 0 && (NativeSessionWire.uuid(requestId) || (requestId.isEmpty() && phase == "PENDING")))
        require(phase in setOf("PENDING", "EMPTY", "BOUND_NATIVE", "BOUND_LEGACY", "IDLE_NATIVE", "UNCERTAIN"))
        require(component in setOf("NONE", "AWG", "OPENVPN", "XRAY"))
        require(reason in setOf("NONE", "INVENTORY_ERROR", "MULTIPLE", "BIND_FAILED", "BIND_TIMEOUT", "DIED", "STATUS_UNPROVEN", "CANCELLED"))
        require(when (phase) {
            "PENDING", "EMPTY" -> component == "NONE" && reason == "NONE"
            "BOUND_NATIVE", "IDLE_NATIVE" -> component == "AWG" && reason == "NONE"
            "BOUND_LEGACY" -> component in setOf("OPENVPN", "XRAY") && reason == "NONE"
            else -> component == "NONE" && reason != "NONE"
        })
        return "{\"schema\":1,\"requestId\":${NativeSessionWire.quote(requestId)},\"generation\":\"$generation\",\"phase\":\"$phase\",\"component\":\"$component\",\"reason\":\"$reason\"}"
    }
    fun admission(generation: String, requestId: String, outcome: String, reason: String): String {
        require(NativeSessionWire.generation(generation) && NativeSessionWire.uuid(requestId))
        require(outcome in setOf("DISPATCHED", "DISPATCH_UNCERTAIN", "REJECTED", "CANCELLED"))
        require(reason in setOf("NONE", "DISCOVERY_UNCONFIRMED", "STALE", "PERMISSION_DENIED", "LIFECYCLE_CANCELLED", "START_EXCEPTION"))
        require(when (outcome) {
            "DISPATCHED" -> reason == "NONE"
            "DISPATCH_UNCERTAIN" -> reason == "START_EXCEPTION"
            "CANCELLED" -> reason in setOf("PERMISSION_DENIED", "LIFECYCLE_CANCELLED")
            else -> reason in setOf("DISCOVERY_UNCONFIRMED", "STALE", "START_EXCEPTION")
        })
        return "{\"schema\":1,\"generation\":\"$generation\",\"requestId\":\"$requestId\",\"outcome\":\"$outcome\",\"reason\":\"$reason\"}"
    }
}
