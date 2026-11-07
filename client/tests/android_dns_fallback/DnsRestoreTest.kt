package org.amnezia.vpn

import org.amnezia.vpn.protocol.DnsSessionOwner
import org.amnezia.vpn.protocol.DnsTransportNoticeGate
import org.amnezia.vpn.protocol.NativeSessionBinding
import org.amnezia.vpn.protocol.NativeSessionDescriptor
import org.amnezia.vpn.protocol.NativeSessionIdentity
import org.json.JSONObject

fun runDnsRestoreContracts(): Int {
    var checks = 0
    fun expect(value: Boolean) { check(value); checks++ }
    val identity = NativeSessionIdentity("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "cccccccc-cccc-cccc-cccc-cccccccccccc")
    val descriptor = NativeSessionDescriptor(identity, "dns-test-server", "AWG")
    val request = "dddddddd-dddd-dddd-dddd-dddddddddddd"
    val config = DnsFallbackConfig("d27.media-uley.com", "1234567890abcdef".repeat(4), java.util.UUID.fromString("12345678-1234-1234-1234-123456789abc"), "https://example.com/", 3)
    val owner = DnsSessionOwner()
    val initial = owner.activate(descriptor, config.profileDigest())
    expect(owner.binding(1000) == null)
    expect(!owner.confirm(initial, 1000, false, true, true))
    expect(!owner.confirm(initial, 1000, true, false, true))
    expect(!owner.confirm(initial, 1000, true, true, false))
    expect(!owner.confirm(initial - 1, 1000, true, true, true))
    expect(owner.confirm(initial, 1000, true, true, true))
    val connected = owner.binding(1000)!!
    val snapshot = connected.snapshot(request, "7")!!
    val json = JSONObject(snapshot)
    expect(json.getInt("schema") == 2 && json.getString("effectiveTransport") == "dns")
    expect(json.getString("state") == "CONNECTED" && json.getString("protocol") == "AWG")
    expect(json.getString("dnsProfileDigest") == config.profileDigest())
    expect(!json.has("peerPublicKey") && !json.has("deviceIpv4Address"))
    expect(!snapshot.contains(config.vlessId.toString()) && !snapshot.contains(config.publicKey))
    expect(owner.isCurrent(connected, 2000))
    expect(owner.binding(999) == null)
    expect(owner.binding(36_000) != null && owner.binding(36_001) == null)
    owner.revokeProof()
    expect(!owner.isCurrent(connected, 2000) && owner.binding(2000) == null)
    expect(owner.binding(2000, "RECONNECTING", false) == null)
    val reconnecting = owner.binding(2000, "RECONNECTING", true)!!
    expect(reconnecting.sessionState == "RECONNECTING" && owner.isCurrent(reconnecting, 2000, true))
    expect(!owner.isCurrent(reconnecting, 2000, false))
    expect(JSONObject(reconnecting.snapshot(request, "8")!!).getString("state") == "RECONNECTING")
    val replaced = owner.invalidateNative()
    expect(replaced > initial && !owner.isCurrent(reconnecting, 2000, true))
    expect(!owner.confirm(initial, 2000, true, true, true))
    expect(owner.confirm(replaced, 2000, true, true, true))
    val next = owner.binding(2000)!!
    expect(next.descriptor.identity == identity && next.nativeGeneration != connected.nativeGeneration)
    expect(!owner.isCurrent(connected, 2000) && owner.isCurrent(next, 2000))
    owner.retire()
    expect(owner.binding(2000) == null && owner.binding(2000, "RECONNECTING", true) == null)
    expect(!owner.confirm(replaced, 2000, true, true, true))
    owner.activate(descriptor.copy(identity = identity.copy(serviceActivationId = request)), config.profileDigest())
    expect(!owner.isCurrent(next, 2000))

    expect(connected.copy(peerPublicKey = java.util.Base64.getEncoder().encodeToString(ByteArray(32))).snapshot(request, "7") == null)
    expect(connected.copy(deviceIpv4Address = "10.0.42.2").snapshot(request, "7") == null)
    expect(connected.copy(sessionState = "UNKNOWN").snapshot(request, "7") == null)
    expect(connected.copy(dnsProfileDigest = "f").snapshot(request, "7") == null)
    val wg = NativeSessionBinding(descriptor, java.util.Base64.getEncoder().encodeToString(ByteArray(32)), "10.0.0.2", 1)
    expect(JSONObject(wg.snapshot(request, "7")!!).getInt("schema") == 1)
    expect(wg.copy(sessionState = "RECONNECTING").snapshot(request, "7") == null)

    val notice = DnsTransportNoticeGate()
    expect(!notice.needsRefresh("0", false) && !notice.needsRefresh("bad", false))
    expect(notice.needsRefresh("3", false)); notice.remember("3", false)
    expect(!notice.needsRefresh("3", false) && notice.needsRefresh("3", true))
    notice.remember("3", true)
    expect(notice.needsRefresh("4", false))
    notice.reset(); expect(notice.needsRefresh("3", true))
    System.getProperty("dns.restore.fixture")?.let { path ->
        java.nio.file.Files.write(java.nio.file.Paths.get(path), listOf(snapshot, reconnecting.snapshot(request, "8")!!), Charsets.UTF_8)
    }
    return checks
}
