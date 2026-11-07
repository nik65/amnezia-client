package org.amnezia.vpn

import org.json.JSONObject
import org.amnezia.vpn.protocol.ProtocolState
import org.amnezia.vpn.protocol.xray.Xray
import org.amnezia.vpn.protocol.xray.LibXrayStopFixture

fun main() {
    var assertions = 0
    fun expect(value: Boolean) { check(value); assertions++ }
    val p = DnsFallbackPolicy(3)
    val t = p.begin(1000)
    expect(!p.primarySample(t, false, true, 6000))
    expect(!p.primarySample(t, false, true, 11000))
    expect(!p.primarySample(t, false, true, 16000)) // three failures cannot skip startup grace
    expect(p.primarySample(t, false, true, 21000))
    expect(p.dnsVerified(t))
    expect(!p.primarySample(t, true, true, 100000)) // no flapping away from a working DNS session
    expect(p.dnsVerified(t)) // authenticated replacement on a changed physical network
    p.stop()
    expect(!p.current(t) && !p.dnsVerified(t))
    val n = p.begin(200000)
    expect(n != t && !p.primarySample(t, false, true, 250000)) // stale jobs cannot switch a newer activation
    expect(!p.primarySample(n, false, true, 220000))
    expect(!p.primarySample(n, true, true, 225000))
    expect(!p.primarySample(n, false, true, 230000))
    expect(!p.primarySample(n, false, false, 235000)) // no physical mobile DNS
    expect(p.primarySample(n, false, true, 240000))
    expect(p.retryPrimary(n, 240000))
    repeat(3) { expect(!p.primarySample(n, false, true, 250000)) }
    expect(p.primarySample(n, false, true, 270000)) // initial 30-second retry cooldown

    fun descriptor(): JSONObject = JSONObject().put("enabled", true).put("domain", "D27.media-uley.com.")
        .put("publicKey", "1234567890abcdef".repeat(4)).put("vlessId", "12345678-1234-1234-1234-123456789abc")
    fun parse(value: JSONObject) = DnsFallbackConfig.parse(JSONObject().put("dnsFallback", value))
    val good = parse(descriptor())
    expect(good != null && good.domain == "d27.media-uley.com" && good.failureThreshold == 3)
    for (field in listOf("domain", "publicKey", "vlessId")) expect(parse(descriptor().removeThenReturn(field)) == null)
    for (domain in listOf("127.0.0.1", "a.local", "a.localhost", "bad_.example", "-bad.example", "a..example", "a".repeat(64)+".com"))
        expect(parse(descriptor().put("domain", domain)) == null)
    for (url in listOf("http://example.com/", "https://u:p@example.com/", "https://example.com/#token", "https://127.0.0.1/", "https://a.local/", "https://example.com:444/", "https://example.com/"+"x".repeat(512)))
        expect(parse(descriptor().put("probeUrl", url)) == null)
    for (bad in listOf(true, "3", 1, 9, 2.5)) expect(parse(descriptor().put("failureThreshold", bad)) == null)
    expect(parse(descriptor().put("enabled", "true")) == null)
    expect(parse(descriptor().put("enabled", false)) == null)
    expect(parse(descriptor().put("probeUrl", JSONObject.NULL)) == null)
    expect(parse(descriptor().put("publicKey", "0".repeat(64))) == null)
    expect(parse(descriptor().put("vlessId", "00000000-0000-0000-0000-000000000000")) == null)
    expect(parse(descriptor().put("unknown", "x".repeat(2048))) == null)
    expect(parse(descriptor().put("failureThreshold", 2))?.failureThreshold == 2)
    expect(parse(descriptor().put("failureThreshold", 8))?.failureThreshold == 8)

    // This method is extracted verbatim from production Xray.kt, including both native stop calls.
    LibXrayStopFixture.reset()
    expect(Xray.instance.stopVpnVerified())
    expect(Xray.instance.fixtureState() == ProtocolState.DISCONNECTED && LibXrayStopFixture.calls == 2)
    for (side in 0..1) {
        LibXrayStopFixture.reset(); if (side == 0) LibXrayStopFixture.xrayError = "failed" else LibXrayStopFixture.tunError = "failed"
        expect(!Xray.instance.stopVpnVerified())
        expect(Xray.instance.fixtureState() == ProtocolState.UNKNOWN && LibXrayStopFixture.calls == 2)
    }
    LibXrayStopFixture.reset(); LibXrayStopFixture.throwXray = true
    expect(!Xray.instance.stopVpnVerified() && LibXrayStopFixture.calls == 2)
    assertions += org.amnezia.vpn.ownerstop.runOwnerStopTests()
    assertions += runDnsRestoreContracts()
    assertions += org.amnezia.vpn.protocol.xray.runXrayNativeRuntimeTests()
    assertions += org.amnezia.vpn.protocol.xray.runXrayEndpointRouteTests()
    assertions += runDnsTunnelReadinessTests()
    assertions += runDnsResolverSelectionTests()
    println("$assertions checks passed; actual policy, descriptor and native-stop method; no app build")
}

private fun JSONObject.removeThenReturn(key: String): JSONObject { remove(key); return this }
