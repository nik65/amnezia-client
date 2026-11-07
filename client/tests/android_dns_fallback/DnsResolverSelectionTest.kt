package org.amnezia.vpn

import java.net.InetAddress

fun runDnsResolverSelectionTests(): Int {
    var checks = 0
    fun expect(value: Boolean) { check(value); checks++ }
    fun ip4(value: String) = InetAddress.getByAddress(value.split('.').map { it.toInt().toByte() }.toByteArray())
    fun ip6(vararg parts: Pair<Int, Int>) = InetAddress.getByAddress(ByteArray(16).apply { for ((i, v) in parts) this[i] = v.toByte() })
    val public = ip4("1.0.0.1"); val other = ip4("9.9.9.9"); val router = ip4("192.168.1.1")
    val public6 = ip6(0 to 0x20, 1 to 1, 2 to 0x48, 3 to 0x60, 15 to 1)
    val literals = mutableMapOf("1.0.0.1" to public, "9.9.9.9" to other, "2001:4860::1" to public6)
    for (v in listOf("0.0.0.0", "0.1.2.3", "127.0.0.1", "10.0.0.1", "172.29.0.1", "192.168.1.1",
        "169.254.1.1", "100.64.0.1", "100.127.255.254", "224.0.0.1", "240.0.0.1", "255.255.255.255",
        "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "192.0.0.1")) literals[v] = ip4(v)
    literals["::"] = ip6(); literals["::1"] = ip6(15 to 1)
    literals["fc00::1"] = ip6(0 to 0xfc, 15 to 1)
    literals["fe80::1"] = ip6(0 to 0xfe, 1 to 0x80, 15 to 1)
    literals["fec0::1"] = ip6(0 to 0xfe, 1 to 0xc0, 15 to 1)
    literals["ff02::1"] = ip6(0 to 0xff, 1 to 2, 15 to 1)
    literals["2001:db8::1"] = ip6(0 to 0x20, 1 to 1, 2 to 0x0d, 3 to 0xb8, 15 to 1)
    literals["::ffff:172.29.0.1"] = ip6(10 to 255, 11 to 255, 12 to 172, 13 to 29, 15 to 1)
    literals["::ffff:1.0.0.1"] = ip6(10 to 255, 11 to 255, 12 to 1, 15 to 1)
    val calls = mutableListOf<String>()
    val parse: (String) -> InetAddress? = { calls.add(it); literals[it] }
    val profile = dnsProfileResolverCandidates(listOf("1.0.0.1", "172.29.0.1"), parse)
    expect(profile == listOf(public))
    // The exact failing WiFi system resolver must not displace an existing valid profile resolver.
    expect(dnsTransportResolverCandidates(listOf(router), profile, true).first() == public)
    expect(dnsTransportResolverCandidates(listOf(router), profile, true) == listOf(public, router))
    expect(dnsTransportResolverCandidates(listOf(router), profile, false) == listOf(router, public))
    expect(dnsTransportResolverCandidates(emptyList(), profile, true) == listOf(public))
    expect(dnsTransportResolverCandidates(listOf(router), emptyList(), true) == listOf(router))
    for ((literal, address) in literals) {
        if (address != public && address != other && address != public6)
            expect(dnsProfileResolverCandidates(listOf(literal), parse).isEmpty())
    }
    for (invalid in listOf<Any?>(null, true, 1, 1.0, "resolver.example", "https://1.0.0.1", "1.0.0.1/32", "fe80::1%wlan0", "", "a".repeat(46))) {
        expect(dnsProfileResolverCandidates(listOf(invalid), parse).isEmpty())
    }
    expect("resolver.example" !in calls && "https://1.0.0.1" !in calls)
    expect(dnsProfileResolverCandidates(listOf("1.0.0.1", "1.0.0.1"), parse) == listOf(public))
    expect(dnsProfileResolverCandidates(listOf("1.0.0.1", "::ffff:1.0.0.1"), parse) == listOf(public))
    expect(dnsProfileResolverCandidates(listOf("2001:4860::1", "1.0.0.1"), parse) == listOf(public6, public))
    expect(dnsProfileResolverCandidates(listOf(null, null, "1.0.0.1"), parse).isEmpty())
    val bounded = dnsTransportResolverCandidates(listOf(router, ip4("192.168.2.1"), ip4("192.168.3.1")), listOf(public, other, public6), true)
    expect(bounded == listOf(public, other, router, ip4("192.168.2.1")) && bounded.size == 4)
    expect(dnsTransportResolverCandidates(listOf(public, router), listOf(public, other), false) == listOf(public, router, other))
    expect(dnsResolverOrderKey(listOf(public, router)) != dnsResolverOrderKey(listOf(router, public)))
    val gateway = DnsFallbackConfig("dns.example", "1234567890abcdef".repeat(4), java.util.UUID.fromString("12345678-1234-1234-1234-123456789abc"), "https://example.com/", 3)
    expect(gateway.copy(profileResolvers = profile).profileDigest() == gateway.profileDigest())
    return checks
}
