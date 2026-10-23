package org.amnezia.vpn.protocol

import java.math.BigInteger
import java.net.InetAddress
import java.io.File
import kotlin.random.Random
import org.amnezia.vpn.util.net.InetNetwork

private var checks = 0
private fun verify(value: Boolean) { check(value); checks++ }
private fun route(text: String, include: Boolean) = Route(InetNetwork.parse(text), include)
private fun number(route: Route) = BigInteger(1, route.inetNetwork.address.address)
private fun lookup(routes: Collection<Route>, address: BigInteger, size: Int): Boolean? {
    var best = -1
    var result: Boolean? = null
    for (route in routes) {
        val network = route.inetNetwork
        if (network.address.address.size != size) continue
        val remaining = size * 8 - network.mask
        if (address.shiftRight(remaining) == number(route).shiftRight(remaining) && network.mask >= best) {
            best = network.mask
            result = route.include
        }
    }
    return result
}
// The LPM result is constant on every interval delimited by a prefix boundary.
// Checking their union proves all addresses, rather than sampling IPs.
private fun equivalent(before: List<Route>): Set<Route> {
    val after = compactRoutes(before)
    verify(compactRoutes(after) == after)
    proveEqual(before, after)
    return after
}
private fun proveEqual(before: Collection<Route>, after: Collection<Route>) {
    for (size in listOf(4, 16)) {
        val limit = BigInteger.ONE.shiftLeft(size * 8)
        val boundaries = sortedSetOf(BigInteger.ZERO, limit)
        for (r in before + after) if (r.inetNetwork.address.address.size == size) {
            boundaries += number(r)
            boundaries += number(r) + BigInteger.ONE.shiftLeft(size * 8 - r.inetNetwork.mask)
        }
        for (point in boundaries) if (point < limit)
            verify(lookup(before, point, size) == lookup(after, point, size))
    }
}

fun main(args: Array<String>) {
    verify(equivalent(listOf(route("0.0.0.0/0", true), route("10.0.0.0/9", false),
        route("10.128.0.0/9", false))).size == 2)
    equivalent(listOf(route("0.0.0.0/0", true), route("10.0.0.0/8", false),
        route("10.1.0.0/16", true), route("10.1.2.0/24", false)))
    equivalent(listOf(route("::/0", true), route("2001:db8::/33", false),
        route("2001:db8:8000::/33", false), route("2001:db8:1::/48", true)))
    equivalent(listOf(route("10.0.0.0/8", true), route("10.0.0.0/8", false)))
    equivalent(listOf(route("10.0.0.0/8", false), route("10.0.0.0/8", true)))
    equivalent(listOf(route("192.0.2.0/24", true))) // No implicit default route.
    val invalid = listOf(route("192.0.2.1/24", false))
    verify(compactRoutes(invalid) == invalid.toSet())
    // Execute the actual production buildVpnInterface body with a recording
    // platform Builder. Its last-writer same-prefix behavior is separate from
    // the LPM equivalence oracle above.
    for (api in listOf(32, 35)) for (brand in listOf("samsung", "other")) {
        Build.VERSION.SDK_INT = api
        Build.BRAND = brand
        val dns = InetAddress.getByName("10.0.0.1")
        for (policy in listOf(
            listOf(route("0.0.0.0/0", true), route("10.0.0.0/32", false), route("10.0.0.1/32", false)),
            listOf(route("0.0.0.0/0", true), route("10.0.0.0/24", false)),
            listOf(route("0.0.0.0/0", true), route("10.0.0.1/32", false), route("10.0.0.1/32", true)),
            listOf(route("0.0.0.0/0", true), route("10.0.0.1/32", true), route("10.0.0.1/32", false))
        )) {
            val config = ProtocolConfig(routes = policy, dnsServers = setOf(dns),
                includedApplications = setOf("selected"), excludedApplications = setOf("excluded"))
            val builder = Builder()
            ActualProtocol().buildVpnInterface(config, builder)
            val original = (if (brand == "samsung") listOf(Route(InetNetwork(dns), true)) else emptyList()) + policy
            proveEqual(if (api < 33) original.filter { it.include } else original, builder.recorded.values)
            verify(builder.allowed == config.includedApplications)
            verify(builder.disallowed == config.excludedApplications)
            verify(builder.dns == config.dnsServers)
        }
    }
    val random = Random(17)
    repeat(160) {
        val routes = mutableListOf<Route>()
        repeat(30) {
            val size = if (random.nextBoolean()) 4 else 16
            val mask = random.nextInt(size * 8 + 1)
            val bytes = random.nextBytes(size)
            for (bit in mask until size * 8)
                bytes[bit / 8] = (bytes[bit / 8].toInt() and (128 ushr (bit % 8)).inv()).toByte()
            routes += Route(InetNetwork(InetAddress.getByAddress(bytes), mask), random.nextBoolean())
        }
        equivalent(routes)
    }
    val fixture = File(args.single()).readLines().filter { it.isNotBlank() }.map { route(it, false) }
    val actual = listOf(route("0.0.0.0/0", true)) + fixture
    val reduced = equivalent(actual)
    println("actual_input=${fixture.size} compacted_excludes=${reduced.count { !it.include }} total=${reduced.size} checks=$checks")
}
