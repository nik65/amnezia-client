package org.amnezia.vpn

import android.system.Os
import android.system.OsConstants
import java.net.InetAddress

/** Profile extras are numeric public literals, never hostname-resolution requests. */
private fun numericProfileResolver(text: String): InetAddress? = runCatching {
    Os.inet_pton(if (text.contains(':')) OsConstants.AF_INET6 else OsConstants.AF_INET, text)
}.getOrNull()

private fun publicProfileResolver(value: InetAddress): InetAddress? {
    val bytes = value.address.map { it.toInt() and 255 }
    if (bytes.size == 16 && bytes.take(10).all { it == 0 } && bytes[10] == 255 && bytes[11] == 255)
        return publicProfileResolver(InetAddress.getByAddress(value.address.copyOfRange(12, 16)))
    if (value.isAnyLocalAddress || value.isLoopbackAddress || value.isLinkLocalAddress ||
        value.isSiteLocalAddress || value.isMulticastAddress) return null
    if (bytes.size == 4) {
        val (a, b, c) = bytes
        // Reserved/shared/documentation/benchmark ranges are not public resolver destinations.
        if (a == 0 || a == 10 || a == 127 || a >= 224 ||
            a == 100 && b in 64..127 || a == 169 && b == 254 ||
            a == 172 && b in 16..31 || a == 192 && b == 168 ||
            a == 192 && b == 0 && c in setOf(0, 2) || a == 192 && b == 88 && c == 99 ||
            a == 198 && b in 18..19 || a == 198 && b == 51 && c == 100 ||
            a == 203 && b == 0 && c == 113) return null
    } else if (bytes.size == 16) {
        // Globally allocated unicast only; excludes ULA, link/site-local and mapped private IPs.
        if ((bytes[0] and 0xe0) != 0x20 ||
            bytes[0] == 0x20 && bytes[1] == 1 && bytes[2] == 0x0d && bytes[3] == 0xb8) return null
    } else return null
    return value
}

internal fun dnsProfileResolverCandidates(values: List<Any?>,
    parseNumeric: (String) -> InetAddress? = ::numericProfileResolver): List<InetAddress> =
    values.take(2).mapNotNull { value ->
        val text = (value as? String)?.trim() ?: return@mapNotNull null
        if (!text.matches(Regex("[0-9a-fA-F:.]{2,45}")) || !text.any { it == '.' || it == ':' })
            return@mapNotNull null
        runCatching { parseNumeric(text)?.let(::publicProfileResolver) }.getOrNull()
    }.distinct().take(2)

/** At most two existing system and two explicit profile candidates; no new public resolver is invented. */
internal fun dnsTransportResolverCandidates(system: List<InetAddress>, profile: List<InetAddress>,
    wifi: Boolean): List<InetAddress> {
    val physical = system.filter { !it.isAnyLocalAddress && !it.isLoopbackAddress }.distinct().take(2)
    val configured = profile.mapNotNull(::publicProfileResolver).distinct().take(2)
    return (if (wifi) configured + physical else physical + configured).distinct().take(4)
}

internal fun dnsResolverOrderKey(resolvers: List<InetAddress>): String =
    resolvers.joinToString(",") { it.hostAddress ?: "" }
