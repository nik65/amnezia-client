package org.amnezia.vpn.protocol

import java.net.InetAddress
import org.amnezia.vpn.util.net.InetNetwork

/** Preserve longest-prefix routing, including include/exclude exceptions.
 * Equal-prefix conflicts keep their original last-writer semantics. Invalid
 * network prefixes are left for the existing platform validation to reject.
 */
internal fun compactRoutes(routes: Collection<Route>): Set<Route> {
    class Node {
        var action: Boolean? = null
        val children = arrayOfNulls<Node>(2)
    }
    val roots = mapOf(4 to Node(), 16 to Node())
    for (route in routes) {
        val bytes = route.inetNetwork.address.address
        val mask = route.inetNetwork.mask
        if (bytes.size !in roots || mask !in 0..bytes.size * 8 ||
            (mask until bytes.size * 8).any { bit ->
                (bytes[bit / 8].toInt() and (128 ushr (bit % 8))) != 0
            }) return routes.toSet()
        var node = roots.getValue(bytes.size)
        for (bit in 0 until mask) {
            val branch = (bytes[bit / 8].toInt() ushr (7 - bit % 8)) and 1
            node = node.children[branch] ?: Node().also { node.children[branch] = it }
        }
        node.action = route.include
    }
    data class Reduced(val mixed: Boolean, val uniform: Boolean?, val routes: List<Route>)
    fun reduce(node: Node?, inherited: Boolean?, prefix: ByteArray, depth: Int): Reduced {
        val action = node?.action ?: inherited
        if (node == null || node.children.all { it == null }) {
            val entries = if (action != null && action != inherited)
                listOf(Route(InetNetwork(InetAddress.getByAddress(prefix), depth), action)) else emptyList()
            return Reduced(false, action, entries)
        }
        val left = reduce(node.children[0], action, prefix, depth + 1)
        val rightPrefix = prefix.copyOf()
        rightPrefix[depth / 8] = (rightPrefix[depth / 8].toInt() or (128 ushr (depth % 8))).toByte()
        val right = reduce(node.children[1], action, rightPrefix, depth + 1)
        if (!left.mixed && !right.mixed && left.uniform == right.uniform) {
            val common = left.uniform
            val entries = if (common != null && common != inherited)
                listOf(Route(InetNetwork(InetAddress.getByAddress(prefix), depth), common)) else emptyList()
            return Reduced(false, common, entries)
        }
        val own = if (action != null && action != inherited)
            listOf(Route(InetNetwork(InetAddress.getByAddress(prefix), depth), action)) else emptyList()
        return Reduced(true, null, own + left.routes + right.routes)
    }
    return roots.flatMap { (size, node) -> reduce(node, null, ByteArray(size), 0).routes }.toSet()
}
