package org.amnezia.vpn.protocol.xray

fun runXrayEndpointRouteTests(): Int {
    var checks=0
    fun verify(value:Boolean) { checks++;check(value) { "Xray endpoint route test $checks" } }
    for (host in listOf("127.0.0.1", "127.42.1.9", "::1", "::ffff:127.0.0.1")) {
        verify(xrayEndpointBypassRoute(host)==null)
    }
    for (host in listOf("85.208.87.69", "192.0.2.1", "::ffff:192.0.2.1")) {
        val route=xrayEndpointBypassRoute(host)
        verify(route!=null && route.isIpv4 && route.mask==32 && !route.address.isLoopbackAddress)
    }
    val v6=xrayEndpointBypassRoute("2001:db8::1")
    verify(v6!=null && v6.isIpv6 && v6.mask==128)
    verify(v6?.address==java.net.InetAddress.getByName("2001:db8::1"))
    return checks
}
