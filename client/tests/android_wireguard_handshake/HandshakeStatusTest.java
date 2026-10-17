package org.amnezia.vpn.protocol.wireguard;

import org.amnezia.vpn.protocol.ProtocolState;

/** JVM test of the production Wireguard handshake parsing/state mapping. */
public final class HandshakeStatusTest {
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        require(WireguardKt.parseLastHandshakeTime(null) == null,
            "missing native config must be unknown");
        require(WireguardKt.parseLastHandshakeTime("private_key=\nlast_handshake_time_sec=42\n") == 42L,
            "valid handshake must parse");
        require(WireguardKt.parseLastHandshakeTime("last_handshake_time_sec=bad\n") == null,
            "malformed handshake must not throw");
        require(WireguardKt.parseLastHandshakeTime("last_handshake_time_sec=bad\n"
                + "last_handshake_time_sec=7\n") == 7L,
            "a later valid field may recover malformed native output");
        require(WireguardKt.parseLastHandshakeTime("rx_bytes=1\n") == null,
            "missing handshake field must be unknown");

        require(WireguardKt.wireguardStateForHandshake(1L) == ProtocolState.CONNECTED,
            "positive handshake must be connected");
        require(WireguardKt.wireguardStateForHandshake(0L) == null,
            "zero handshake must keep waiting");
        require(WireguardKt.wireguardStateForHandshake(-1L) == ProtocolState.DISCONNECTED,
            "missing tunnel handle must be disconnected");
        require(WireguardKt.wireguardStateForHandshake(-2L) == ProtocolState.UNKNOWN,
            "unreadable native config must never be connected");
        require(WireguardKt.shouldRetryHandshakeRead(-2L, 1),
            "first unreadable native read must be retried");
        require(WireguardKt.shouldRetryHandshakeRead(-2L, 4),
            "unreadable native read must be retried before the limit");
        require(!WireguardKt.shouldRetryHandshakeRead(-2L, 5),
            "unreadable native read must have a bounded retry limit");
        require(!WireguardKt.shouldRetryHandshakeRead(0L, 1),
            "a zero handshake uses the normal polling path");

        System.out.println("production WireGuard handshake parsing/state mapping PASS");
    }
}
