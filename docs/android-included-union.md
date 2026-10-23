# Android included sites and applications

AmneziaWG and WireGuard combine nonempty included site and application lists by
OR on Android 10 or newer. A selected application sends its TCP/UDP traffic to
VPN regardless of destination. A selected destination goes to VPN regardless
of application. A known unselected application's other TCP/UDP traffic goes
directly. Single-filter configurations retain their existing platform routing.

Android's VpnService application allowlist and route list intersect. The union
therefore admits traffic into one system TUN without an application allowlist,
uses default native peer AllowedIPs, and classifies it inside the AWG backend.
The original selected prefixes and package UIDs are retained as native policy.
Selected packets retain the AWG packet transport. Other eligible flows enter a
gVisor TCP/UDP forwarder whose sockets require VpnService.protect before connect.
Protection failure rejects and drops the known-unselected direct flow. It is
never re-injected into AWG and is never exposed through an unprotected socket.
There is no direct fallback for a selected VPN flow or a failed AWG connection.

The native policy validates IPv4/IPv6 headers and extension lengths. Unknown
owners, fragmented packets, unsupported transports, and configured shared DNS
remain in VPN. Android shares a UID between some applications; selecting one
also selects traffic from its shared UID. These limits must be included in
phone acceptance. Android below version 10 rejects the combined configuration
before interface establishment, since reliable owner lookup is unavailable.

TCP route decisions are bounded and pinned across retransmits. A new SYN with a
different sequence rechecks the owner. UDP owner lookup is per datagram because
another application can reuse a tuple without a handshake. Prefix matching uses
indexed prefix lengths rather than scanning the entire site list per packet.
Direct sockets and forwarding tasks are closed when the native device closes.
The JNI callback object remains owned until native device cleanup finishes.
The AWG bind protects its IPv4/IPv6 sockets before exposing receive functions,
including later bind reopen operations.

The Conan recipe exports a reviewed overlay and installs it into fresh pinned
upstream source. Exact patch anchors reject source drift and already-patched
inputs. Module versions and sums are included; an existing unmodified native
library cannot silently provide union routing.

## Verification

- `recipes/awg-android/union/uniontun/*_test.go` executes production routing and
  forwarding: all four app/site combinations for TCP/UDP and IPv4/IPv6, unknown
  owners, DNS, malformed/fragmented packets, reused tuples, bounded caches,
  actual packet transfer, socket protection rejection and live-flow cleanup.
  Forwarding tests use owned loopback servers, including the protection Control
  hook, and run on Linux; they do not create an Android device or an OS TUN.
- `client/tests/android_included_union/ConfigRoutingTest.java` runs actual
  compiled production Android configuration classes on a JVM. It verifies
  default peer AllowedIPs for the union, preservation of both lists, unchanged
  single-filter behavior and the IPv4-only server gate.
- Compile `:wireguard:compileReleaseKotlin` and `:awg:compileReleaseKotlin` with
  the project's Qt/SDK properties. Build the patched native `libwg-go` for the
  supported Android ABIs. Compilation alone is not phone acceptance.

## Required real-phone acceptance

Use a user-supplied phone and AmneziaWG/WireGuard profile with default AllowedIPs.
For selected and unselected applications, verify selected/unselected destination
egress, DNS, TCP and UDP/QUIC, and IPv6 when the server supports it. Verify idle
traffic, Wi-Fi/mobile handover, reconnect and cleanup, shared/unknown UID cases,
and always-on/lockdown settings where used. Confirm included flows never fall
back to physical egress when VPN is unavailable. Record the exact app/native
artifact hashes and installed version. Android emulator, CVD and ADB execution
are disabled by repository policy; no sandbox receipt can satisfy this gate.
