# DNS transport prototype (2026-10-27)

This is an isolated diagnostic prototype, **not an Amnezia transport or release**.
The application, its VPN service, routes and system DNS are not changed.

## Verified path

Physical Android → a UDP socket bound to the cellular network → carrier recursive
DNS → `d27.media-uley.com` delegated to ServerX → DNSTT → loopback diagnostic
HTTP backend. HTTPS remains end-to-end TLS, with certificate/hostname validation.

DNSTT is pinned to upstream `v1.20260501.0`, commit
`0c5c52a57d899c05428c116898941761a2ed83c2` from
<https://www.bamsoftware.com/git/dnstt.git>. Its server public key is pinned on
the client. Do not replace this with custom cryptography.

The carrier's recursive server requested 512-byte DNS responses even though the
phone advertised EDNS 1232. DNSTT's default/server `-mtu 1232` rejected those
requests with FORMERR. Server `-mtu 512` made the measured path work. This is the
DNS response limit, **not the VPN/TUN MTU**.

## Source files

- `mobile_dns_relay.cpp`: bounded Android NDK UDP relay. Binds only its upstream
  socket via `android_setsocknetwork`; one loopback client, one fixed recursive
  resolver, explicit lifetime (1–3600 seconds; explicit 0 runs until stopped).
  It does not bind the whole process or
  alter network settings.
- `probe_backend.go`: authenticated loopback HTTP endpoint. Transfers at most
  1 MiB per request with SHA-256 verification. CONNECT is limited to
  `example.com:443` and `www.wikipedia.org:443`; it is not an open proxy.
  At most four requests, bounded headers, byte counts and timeouts.
- `DnsTunnelProbe.java`: standalone Android diagnostic class, not an APK.
  Exercises byte-for-byte transfer, token rejection, forbidden CONNECT and TLS.
- `SocksTlsProbe.java` / `SocksUdpProbe.java`: authenticated SOCKS tests for
  verified HTTPS and UDP DNS through the permanent VLESS/DNSTT gateway.
- `VlessDenyProbe.java`: verifies rejection of a bad device UUID and a private
  destination; credentials are read from a private profile file.

Test credentials and transport keys are generated separately and never stored in
these sources. Read the token from a private file; do not pass it on a command
line. Run the backend with its token-file path as the first argument. The relay
arguments are `networkHandle resolverIPv4 localPort lifetimeSeconds`; derive the
current cellular handle and DNS addresses before every run.

Build the relay with the Android NDK for the actual device ABI, linking `android`.
Compile the Java diagnostic with Android's boot class path, convert to dex, and
use `app_process -Xmx32m` on an owner-authorized real device. No emulator or app
installation is required. DNSTT/client and the backend are separate diagnostic
binaries, not part of application/release build targets.

## Live-test boundaries

The 2026-10-27 run used an isolated Cloud.ru ingress group permitting UDP 53 only
on ServerX's public interface, added alongside the existing security group after
explicit owner confirmation. Do not change the existing shared group, VPN ports,
production containers, host routes or DNS. DNS delegation alone does not open a
cloud security group port. An ordinary DNS answer is not tunnel acceptance.

Prototype systemd units use DynamicUser, credentials, resource limits and a
two-hour maximum lifetime; they are not enabled at boot. On this Ubuntu/systemd,
ExecStart credential paths use `${CREDENTIALS_DIRECTORY}`, not unsupported `%d`.
Only the DNS listener needs CAP_NET_BIND_SERVICE. The backend listens on
127.0.0.1:18081. Stop only identified prototype processes/units during cleanup.

The dated receipt lives under
`dist/diagnostics/dns-prototype-20261027/REPORT_RU.md`. Recheck live state before
reuse; that receipt is not evidence of perpetual availability.

## Remaining integration work

The later 2026-10-27 integration lives in `client/android/dnsTransport` and
`deploy/dns_transport`. Server units are now permanent; the original temporary
backend was retired. Its acceptance receipt is separate:
`dist/diagnostics/dns-integration-20261027/phone-acceptance-native.json`.
Telegram's actual app was tested through a local authenticated SOCKS proxy.
Those diagnostic processes survive USB disconnection, but not phone reboot;
the fixed network handle must be refreshed when the cellular network changes.

No installed Amnezia client selects this path automatically yet. Runtime
acceptance of enrollment, protected sockets, cellular-network changes,
cancellation, retries/backoff and health reporting requires the future APK.
Fleet enrollment/key rotation and prolonged battery/load tests remain separate
work. DNS throughput and carrier
behavior can vary. Do not announce a general or permanent whitelist bypass from
this bounded test.
