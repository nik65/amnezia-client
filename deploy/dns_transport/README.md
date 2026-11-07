# Authenticated DNS fallback

The transport is DNSTT -> loopback VLESS -> the existing ServerX SOCKS backbone.
It does not replace or restart the ordinary VPN or change host routing.
TCP and UDP are carried inside the authenticated VLESS stream. DNS delegation
and inbound UDP/53 on the authoritative public IP are prerequisites.

## Server files

- `/opt/amnezia-dns-transport/dnstt-server` (0555): pinned DNSTT server.
- `/etc/amnezia/dns-transport/server.key` (0400), `server.pub`.
- `/etc/amnezia/dns-transport/gateway.json` (0400), directory mode 0700.
- The two systemd units in this directory; render only `@PUBLIC_IPV4@` and
  `@DNS_DOMAIN@` in the transport template. Validate the gateway with
  `sing-box check -c /etc/amnezia/dns-transport/gateway.json` before starting.

The units use systemd credentials, DynamicUser, bounded RAM/CPU and automatic
restart. Enable both units for boot persistence. They have no prototype expiry.
Gateway AF_NETLINK is required for sing-box route notifications; denying it
causes `subscribe route updates: address family not supported by protocol`.
The gateway listens only on loopback and rejects private destinations after
resolution. It uses the existing authenticated backbone via local SOCKS 10808.
Never copy an owner's UUID into another device's export: provision a distinct
UUID on the gateway and in that device's profile. Automatic fleet enrollment is
not implemented by these templates.

The ServerX collector exception permits only the authenticated `dns-vless`
inbound's TCP traffic to `172.29.172.251/32:17866` through `client-logs-direct`.
Adapt that exact address/port to another deployment's private collector; retain
all other private-destination rejection. The phone must use its own dedicated
nonlegacy `clientLogs` explicit token; legacy AWG peer/IP checks remain intact.
Collector HTTP travels inside the authenticated encrypted DNS transport from
phone to ServerX, then on the private collector bridge. No public HTTP endpoint
is introduced.

DNSTT upstream: `www.bamsoftware.com/git/dnstt.git`, tag `v1.20260501.0`,
commit `0c5c52a57d899c05428c116898941761a2ed83c2`.
Verified deployed linux/amd64 binary SHA-256:
`ad8d2a0fef0e60f47e2cf8f0b33185619a4eb453450e9f4cc7d2324ed35264d6`.
Use response MTU **512**: the tested mobile resolver advertises/forwards a
512-byte budget even when the client's request carries a larger EDNS value.

## Acceptance boundary

The 2026-10-27 real-phone tests cover authenticated HTTPS, UDP DNS and Telegram
through a standalone diagnostic SOCKS/DNSTT chain on mobile data. They do not
constitute acceptance of the newly integrated Amnezia fallback state machine.
That requires a future APK containing the sources and bundled DNSTT executable.
The current user instruction forbids building that APK.

The owner enrollment descriptor is held in the protected local diagnostic
directory and Secret Store; it is deliberately absent from this repository.
The profile field is `dnsFallback`, with `enabled`, `domain`, `publicKey`,
`vlessId`, `probeUrl` and `failureThreshold`. Only explicitly enrolled Android
AWG/Wireguard profiles use it. This change does not silently enroll other
devices or reuse one UUID across newly exported clients.

Phone-side diagnostic processes are not an installed background service and
do not survive a phone reboot. Do not represent them as permanent client
integration. Server service enablement/restart is a separate acceptance check;
a full server reboot was not requested or performed.

Observed restart failure: the old DNSTT process can remain alive after its
server session has been lost. Process liveness alone is insufficient. The
Android wrapper must periodically verify the authenticated path and actual VPN
traffic, then recreate a stale transport. During the standalone phone test,
the diagnostic processes were explicitly recreated after the server restart;
the installed old APK did not perform that recovery automatically.
