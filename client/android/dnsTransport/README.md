# Android DNS reserve transport

Source integration is opt-in per profile: only a valid top-level `dnsFallback`
descriptor enables the AWG/Wireguard wrapper. The same private service instance
and activation identity retain ownership. The selected protocol in saved
preferences remains unchanged. No executable is downloaded at runtime.

The wrapper samples HTTPS on the app-owned VPN Network. Three default failures
and a 20-second startup grace permit a DNS attempt only while a physical cellular
network and carrier DNS resolvers are available. It protects and binds only the
relay's upstream DatagramSocket; DNSTT uses a loopback UDP socket. The server
public key is pinned, and a per-profile VLESS UUID authenticates the backend.

Before retiring the primary TUN, the wrapper verifies the DNSTT/VLESS path with
hostname-verified TLS. Native primary cleanup must be confirmed. It then starts
the existing Xray/tun2socks backend, checks actual VPN-network HTTPS and only
then publishes CONNECTED. Private AWG DNS is replaced in the effective backup
configuration by 1.1.1.1 and 1.0.0.1; these DNS datagrams travel inside VLESS.
Original configuration and preferences are preserved.

Every 20 seconds, authenticated transport and actual VPN-network HTTPS are
checked again. A live DNSTT process is insufficient: server restarts can strand
KCP/Noise sessions. Failed health or changed physical networks recreates the
client and relay with 30вЂ“300-second retry backoff. Missing physical connectivity
reports RECONNECTING while retaining the existing TUN. User stop invalidates
the generation, closes sockets, cancels work and verifies native/child cleanup;
unconfirmed cleanup reports UNKNOWN and blocks new admission. Explicit stop of
the current owner remains possible from UNKNOWN.

An active DNS TUN never fabricates a Wireguard peer or migration receipt.
It uses a separate schema-2 restore snapshot: logical server/protocol, exact
service instance/activation/connection nonce, native generation,
`effectiveTransport: "dns"`, and `dnsProfileDigest` (SHA-256 of canonical domain,
public key and per-profile VLESS ID separated by LF). No Wireguard peer or
address is included. CONNECTED requires a fresh authenticated data-path proof;
RECONNECTING can restore stop/control for the actual owned backend/TUN while
physical connectivity is unavailable. A saved profile/connected flag alone
never creates a restore binding. Native discovery reports the wrapper owner.

Native replacement revokes the prior generation before closing the TUN.
The final Main-thread restore commit rechecks that exact generation/owner,
blocking an IO snapshot overtaken by handover or user stop. UI metadata merely
requests a new challenged snapshot; it never authorizes restoration itself.
The Activity refreshes its challenge after DNS native-generation/readiness
changes, and the service reactivates the exact-owner restore gate when reconnecting
or connected. A new UI process rebinds the still-running service; a new service
activation has a different identity and cannot inherit an old binding. Native failures in ordinary Xray cleanup also retain UNKNOWN rather
than falsely claim disconnection, with explicit current-owner cleanup retry.

The owner app must be in an include-only application split list so VPN-network
health probes traverse its TUN. The C++ bridge adds that same existing owner-app
allowance for DNS-enabled profiles. If an exclude list explicitly excludes
Amnezia, fallback is withheld with `owner_excluded_by_app_split`; it never
overrides an explicit exclusion.

## Prepare the native component for the next authorized APK build

Run `build_client.ps1` with `-Abi`, `-GoExecutable`, `-NdkDirectory` and
`-OutputDirectory`. It builds only the native DNSTT component from pinned
upstream commit `0c5c52a57d899c05428c116898941761a2ed83c2` / v1.20260501.0 and
verified module sum. Output is an actual Android PIE executable named
`libdnstt.so` with `dnstt-manifest.json`. It uses Go's Android target and the NDK
compiler, not a Linux executable renamed to a library.

**The application build must receive**
`-DAMNEZIA_DNSTT_ANDROID_CLIENT=<absolute path to libdnstt.so>` or the identically
named environment variable for that ABI. `client/cmake/android.cmake` invokes
the actual packaging admission module, which verifies hash, ABI, API and pinned
source identity before adding it to `QT_ANDROID_EXTRA_LIBS`. Gradle's existing
legacy JNI packaging extracts the executable into `nativeLibraryDir`.

Component preparation is currently explicit, not a default download/build step
of every ordinary Android build. Without that build input the package omits
DNSTT; runtime retains the primary transport and logs
`dns_binary_unavailable`. Therefore do not call a new APK DNS-capable until its
extracted component and runtime tests have been verified.

## Acceptance boundary

Focused contracts do not build an application/APK. The separately prepared
Android component has a transport-chain receipt from the real phone, including
Telegram, HTTPS, UDP DNS and invalid-credential rejection. That component
receipt does not substitute for running the automatic wrapper in a specific APK.
Record separate physical-device acceptance for each built APK: automatic takeover,
post-TUN probe, application splits, UI-only process restart and restored control,
physical network/resolver handover, prolonged idle, and stop/cancellation.
Never reuse a prior component-only receipt as acceptance of a later APK.

Preflight TLS uses a bounded SSLEngine over the VLESS byte stream. Some VLESS
servers defer response framing until the remote destination produces its first
bytes, so ClientHello must be sent before reading the response header. The
response version/addons are validated lazily before TLS records are consumed.
Default platform certificate trust and HTTPS hostname verification remain enabled;
no socket-provider/native-FD shortcut may bypass VLESS framing.

AWG and gomobile Xray contain independent Go runtimes. Real-device isolation
reproduced a fatal cgo pointer error when one Java thread entered AWG JNI and then
Xray JNI; merely co-loading libraries did not reproduce it. Xray now owns one
process-wide `amnezia-xray-native` executor. All Seq initialization, generated JNI
proxy construction and LibXray calls run there. Protocol initialization defers
native loading until suspend startup dispatches to this lane. Cleanup is serialized
on the same lane, and same-lane reentry avoids submit/wait deadlock. Native callbacks
only log or protect sockets; they must not enter AWG or synchronously re-enter Xray
from a foreign callback thread. Service cleanup callers already run on Dispatchers.IO.
This preserves the underlying dependency and requires new real-device acceptance.
