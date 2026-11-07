# Android automatic DNS fallback contracts

`run_tests.py --output <directory>` compiles the actual production policy,
descriptor parser, DNS relay/process manager and wrapper against Android SDK
36, Kotlin stdlib and coroutines. It runs JVM contracts for generation fencing,
startup grace, consecutive failures, retry cooldown, descriptor rejection,
the native-stop method extracted verbatim from Xray, and the actual service
disconnect method with inert owners (including UNKNOWN-state cleanup).
It also tests DNS schema-2 CONNECTED/RECONNECTING bindings, expiring data-path
leases, exact activation/native-generation fences, revoked handover/stop proofs,
absence of synthetic Wireguard fields, and UI metadata refresh deduplication.
`kotlin-dns-snapshots.jsonl` contains actual Kotlin-generated transport-specific
snapshots for the C++ decoder/matching contracts.

The Android framework/protocol owners are inert fixtures. This is source
compilation and focused contract validation, **not a full service/app build or
on-device automatic-fallback acceptance**. The JSON test dependency is pinned
to org.json 20240303, downloaded only to the supplied test output directory.

`run_packaging_checks.py --component <libdnstt.so> --output <directory>` configures
an INTERFACE-only CMake fixture with the real admission module. It admits the
prepared pinned Android component and rejects changed hash, ABI, source commit
and minimum API. It never configures/builds Amnezia or creates an APK.

`run_qt_packaging_tests.py --component <libdnstt.so> --qt-host <host-kit>
--qt-android <android-kit> --sdk <sdk> --ndk <ndk> --output <directory>` builds
a tiny ARM64 Qt fixture and invokes the real `androiddeployqt --aux-mode`.
It uses the actual product library-list template and checks exact component
bytes, executable permission and exclusion from extra JNI libraries/startup lists.
The optional `--module <preserved-module>` checks the former JNI classification;
`--qt-default-template` additionally exposes Qt's automatic-loading behavior.
The product template currently suppresses extra-library list insertion; the
module must preserve executable-only packaging independently of that template.
This fixture creates no APK or Android process and establishes no device acceptance.

Existing native-session restore, activity/service discovery and native-idle
suites must remain green when the wrapper/service ownership wiring changes.

DNS VLESS preflight TLS regression: `run_tls_tests.py --output <owned-output>`
compiles the actual provider-independent SSLEngine helper and runs a local lazy
VLESS gateway in front of a real TLS server. It verifies HTTP success only after
certificate/hostname validation, rejects wrong hostname and untrusted certificate,
checks fragmented/addon framing, malformed/truncated responses and a silent-peer
deadline. Fixture certificates/private keys are disposable test-only output.
The normal SDK compilation includes the helper; no APK/Gradle build is invoked.

The slow-trickle regression sends each VLESS header/addon byte within the socket
read timeout while exceeding the global TLS deadline. A callback before every
framing read applies the remaining monotonic budget; removing that callback is
compiled as a negative mutant and fails the elapsed-time assertion.

HTTP acceptance now uses the shared production `dnsHttpsSuccess` parser in both
the native preflight and real TLS fixture. It requires bounded CRLF framing and
a valid HTTP/1.x 2xx/3xx status, removing the CR delimiter before validation.
Regression vectors reject LF-only/truncated/oversized/control-character status
lines and demonstrate the old regex rejecting a genuine `200 OK` with trailing CR.
Preflight logs expose only fixed stage, exception class and elapsed milliseconds.

The actual `XrayNativeRuntime` is exercised for stable exclusive thread identity,
32 concurrent callers without native overlap, same-lane reentry, original exception
propagation/recovery and suspending startup without blocking the caller dispatcher.
Source contracts check every current Xray JNI producer and Tun2SocksConfig boundary
is reached from an asserted exclusive lane. Native-stop semantics remain tested
from the exact production method. These tests do not replace the phone JNI test.

`run_failed_cleanup_tests.py --output <owned-output>` executes actual failed-start
cleanup, retry-entry, retained-health and terminal-stop fragments with deterministic
host JVM doubles. It checks native-stop-before-relay-close, failed/throwing stop
retention, stale-health rejection, cancellation, unjoined monitor ownership and
next-stop recovery. The monitor timeout is a deterministic control-flow fixture;
it does not establish a native stop deadline or replace real-phone validation.
