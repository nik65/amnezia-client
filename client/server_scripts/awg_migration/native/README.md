# AWG native components: staged runtime boundary

This directory contains C++17 server components. Existing Python deployment
resources, production control recipes and running generations have not been
replaced. Standalone tests are source validation, not deployment or release
acceptance. Python build/test tooling and Conan recipes remain supported.

## Implemented interfaces

| Component | Native scope | Remaining integration |
| --- | --- | --- |
| `feed_file`, `feed_server` | Descriptor-pinned feed files and bounded HTTP serving | Source wiring complete; static bundle delivery and guest acceptance remain |
| `ready_config` | Pure typed AWG config parsing | Native prepare/preflight wired; maintenance and delivery remain |
| `automatic_plan`, `trusted_image` | UDP inventory, stable planning/reuse, pinned catalog and bounded process/sandbox adapter | Native automatic planning/inventory/port/catalog wired; orchestration and delivery remain |
| `policy`, `policy_runtime` | Typed policy, filesystem and bounded JSON/read-only process adapters | Native prepare/preflight wired; maintenance and environment acceptance remain |
| `ready_attestation` | Config, engine, peer and epoch proof core | New-prepare adapter wired; existing-generation/recovery and delivery remain |
| `transaction_journal` | Locked transactional filesystem core, durability and bounded read/save | Prepare/maintenance transaction wiring and recovery acceptance |
| `control_service` | Canonical signed requests, challenges/grants/ACK, crypto and SQLite state | HTTP adapter, PID1 lifecycle and native control recipe |

Dependencies are json-c, RapidJSON headers, OpenSSL Crypto, SQLite3 and Threads.
RapidJSON supplies parsing for control canonicalization; json-c supplies typed
JSON objects. Crypto and database logic use their established libraries. No Qt
runtime is required by these AWG components. Headless provisioning is a separate
component and retains its QtCore dependency.

`ProcessRunner`/port interfaces and test probes use scripted fake responses;
planner tests do not execute Docker or bind UDP. Test probes can expose synthetic
parsed config maps or protocol bytes and are not production inspection tools.
A real server adapter must preserve bounded capture, typed sanitized failures,
argument-vector execution and ownership/epoch checks.

### Feed/config executables

`awg_feed_server` is runnable without Python. With no arguments, only explicit
17864/17865 entries in `AMNEZIA_FEED_PORTS` enable listeners on `0.0.0.0`, rooted at
`/routing` and `/updates`; empty/unrecognized selection fails before listening.
An explicit standalone mode is:

```sh
awg_feed_server --single updates /path/to/public 127.0.0.1 0
```

Startup JSON reports the selected port. GET/HEAD use exact Content-Length,
no-store headers and bounded 128 KiB transfer buffers. The server limits workers,
queue, header bytes and deadlines; malformed headers and transfer encoding are
rejected. Shutdown interrupts waits and joins workers. Early EOF aborts transfer;
appended bytes beyond the advertised length are not sent. Logs exclude private
request/file content and raw exceptions.

`openFeed` uses descriptor-relative `openat`, `O_NOFOLLOW`, `O_NONBLOCK` and RAII;
it rejects traversal, symlinks, hardlinks, nonregular files and oversized content.
Only origin-form paths and configured roots without trailing slashes are allowed.
An open descriptor does not prevent concurrent inode writes, so HTTP serving
also binds its advertised size and EOF behavior. Linux `.run` files are allowed
only within the exact update allowlist; `.run.bak` is denied. MIME classification
uses the decoded canonical path rather than query-bearing input.

`awg_ready_config_check` reads at most 1 MiB from stdin and prints validity/peer
count only. `awg_ready_config_probe` is test-only and may print complete synthetic
parsed maps; never use it on private production configurations.

## Standalone verification

```sh
cmake -S client/server_scripts/awg_migration/native -B /tmp/awg-native-tests
cmake --build /tmp/awg-native-tests
ctest --test-dir /tmp/awg-native-tests --output-on-failure
```

Use 64-bit Linux; Windows cannot substitute for Linux descriptor semantics.
Supply verified dependency paths when development headers/libraries are staged
outside normal discovery paths. These targets are standalone components/tests,
not an application release build. `-DBUILD_TESTING=OFF` does not discover or
require Python and excludes the differential test executables.

The current aggregate suite passes **22/22 CTest tests**. Fixtures cover owned
filesystem failures, fake process responses, loopback HTTP, config parity,
planner/catalog, policy, attestation, journal and control contracts. Control
canonicalization explicitly covers NUL and DEL handling. Journal save and read
share a 4 MiB cap. Policy tests cover safe FS handling, including nonregular,
symlink and concurrent replacement boundaries. Python differential fixtures
remain verification tools; some native rejection rules intentionally tighten
legacy behavior, so successful fixtures do not imply unrestricted equivalence.

Planner source fixes include nonblocking FIFO refusal and strict generation
binding: a ready request must use a positive safe integer matching its canonical
directory name. Source/fake-fixture defects do not establish a production incident.

## Optional bundle source integration

`client/cmake/serverNativeBundle.cmake` accepts
`AMNEZIA_SERVER_NATIVE_BUNDLE_DIR`: manifest SHA, paths and sizes are validated
before QRC generation. Only reviewed static ELF64 ET_EXEC x86_64/aarch64 binaries
without PT_INTERP, PT_DYNAMIC or PIE are accepted. `serverNativeBundle.h` repeats
these checks. No bundle selects legacy; a present invalid bundle or missing
architecture/role fails closed.

`exportController` dispatches native collector/route roles by architecture, uses
the real native entrypoint and host route ExecStart, and verifies PID / loaded
SHA. `installController` captures and validates the native feed through prepare,
retaining the same generation journal. A read-only binary mount uses `--serve`;
native `--check-feed` validates SHA with a 1 MiB cap and five-second deadline.
Feed and route now also require OpenSSL Crypto for SHA verification.

No real static bundle has yet been built or supplied. Source wiring is complete,
but delivery and production activation are not. The default ordinary release
still uses Python. Existing native generation/reuse requires future maintenance /
PID1 attestation; prepare, maintenance and control remain Python runtime paths.

Evidence: `dist/diagnostics/python-native-wiring-20261020`. Additional isolated
checks: generic 62 checks / one CTest; CMake 21 Windows / 24 Linux; collector
route 40, Qt 6 and guard 8; feed regressions 65 and HTTP 8. These do not establish
full runtime/release acceptance.

Headless preauthentication verifies Qt libraries required to execute its helper;
further Python removal is blocked here and must not weaken that trust boundary.
Its QtCore dependency and exact nine-file contract remain intact.

No application/release build, version bump, publication, server mutation or host
VPN/application/service control occurred as part of this source integration.

## Deployment barrier and unfinished runtime work

`prepare` and `maintenance` orchestration, native control recipes, PID1 lifecycle,
control/target HTTP adapters and their runtime delivery remain unfinished. The
implemented core modules must not be described as an activated replacement for
those adapters. Current source resources and historic control-source hashes
still identify Python code; renaming a binary to `.py` or retaining a Python hash
for native bytes would break that identity contract.

A cutover requires all of the following:

1. Bind executable bytes, architecture, shared dependencies and protocol version
   to a reviewed artifact receipt and deliver through the existing client flow.
2. Use an explicit native recipe identity while preserving legacy recovery
   allowlists. Do not compile downloaded sources on a production server.
3. Keep one authoritative generation journal and grant database. Errors must not
   create a parallel journal, rotate generations/peers/signers, or silently invoke
   a mutating fallback.
4. Stage and read back exact files before authorized maintenance. Test source and
   target epochs, Docker DNS, partial replacement, busy locks, grant/ACK handling,
   durability and rollback in owned disposable guests with exact tested bytes.

Separately, the headless installer now selects its native journal after helper
authentication. Its preauthentication and legacy Python paths, QtCore dependency
and exact nine-file provisioning contract are preserved. That source integration
does not activate these AWG server components.

No Python runtime is claimed removed from deployed servers. No live server
operation or final runtime/release acceptance is established by this directory.

## Native policy source adapter (2026-10-21)

The feed executable also accepts `--policy-json` before listener setup. Native
prepare/preflight selects snapshot/firewall/epoch through this adapter; MTU is
exposed through the same typed interface. It executes captured, sealed memfd ELF
bytes with bounded request/output/deadlines and a fixed read-only Docker argv
allowlist. Native failures never silently invoke legacy Python. The prepare
orchestrator, maintenance, PID1 and control delivery remain Python/unfinished.
No deployed runtime is claimed changed. Current receipts are in
`dist/diagnostics/python-native-resume-20261021/`.

## Native configuration source adapter (2026-10-21)

The captured feed helper accepts `--config-json` before listener setup. This pure
command reads at most 1 MiB of raw UTF-8 configuration with a five-second input
deadline, invokes `parseConfig`, and returns private typed JSON. Output is bounded
at 8 MiB (plus the CLI newline) because JSON may expand control characters sixfold.
Interface/peer values, Unicode, opaque NUL and peer order are preserved. Errors
contain fixed codes only; successful stdin/stdout include key material and must
remain private. This command opens no listener and executes no process adapter.

Explicit native selection in `prepare.py` uses this parser for source config and
preflight through the already captured/sealed executable. Legacy selection keeps
the Python parser. Native errors never invoke a Python fallback. Existing native
generation/recovery remains held behind the prior maintenance barrier; this work
did not connect the journal or ready attestation adapter at that checkpoint. Preparation/maintenance,
control/PID1 and delivery are still unfinished runtime work.

The same audit fixed an encoded Android APK filename in both feed implementations:
the manifest's `android9%2B_arm64-v8a.apk` now maps to the actual plus-bearing file.
Single decoding, suffix, traversal and descriptor protections remain. A malformed
IPv6 host containing NUL now reports the same address error as Python; both parsers
already rejected it. Unexpected helper error types/invalid UTF-8 now yield bounded
generic bridge errors instead of leaking TypeError/UnicodeDecodeError.

Final standalone suite:22/22 CTest, config bridge9 methods, config CLI5 methods;
additional parser differential510 cases and owned native HTTP6 cases pass. These
are source/component tests, not application/release or deployed-runtime acceptance.
Evidence: `dist/diagnostics/python-native-config-20261021/`. No static delivery
bundle or application version was built or published.


## Native new-generation readiness adapter (2026-10-21)

`--ready-json` connects the existing C++ `validateReadyTarget` core to new prepare
through the captured/sealed ELF. Its exact private request carries two raw UTF-8
configs (each <=1 MiB), all 20 generated parameters and the original target pin.
The JSON frame is at most16 MiB, input deadline5s, output at most4096bytes and the
bridge accepts only exact boolean success. The C++ runner allows fixed read-only
Docker commands against the pinned64-hex ID, with3s command deadlines and bounded
output. ID/name/image/owner/Running/StartedAt are checked before and after core
observations; no native error silently invokes Python.

New prepare now uses the full validator in both explicit native and legacy paths.
It checks readiness during startup, immediately before source endpoint activation
and again before saving ready. The persisted targetEpoch is the original pin, not
a newly observed incarnation. This closes the reproduced creation-path gap that
accepted a wrong listen port/Jc/RandomTrailers or raised IndexError for short rows.
Backend inspection failure no longer counts as container-name availability.
The C++ core rejects invalid UTF-8 across each bounded process output before
comparing fields. Shared process FD setup now fails before exec if any required
fcntl/open/dup2 operation fails; six inert fault cases reproduce the old gap.

The60s/20attempt readiness limit is a scheduling window, not a whole-prepare wall
clock cap. An active native helper may finish up to45s later; the initial parent
pin remains outside that window with the old180s command timeout. Legacy commands
and ownership inspections retain180s per command. No whole-flow105s bound is claimed.

Existing native-generation reuse/maintenance HOLD and the single legacy journal
remain. The filesystem/source-SHA/generation parts of `validateExistingTarget`
are not wired by this change. Prepare orchestration, maintenance, control/PID1,
planner/target adapters, static delivery and runtime guest acceptance remain.
No deployed server is claimed switched from Python. Whole-prepare fixtures use
actual function bodies and C++ config/ready dispatch, but substitute every external
effect; cleanup assertions mean cleanup requested, not proven real rollback.

Evidence: `dist/diagnostics/python-native-ready-20261021/`. No application/new
version/static delivery bundle was built or published; host VPN was untouched.


## Native automatic planning/inventory/port probe (2026-10-21)

Explicit native automatic prepare now selects `--automatic-json` for both UDP
inventories, planning and the last port availability probe. It invokes the existing
C++ `occupiedUdpPorts`, `automaticPlan` and `verifyAutomaticPort` cores through the
captured sealed helper. Trusted-image resolution (including pull/sandbox checks),
prepare orchestration, transaction writing/recovery and control/PID1 remain separate
Python/unfinished paths. Existing native-generation/reuse maintenance HOLD remains.

The private exact JSON schema permits only inventory, plan and verify-port. Input
is capped at8MiB/5s; raw config at1MiB with Unicode/opaqueNUL retained for its hash.
Metadata/integers are bounded and typed. Inventory responses are sorted unique
ports; the parent validates exact response types and fails without Python fallback.
Read-only inventory processes allow only fixed `/usr/bin/ss -H -uan`, Docker ps and
inspect with validated IDs, sharing prior3s/1MiB process bounds and FD/lifecycle
cleanup. Port probing holds both IPv4 and IPv6-only UDP leases until it finishes;
RAII closes them on every path. This is best effort, not a port reservation after
return: Docker atomic publication remains the final race check as in Python.

Before source integration, owned regressions exposed and fixed two core defects:
plannerJson accepted duplicate decoded JSON keys/nonfinite constants; readJournal
could return stale bytes after an atomic path replacement during read. Strict
RapidJSON grammar/key checks now precede json-c; stable regular-file identity,
metadata and byte count are checked before/after the readonly read. This is not
the blocked transaction-journal/FLOCK write integration; that code was untouched.

Standalone CTest34/34 passes, including automatic bridge9 methods, readiness13,
planner unit33, differential44 (plus2 strict NUL cases) and stability4. Additional CLI15 cases cover actual
dispatch with process/syscall interposers and owned temporary journal files; no
Docker/ss executable or UDP socket/bind operation runs in those fixtures. These
checks prove source/component behavior, not production or release acceptance.
Evidence: `dist/diagnostics/python-native-planner-20261021/`.

Without a reviewed static delivery bundle ordinary deployment retains Python.
No app/new-version/static-delivery package was built or published, no server was
changed, and no host VPN/application/service/network controls were performed.


Independent follow-up also fixed a legitimate JSON compatibility case: a raw
substring search mistook literal backslash-u0000 text for an actual decoded NUL.
SAX now checks decoded String/Key bytes; literal text (including escaped-backslash
spelling) passes, while actual NUL/duplicates/nonfinite/invalid UTF-8 still fail.
The full captured-helper inventory fixture now includes that legitimate opaque
Docker Env text. Final post-correction aggregate34/34 and CLI15/15 passed.


## Native trusted-image catalog adapter (2026-10-21)

Automatic prepare with explicit native feed now selects `--trusted-image-json`
instead of Python resolve_image. It accepts exactly private {op:resolve}, at most
4096bytes with5s input deadline; no image/tag/architecture/command/budget is supplied
by an operator. The existing C++ catalog checks the exact reviewed RepoDigest,
config-ID/descriptor, Linux/amd64, engine SHA, reported version and fixed tool list.
The parent accepts only the catalog's exact image string and never falls back.

Fixed read-only image metadata commands have10s process budgets, the exact pinned
pull180s and three fixed sandbox probes30s. Their maximum sequential budgets sum
to300s; only this private captured-helper mode has330s parent cap. Other helper
modes retain45s; existing Docker/ss process calls retain3s. Typed failure kinds
preserve retryability only for actual pull Exit/Timeout/OS failures. Final
trust/probe errors and unknown failures remain permanent. The opportunistic cache check
retains its legacy single pinned pull attempt before final verification. Sandbox
argv retains no network,
read-only root, cap-drop ALL/no-new-privileges and resource bounds; no TUN/mount/
host-namespace/elevated network capability was introduced.

Confirmed audit corrections: Unicode boundary whitespace now matches Python strip
via RapidJSON UTF-8 decoding and an empirically checked29-codepoint set; malformed
UTF-8 remains rejected. Shared process waiting no longer polls a permanently-HUP
stdout in a tight loop before child exit: an owned300ms probe fell from306675polls/
0.300s parent CPU to16polls/0.000293s. Existing FD/death/group/reap guards remain.

Standalone suite42/42 passes. Components include catalog unit37, core70,
differential171+2 strict NUL cases, catalog bridge6, existing planner/ready bridges,
FD/process cleanup and six separately registered transport cases. CLI16 passes;
all valid catalog backend calls use link-time fake exec, no real Docker/pull/run.
Independent review and final CMake registration proof are in the stage evidence.

Killing a Docker CLI/group does not prove daemon-side sandbox cleanup: no owned
CID/name cleanup acceptance was established. These fixtures are not live registry,
daemon, migration, VPN or release acceptance. Python legacy/catalog constants,
orchestration, transaction write/recovery, maintenance/control/PID1 and delivery
remain; existing native-generation HOLD and blocked journal/bootstrap are unchanged.
No default deployment changed, and no app/release/static bundle was built/published.
Evidence: `dist/diagnostics/python-native-image-20261021/`.


## Native target configuration generator (2026-10-21)

Explicit native prepare now uses the captured helper's --generate-config-json for
target quick/UAPI serialization and fresh32-byte HeaderProtectionKey generation.
It calls the existing C++ parser, preserves source private key/address and every
peer value/order, discards source hooks and emits exactly20 established parameters.
OpenSSL RAND_priv_bytes must succeed; no CLI seed, retry or Python fallback exists.
Only the test fixture has a deterministic/failing RNG interposer. Legacy selection
without a reviewed native bundle remains Python; journal ownership is unchanged.

The exact private request is {source:string,port:int1024..65535,mtu:int576..9000}.
Input8MiB/5s and source1MiB bounds are separate from per-generated-config1MiB and
JSON output16MiB bounds. Two escaped configs may exceed8MiB. UTF-8, duplicate decoded
keys, types, depth and extra fields are checked. Opaque parsed peer values including
NUL are preserved with length-aware APIs; parent validates typed maps/key/limits
and compares source identity before writing UTF-8 files with0600 permissions.

Confirmed prior native-selected defect: old inline Python serialization accepted
an exact1MiB source then expanded the target above the native readiness1MiB cap.
The C++ generator rejects before filewrite/container creation. This is a synthetic
source-boundary finding, not a diagnosed production incident or pure-legacy bug.

Standalone CTest44/44, new generator unit57 checks, private generation bridge12/12
and pure CLI30/30 pass, including real OpenSSL key generation, test-only RNG failure,
actual5s no-EOF rejection and two escaped outputs over8MiB. Initial unit compilation
found an unused json-c header with a private include path; removing the unused
include repaired the test target. Existing helper/library build is component-only.

Migration/orchestration, transaction writing/recovery, maintenance/control/PID1,
delivery and live acceptance remain incomplete. Existing native-generation HOLD,
model-blocked journal/bootstrap branches and sandbox cleanup acceptance gap remain.
No app/new-version/release/static-delivery build, publication, production change or
host VPN/application/service/network action occurred. Evidence:
dist/diagnostics/python-native-generation-20261021/.


## Native control business logic adapter (2026-10-21)

New native-selected prepare now routes all five migration-control operations to
C++ ControlService through private --control-json. Python still owns HTTP/PID1
and the original authentication callback; absent native bundle retains legacy.
The production state root is fixed /migration; no caller directory/clock/seed is
accepted. Request256KiB/5s, body16KiB, JSON output16MiB are bounded separately.

Authentication is deferred at the core callback via an exception, forcing SQLite
rollback. Parent authenticates once and repeats the same request with verified
client ID; None preserves an already-sent HTTP error. At most two passes occur;
no token/PEM enters the frame and no Python business-logic fallback runs. The same
grants.sqlite3 is shared; no parallel journal or state store was introduced.

Startup captures the exact validated static ELF into sealed memfd. Both control
containers receive the same read-only helper and expected SHA; pure capability
checks reject an old helper before preparation/listener setup. Pre-ready checks
bind actual Python PID1/start time, source pair and retained sealed FD bytes/hash.
Existing native-generation maintenance now explicitly HOLDs before recipe/runner
operations; blocked transaction-journal/FLOCK and collector bootstrap are untouched.

Confirmed control state size defect fixed:6000 valid peers have source522911B,
native quick553255B, ready1245098B. Native formerly403 where Python200; only ready
read/parse grows to8MiB, with exactcap/+1/no-new-grant regression. Request/canonical,
signer and handshake limits remain. Windows legacy import/tests are preserved by
loading fcntl only for explicit Linux native capture.

Final standalone CTest47/47; control runtime unit53 checks, private business bridge8,
wiring10, CLI26, Windows legacy22, separate maintenance24 pass. Actual Ed25519/SQLite
tests use ephemeral owned data; prepare/Docker/proc metadata are inert. The static
capture fixture does not execute, and the dynamic business fixture is manually
sealed/test-only. Real container PID1/listener/loaded-FD acceptance is still pending.
No app/version/release/static-delivery build, install, publication, production or
host VPN/app/service/network operations occurred. Evidence:
dist/diagnostics/python-native-control-20261021/.


## Pure observed network topology adapter

`--network-json` dispatches before listener setup. `network_topology` parses only
observations: it has no process runner, network/socket or filesystem operations.
The `networks` operation accepts raw container-inspect JSON and returns sorted
exact allowed network names. `validate` accepts raw version/container/address/
default-route/network-inspect observations and returns options plus binding.
It preserves legitimate Python IPv4/prefix/netmask/hostmask and Unicode version
whitespace behavior; malformed duplicate keys, nonfinite JSON, invalid UTF-8,
ambiguous types, mismatched networks/interfaces/defaults fail with one fixed error.

The private frame is8MiB, each observed field1MiB, output16KiB and EOF deadline5s.
These are separate aggregate/per-field limits. The Python bridge captures through
its existing runner, checks bytes/UTF-8 limits after capture, and validates the
native result before modifying binding. It never falls back after native failure.
Explicit native prepare/preflight use this adapter; default deployment without
the reviewed static bundle retains the unchanged legacy Python function.

Standalone final CTest52/52 includes81 pure checks,147 differential/strict cases,
9 captured bridge tests and4 CLI tests (real frame/observation caps, noEOF5s).
Other whole-prepare fixtures keep inert topology seams; dedicated tests execute
the actual source selection nodes. No static delivery or real Docker acceptance
was performed. Python orchestration and model-blocked branches remain unchanged.


### Stopped target observations

The `stopped` operation takes identity, typed binding, raw container inspection and
raw network inspections, then returns only literal true after pure validation.
It requires created state, integer Pid0, boolean Runningfalse, zero StartedAt,
bridge NetworkMode, exact endpoint/binding identities/options/priorities and no
assigned endpoint/IP fields. Missing/null/empty inactive fields remain compatible;
malformed booleans/floats/arrays are deliberately stricter than legacy truthiness.
This inspects JSON data only, not live processes, control/PID1 or authentication.
Existing input/output/EOF caps apply. Python observations, journal and mutation
orchestration remain; native errors never fall back. Original start commands and
fresh post-start binding checks are preserved. Tests use owned helper processes
and fake observation/command adapters, never real Docker actions.

Final standalone CTest54/54 includes259 pure checks (81original+178stopped), the
prior147-case topology corpus plus147 stopped cases (66compat/81strict), and10
stopped bridge tests. Static delivery and live orchestration remain unverified.


### Bounded native network observations (21 October)

The explicit native path now requests `snapshot` and `stopped-snapshot` from
`--network-json`; Python no longer captures Docker output for these operations.
The existing bounded C++ transport uses fixed `/usr/bin/docker` read-only argv,
1MiB stdout per command and a 3s command deadline. Container names are limited
to AWG/AWG2 and canonical migration generations; inspected 64-lowerhex identity
pins subsequent IP reads. Stopped binding is validated before observations.
Pure `networks`, `validate`, and `stopped` data adapters remain available.

`capability` is effect-free and reports observerVersion1. Prepare checks it before
journal cleanup or mutation; unsupported/stale helpers fail without Python
fallback. Other preparation/orchestration and default legacy deployment remain
Python. The prior post-capture Python limit was reproduced with an owned 32MiB
synthetic child; this change closes that resource gap only in the native path.
The pipe reader can temporarily exceed the cap by one 8192-byte read chunk before
rejecting; it never accumulates the complete oversized stdout.

These observations are sequential snapshots, not an atomic Docker transaction.
No final name re-resolution or daemon-side completion attestation is claimed.
The 45s parent-helper limit and 5s input-EOF deadline are separate limits, not a
whole-prepare deadline. Test-only executable intercepts execve and cannot run
real Docker; fixture data is not accepted by the production protocol.

Evidence: dist/diagnostics/python-native-network-observer-20261021/. No app,
release, static delivery, installation, publication or live Docker/VPN acceptance.

Final standalone CTest55/55: observer81 checks, prior259 pure and147+147 corpus,
network/stopped bridges11/11 each,36 streamed fault cases including9 actual3s
timeouts. All fixture Docker exec is intercepted; no live acceptance claimed.


### Native source configuration capture (21 October)

All four prepare/preflight source-config reads now select `--source-config-json`
for explicit native. Capability `sourceConfigVersion:1` is pure; prepare checks
it before cleanup. `read` accepts only amnezia-awg/awg2 and no path/argv/budget.
Fixed source inspect(128B), pinned-ID cat(mapped config path,1MiB), immediate
parseConfig and same-source ID recheck use3s per command. Raw bytes including
Unicode/CRLF/opaque NUL remain unchanged in private JSON. Parent does not call
its Python runner or fallback. Input8KiB/output8MiB/EOF5s/helper45s are separate
limits; capture may overshoot by one8192B read chunk before refusal.

The old actual read+parser was reproduced buffering32MiB before1MiB refusal.
This closes the native resource gap; ordinary legacy deployment stays Python.
ID pin/recheck does not promise atomic config, same-ID epoch, or daemon completion.
CLI ROOT mkdir/lock still precedes prepare capability. Blocked branches untouched.

Final standalone CTest58/58: source unit73, source bridge13/13 and CLI3/3,12 streamed
fault cases including3 actual3s deadlines plus5s EOF. Tests use an interposed exec
fixture. Initial parser-integration seams failed because they still mocked only
Python reads; corrected seams and full rerun are documented, not runtime fixes.
No static delivery, app/release build, deployment or host VPN controls performed.
Evidence: dist/diagnostics/python-native-source-config-20261021/.


### Routed policy epoch HTTP client (21 October)

Explicit native prepare now checks the target namespace's routed policy feed
with `/app/awg-feed --check-policy-epoch REV HASH`, replacing its inline Python
urllib subprocess. Endpoint is fixed to172.29.172.253:17864/rules.json; no URL,
proxy, DNS, redirect, fixture path or port is accepted from callers. Revision
is canonical1..9007199254740991, HASH is sha256:lowerhex64. The client compares
only the expected revision/content identity: resolved DNS routes are mutable.

The C++ socket adapter uses a5s absolute steady-clock budget across connect,
send, response and EOF. Header8KiB/body1MiB, exact Content-Length, no transfer
encoding/duplicate headers/trailing bytes; strict JSON duplicate-key/UTF8/NUL/
depth32 validation precedes existing pure policy epoch decoding. The existing
parent Docker runner retains its180s outer budget; this is no whole-prepare or
daemon scheduling deadline. Success has empty output, errors are sanitized.

Pure `--policy-epoch-capability` reports policyEpochVersion1. Both CLI branches
return before feed signal/listener/worker setup. Captured immutable ELF capability
is checked before prepare's journal/recovery work; old helpers fail closed.
CLI ROOT mkdir/lock still precedes prepare capability. Legacy deployment keeps
its supported Python path; native failures never fall back to it. Existing
generation maintenance HOLD, native control/PID1 and journal restrictions remain.

Standalone tests cover33 pure response cases,8 syscall-interposed transport
cases (including real5s slow-drip clock),11 bridge methods including real captured
capability and18 capability/invalid-argument CLI cases. Transport uses no kernel
network sockets; EINTR/EAGAIN/POLLERR/getsockopt-error fault modes are not targeted.
No live server, Docker daemon, application/release/static delivery build or VPN
acceptance is implied. Evidence: dist/diagnostics/python-native-epoch-20261021/.


### Native peer mapping in prepare (21 October)

The same captured helper --generate-config-json now accepts the pure capability
{op:capability} (result peerMappingVersion:1) and peer-mapping operation with
exact scope amnezia-awg/awg2 and source configuration. It reuses parseConfig,
keeps each validated AllowedIPs spelling, derives its canonical IPv4 host, and
computes clientId as OpenSSL SHA256(scope + TAB + PublicKey), lowercase hex.
Source1MiB/frame8MiB/output16MiB bounds are unchanged; duplicate JSON keys,
invalid UTF8, wrong scope, duplicate peer identities/addresses and missing peers
are refused. Opaque NUL in unrelated configuration values retains legacy semantics.

Explicit native prepare checks captured-helper capability before directory
creation/recovery inside prepare (CLI ROOT mkdir/lock still precedes prepare).
It uses the returned mapping in the same state/ready.json and journal flow.
Errors never fall back to Python mapping. Legacy/default delivery remains Python,
with its supported calculation. No static bundle was built or activated.

Standalone full CTest64/64 passes: new pure mapping checks and11 Python bridge/
parity methods cover both scopes, peer order, prefixes, exact known hashes,
invalid requests and early capability failure without prepare mutation. A first
63/64 run exposed an old isolated capability mock; its one new capability seam
was added while preserving the original existing-generation HOLD assertion.
These are controlled helper/prepare fixtures, not live transaction acceptance.
Evidence: dist/diagnostics/python-native-peer-mapping-20261021/.

### Native server public key derivation (21 October)

Explicit native prepare now derives serverPublicKey through the same captured
--generate-config-json helper: {op:server-key-capability} returns exactly
{result:{serverKeyVersion:1}}, while {op:server-key,source:UTF8config} returns
{result:base64PublicKey}. The existing peerMappingVersion capability is unchanged.
The separate server-key capability is checked before recovery/mutation inside
prepare; the outer Python CLI ROOT mkdir/lock still precedes prepare.

The pure bounded operation reuses parseConfig (source1MiB/frame8MiB), decodes
exactly32 private-key bytes with OpenSSL, requires canonical base64 padding bits
as the vendored awg/wg decoder does, and derives X25519 with OpenSSL EVP. Generic
config/parser and peer-map key acceptance are unchanged. Native errors fail
closed without Docker shell pubkey or Python fallback. The legacy/default branch
retains its awg/wg command. Orchestration, default delivery, journal and control
HTTP/PID1/authentication remain Python; no static delivery bundle was built.

Standalone CTest66/66 passes (93.55s), including two new server-key tests.
RFC7748 Alice/Bob vectors, scalar clamping, malformed keys/padding, early
capability rejection and inert native prepare propagation into readiness plus
persisted ready.json are covered. A pure production-helper CLI smoke passes3/3
without starting listeners or accessing Docker/network. These fixtures do not
prove live server/VPN/Android acceptance. Evidence:
dist/diagnostics/python-native-server-key-20261021/.
