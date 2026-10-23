# Windows guest netstack capability prototype

This is a diagnostic helper, not a release gate or production migration server.
Do not execute its main program on the workstation. No VM execution is authorized
by this prototype. The fixed owned-guest adapter action is source-integrated into the normal
`outer-clean` scenario before its existing reset. Guest execution awaits independent
review and exact rebuilt artifact approval. NICnone policy and historical runtime
receipts are unchanged.

## Proven component boundary

The pinned AWG Go v3 device encrypts real packets. Tests create independent source
and target peer pairs and exchange exact HTTP bytes over gVisor TCP/IP, AWG crypto,
and an in-memory datagram Bind. They assert real handshake timestamps, rx/tx and
AWG3 flags. No test opens an OS socket, host listener, OS TUN, route, DNS or firewall.
These tests prove component interoperability, not the installed GUI/daemon,
Windows loopback UDP/WFP behavior, signed migration challenge or profile commit.

The main program uses two separate AWG peer devices/netstacks, bound only to
guest `127.0.0.1` UDP sockets. Those sockets retain their OS-allocated ports until
device shutdown. gVisor addresses `.253:17864` and `.251:18082` are not Windows
NICs. Real product tunnel traffic can reach them only through its encrypted peer.
Source/target private keys and the fixture client public key come from a private
guest config. They are never included in receipts or error output.

## Ownership and future fixed adapter action

Proposed fixed action: `netstack-fixture` within a new owned diagnostic case;
no generic command execution or supplied script callback. Before launch, the
existing adapter must verify VM ID, differencing disk, parent SHA, run/profile/
case marker, privacy, and frozen helper/config/route hashes, then stage exact bytes
using PowerShell Direct. The helper accepts only the canonical case root:

`C:\ProgramData\AmneziaLab\runs\RUN\windows-x64\CASE\netstack-fixture\config.json`

Marker must be the case's existing `run-marker.txt`, routes must be the helper's
`routes.json`; symlink ancestors are rejected. Config identity includes run,
case, actual VM UUID, 48-hex attempt nonce, route SHA, keys, client address and
TTL 1..300 seconds. The helper creates an exclusive immutable lease containing
PID, kernel creation timestamp, executable SHA, run/case/VM/nonce. It never
overwrites another lease or kills another PID. Readiness adds held UDP ports.
On normal TTL expiry devices close before terminal evidence. On an early failure
or crash there is no success/cleanup claim: the adapter must preserve diagnostics
and terminate only an exact PID+creation+exe+nonce-owned process, verify ports
closed, then perform normal owned guest reset. External termination/stop protocol
and ACL checks belong to the unimplemented adapter; root review is required.

## Deliberate fail-closed gaps

`/rules.json` serves only supplied, SHA-bound bytes, without inventing routes.
`/probe` requires the attempt nonce. All control paths including offer, challenge,
commit and ACK return HTTP 501. `production_journal=false` and `runtime_pass=false`
remain explicit in every helper receipt. No fixture HTTP response counts as
production Journal/CAS/ACK acceptance. Real signed offers/challenges need the
existing production contract, pinned signer/public key, epoch/nonce/peer/config
binding, expiry checks and request transcript/provenance; those are not implemented.

The logged production shape 1263 and historical synthetic test shape 1266
are not acceptance datasets here. `prepare_capsule.py` creates the explicitly named
`synthetic-windows-dataplane-v1`: five unique normalized prefixes with exact feed
and expected-list hashes. No padding or historical reproduction claim is made.

Before a guest run, review helper paths/build receipt and the fixed adapter
action, then test installed product profile import and loopback endpoint/WFP
support. Only subsequent real GUI/daemon receipts can prove exact route rows,
unchanged-feed reconcile without tunnel/service restart, route delta behavior,
source/target traffic, challenge, CAS and ACK. No host networking mutation or
Hyper-V virtual switch is needed by the proposed path.

## Offline build

Use the receipt's exact Go 1.26.0 binary, `GOPROXY=off GOSUMDB=off
GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=windows GOARCH=amd64`, then
`go mod verify`, `go test -mod=readonly -count=1 -timeout=30s -v ./...`,
and `go build -mod=readonly -trimpath -buildvcs=false -o OUTPUT.exe .`.
Never run OUTPUT.exe on the host. Tests run only the component test binary.

## Concrete pending runner sequence

Run on the existing controller host only after root approves the exact rebuilt
outer artifact and installed GUI hashes. The offline generator never launches
the helper or product. Keep its private output out of logs.

```text
python deploy/release_lab/windows_netstack_fixture/prepare_capsule.py --output PRIVATE_CAPSULE --helper dist/diagnostics/awg31-migration-20261017/windows-netstack-fixture.exe --observer deploy/release_lab/windows_netstack_fixture/product_observer.ps1 --artifact-sha256 NEW_OUTER_SHA --installed-exe-sha256 NEW_GUI_SHA
python deploy/release_lab/lab.py --state-root LAB_ROOT run --run-id FRESH_PLANNED_RUN --profile windows-x64 --step outer-clean --preserve-failed-guest --windows-route-fixture PRIVATE_CAPSULE/manifest.json --windows-route-fixture-sha256 GENERATOR_MANIFEST_SHA
```

The fresh run must be planned by the current separate harness against those exact
new artifacts. This hook rejects an existing VM or case receipt, dry-run, any
other scenario/backend, and a changed capsule. It binds the real newly-created
VM ID, nonce and task token after creation, stages exact bytes through PowerShell
Direct, and retains only diagnostic evidence. Failure preserves the owned guest
for inspection; cleanup is pending until actual process/UDP/task absence and
normal parent-preserving reset are observed. No standalone VM start is needed.

The observer proves only installed GUI/native tunnel dataplane for that named set:
real UAPI handshake/counters, exact managed route rows (allowing explicit Windows
interface host/multicast/broadcast routes), source-bound HTTP feed and nonce.
PID/route polling and DNS-server reorder do not prove worker epochs, every
disconnect event, historical recurrence, source/target migration, CAS or ACK.
Control paths remain HTTP 501 and all runtime/migration/release flags remain false.
