# Disposable release lab

`lab.py` controls four release product lanes from the existing Ubuntu 24 WSL
instance: Windows x64 and two Linux x64 QEMU guests through QMP/QGA, plus the
Android arm64-v8a adapter/emulator lane. The isolated `server-router` QEMU
guest is an auxiliary consumer-fixture lane, not a fifth product artifact.
The host boundary is QMP/QGA or the owned Android adapter. The controller never
runs an Amnezia binary, installer, service command, VPN command, route
command, DNS command, or firewall command on the Windows host or in production.

The durable lab state belongs at `/var/lib/amnezia-release-lab` in WSL. It
contains base images, owned per-run overlays, QEMU sockets and guest evidence.
The checkout only contains code and profile contracts. Host-side logs and
exports go under `dist/release-lab/` and are ignored by Git.

QEMU profiles require a provisioned, immutable golden disk and an adjacent
sealed readiness receipt. A raw vendor image is never treated as a ready
guest. The receipt records the matching disk SHA-256, profile, QGA
availability, completed provisioning, and absence of candidate credentials.
The Windows receipt also records the sealed OVMF NVRAM and TPM-state hashes;
each run clones those exact states and never creates fresh firmware state.

The Linux profiles use explicit KVM acceleration and `-nic none` for ordinary
release runs. The QEMU Windows profile remains blocked by its signed
UEFI/swtpm boot issue; a separate Hyper-V OS baseline is sealed and
independently read back, but is not wired into this QEMU controller. The
reviewed TCG software experiment is recorded separately and is not silently
substituted for KVM. The server-router consumer fixture is the one explicit exception: it uses
QEMU user networking with `restrict=on` and a loopback-only hostfwd to guest
port `17865`. Android uses the owned `android/android-lab.sh` adapter and its
dedicated ADB/emulator; it is not treated as a Linux/QGA guest. If an adapter
cannot emit the common receipt, the controller stops rather than inferring
success.

Each QEMU profile must have a prepared golden and a guest-side runner. The
runner is responsible for platform-specific install/update/service checks. The
controller waits for every QGA `guest-exec` PID to exit, requires a JSON
`passed: true` assertion, and constructs evidence only from QGA marker and
step readback. A host-created JSON file, a CLI `PASS` flag, or a dry run can
never satisfy the gate.

## Workflow

Run `python deploy/release_lab/lab.py preflight --json` before provisioning.
It is expected to fail closed until QEMU, `/dev/kvm`, all required goldens and
profile harnesses exist. At the current checkpoint Linux headless v2 and the
Linux GUI v9 OS/QGA golden plus strict GNOME/X11 session evidence are
available. The v9 product run installed baseline `5.0.1.37` successfully with
an active service and canonical runtime version; candidate `5.0.1.38` failed
in the legacy maintenance tool (exit 6), leaving baseline version/service
active. The separate Hyper-V Windows OS baseline is sealed with marker/VHD
SHA-256 `8ded92f7c7a2f522dd6609f6afbb9e023515055ac3cd3db1309df9214e7275cb`,
VM Off, 128 GiB self-contained disk, 0 DVD/0 NIC/0 checkpoints, Secure Boot
`MicrosoftWindows`, first boot on the owned VHD, and licensed EnterpriseEval
25H2/build 26200. It remains separate from `lab.py`: the backend is code-level
GO, but the product installer runner/receipt adapter is still pending. Android's
installer and lavapipe UI receipts do not yet prove the
real application update on the current x86 guest. The server-router fixture
has health/manifest traffic only and is not publication evidence. Then the
pipeline uses `plan`/`create`, starts and probes each selected lane, runs
reinstall/update/health steps, collects each receipt, and calls `gate`.

The evidence matrix is intentionally split: OS/QGA or emulator readiness,
product installation/update, reboot/rollback, and self-hosted publication are
separate gates. A lane with a ready OS but a missing product or publisher
receipt remains unavailable to release. The 2026-09-08 lab snapshot has
`152` passed tests and `21` skipped tests. Skipped platform/tool gates are
reported separately from runtime blockers; this count is not a coverage or
release-readiness percentage. Reboot and rollback scenarios were not
completed, and preserving a working baseline after a failed candidate update
does not count as rollback evidence.

The controller records a live QMP/QGA binding with `server-observe --run-id ...
--ssh-host-key-pin ...`. That observation proves only the owned server guest
is alive and the configured pin is present; it does not prove self-hosted
publication or served artifact bytes. A release gate must additionally receive
an actual guest publication/client-flow receipt with server-side endpoint and
manifest/artifact hash readback. Without that receipt, release remains blocked.

Every run must provide both sides of the upgrade: `--baseline-version` and
`--candidate-version`, plus one `--baseline-artifact platform=path` for each
candidate artifact. The guest sequence keeps the N-1 baseline and N candidate
separate, so a missing or changed baseline blocks the gate.

The guest runner receives one guarded artifact path at a time. The controller
stages N-1 there for `reinstall`, then stages N at the same path for `update`,
passing the run ID, expected version, expected SHA-256, and guest receipt path
on every invocation. This prevents an unbound baseline or an implicit
metadata-only upgrade from becoming evidence.

The release lane takes the final outer self-hosted Windows candidate, signed
manifest, and its platform artifacts. Every file is hashed during planning
and compared again at the gate. Any rebuild or byte change after testing
fails. The server condition is satisfied only by a live QMP/QGA observation
of the registered isolated `server-router` VM, bound to this run's UUID,
outer/manifest hashes, and the configured lab SSH pin. External server JSON
receipts are rejected. A successful release gate writes
`exports/<run-id>/publishable.json` with the same outer SHA-256. Candidate mode
may be used for a thin iteration of selected products; it reports
`candidate_passed` only and never writes a publishable marker or claims
`release_passed`.

`reset` can remove only an overlay carrying the run/profile ownership marker.
It refuses base, foreign, production, or unmarked paths.
