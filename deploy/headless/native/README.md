# Native provisioning filesystem helper

`amnezia-headless-fs` is a Linux C++17 executable. Its filesystem commands are
`fsync-directory`, `fsync-file`, `verify-elf64-x86-64`, and
`verify-root-private-tree`; its journal commands are described below. The linked
QtCore journal reads and writes JSON. The helper contains no shell execution,
service management, installer launch, network access, signature or archive parser.
Failure is nonzero and cannot trigger a Python retry after native activation.

The regular headless CMake build has a standalone helper target for development
and compatibility tests. The canonical provisioning packager declares
`nativeHelper: "amnezia-cli"`; the same commands run through the authenticated
private CLI snapshot with `--provisioning-fs`. Legacy optional-helper packages
may instead declare `amnezia-headless-fs`. Both variants are covered by exact
schema2 membership and authenticated SHA256SUMS. The automatic update archive
retains its two binaries; no extra global filesystem helper is installed.

The installer first copies optional helper bytes into its root-owned0700 private
snapshot without executing them. Native activation follows metadata, exact
receipt membership, checksums and public-key fingerprint validation. Tree checks
then run before any installation transaction. A present-but-invalid helper is a
hard error. Native checks reject final symlinks and unsupported file types;
directory recursion uses descriptor-relative nofollow opens.

Post-authentication durable journal write/read/backup validation uses the
QtCore C++ journal module linked into the authenticated helper. Its fixed root
commands are `journal-write`, `journal-recovery-read`, and
`journal-validate-backup`. A native refusal returns directly; it never retries
with Python.

The non-mutating capability query is `journal-protocol`, returning exactly
`headless-journal-v1` plus a newline. The production CLI spelling is
`amnezia-cli --provisioning-fs journal-protocol`; it dispatches before Qt app/IPC
initialization and does not require root, read a journal or modify a path.
Extra arguments are rejected. This is a protocol query, not authentication: a
future recovery bootstrap must verify trusted bytes before executing it.

A persisted CLI recovery worker may continue to use the already required OS
Qt6/OpenSSL runtime. Keeping an authenticated worker copy protects it from the
two application-binary replacements, not from a broken OS runtime. Loader or
runtime failure during declared native recovery must refuse and preserve
recovery state, never silently retry with Python. Static embedding of the
Qt-based journal into the standalone verifier is not part of this capability.

The optional authenticated `nativeVerifier` package role supplies native
`--stage-inputs`, `--validate-package`, and `--probe-host` operations. After
package, receipt, checksum and mode validation succeeds, metadata output also
reports exactly one `validated native helper role: none|amnezia-headless-fs|amnezia-cli`
record. The installer consumes this result without a Python role reader. A
missing, duplicate, unknown or failed native result is an error, including an
older verifier without that record. A declared native verifier never silently
falls back to Python. Delivery still requires an exact package-bound native
build and real guest acceptance; local tests do not establish that acceptance.

Python dependency boundaries remain explicit:

| Entry/path | Implementation and remaining requirement |
| --- | --- |
| Package with authenticated native verifier | Native staging, metadata/receipt validation and host probes; native role output selects the authenticated helper. |
| Package without native verifier | Python staging and metadata/receipt/role parsing remain the compatibility path. |
| Authenticated helper activated | Native fsync, ELF/tree checks and journal operations; failures propagate directly. |
| No declared helper | Python filesystem/journal compatibility path remains. |
| `--recover` or a preexisting transaction journal at startup | OS-only checks authenticate a persisted private anchor before its capability query. A valid anchor supplies native journal/fsync operations. Only complete anchor absence retains Python compatibility; a present invalid anchor or failed native query refuses without fallback. |
| Bootstrap and signed runtime manifest | Native-verifier + canonical CLI packages omit the unconditional interpreter prerequisite and runtime `python3` command. Explicit legacy recovery/staging/no-helper checks still require an actual Python executable before entering their path. |

`bootstrap_n.cpp --recovery-anchor` can validate a root-private backup anchor
against journal metadata and an optional caller hash, but never executes it.
That decision alone is not execution authority. The native path supplies a
separate persisted-worker storage operation, early OS-only consumer and late
installer producer. The mutable transaction journal cannot produce their
execution pin. Native-verifier + canonical CLI packages no longer require
runtime Python along this path. Complete Python elimination is **not claimed**:
legacy recovery/staging/no-helper compatibility and build/sign/test tooling
retain explicit interpreter dependencies.

The remaining startup/recovery work is finite:

1. The existing signed `nativeHelper: "amnezia-cli"` contract binds the selected
   CLI and checksum row. Bootstrap retains that independently authenticated row;
   no new manifest role or hash recomputed from the worker supplies authority.
2. Native storage verifies/copies and durably selects the independent worker;
   the late producer calls it only after metadata, receipt, ELF, ldd, version and
   installation-state validation, before any transaction backup/journal begins.
3. Early recovery checks the fixed directory chains, inherited lock, exact
   records, modes and bytes using OS commands before any worker execution. The
   capability query must succeed with exact output. No source-package path,
   environment root override or unsigned journal chooses a worker.
4. Root-owned crash/corruption/recovery/cleanup acceptance against exact package
   bytes is still required in owned Linux guests. Local fixtures use the real OS
   with an explicit ownership model, not genuine UID0 acceptance.
5. Conditional interpreter requirements now follow the package variant:
   canonical native-verifier+CLI runtime metadata omits `python3`; no-verifier
   packages retain it. A preexisting legacy transaction without a native anchor
   still requires Python even when a new native package is being invoked.
   Missing legacy requirements fail before recovery/transaction mutation, and
   declared native refusal remains terminal rather than falling back. Owned
   guest acceptance remains the release gate for these source/fixture results.

The native storage prerequisite is available as
`amnezia-cli --provisioning-fs anchor-install SOURCE EXPECTED_SHA256` (or the
standalone helper's `anchor-install`). The installer producer and early
recovery consumer are wired to it, with conditional legacy interpreter checks.
The command accepts only the fixed production namespace
`/var/lib/amnezia-headless-provisioning/native-anchor` and UID0; fixture paths
and UID overrides are library-only test policy, never argv/environment options.
The caller must supply a lowercase SHA-256 from independently authenticated
package checksums. The storage operation does not verify a signature or obtain
execution authority by hashing its own input.

The source is opened without following symlinks, must be an owner-root regular
executable with exact mode 0700 or 0755 and at most 8 MiB, and is copied/hashed
with stable opened-file metadata. No worker is executed. Each retained
`payload-<sha>` generation is owner-root0700 and contains only `worker` (0700)
and independent `PIN` (0600, `<sha>\n`). `CURRENT` is owner-root0600 and contains
exactly `headless-journal-v1\n<sha>\n`. Existing selections/generations must be
valid before reuse or replacement; old generations are preserved.

Worker and pin files, generation directory and parent are fsynced before
atomic `CURRENT` selection; the parent is then fsynced again. A durability
failure returns an error even if the atomic selection already occurred.
Exclusive-create collisions retry with bounded fresh names and never clean up
another invocation's preexisting record. Production requires inherited fd9
before any anchor write: its root-owned0600, single-link regular inode must
match the fixed `/var/lib/amnezia/updates/update.lock` opened without following
symlinks. `flock(9, LOCK_EX|LOCK_NB)` retains that same open-file-description;
the helper never closes or unlocks the borrowed descriptor. The proof is
rechecked before selection. A separate anchor-local flock serializes anchor
writers, while journal/recovery-marker absence is also checked before copying
and before selection. Active journal/marker entries, including dangling
symlinks, cause refusal. Path/UID/lock-descriptor fixture overrides exist only
in the library tests, never in production argv or environment.

Owned filesystem tests exercise copy/pin/mode/symlink/bounds checks, retained
generations, collisions, concurrent anchor lock, injected durability failures
and a journal appearing before selection. They use the current UID and an
owned temporary policy root; passing them does not establish real UID0 host
acceptance. Early OS-only trust checks and the producer have source/fixture
coverage, including canonical-byte/NUL refusals and an actual PATH without
Python. Genuine installed recovery remains unaccepted; conditional prerequisite
removal is implemented only for the native-verifier+CLI package variant.

Source-only regression checks (no installer, helper, compiler or service run):

```
python3 deploy/headless/test_installer_native_order.py
python3 deploy/headless/test_installer_native_role.py
python3 deploy/headless/test_installer_anchor.py
bash -n deploy/headless/install_headless.sh
```

These evaluate inert command substitutions of the actual shell fragments,
including nonzero native exits and missing private snapshots. They cover
source wiring and failure propagation, not root ownership or installed recovery.

Standalone verification (only temporary test files, no installer/service):

```
cmake -S deploy/headless/native -B /tmp/amnezia-native-test -DBUILD_TESTING=ON
cmake --build /tmp/amnezia-native-test
ctest --test-dir /tmp/amnezia-native-test --output-on-failure
```

The standalone verifier also has local CTest coverage under
`deploy/headless/native/provisioning_verifier`. It executes the actual verifier
on signed inert archive fixtures, including native role stdout consumption and
refused bytes/pins/modes/signatures. Packaged executables are never run; host
probes in the extracted installer consumer are explicitly modeled.

The provisioning member limit remains 8 MiB. Debug and unstripped static
binaries can exceed it. A standard GNU `strip --strip-unneeded -o NEW_OUTPUT INPUT`
produces a separate candidate while retaining the original; remeasure, rehash,
and rerun verification against those exact output bytes before packaging.
Stripping symbols is not a change to the member limit or an authenticity bypass.
A local Debian build, even when static and within the limit, is not Ubuntu guest
runtime acceptance or a published release artifact.

The positive root-owned-tree test runs only if the test runner already has uid0;
tests never create groups or request privilege elevation. Full provisioning and
rollback acceptance in owned guests is still required before delivery.
