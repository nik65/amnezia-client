# Repository instructions

## Installer launch policy

Codex must never launch an AmneziaVPN installer autonomously. This includes
launching it from a build, release publication, update check, debugging step,
test, command-line operator mode, or `Start-Process`/equivalent wrapper.
If installation or an installer launch is needed, stop and ask the user to
launch it manually; do not infer permission from a request to build, publish,
or prepare an artifact. Explicit exceptions are the verified disposable
Windows/Linux release-lab guests and the user-supplied physical Android phone
under the narrowly scoped authorization below. Neither exception applies to
installers or updaters on this Windows host.

## Release publication policy

Server-side release publication must be performed only by the self-hosted
Amnezia client flow. Do not add or run a standalone publisher, direct SSH/SCP
release upload, or equivalent server-side publication shortcut. Local manifest
and artifact generation is allowed; the resulting self-hosted client artifact
must be launched manually by the user when publication is required.

## Local workstation and orchestration policy

On this local PC only, Codex must never disconnect, reconnect, stop, restart,
or otherwise control an active VPN tunnel, the AmneziaVPN application or
service, or local VPN routes, DNS, or firewall. Codex must also never
uninstall, reinstall, launch, or otherwise initiate an AmneziaVPN/Amnezia
Client installer or local updater.

These prohibitions remain in force during release, publication, update,
debugging, testing, build, or operator requests; such requests do not grant
permission for those local actions. If any such action is needed, stop and
require the user to perform it manually. The guest exception below applies
only inside an owned disposable guest, never to this Windows host.

The user explicitly authorizes automated installer, VPN, service, route, DNS,
and firewall operations only inside verified disposable Windows and Linux
release-lab guests controlled by `deploy/release_lab/lab.py`. The separate
physical-Android authorization below permits USB/ADB testing and AmneziaVPN
installation/update on the user-supplied phone, not Android sandbox use.
The Windows/Linux exception requires
backend-specific proven ownership, an isolated profile-owned disk/state, and a
guest marker matching the run and profile: QEMU uses PID/UUID/QMP and QGA;
Hyper-V uses the owned VM ID and PowerShell Direct. It never authorizes those
actions on the Windows host, the host VPN/application/service, host
routes/DNS/firewall, production servers, or publication infrastructure. A
release gate must reject dry-run, missing profiles/steps, host supplied
receipts, and artifacts whose bytes changed after guest testing.

## Android: physical USB device authorized; sandboxes disabled

The user explicitly authorizes debugging/testing on their supplied physical
Android smartphone over USB/ADB, including automated installation and update
of the AmneziaVPN APK and app/VPN interaction needed for those tests. Before
mutating the device, verify that it is an authorized physical USB device,
pin every ADB command to its exact serial, and bind installation/acceptance
evidence to the exact APK bytes and installed version. Preserve the user's
profiles, app data, accounts, and unrelated files; this does not authorize
uninstalling the app, clearing its data, rooting, unlocking, or wiping the phone.
If no authorized physical phone is available, report Android validation pending.

Android emulator and Cuttlefish sandboxes remain disabled by explicit user
policy. Do not start, install into, probe, or run Android emulator/CVD
release-lab profiles. Keep existing implementation and historical evidence for
reference. Guarded stop/reset cleanup of an already-owned Android guest remains
allowed so stale resources can be removed safely. Android acceptance must come
from the real device and must never be synthesized from an emulator receipt.
Automated guest plans cover Windows/Linux only; report real-device Android
results separately and never claim an Android or overall release PASS while
required real-device checks are missing or failed.

## Efficient integration, testing and release work

These workflow rules never relax the permissions or safety gates above.

1. Maintain one authoritative integration candidate, a short current-state note,
   and a finite critical path to build and acceptance. Read the current state
   and relevant evidence, not the complete history on every continuation; reload
   instructions when changed or lost from context.
2. Integrate reviewed, disjoint fixes promptly. Verify their exact input hashes
   and allowed delta once, then test the combined candidate. Do not turn every
   mechanical copy or hypothesis into another successor/review cycle.
3. Order verification as **critical-boundary smoke -> delta regressions ->
   full-final**. Real API compilation, process/transport framing and actual
   consumer paths come before expanding mocked matrices. Re-run affected
   regressions after a change; run the full required set on the final candidate,
   not automatically on every intermediate version.
4. Prefer parameterized runners with explicit subject, suite and output paths.
   Preserve commands, input hashes, toolchain, arguments, environment, native
   exits and timestamps in a new attempt directory. Never overwrite failed
   evidence. Reuse a build/test only when its complete applicable binding is
   unchanged; a filename or component label is not a cache key.
5. Rebuild only affected product artifacts after tracing their real dependencies.
   Harness-only changes do not justify rebuilding unchanged product bytes.
   Runtime receipts still require the exact artifact/context and valid expiry;
   source-test reuse never authorizes reusing stale or differently bound receipts.
6. Measure progress by completed acceptance requirements and usable build
   artifacts, not assertion totals. Keep the per-function update checklist
   explicit. Characterization of a known defect is not a functional PASS;
   required FAIL/BLOCKED/NOT RUN rows cannot silently disappear.
7. Keep new hypotheses separate from the release blocker list. Promote one only
   after a minimal reproduction on a reachable input ties it to a required
   invariant. Already demonstrated false success, incomplete capture, ownership
   or fail-closed violations must be fixed or reported as blockers, never
   reclassified as optional hardening merely to finish sooner.
8. Timebox triage and integration review (start with approximately 15 and
   30 minutes respectively). At the boundary, reassess the critical path and
   state the concrete blocker/next necessary action instead of restarting
   open-ended exploration. These are management budgets, not promises or changes
   to product deadlines, cleanup bounds, resource admission or expiry checks.
9. Batch independent reads and run independent lightweight work in parallel.
   Give workers narrow, disjoint scopes. Serialize heavy guest lanes and verify
   owned cleanup before the next lane; preserve all resource/ownership gates.
10. After the combined component gate, proceed to the bounded canonical delta,
    source freeze, affected build and byte-bound runtime acceptance. Preserve
    unrelated dirty files and index flags; an empty git diff is not a physical
    source-integrity proof. Do not commit or publish unless explicitly requested.
    Report source/component success, build completion and release acceptance
    separately, with a short verified handoff rather than a replay of the work.
