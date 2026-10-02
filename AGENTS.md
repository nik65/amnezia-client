# Repository instructions

## Installer launch policy

Codex must never launch an AmneziaVPN installer autonomously. This includes
launching it from a build, release publication, update check, debugging step,
test, command-line operator mode, or `Start-Process`/equivalent wrapper.
If installation or an installer launch is needed, stop and ask the user to
launch it manually; do not infer permission from a request to build, publish,
or prepare an artifact.

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
release-lab guests controlled by `deploy/release_lab/lab.py`. Android sandbox,
emulator, CVD, and ADB work is disabled; Android validation remains pending for
a real smartphone supplied by the user. The Windows/Linux exception requires
backend-specific proven ownership, an isolated profile-owned disk/state, and a
guest marker matching the run and profile: QEMU uses PID/UUID/QMP and QGA;
Hyper-V uses the owned VM ID and PowerShell Direct. It never authorizes those
actions on the Windows host, the host VPN/application/service, host
routes/DNS/firewall, production servers, or publication infrastructure. A
release gate must reject dry-run, missing profiles/steps, host supplied
receipts, and artifacts whose bytes changed after guest testing.

## Android sandbox disabled

Android emulator and Cuttlefish sandboxes are disabled by explicit user policy.
Do not start, install into, probe, or run Android emulator/CVD release-lab
profiles. Keep the existing Android implementation and historical evidence for
reference. Guarded stop/reset cleanup of an already-owned Android guest remains
allowed so stale resources can be removed safely. Android validation is pending
on a real smartphone supplied by the user and must never be synthesized from
an emulator receipt. Automated release plans and suites cover only the Windows
and Linux sandboxes and must keep Android real-device validation explicitly
pending rather than report an Android or overall release PASS.
