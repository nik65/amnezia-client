# Android release lab

This profile runs an official Google APIs `x86_64` emulator inside the existing
WSL2 KVM environment. The APK under test is `arm64-v8a`; the emulator must use
Android Native Bridge (`libndk_translation.so`). An x86 or x86_64 APK is never a
passing substitute for the ARM64 release. API 35 is the primary image and API
30 is an explicitly documented translation fallback.

The profile is isolated in one external WSL directory. `ANDROID_SDK_ROOT`,
`ANDROID_AVD_HOME`, the ADB server, serial, PID file, qemu UUID, logs and
screenshots all belong to that directory. The script never calls a global
`adb kill-server`, enumerates or selects a physical device, changes Windows
routes/firewall, or connects to a production server. ADB commands always carry
the profile's explicit emulator serial.

The command-line tools archive and release APK hashes are pinned in
`android-lab-profile.json`. `prepare` downloads only the official command-line
tools archive, snapshots official repository metadata into an owned lock, and
verifies every installed package against that lock. It does not use
Android Studio, a host-wide SDK, or an unpinned system image.

## Contract

Run `bash android-lab.sh <command>` from WSL:

| Command | Behaviour | Passing evidence |
| --- | --- | --- |
| `prepare` | Check WSL/KVM and provision the pinned SDK, emulator and image | checksum and package-list receipts |
| `doctor` | Query actual SDK, lock, AVD and KVM readiness | machine-readable filesystem preflight |
| `create` | Create or verify the isolated AVD | profile marker and AVD metadata |
| `start` | Start one owned emulator and wait for boot | owned PID, serial and qemu UUID |
| `probe` | Verify image, ABI, Native Bridge and SDK/package properties | live `getprop`/`dumpsys` evidence |
| `network-gate` | Verify the controller's fail-closed guest rule receipt | marker bound to qemu UUID plus guest DROP rule |
| `fixture-network <port>` | Allow only the owned HTTP fixture peer inside Android | guest DNAT `10.8.1.0:17865` to `10.0.2.2:<port>` |
| `install-baseline` | Install the previous APK with `--abi arm64-v8a` | package/version/ABI receipt |
| `test-update` | Open the system package installer and drive its UI | UI XML, clicks, resulting version 2186 |
| `run` | Controller adapter entry point for the complete ARM64 installer smoke scenario | probe + baseline + UI installer + collect + JSON receipt |
| `collect` | Save logcat, UI hierarchy, properties and a screenshot | timestamped artifact directory |
| `reset` | Stop only the owned emulator and clear its lab state | no global ADB operation |

`install-baseline` is an install smoke test. It is deliberately not used as
evidence of the updater. `test-update` is a system package installer smoke
scenario: it pushes the new APK to the emulator, opens Android's Downloads UI,
selects it there, and opens the system package installer; it confirms visible
installer UI and clicks `Install`/`Update`/`Done` using `uiautomator` XML and
`adb shell input`. A direct `adb install -r` is not accepted by this scenario.

The baseline/update scenario also writes a marker in the app's external lab
state directory and checks it after the update. This checks persistence that is
observable without root. A private-data check is reported as pending unless the
APK exposes a supported `run-as` test hook; it is never silently reported as
passing. The real app/server update flow remains pending until the controller
implements its app-level download and server update handoff. Network tests are pending until the controller's owned peer and
fail-closed network gate are available; this profile does not alter host
networking and does not claim VPN UDP coverage from an HTTP proxy.

The initial bootstrap is intentionally offline-friendly. The final release
gate must run the real sequence on API 35 (and API 30 when enabled), then
archive `collect` output for each emulator. host network changes are outside
this profile and remain disabled.

The controller calls `run baseline.apk candidate.apk baseline-manifest.json
candidate-manifest.json`. It must supply the signed manifest paths and the run
id; the adapter never selects a fixed previous/current release pair for a new
run. The receipt path is `AMNEZIA_ANDROID_LAB_CONTROLLER_RECEIPT` (inside the
lab root) records `run_id`, `profile`, `artifact`, `artifact_sha256`,
baseline/candidate versions, `observed_at`, a `steps` list, `device_identity`,
`origin=guest`, `injected=false`, `transport=android-adapter`, guest network
policy, and the pending real app/server update.
