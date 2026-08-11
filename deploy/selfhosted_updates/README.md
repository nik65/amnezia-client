# Self-hosted update channel

This directory contains tooling for the private update channel used by the
server-managed Amnezia fork.

Runtime update behavior lives in the client C++/Qt code:

- `client/core/controllers/updateController.cpp` checks and verifies the signed
  manifest, downloads artifacts, validates sha256/size, and launches the
  platform installer.
- `client/vpnConnection.cpp` keeps the update endpoint inside the managed VPN
  route set.
- `client/platforms/android/*` handles the Android APK installer handoff.

The local release helpers in this directory do not ship inside the app. The
exception is `install_server_update_host.sh`, which is embedded as a Qt resource
so the self-hosted Windows client can refresh the update host on the server.
Local release automation uses these helpers after platform builds to generate
the signed manifest and verify artifacts.

The client checks signed manifests from:

- `http://<default-self-hosted-server>:17865/manifest.json`
- `http://<SELFHOSTED_UPDATE_SYNC_HOST>:17865/manifest.json`

On this release workstation the verified VPN client-facing host is
`10.8.1.0`, so local builds set `SELFHOSTED_UPDATE_SYNC_HOST=10.8.1.0`.
That is a concrete host address, not the CIDR route `10.8.1.0/1`. The Docker
bridge endpoint `172.29.172.252` may still exist server-side, but do not use it
as the compiled fallback unless a representative client can actually reach it.
The published manifest keeps local artifact URLs relative under `files/`, so
artifacts resolve from whichever manifest host the client reached. Forward
artifacts are content-addressed as `files/artifacts/<sha256>/<filename>`: a
failed, stale, or concurrent publisher cannot overwrite bytes referenced by a
manifest that is already live.

## Release freeze automation

The local Codex maintenance automation is the daily guard for `dev`. GitHub
Actions stay disabled and `.github/workflows` must remain absent. The automation
watches the latest published upstream GitHub Release that is non-draft and
non-prerelease and whose tag matches `x.y.z.w`; a tag or ordinary
`upstream/dev` commit alone is not an update signal. In other words, an upstream tag alone is not enough.

- While no published release newer than `.github/upstream-release-freeze.json`
  `baselineTag` exists, it leaves `dev` unchanged.
  Ordinary `upstream/dev` commits are intentionally not merged between releases.
  Consequently, post-release `upstream/dev` commits are not retained.
- When a newer published release appears, the automation first creates a backup
  branch and verified bundle, then resolves the release in a temporary worktree
  while preserving the previous `dev` tip and every fork commit as ancestors.
  It builds and validates the supported local targets before a normal
  fast-forward push. It never force-rewrites `dev`.
- After the state is frozen, later scheduled runs keep waiting and advance the
  fork only when a newer published upstream release appears.

`.github/upstream-release-freeze.json` records the currently observed published
release and keeps `targetBranch` set to `dev`. Update that state only through a
verified release-advance run.

## Key setup

Generate an Ed25519 signing key:

```bash
openssl genpkey -algorithm Ed25519 -out selfhosted-update-private.pem
openssl pkey -in selfhosted-update-private.pem -pubout -out selfhosted-update-public.pem
```

Build clients with the public key embedded as base64 PEM:

```bash
export SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64="$(base64 -w0 selfhosted-update-public.pem)"
```

Keep `selfhosted-update-private.pem` off client devices and logs.

## SSH server identity pinning

Self-hosted administrative SSH connections are fail-closed on the server host
key. Verify the SHA-256 host-key fingerprint through an independent trusted
channel before entering it in the setup wizard or release configuration. The
client does not use trust-on-first-use and does not send a password or attempt
public-key authentication until the key received during the SSH handshake
matches the effective pin.

Release builds embed a fallback only for one exact, case-sensitive original
hostname. Configure the pair together:

```powershell
$env:SELFHOSTED_SSH_TRUSTED_HOST = "85.208.87.69"
$env:SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 = "SHA256:2UtHIoVd4Lft+s4E/LZlA8+reysEexYyhkt03rg8Rdg"
```

`setup_release_workstation.ps1` writes this non-secret pair to
`dist\selfhosted-release-env.ps1`; `local_release.ps1` requires and validates
both values and forwards them to Windows, Linux, and Android builds. Supplying
only one value or a padded, whitespace-containing, URL-safe, non-canonical, or
non-32-byte fingerprint fails before a build starts. Generic source builds may
omit both compile-time values, but every new self-hosted server must then carry
an explicit verified fingerprint in its stored admin configuration. An
explicit malformed value never falls back to the compiled pin.

SSHFS/SFTP mounting uses the operating SSH client's separate `known_hosts`
trust store with `StrictHostKeyChecking=yes`; it does not bypass host checking
or reuse the administrative libssh pin automatically.

`SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64` is required at build time because the
clients must embed that public key to accept the signed private update manifest.
The private signing key is used only by the local publisher. The manifest tools
inspect the key type and reject RSA, generic EC, or any other non-Ed25519 keypair
instead of emitting an envelope whose algorithm label clients cannot verify.

## Local release build

Self-hosted releases are built locally on the release workstation. The Windows
release client can carry the update payload and upload it to the Amnezia VPN
server after installation. The default local release set is:

- `windows-x64`
- `linux-x64`
- `android-arm64-v8a`

macOS and iOS are intentionally not part of this local self-hosted release set.
Android releases are intentionally arm64-v8a only for Android 9+ devices.

Prepare the release workstation first:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\selfhosted_updates\setup_release_workstation.ps1
```

By default this only reports missing dependencies and writes
`dist\selfhosted-release-env.ps1`. Re-run with `-InstallMissing` to install
missing dependencies that are available non-interactively: WSL Java under
`~/.local/jdk-17`, Conan and aqtinstall through WSL `pip`, Linux Android
command-line tools/SDK/NDK under `WSL_ANDROID_HOME`, desktop Qt through
`linux desktop`, Linux Qt Installer Framework `qt.tools.ifw.47`, and the
Android arm64-v8a Qt kit through `all_os android`.
Android builds run inside WSL, so `WSL_ANDROID_HOME` must point to a
Linux Android SDK/NDK; the Windows SDK in `ANDROID_HOME` is not enough because
its NDK does not include the `linux-x86_64` compiler toolchain. If `aqtinstall`
does not publish the required Android kit for the selected Qt version, install
it with Qt MaintenanceTool and rerun preflight. Re-run with
`-GenerateUpdateKeys` to create the Ed25519 self-hosted update signing keypair
under `C:\keys`. On the release workstation, also run
`-GenerateAndroidKeystore` once to create `C:\keys\android-release.keystore`
and `C:\keys\android-release-keystore.env.ps1`. Future Android updates must be
signed by this same key, so keep both files backed up and private.

If Qt downloads time out, set `QT_MIRROR_BASE` or pass `-QtMirrorBase`; the
default mirror is `https://mirrors.20i.com/pub/qt.io`.

Run from the repository root:

```powershell
. .\dist\selfhosted-release-env.ps1

$env:SELFHOSTED_UPDATE_BASE_URL = "http://SERVER_IP:17865"
# Optional override; setup writes this automatically.
$env:WSL_ANDROID_HOME = "/home/<wsl-user>/Android/sdk"
# Optional override for Linux .run packaging; must be a Linux IFW root, not C:\Qt.
$env:WSL_QIF_ROOT_PATH = "/home/<wsl-user>/Qt/Tools/QtInstallerFramework/4.7"

# Android APKs must be signed with the same key as installed clients.
# setup_release_workstation.ps1 dot-sources this file automatically after
# -GenerateAndroidKeystore has created it:
. C:\keys\android-release-keystore.env.ps1

powershell -ExecutionPolicy Bypass -File deploy\selfhosted_updates\local_release.ps1
```

For the normal release-workstation path, use the one-command rebuild wrapper.
It loads `dist\selfhosted-release-env.ps1`, runs preflight, writes stdout/stderr
logs under `dist\build-logs`, and then calls `local_release.ps1` for the local
release platform set:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\selfhosted_updates\rebuild_clients.ps1 -BuildJobs 24
```

Use `-BuildPlatform windows`, `-BuildPlatform linux`, or
`-BuildPlatform android` only when intentionally rebuilding a single client.
Use `-NoBundleUpdatesInWindowsClient` for a faster smoke rebuild that does not
produce the self-hosted Windows installer carrying the update payload.

The self-hosted fork keeps its own monotonically increasing app version. Do not
reset `AMNEZIAVPN_VERSION` or `APP_ANDROID_VERSION_CODE` down to the upstream
release tag after a newer fork build has been published. Upstream releases are
only the source for official fixes/features that are ported into this branch;
the self-hosted update version must stay higher than the last published fork
artifact so installed clients never update backward to an older fork release.

The current self-hosted release line is `4.9.2.12` with Android
`versionCode` `2146`, following the `4.9.2.11` / `2145` artifact set.

Release notes for `4.9.2.12`: Windows replacement now treats the legacy
maintenance-tool process exit code as diagnostic because its unelevated
bootstrap can return `1` while the elevated child continues a successful
removal. The outer installer waits up to ten minutes for both the maintenance
tool path and process to become quiescent, rejects duplicate x86/x64 legacy
installations instead of launching two uninstallers, and only restores the old
service after a positively verified cancellation. It then verifies service/file
cleanup before proceeding. The delayed Next transition is owned by
`IntroductionPageCallback`, after the live page is entered. Installer JSONL
logging no longer contains PowerShell at-sign array/hash syntax that Qt IFW
interprets as variable placeholders; writes use UTF-8 without a BOM and retain
the same privacy and retention bounds.

Release notes for `4.9.2.11`: the Windows upgrade handoff now uses Qt IFW's
documented delayed `gui.clickButton(..., delayInMs)` overload. This queues Next
until after the controller constructor returns from the nested legacy
maintenance tool, and queues Commit in the same way. Installer phase journals
now use the interactive user's `%LOCALAPPDATA%\AmneziaVPN-InstallerLogs`, which
is writable before and after the IFW elevation handoff; reparse points remain
rejected and the existing size/count/age limits are unchanged.

Release notes for `4.9.2.10`: the Windows full offline installer now drives
the Next transition directly from the successful legacy-cleanup branch instead
of relying on a page callback after the nested maintenance tool exits.  The
transition and Commit are idempotent.  A privacy-reduced JSONL phase journal is
kept under `%LOCALAPPDATA%\AmneziaVPN-InstallerLogs`; the directory rejects
reparse points. The journal is capped at 256 KiB per run, 20 runs, 14 days, and
5 MiB total, and survives removal of the old application payload.

Release notes for `4.9.2.9`: after the user approves replacing an existing
Windows installation and the legacy uninstaller plus fail-closed cleanup checks
finish successfully, the outer full offline installer now automatically
continues through Ready for Installation and starts extraction. This fixes both
ordinary and self-hosted installers appearing to stop after removing the old
version.

Release notes for `4.9.2.8`: after the Windows uninstaller proves all owned
service registrations absent, the full offline installer now waits for up to
15 seconds for the complete protected residue set to disappear. This bounded
poll closes the observed filesystem cleanup delay without weakening the
fail-closed guard against real stale binaries, drivers, or recovery receipts.

Release notes for `4.9.2.7`: the Windows full offline installer now obtains
Qt IFW administrator rights before its early SCM recovery-action preflight,
rechecks pending service deletion after UAC, retains elevation across the
legacy uninstaller rollback window, and drops only the admin session it
acquired. This fixes the ordinary double-click upgrade failure where `sc.exe`
returned access denied before uninstall began.

Release notes for `4.9.2.6`: the Windows full offline installer now disarms
the installed service's SCM recovery actions before handing control to a
legacy maintenance tool, and restores the managed recovery/startup policy if
that uninstall is cancelled while the old installation remains. The bundled
uninstaller polls for a real stopped state before using its bounded forced
fallback, proves all three Amnezia-owned service registrations absent via SCM
error `1060`, and refuses to force-delete the main service unless recovery
actions were proven disabled. This closes the observed restart race that left
the old service registered and caused the next installer to stop before file
extraction.

Release notes for `4.9.2.5`: this self-hosted port incorporates upstream
release `5.0.0.5` while retaining the fork's server-managed split tunnel,
always-on remote client logging, self-hosted updates, and Windows route
hardening. It adds upstream AWG3 support, Android 16 KiB/shared-OpenSSL
compatibility, WireGuard keepalive propagation, and Windows
WFP/path-conversion fixes. Marketplace update checks remain disabled in
self-hosted builds so their independent version line cannot redirect clients
away from the signed self-hosted update channel. The fork version remains
independent of the upstream tag so installed self-hosted clients keep a
monotonic update path.

Release notes for `4.9.2.4`: the Windows WireGuard-family tunnel process now
exits as soon as `WireGuardTunnelService` returns instead of falling through
into a second privileged `LocalServer`. This prevents stale tunnel processes
from retaining the split-tunnel driver, IPC pipe, and SCM registration across
disconnect/reconnect or uninstall. The Qt IFW Windows controller requests a
normal desktop-client shutdown before maintenance, uses a bounded forced-exit
fallback scoped to the exact installed executable only after the authenticated
operator command confirms VPN disconnection, and waits for asynchronous SCM
deletion (`ERROR_SERVICE_MARKED_FOR_DELETE`) before requiring a reboot.

Release notes for `4.9.2.3`: the five-feature completion audit makes
privileged settings access brokered and read-only outside the owning thread,
keeps server-managed and local split-tunnel routes separated through the
shared matcher and receipt-backed reconciliation, and makes the Guardian
connectivity probe fail closed unless the final request still uses the direct
network path. Desktop and Android remote-log uploaders now persist secret-set
transitions in two phases and require an independent stable-source scan before
leaving quarantine. Self-hosted administration requires an exact out-of-band
`SHA256:` SSH host-key pin and verifies it after the handshake but before any
private-key import or authentication. Bundled update publication uses bounded
absolute deadlines, durable transaction receipts and crash reconciliation;
lost-ack upload reconciliation must prove the parent-directory sync, and
remote installer/verification output is byte-bounded and never copied raw into
the client log.

Release notes for `4.9.2.2`: the Windows split-tunnel package advances from
the signed upstream driver `1.2.5.0` to `1.3.0.0`, which fixes its upstream
reset/event-processing race. The service supplies the existing shared WFP
sublayer GUIDs through the new initialize ABI. Ruleset application now runs in
an isolated helper with a five-second IOCTL deadline and bounded handoff. On
timeout the helper and device are quarantined, main VPN activation resumes,
and a late configuration is cleared on a best-effort basis before the helper
releases the device. The v1.3 driver does not offer cancelable or
generation-bound requests, so the fallback reports its state as indeterminate
until cleanup completes instead of pretending that kernel cancellation is
guaranteed. Because `1.3.0.0` changes the driver initialize ABI, Windows
upgrades must use the full offline installer. It runs the previous uninstaller
before archive extraction and independently verifies that the old services,
driver payload, and protected cleanup-failure receipts are absent. Direct Qt
IFW maintenance-tool updates and stale/partial installations fail closed before
the new archive is extracted.

Release notes for `4.9.2.1`: an incomplete client-side managed-DNS pass now
keeps the persisted last-known-good route cache and the currently installed
routes unchanged. The client retries with bounded exponential backoff instead
of turning partial DNS answer changes into repeated AWG/WireGuard reconnects.

`local_release.ps1` parallelizes platform builds with the logical processor
count by default. Override it when you want to leave CPU/RAM for other work:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\selfhosted_updates\local_release.ps1 -BuildJobs 24
```

The script calls `deploy\build.bat` for Windows and `deploy/build.sh` through
WSL for Linux and Android. It copies release artifacts into
`dist\selfhosted-local-artifacts\<version>`, generates and verifies the signed
manifest, then rebuilds a separate Windows release client with that payload
installed under `selfhosted_updates` next to `AmneziaVPN.exe`. That bundled
installer is written to
`dist\selfhosted-windows-client\<version>\AmneziaVPN_<version>_windows_x64_selfhosted.exe`.
Install that file on the release workstation. On startup, the Windows client
uses the saved self-hosted admin SSH credentials to upload immutable `files/`
objects, refresh the update-host container, and switch `manifest.json` on the
server last.
The bundled publisher always requires a signed `windows-x64` artifact. It may
carry only that platform for an intentional Windows-only hotfix, or every local
artifact declared by the signed manifest for the normal three-platform release;
in both cases it preserves the complete content-addressed `files/artifacts/...`
path during validation, upload, publication, and remote verification.
`local_release.ps1` does not upload to the server. Use
`-NoBundleUpdatesInWindowsClient` only when you intentionally need a thin
Windows installer without embedded payload. `-SkipBuild` skips rebuilding
platform artifacts, but still rebuilds the bundled Windows release client from
the existing manifest payload unless `-NoBundleUpdatesInWindowsClient` is also
set.

The Windows artifact inside the manifest is the thin Windows installer from
`dist\selfhosted-local-artifacts\<version>`. The self-hosted release workstation
installer is built after manifest generation and contains that thin Windows
artifact plus Linux and Android artifacts. This avoids a recursive package where
the signed manifest would need to hash an installer that contains the manifest
that hashes the installer.

Run a fast preflight before the release build:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\selfhosted_updates\local_release.ps1 -Preflight
```

Preflight does not build or upload anything. It verifies required local commands,
self-hosted signing inputs, WSL readiness for Linux/Android builds, Android
signing key inputs, Linux Qt Installer Framework inside WSL, and SSH inputs
when publishing is enabled.

### Windows uninstall recovery

The Qt IFW 4.7 uninstaller bounds persistent-firewall cleanup retries so a
broken service cannot leave the UI stuck indefinitely. If cleanup still fails,
it first copies the complete installed Windows payload to
`%ProgramFiles%\AmneziaVPN-Recovery\uninstall-recovery`, after rejecting
reparse points and verifying a protected DACL that grants access only to
LocalSystem and Administrators. It validates `AmneziaVPN-service.exe` and
`post_uninstall.cmd`, then records the outcome in the same protected
`%ProgramFiles%\AmneziaVPN-Recovery` root before the installer can continue.
It never writes elevated recovery files through an unverified ProgramData or
TEMP path. Run the recovered `post_uninstall.cmd` from an elevated Command
Prompt to retry the cleanup. If the receipt says `recovery_validated=0`, use
the separate `uninstall-recovery-required.txt` marker in that protected root:
reinstall a fixed Windows package and run its uninstaller elevated. Do not
manually delete WFP rules or Amnezia driver services.
The Windows installer fixes `TargetDir` to literal
`C:\Program Files\AmneziaVPN` instead of trusting Qt IFW command-line
InstallerValue overrides because it installs a LocalSystem service. Before
invoking maintenance scripts, the packaged runner rejects reparse points,
untrusted owners, and directories writable by non-administrative principals.
It also restores trusted known-folder variables and runs from the protected
system directory with a minimal system-only `PATH`.

Windows driver-ABI upgrades are intentionally uninstall-first. The full
offline installer waits for the old `maintenancetool.exe`, accepts only a
successful uninstaller result, and then requires `sc.exe query` to report
`ERROR_SERVICE_DOES_NOT_EXIST` (`1060`) for all Amnezia-owned services before
Qt IFW may extract new files. Any remaining install payload or protected
cleanup-failure marker cancels the install and asks for a reboot plus a retry
with the full offline installer. The maintenance-tool updater is disabled for
this path because Qt IFW performs archive `Extract` operations before ordinary
install operations.

## Manifest build

Example:

```bash
python deploy/selfhosted_updates/make_manifest.py \
  --version 4.9.2.8 \
  --release-date 2026-08-01 \
  --base-url http://172.29.172.252:17865 \
  --private-key selfhosted-update-private.pem \
  --out-dir dist/selfhosted-updates \
  --artifact windows-x64=deploy/build/AmneziaVPN_4.9.2.8_windows_x64.exe \
  --artifact linux-x64=deploy/build/AmneziaVPN_4.9.2.8_linux_x64.run \
  --artifact android-arm64-v8a=deploy/build-android-arm64-v8a/client/android-build/AmneziaVPN_4.9.2.8_android9+_arm64-v8a.apk \
  --android-version-code 2142 \
  --auto-install
```

### Safe fleet policy (payload schema 2)

The manifest envelope remains `amnezia-selfhosted-update-v1` because it still
contains an Ed25519 signature over the exact base64url payload bytes. Fleet
policy uses payload `schema: 2`; all policy fields are inside those signed
bytes, so changing a channel, cohort, eligibility window, expiry, health
deadline, or rollback artifact invalidates the signature.

Payload schema 1 remains the default for release-tool compatibility and never
contains `releasePolicy`. It is allowed only for an unrestricted `stable` 100%
release. `make_manifest.py` rejects canary/emergency channels, partial or paused
rollouts, eligibility limits, custom expiry/health settings, and rollback flags
unless `--payload-schema 2` is present. This is a security boundary: an old
client would otherwise ignore unknown policy fields and bypass the restriction.

Migration must therefore happen in two releases:

1. Publish a payload-schema-1 bootstrap client whose update controller accepts
   and enforces both payload schemas 1 and 2.
2. After that bootstrap is deployed, publish policy-controlled manifests with
   `--payload-schema 2`. Clients that predate the bootstrap reject schema 2
   fail-closed instead of bypassing its rollout.

`publish_release.py`, `local_release.ps1`, and `rebuild_clients.ps1` expose the
same policy controls. Their defaults intentionally remain payload schema 1,
`stable`, and 100%, producing the legacy unrestricted manifest. Supplying any
restrictive option while schema 1 is selected fails; policy mode never enables
itself implicitly. Select schema 2 and provide a new positive monotonic
generation explicitly for every policy publication. Before a server upload,
the publisher reads and verifies the live signed manifest. Once that channel has
accepted schema 2 it refuses a schema-1 downgrade, a lower generation, reuse of
the same generation for different payload bytes, or a lower four-part release
version. Equal release versions remain valid for an idempotent publication or a
higher-generation rollout-policy update, but the non-policy release content
(including artifact URLs, hashes, changelog, and install flags) stays bound to
that version. Version components are canonical decimal numbers and cannot
contain leading zeroes. The final manifest switch
checks both the previously observed envelope hash and the uploaded candidate
hash under a server-side lock, so concurrent publishers cannot substitute a
different candidate or overwrite state that changed after validation. Local
publication holds one channel lock from the fresh local transition check through
the optional remote commit and the final local switch. Immutable local files are
merged first and `manifest.json` is replaced atomically last; interruption cannot
remove the previously published local manifest, and a retry reuses identical
content-addressed files.

Remote publication requires a dedicated normalized absolute `--server-dir`;
root, dot/dot-dot aliases, and a path resolving to the host root are rejected
before upload. The directory carries the root-owned
`.amnezia-update-channel-v1` marker and may contain only the channel marker,
manifest, publication lock, and `files/` tree. An empty directory is adopted on
first publication; a legacy nonempty channel is adopted only when its regular
`manifest.json` still matches the signed envelope verified by the local
publisher. This prevents accidentally serving an unrelated root-owned directory.
Each upload uses a fresh random mode-0700 staging directory. File publication and
temporary-file recovery run under the same channel lock. Uploaded bytes are first
snapshotted without privilege, handed into a root-only quarantine, then copied
with signed byte limits into fresh root-owned inodes. Exact candidate paths,
sizes, and SHA-256 values are checked again on the sealed tree and on any
concurrent no-clobber winner before it can be referenced by `manifest.json`.
The manifest uses the same bounded two-stage seal. Signal/exit traps remove
unfinished stages; a retry can reconcile an exact remote manifest committed just
before a local crash without republishing or changing its signed policy window.

Example of a signed 10% canary with an explicit eligibility window, one-hour
post-install health deadline, seven-day policy lifetime, and a previous Windows
artifact available for rollback:

```bash
python deploy/selfhosted_updates/make_manifest.py \
  --version 4.9.2.8 \
  --payload-schema 2 \
  --channel canary \
  --rollout-percentage 10 \
  --cohort-salt-id canary-2026q3 \
  --minimum-eligible-version 4.9.0.1 \
  --maximum-eligible-version 4.9.0.11 \
  --health-deadline-seconds 3600 \
  --policy-generation 1721470000 \
  --generated-at 2026-07-20T10:00:00Z \
  --expires-at 2026-07-27T10:00:00Z \
  --previous-version 4.9.2.0 \
  --rollback-artifact windows-x64=dist/previous/AmneziaVPN_4.9.2.0_windows_x64.exe \
  --base-url http://172.29.172.252:17865 \
  --private-key selfhosted-update-private.pem \
  --out-dir dist/selfhosted-updates \
  --artifact windows-x64=dist/current/AmneziaVPN_4.9.2.8_windows_x64.exe \
  --auto-install
```

The artifact-discovery publisher accepts the same flags, including repeatable
rollback artifacts:

```bash
python deploy/selfhosted_updates/publish_release.py \
  --version 4.9.2.8 \
  --payload-schema 2 \
  --channel canary \
  --rollout-percentage 10 \
  --cohort-salt-id canary-2026q3 \
  --policy-generation 1721470000 \
  --expires-at 2026-07-27T10:00:00Z \
  --previous-version 4.9.2.0 \
  --rollback-artifact windows-x64=dist/previous/AmneziaVPN_4.9.2.0_windows_x64.exe \
  --private-key selfhosted-update-private.pem \
  --artifact-dir dist/current \
  --base-url http://172.29.172.252:17865 \
  --auto-install
```

For a local multi-platform build, use the corresponding PowerShell names. A
rollback-enabled release must provide one rollback artifact for every supported
local rollback platform in the current manifest. Android remains in the forward
release, but is excluded from rollback coverage because the normal package
installer rejects an ordinary APK with a lower `versionCode`:

```powershell
& .\deploy\selfhosted_updates\rebuild_clients.ps1 `
  -PayloadSchema 2 `
  -Channel canary `
  -RolloutPercentage 10 `
  -CohortSaltId canary-2026q3 `
  -PolicyGeneration 1721470000 `
  -PolicyValidForHours 168 `
  -PreviousVersion 4.9.0.11 `
  -RollbackArtifact @(
    'windows-x64=dist\previous\AmneziaVPN_4.9.0.11_windows_x64.exe',
    'linux-x64=dist\previous\AmneziaVPN_4.9.0.11_linux_x64.run'
  )
```

`setup_release_workstation.ps1` can persist these values into
`dist\selfhosted-release-env.ps1` using the same parameter names. Treat
`PolicyGeneration`, `GeneratedAt`, `ExpiresAt`, `PreviousVersion`, and rollback
paths as per-release values: refresh them before publishing rather than reusing
an old workstation environment unchanged. Rollback artifact environment values
are stored as a semicolon-separated
`SELFHOSTED_UPDATE_ROLLBACK_ARTIFACTS` list.

The signed `releasePolicy` has this shape:

```json
{
  "schema": 2,
  "generation": 1721470000,
  "generatedAt": "2026-07-20T10:00:00Z",
  "expiresAt": "2026-07-27T10:00:00Z",
  "channel": "canary",
  "rollout": {
    "percentage": 10,
    "cohortSaltId": "canary-2026q3"
  },
  "eligibility": {
    "minimumVersion": "4.9.0.1",
    "maximumVersion": "4.9.0.11"
  },
  "healthDeadlineSeconds": 3600,
  "previousVersion": "4.9.0.11",
  "rollback": {
    "version": "4.9.0.11",
    "platforms": {
      "windows-x64": {
        "url": "files/rollback/1721470000/4.9.0.11/AmneziaVPN_4.9.0.11_windows_x64.exe",
        "sha256": "<lowercase-sha256>",
        "size": 123456789,
        "autoInstall": true
      }
    }
  }
}
```

Rules enforced by the generator:

- `channel` is exactly `stable`, `canary`, or `emergency`.
- `rollout.percentage` is an integer from 0 (pause) through 100 (all eligible
  clients). `cohortSaltId` is a public 1-64 character identifier, never a key or
  secret.
- `generation` is a required positive JSON-safe integer for schema 2, capped at
  `9007199254740991` (`2^53 - 1`) so it remains lossless in Qt's JSON number
  representation. Publishers must persist and increment it monotonically so
  clients can reject policy replay; no timestamp-derived fallback is used.
- Timestamps are canonical UTC. Generation time cannot be materially in the
  future, expiry must still be in the future, and the signed window cannot be
  longer than one year, including when `--expires-at` is explicit.
  `--policy-valid-for-hours` defaults to 168.
- Eligibility versions use the canonical four-part numeric application version
  format with no leading-zero components;
  minimum cannot be newer than maximum.
- `healthDeadlineSeconds` is from 60 through 86400. The 60-second floor leaves
  margin beyond the 30-second post-launch stabilization window before startup
  health readiness is acknowledged.
- `previousVersion` must be older than the release. Rollback artifacts use the
  same relative URL, lowercase sha256, positive size, and boolean `autoInstall`
  metadata contract as current local artifacts. They are copied under
  `files/rollback/<generation>/<previousVersion>/`. The generation directory is
  immutable: it is copied to a hidden server-side stage and atomically renamed
  before the new manifest becomes visible, so a failed publish cannot overwrite
  a rollback file referenced by the previous manifest. `macos`, `macos-x64`,
  and `macos-arm64` rollback are rejected while those aliases can also target
  MACOS_NE clients, which cannot apply a verified local rollback package.
  Android rollback aliases are also rejected. Android forward artifacts do not
  require a rollback counterpart, because ordinary lower-`versionCode` APKs
  cannot be installed as a downgrade through the package installer.
- Every generated local Android artifact may carry signed `versionCode`
  metadata from `--android-version-code` (integer `1..2100000000`). Payload
  schema 2 requires it whenever a local Android artifact is present. Schema 1
  may omit it only to preserve compatibility with legacy manifests; the local
  release wrapper reads `APP_ANDROID_VERSION_CODE` from `CMakeLists.txt` and
  emits it for new schema-1 and schema-2 releases. The exact signed Android
  `versionName` remains the enclosing top-level payload `version`, rather than a
  duplicate artifact field.
- The complete JSON envelope must remain at or below 1 MiB, matching the client
  response cap. Oversized changelogs fail generation before `manifest.json` is
  written.

Cohort assignment is deterministic across platforms. Normalize the installation
UUID with `trim().lower()`, hash UTF-8 bytes of
`amnezia-update-cohort-v1\0<cohortSaltId>\0<installationUuid>` with SHA-256,
interpret the first eight digest bytes as an unsigned big-endian integer, and
take modulo 10000. A client is included when its bucket is lower than
`percentage * 100`. Contract vector: installation UUID
`123e4567-e89b-12d3-a456-426614174000` with `fleet-v1` has bucket `4110`.

When a valid schema-2 manifest excludes a client, is paused, or has expired, the
client must stop manifest fallback and report a valid no-update result. It must
not try a stale mirror, because that could bypass the signed policy.

Do not upload `dist/selfhosted-updates/<version>` with the release script. The
generated Windows self-hosted client is the deployment vehicle: install/run
`dist\selfhosted-windows-client\<version>\AmneziaVPN_<version>_windows_x64_selfhosted.exe`
on the release workstation, and that client uploads the signed manifest and all
three platform artifacts through the saved self-hosted admin SSH credentials.
The client refreshes the server update-host container and writes
`manifest.json` last so clients never read a half-published release. Rollback
trees use generation-specific immutable paths and a unique no-clobber directory
stage; forward artifacts use SHA-256-addressed immutable paths. The manifest
itself is switched under `flock` with compare-and-swap checks for both the live
envelope and the exact staged candidate that the publisher validated.

For `local_release.ps1` configure:

- `SELFHOSTED_UPDATE_BASE_URL`: client-facing base URL, for example
  `http://SERVER_IP:17865`.
- `SELFHOSTED_UPDATE_PRIVATE_KEY_PATH`: local path to the Ed25519 update
  signing key.
- `SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64`: base64 PEM public key embedded in
  built clients; it must match `SELFHOSTED_UPDATE_PRIVATE_KEY_PATH`.
- `SELFHOSTED_UPDATE_SYNC_HOST`: compiled fallback host for the private
  manifest endpoint. On this workstation it is `10.8.1.0`; do not include a
  CIDR suffix such as `/1`.

The signed manifest sets `autoInstall=true`; clients will start the platform
installer once per version/platform/artifact identity. This respects OS rules:
Windows/Linux can launch installers, and Android opens Package Installer.

By default the helper publishes `0.0.0.0:17865` on the server host and also
serves `172.29.172.252:17865` on the Amnezia Docker bridge. If an active
Amnezia VPN container is present, the helper also starts a tunnel endpoint in
that container namespace, using the same port. For the current server, the
verified client-facing VPN endpoint is `http://10.8.1.0:17865`. To keep the
public host port closed and serve only through VPN/internal routes, run it with
`AMNEZIA_UPDATE_PUBLISH_HOST_PORT=0`.

The helper autodetects `amnezia-awg2`, `amnezia-awg`, `amnezia-wireguard`, and
`amnezia-openvpn`. To force a specific VPN container network namespace, set
`AMNEZIA_UPDATE_VPN_CONTAINER` to that Docker container name, for example:

```bash
ssh root@SERVER 'AMNEZIA_UPDATE_VPN_CONTAINER=amnezia-awg sh -s' < deploy/selfhosted_updates/install_server_update_host.sh
```

The manifest envelope is signed, and desktop installers are additionally
checked by sha256 before launch. Android APK artifacts are downloaded by the
app, checked by sha256, and then handed to Android Package Installer; if the
unknown-app install permission is missing, the app opens the permission screen
and resumes installation when the user returns. Android can still use an
external store/browser URL when the manifest artifact has `openExternal=true`.
