# Amnezia VPN — self-hosted fork

**English** | [Русский](README_RU.md)

Our fork of [AmneziaVPN](https://github.com/amnezia-vpn/amnezia-client) for a private
VPN server and Windows, Android and Linux clients. It retains Amnezia's core
features and adds server-managed routing, Fleet Center, diagnostics, a signed
self-hosted update channel and a Linux client without a GUI.

**Version 5.0.3.14 / Android versionCode 2200 was published on 23 October 2026.**
The live self-hosted channel passed Ed25519 signature verification and complete
artifact downloads with exact size and SHA-256 checks.
[Release evidence and checksums](docs/releases/5.0.3.14.md).

| Release platform | Package |
|---|---|
| Windows x64 | Standard EXE and administrator self-hosted client |
| Android 9+, arm64-v8a | APK, versionCode 2200 |
| Linux x64 desktop | `.run` installer |
| Linux x64 headless | Update archive and separate provisioning archive |

This fork receives updates from its configured self-hosted server. Downloads
from the official Amnezia website belong to upstream. Apple sources are retained;
macOS, iOS and other architectures are absent from this release manifest.

## Core Amnezia features

- Very easy to use - enter your IP address, SSH login, password and Amnezia will automatically install VPN docker containers to your server and connect to the VPN.
- Classic VPN-protocols: OpenVPN, WireGuard and IKEv2 protocols.
- Protocols with traffic Masking (Obfuscation): OpenVPN over [Cloak](https://github.com/cbeuw/Cloak) plugin, Shadowsocks (OpenVPN over Shadowsocks), [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) and XRay.
- Split tunneling support - add any sites to the client to enable VPN only for them or add Apps (only for Android and Desktop).
- The upstream codebase supports Windows, macOS, Linux, Android and iOS; this fork’s release targets are listed above.
- Support for AmneziaWG protocol configuration on [Keenetic beta firmware](https://docs.keenetic.com/ua/air/kn-1611/en/6319-latest-development-release.html#UUID-186c4108-5afd-c10b-f38a-cdff6c17fab3_section-idm33192196168192-improved).

## What this fork adds and improves

### Server-managed routing and split tunneling

- **Server Routing rules** centralize domain, IP and CIDR policies and combine
  them with client split-tunneling settings.
- Server bypass lists send selected destinations directly. An individual
  server's address list is not a universal built-in policy for every user.
- **Route Inspector** explains local, server-managed, tunnel-safety and default
  decisions. It uses confirmed client route receipts when available and otherwise
  previews saved policy; it does not inspect the operating system route table.
- IP/CIDR normalization, domain matching, policy revisions and installed-route
  context handling have been strengthened. Server, diagnostic and update access
  routes are handled explicitly.

### Fleet Center and diagnostics

- **Fleet Center** brings together device/connection state, observed tunnel
  health, recovery events and update policy.
- Sender health exposes confirmed log delivery, queued data, collector responses,
  errors and retry times where available. Missing evidence is shown explicitly.
- Windows, Android and headless log delivery gained bounded transfers,
  acknowledgements, retries and heartbeats.
- Android sanitization covers credentials and secrets across upload boundaries;
  log-source readiness and completeness checks have been added.
- A server helper and systemd timer reconcile diagnostic forwarding with the
  container's current network namespace without restarting the VPN.

### Windows and Android

- **Windows:** tunnel-service lifecycle and WinTun startup recovery fixes,
  with stronger context checks during managed-route reconciliation.
- **Android:** Activity/service/native-session restoration with session identity
  checks, verified cleanup, duplicate-tunnel prevention and clearer error states.
- Large route sets are transferred within Binder constraints; route compaction
  preserves the covered address set.
- Coroutine cancellation, unnecessary backend construction and traffic-counter
  source selection were corrected. Full log delivery was checked on a real phone.
- Source support for included sites OR included applications on Android 10+ has
  a separate real-phone routing acceptance matrix still to complete.
  [Contract and limitations](docs/android-included-union.md).

### Linux desktop and headless

- Linux GUI adds privileged IPC peer attribution using process identity and the
  protected systemd service, plus post-install and packaging fixes.
- **`amneziad` and `amnezia-cli`** provide profiles, VPN operation, server routing,
  diagnostics and signed updates without a graphical interface.
- The C++ headless rollback coordinator handles rollback, holding the previous
  version across reboot and explicit update resumption, with state/journal
  validation before transitions.
- Provisioning and update archives are separate. Profile read limits, dependency
  verification and filesystem operations have been strengthened.

### AWG 3.1 and native C++ runtime work

- Administrator profiles can discover server capabilities, prepare a parallel
  AWG endpoint, select an available UDP port, verify a pinned image and reuse a
  compatible generation.
- Signed migration offers travel through the existing tunnel. Server readiness
  and each client's migration remain separate states.
  [AWG 3.1 workflow](docs/automatic-awg31-migration.md).
- C++ implementations cover log collection, route reconciliation, feed/config
  runtime, planning, policy/epoch, topology, readiness/attestation, control
  operations and transaction journals. Selected paths use native adapters;
  server modules have a verified optional-bundle integration path.
- **Python removal is incomplete.** Default/legacy delivery and parts of
  orchestration, maintenance and control HTTP/PID1 still use Python. Implemented
  native code does not imply deployment on every server. Conan, build tools,
  the release lab and tests also retain Python.
  [Detailed migration status](docs/python-runtime-migration.md).

### Imports, interface and reliability

- Configuration, QR and URI parsing now explicitly reject malformed JSON,
  empty hosts, invalid addresses and import errors.
- Port initialization and AWG packet-size overflow were corrected; profile
  input and network response sizes are bounded.
- Asynchronous update-check/download lifetimes, UI model notifications and
  website/log-directory opening were corrected.
- Windows toolchain selection, ARM64 package naming and notarization password
  redaction were improved. These fixes do not imply ARM64 or Apple release availability.

## Self-hosted update channel

Ed25519 authenticates the manifest; exact size and SHA-256 verify every artifact.
Content-addressed URLs protect published bytes. The administrator client publishes
through the self-hosted flow with SSH host-key verification, preparation, commit,
readback and failure recovery. Where supplied, signed rollout policies include
version/generation, expiry, channel, device cohort and release pause controls.

The standard installer updates a client; the self-hosted package also carries
publication payloads. Server availability and installation on individual devices
are separate outcomes. [Update-channel documentation](deploy/selfhosted_updates/README.md).

## Upstream project links

- [https://amnezia.org](https://amnezia.org/?utm_source=github&utm_campaign=amnezia_website-read) - Project website | [Alternative link (mirror)](https://storage.googleapis.com/amnezia/amnezia.org?utm_source=github&utm_campaign=amnezia_website-read)
- [https://docs.amnezia.org](https://docs.amnezia.org/?utm_source=github&utm_campaign=amnezia_website-read) - Documentation | [Alternative link (mirror)](https://storage.googleapis.com/amnezia/docs?utm_source=github&utm_campaign=amnezia_website-read)
- [https://www.reddit.com/r/AmneziaVPN](https://www.reddit.com/r/AmneziaVPN) - Reddit  
- [https://telegram.me/amnezia_vpn_en](https://telegram.me/amnezia_vpn_en) - Telegram support channel (English)
- [https://telegram.me/amnezia_vpn_ir](https://telegram.me/amnezia_vpn_ir) - Telegram support channel (Farsi)
- [https://telegram.me/amnezia_vpn_mm](https://telegram.me/amnezia_vpn_mm) - Telegram support channel (Myanmar)
- [https://telegram.me/amnezia_vpn](https://telegram.me/amnezia_vpn) - Telegram support channel (Russian)
- [Get Premium for 6 or 12 months](https://storage.googleapis.com/amnezia/pay?utm_source=github&utm_campaign=ampay-read)

## Acceptance and verified release

Windows and Linux validation uses owned disposable Hyper-V or QEMU release-lab
guests through PowerShell Direct or QGA/QMP. Guest ownership, exact artifact
bytes, operation results and cleanup are checked. Android validation uses a real
phone; Android emulators and CVD are disabled in the current workflow.

For **5.0.3.14 / 2200**, seven Windows installation/update/UI scenarios, Linux GUI
continuous desktop observation, headless update → reboot → rollback → held reboot
→ resume, and real Android connection/log delivery checks completed. All five
published payloads passed full signed HTTP readback. This does not claim Windows
VPN traffic validation or installation on every device.

The historical Linux GUI SIGSEGV and two initial Android placeholder batches
remain unexplained. Production container recreation was not performed to test
diagnostic forwarding recovery. See [release evidence](docs/releases/5.0.3.14.md)
and the [release lab](deploy/release_lab/README.md) for scope and limitations.

Builds and publication require a separate owner decision. Daily maintenance
checks official stable upstream releases; otherwise it reviews logs and fixes
confirmed defects without producing a release. Ordinary upstream/dev commits
are not treated as a new release.

## Tech

AmneziaVPN uses several open-source projects to work:

- [OpenSSL](https://www.openssl.org/)
- [OpenVPN](https://openvpn.net/)
- [Qt](https://www.qt.io/)
- [LibSsh](https://libssh.org)
- [WireGuard](https://www.wireguard.com/)
- [Xray-core](https://xtls.github.io/en/)
- [Conan](https://conan.io/)
- and more...

## Help us with translations

Download the most actual translation files.

Go to ["Actions" tab](https://github.com/amnezia-vpn/amnezia-client/actions?query=is%3Asuccess+branch%3Adev), click on the first line.
Then scroll down to the "Artifacts" section and download "AmneziaVPN_translations".

Unzip this file.
Each *.ts file contains strings for one corresponding language.

Translate or correct some strings in one or multiple *.ts files and commit them back to this repository into the ``client/translations`` folder.
You can do it via a web-interface or any other method you're familiar with.

## Checking out the source code

Make sure to pull all submodules after checking out the repo.

```bash
git submodule update --init --recursive
```

## Hacking guide

Want to contribute? Welcome!

### Build requirements

* [`CMake`](https://cmake.org/download/)
* Compiler and underlying build system, depending on the target:
  - [Linux] Any of `make` and `gcc`
  - [Apple] [`Xcode`](https://developer.apple.com/xcode/) or [`Xcode command line tools`](https://developer.apple.com/xcode/)
  - [Windows] [`Visual Studio 2022`](https://aka.ms/vs/17/release/vs_community.exe) or [`VS 2022 Build Tools`](https://aka.ms/vs/17/release/vs_buildtools.exe)
  - [Android] [`Android SDK`](#installing-android-sdk) and [`Ninja`](https://ninja-build.org/)
* [`Qt 6.10+`](https://www.qt.io/download-open-source) with the following modules:
  - Core module for targeting platform (Desktop/Android/iOS)
  - Qt 5 Compatibility module
  - Qt Remote Objects
* [`Conan`](https://conan.io/downloads) package manager
  - On MacOS is enough just to use `homebrew` or install it in `.venv` in project root
  - Other systems must have it in `PATH`
* (Optional) Installer dependencies:
  - [Windows/Linux] [`Qt Installer Framework`](https://www.qt.io/download-open-source)
  - [Windows] [`WIX toolset`](https://github.com/wixtoolset/wix/releases)

### Building the project using scripts

* Run scripts located in `deploy` directory
* Basically, if dependencies are located in default installation paths, the scripts will find them automatically.
* If they differ, specify them using the following variables:
  - `QT_INSTALL_DIR` - Qt root installation folder
  - `QT_ROOT_PATH`   - Qt framework root directory
  - `QIF_ROOT_PATH`  - Qt Installer Framework root path
  - `ANDROID_HOME`   - Path to Android SDK root folder
  - and others. Check scripts for more

Unix-like:
```bash
# Build executables for the host platform
deploy/build.sh

# Or just
deploy/build.sh

# Build executables and installers for the host platform
deploy/build.sh --installer all

# Build Android APK and AAB
deploy/build.sh -t android --aab

# Call for help
deploy/build.sh -h
```

Windows:
```batch
:: Build executables for Windows
deploy/build.bat

:: Build executables with IFW installer for Windows
deploy/build.bat --installer ifw

:: Build executables with IFW and WIX installer for Windows
deploy/build.bat --installer ifw --installer wix

:: Or just
deploy/build.bat --installer all
```

### Developing the project in IDEs

* Basically, you can use any IDE that handles CMake and Qt kits properly to run configure and build steps, and to navigate through the code nicely. For example:
  - `Qt Creator`
  - `Visual Studio Code` with `Qt Extension Pack`
  - and so on

* To use `Xcode`, you have to configure project first by using `cmake`. The easiest way to do it is to use `Qt Creator` for configuration. Then open `AmneziaVPN.xcodeproj` file from the build folder by using `Xcode`. Note that none of the files changed are saved - the files actually getting changed in build directory. Copy them manually if necessary

* `Android studio` could be used in the same way - just configure the project by using `cmake` manually or by using `Qt Creator`. Open `<build-dir>/client/android-build` in `Android studio` then. Do not forget to copy the changes - everything you do is saved under the build directory actually.

### Installing Android SDK

* Android SDK could be installed using the following methods:
  - Using `Qt Creator`. Use `Preferences`->`SDKs`
  - Using `Android studio`. By default it installs necessary `SDKs` automatically during the installation
  - Manually by using `sdk-manager`. Check [this](https://developer.android.com/tools) page for details

## License

This project is licensed under the GNU General Public License v3.0 (see LICENSE) and also includes third-party components distributed under their own terms (see THIRD_PARTY_LICENSES.md).

## Donate

Patreon: [https://www.patreon.com/amneziavpn](https://www.patreon.com/amneziavpn)

Bitcoin: bc1qmhtgcf9637rl3kqyy22r2a8wa8laka4t9rx2mf <br>
USDT BEP20: 0x6abD576765a826f87D1D95183438f9408C901bE4 <br>
USDT TRC20: TELAitazF1MZGmiNjTcnxDjEiH5oe7LC9d <br>
XMR: 48spms39jt1L2L5vyw2RQW6CXD6odUd4jFu19GZcDyKKQV9U88wsJVjSbL4CfRys37jVMdoaWVPSvezCQPhHXUW5UKLqUp3 <br> 
TON: UQDpU1CyKRmg7L8mNScKk9FRc2SlESuI7N-Hby4nX-CcVmns
## Acknowledgments

This project is tested with BrowserStack.
We express our gratitude to [BrowserStack](https://www.browserstack.com) for supporting our project.
