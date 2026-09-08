#!/usr/bin/env bash
# Android release-lab driver. All device operations are scoped to one owned AVD.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"
PROFILE_FILE="${SCRIPT_DIR}/android-lab-profile.json"

LAB_ROOT="${AMNEZIA_ANDROID_LAB_ROOT:-/var/lib/amnezia-release-lab/android}"
SDK_ROOT="${AMNEZIA_ANDROID_SDK_ROOT:-${LAB_ROOT}/sdk}"
AVD_HOME="${LAB_ROOT}/avd"
WORK_HOME="${LAB_ROOT}/work"
RECEIPTS_DIR="${LAB_ROOT}/receipts"
ARTIFACTS_DIR="${LAB_ROOT}/artifacts"
DOWNLOAD_DIR="${LAB_ROOT}/downloads"
API_LEVEL="${AMNEZIA_ANDROID_API_LEVEL:-35}"
AVD_NAME="${AMNEZIA_ANDROID_AVD_NAME:-amnezia-release-api${API_LEVEL}}"
ADB_SERVER_PORT="${AMNEZIA_ANDROID_ADB_PORT:-5039}"
EMULATOR_PORT="${AMNEZIA_ANDROID_EMULATOR_PORT:-5556}"
SERIAL="${AMNEZIA_ANDROID_SERIAL:-emulator-${EMULATOR_PORT}}"
GPU_MODE="${AMNEZIA_ANDROID_GPU_MODE:-software}"
ADB_SERVER_SOCKET="tcp:127.0.0.1:${ADB_SERVER_PORT}"

PACKAGE="org.amnezia.vpn"
MAIN_ACTIVITY="org.amnezia.vpn/org.amnezia.vpn.AmneziaActivity"
RELEASE_VERSION="5.0.1.38"
RELEASE_CODE="2186"
BASELINE_VERSION="5.0.1.37"
BASELINE_CODE="2185"
RELEASE_APK_NAME="AmneziaVPN_5.0.1.38_android9+_arm64-v8a.apk"
BASELINE_APK_NAME="AmneziaVPN_5.0.1.37_android9+_arm64-v8a.apk"
RELEASE_SHA256="aa6296143198e416b1baaccc6e36d9e06965beebd9d48168e9927efb5cd75d7a"
BASELINE_SHA256="9592e64c1d3d32ecefad033599614d5bcbc37ace8a430426b9803571f97b37da"

PID_FILE="${WORK_HOME}/emulator.pid"
UUID_FILE="${WORK_HOME}/qemu.uuid"
SERIAL_FILE="${WORK_HOME}/serial"
LOG_FILE="${WORK_HOME}/emulator.log"
SERVER_PID_FILE="${WORK_HOME}/adb-server.pid"
SERVER_STARTTIME_FILE="${WORK_HOME}/adb-server.starttime"
LAB_STATE_PATH="/sdcard/Android/data/${PACKAGE}/files/release-lab/state-marker.txt"
PROFILE_ID="android-arm64-v8a"
RUN_ID="${AMNEZIA_ANDROID_LAB_RUN_ID:-unassigned}"
CONTROLLER_RECEIPT="${AMNEZIA_ANDROID_LAB_CONTROLLER_RECEIPT:-${RECEIPTS_DIR}/controller-receipt.json}"
RUN_ARTIFACT=""

sdk_lock_path() {
  printf '%s\n' "${AMNEZIA_ANDROID_SDK_LOCK:-${WORK_HOME}/sdk-lock-api${API_LEVEL}-tools13114758.json}"
}

log() { printf '[android-lab] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

setup_env() {
  [[ "$LAB_ROOT" == /var/lib/amnezia-release-lab/android || "$LAB_ROOT" == /var/lib/amnezia-release-lab/android/* ]] \
    || die "AMNEZIA_ANDROID_LAB_ROOT must stay under /var/lib/amnezia-release-lab/android"
  [[ "$AVD_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "AVD name contains unsafe characters"
  [[ "$ADB_SERVER_PORT" =~ ^[0-9]+$ && "$ADB_SERVER_PORT" != 5037 ]] || die "ADB server port 5037 is forbidden"
  (( ADB_SERVER_PORT >= 5038 && ADB_SERVER_PORT <= 5100 )) || die "dedicated ADB server port is outside 5038..5100"
  [[ "$SERIAL" == "emulator-${EMULATOR_PORT}" ]] || die "serial must match the owned emulator port"
  [[ "$GPU_MODE" =~ ^(auto|host|software|lavapipe|swiftshader|swangle)$ ]] || die "GPU mode is not documented by emulator -help-gpu"
  [[ "$CONTROLLER_RECEIPT" == "$LAB_ROOT/"* ]] || die "controller receipt must be inside the lab root"
  [[ ! -L "$LAB_ROOT" ]] || die "lab root must not be a symlink"
  [[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "run id contains unsafe characters"
  export ANDROID_SDK_ROOT="$SDK_ROOT"
  export ANDROID_HOME="$SDK_ROOT"
  export ANDROID_AVD_HOME="$AVD_HOME"
  export ANDROID_EMULATOR_HOME="$AVD_HOME"
  export ANDROID_ADB_SERVER_PORT="$ADB_SERVER_PORT"
  # ADB_SERVER_SOCKET makes the adb client treat tcp:127.0.0.1 as a remote
  # daemon and prevents local start-server. Port isolation is provided by the
  # dedicated ANDROID_ADB_SERVER_PORT below; the expected socket is still
  # checked against the owned server process command line.
  export -n ADB_SERVER_SOCKET || true
  export ADB_VENDOR_KEYS="${WORK_HOME}/adb-keys"
  mkdir -p "$SDK_ROOT" "$AVD_HOME" "$WORK_HOME" "$RECEIPTS_DIR" "$ARTIFACTS_DIR" "$DOWNLOAD_DIR" "$ADB_VENDOR_KEYS"
  chmod 700 "$LAB_ROOT" "$SDK_ROOT" "$AVD_HOME" "$WORK_HOME" "$RECEIPTS_DIR" "$ARTIFACTS_DIR" "$DOWNLOAD_DIR"
}

sdkmanager_bin() { printf '%s/cmdline-tools/latest/bin/sdkmanager' "$SDK_ROOT"; }
avdmanager_bin() { printf '%s/cmdline-tools/latest/bin/avdmanager' "$SDK_ROOT"; }
adb_bin() { printf '%s/platform-tools/adb' "$SDK_ROOT"; }
emulator_bin() { printf '%s/emulator/emulator' "$SDK_ROOT"; }

find_owned_emulator_pid() {
  local emulator="$1" candidate
  while read -r candidate _; do
    [[ "$candidate" =~ ^[0-9]+$ && -r "/proc/${candidate}/stat" ]] || continue
    [[ "$(readlink -f "/proc/${candidate}/exe" 2>/dev/null || true)" == "${SDK_ROOT}/emulator/"* ]] || continue
    local cmdline="$(tr '\0' ' ' < "/proc/${candidate}/cmdline" 2>/dev/null || true)"
    [[ "$cmdline" == *"-avd $AVD_NAME"* && "$cmdline" == *"-port $EMULATOR_PORT"* && "$cmdline" == *"-uuid $(<"${WORK_HOME}/avd-identity.nonce")"* ]] || continue
    printf '%s\n' "$candidate"
    return 0
  done < <(ps -eo pid=,args=)
  return 1
}

adb_cmd() {
  assert_transport_owner
  local adb
  adb="$(adb_bin)"
  [[ -x "$adb" ]] || die "isolated adb is not installed; run prepare"
  # Every device command is explicitly scoped. Never replace this with a global adb call.
  "$adb" -s "$SERIAL" "$@"
}

adb_server_cmd() {
  assert_server_owner
  local adb
  adb="$(adb_bin)"
  [[ -x "$adb" ]] || die "isolated adb is not installed; run prepare"
  "$adb" "$@"
}

assert_server_owner() {
  [[ -s "$SERVER_PID_FILE" && -s "$SERVER_STARTTIME_FILE" ]] || die "dedicated ADB server ownership is absent"
  local pid exe uid starttime expected
  pid="$(<"$SERVER_PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || die "invalid dedicated ADB server PID"
  kill -0 "$pid" 2>/dev/null || die "dedicated ADB server is not alive"
  exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
  [[ "$exe" == "${SDK_ROOT}/platform-tools/adb" ]] || die "ADB server executable is not owned by SDK_ROOT"
  uid="$(stat -c '%u' "/proc/${pid}" 2>/dev/null || true)"
  [[ "$uid" == "$(id -u)" ]] || die "ADB server UID ownership check failed"
  starttime="$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null || true)"
  expected="$(<"$SERVER_STARTTIME_FILE")"
  [[ -n "$starttime" && "$starttime" == "$expected" ]] || die "ADB server start-time ownership check failed"
  local cmdline
  cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  [[ "$cmdline" == *"-L $ADB_SERVER_SOCKET"* || "$cmdline" == *"-L tcp:localhost:${ADB_SERVER_PORT}"* || "$cmdline" == *"-L tcp:127.0.0.1:${ADB_SERVER_PORT}"* || "$cmdline" == *"-L tcp:${ADB_SERVER_PORT}"* ]] \
    || die "ADB server socket ownership check failed"
}

assert_transport_owner() {
  [[ -s "$PID_FILE" && -s "${WORK_HOME}/emulator.starttime" ]] || die "owned emulator identity is absent"
  [[ -s "${AVD_HOME}/${AVD_NAME}.lab-profile" ]] || die "owned AVD marker is absent"
  grep -Fxq "profile=$PROFILE_ID" "${AVD_HOME}/${AVD_NAME}.lab-profile" || die "owned AVD profile marker mismatch"
  grep -Fxq "run=$RUN_ID" "${AVD_HOME}/${AVD_NAME}.lab-profile" || die "owned AVD run marker mismatch"
  assert_owned_emulator_process "$(<"$PID_FILE")"
  assert_server_owner
}

find_owned_server_pid() {
  local adb="$(adb_bin)" candidate
  while read -r candidate _; do
    [[ "$candidate" =~ ^[0-9]+$ && -r "/proc/${candidate}/stat" ]] || continue
    [[ "$(readlink -f "/proc/${candidate}/exe" 2>/dev/null || true)" == "$adb" ]] || continue
    printf '%s\n' "$candidate"
    return 0
  done < <(ps -eo pid=,args= | awk -v port="$ADB_SERVER_PORT" '$0 ~ port && $0 ~ /fork-server server/ {print}')
  return 1
}

assert_wsl_kvm() {
  [[ "$(uname -s)" == Linux ]] || die "run this profile inside WSL/Linux"
  [[ "$(uname -m)" == x86_64 ]] || die "the pinned Google APIs image requires an x86_64 WSL host"
  [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is unavailable; refuse a slow/unverified non-KVM run"
}

assert_profile() {
  [[ -s "$PROFILE_FILE" ]] || die "missing profile: $PROFILE_FILE"
  need_cmd sha256sum
  need_cmd python3
  python3 - "$PROFILE_FILE" <<'PY'
import json, sys
p = json.load(open(sys.argv[1], encoding="utf-8"))
assert p["guest"]["abi_under_test"] == "arm64-v8a"
assert p["guest"]["host_abi"] == "x86_64"
assert p["guest"]["native_bridge_required"] is True
assert p["artifacts"]["release_version_code"] == 2186
assert p["artifacts"]["previous_version_code"] == 2185
assert p["network"]["host_routes_or_firewall"] is False
PY
  [[ "$API_LEVEL" == 35 || "$API_LEVEL" == 30 ]] || die "API_LEVEL must be 35 or the documented fallback 30"
  [[ "$EMULATOR_PORT" =~ ^[0-9]+$ ]] || die "emulator port must be numeric"
  (( EMULATOR_PORT >= 5554 && EMULATOR_PORT <= 5682 && EMULATOR_PORT % 2 == 0 )) \
    || die "emulator port must be an even port in 5554..5682"
}

download_checked() {
  local url="$1" expected="$2" output="$3"
  if [[ -f "$output" ]]; then
    printf '%s  %s\n' "$expected" "$output" | sha256sum -c - >/dev/null || die "checksum mismatch: $output"
    return
  fi
  need_cmd curl
  log "downloading official archive: $url"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$output.part" "$url"
  printf '%s  %s\n' "$expected" "$output.part" | sha256sum -c - >/dev/null || die "checksum mismatch: $output.part"
  mv -- "$output.part" "$output"
}

prepare() {
  setup_env
  assert_profile
  assert_wsl_kvm
  local tools_zip="${DOWNLOAD_DIR}/commandlinetools-linux-13114758_latest.zip"
  download_checked \
    'https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip' \
    '7ec965280a073311c339e571cd5de778b9975026cfcbe79f2b1cdcb1e15317ee' \
    "$tools_zip"
  need_cmd unzip
  if [[ ! -x "$(sdkmanager_bin)" ]]; then
    mkdir -p "${SDK_ROOT}/cmdline-tools/new" \
      || die "cannot create isolated command-line tools directory"
    unzip -q -o "$tools_zip" -d "${SDK_ROOT}/cmdline-tools/new"
    [[ -d "${SDK_ROOT}/cmdline-tools/new/cmdline-tools" ]] || die "unexpected command-line tools archive layout"
    rm -rf "${SDK_ROOT}/cmdline-tools/latest"
    mv -- "${SDK_ROOT}/cmdline-tools/new/cmdline-tools" "${SDK_ROOT}/cmdline-tools/latest"
    rmdir "${SDK_ROOT}/cmdline-tools/new" 2>/dev/null || true
  fi
  [[ -x "$(sdkmanager_bin)" ]] || die "sdkmanager was not provisioned"
  local image="system-images;android-${API_LEVEL};google_apis;x86_64"
  local metadata_xml="${DOWNLOAD_DIR}/repository2-3.xml"
  local image_metadata_xml="${DOWNLOAD_DIR}/sys-img2-3.xml"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    --output "${metadata_xml}.part" 'https://dl.google.com/android/repository/repository2-3.xml'
  mv -- "${metadata_xml}.part" "$metadata_xml"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    --output "${image_metadata_xml}.part" 'https://dl.google.com/android/repository/sys-img/google_apis/sys-img2-3.xml'
  mv -- "${image_metadata_xml}.part" "$image_metadata_xml"
  local metadata_sha image_metadata_sha combined_metadata_sha
  metadata_sha="$(sha256sum "$metadata_xml" | awk '{print tolower($1)}')"
  image_metadata_sha="$(sha256sum "$image_metadata_xml" | awk '{print tolower($1)}')"
  combined_metadata_sha="core:${metadata_sha};system-image:${image_metadata_sha}"
  local sdk_lock="$(sdk_lock_path)"
  if [[ -f "$sdk_lock" ]]; then
    local locked_sha
    locked_sha="$(python3 - "$sdk_lock" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["metadata_sha256"])
PY
    )"
    [[ "$locked_sha" == "$combined_metadata_sha" ]] || die "official SDK metadata changed; refresh only the owned API/tools lock deliberately"
  else
    python3 - "$metadata_xml" "$image_metadata_xml" "$combined_metadata_sha" "$image" "$sdk_lock" <<'PY'
import json, sys
import xml.etree.ElementTree as ET

core_xml, image_xml, metadata_sha, image, output = sys.argv[1:]
roots = [ET.parse(core_xml).getroot(), ET.parse(image_xml).getroot()]
paths = ["platform-tools", "emulator", "build-tools;35.0.0", "platforms;" + image.split(";")[1], image]
packages = {}
def local(node, name):
    return next((x for x in node.iter() if x.tag.endswith(name)), None)
def text(node, name, default=""):
    item = local(node, name)
    return (item.text or default) if item is not None else default
for wanted in paths:
    found = None
    for root in roots:
      for node in root.iter():
          if not node.tag.endswith("remotePackage") or node.attrib.get("path") != wanted:
              continue
          channels = [x.attrib.get("ref", "") for x in node if x.tag.endswith("channelRef")]
          if channels and "channel-0" not in channels:
              continue
          rev = local(node, "revision")
          parts = [text(rev, k, "0") for k in ("major", "minor", "micro")] if rev is not None else []
          while len(parts) > 1 and parts[-1] == "0":
              parts.pop()
          version = ".".join(parts) or "0"
          archive = None
          for item in node.iter():
              if not item.tag.endswith("archive"):
                  continue
              host = local(item, "host-os")
              if host is not None and (host.text or "").strip().lower() != "linux":
                  continue
              complete = text(item, "url", "")
              checksum = text(item, "checksum", "")
              size = text(item, "size", "")
              if complete and checksum and size.isdigit():
                  algorithm = {40: "sha1", 64: "sha256"}.get(len(checksum.lower()))
                  if algorithm is None or any(c not in "0123456789abcdefABCDEF" for c in checksum):
                      continue
                  archive = {
                      "url": complete,
                      "checksum": checksum.lower(),
                      "checksum_algorithm": algorithm,
                      "size": int(size)
                  }
                  break
          if archive is None:
              raise SystemExit(f"missing checksummed Linux or OS-independent archive metadata: {wanted}")
          found = {"revision": version, "channel": "channel-0" if channels else "unspecified", "archive": archive}
          break
      if found:
          break
    if not found:
        raise SystemExit(f"missing official SDK package metadata: {wanted}")
    packages[wanted] = found
json.dump({"metadata_sha256": metadata_sha, "api": image.split(";")[1].removeprefix("android-"), "tools": "13114758", "channel": "channel-0", "packages": packages}, open(output, "w", encoding="utf-8"), indent=2)
PY
  fi
  local sdk_status
  set +e
  printf 'y\n%.0s' {1..128} | "$(sdkmanager_bin)" --sdk_root="$SDK_ROOT" \
    'platform-tools' 'emulator' "platforms;android-${API_LEVEL}" \
    'build-tools;35.0.0' "$image" >/dev/null
  sdk_status="${PIPESTATUS[1]}"
  set -e
  (( sdk_status == 0 )) || die "sdkmanager failed with status $sdk_status"
  "$(sdkmanager_bin)" --sdk_root="$SDK_ROOT" --list_installed >"${RECEIPTS_DIR}/sdk-list.txt"
  python3 - "$SDK_ROOT" "$image" "$sdk_lock" <<'PY'
import json, os, pathlib, sys
import xml.etree.ElementTree as ET
sdk, image, lock_path = map(pathlib.Path, sys.argv[1:])
lock = json.loads(lock_path.read_text(encoding="utf-8"))
def revision(path):
    xml = (sdk / pathlib.Path(*path.split(";")) / "package.xml")
    root = __import__("xml.etree.ElementTree", fromlist=["parse"]).parse(xml).getroot()
    rev = next((x for x in root.iter() if x.tag.endswith("revision")), None)
    parts = [next((x.text or "0" for x in rev.iter() if x.tag.endswith(k)), "0") for k in ("major", "minor", "micro")]
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts) or "0"
for path, item in lock["packages"].items():
    if revision(path) != item["revision"]:
        raise SystemExit(f"SDK package revision changed for {path}: expected {item['revision']}")
PY
  python3 - "$SDK_ROOT" "$image" "$sdk_lock" "${RECEIPTS_DIR}/sdk-prepare.json" <<'PY'
import hashlib, json, pathlib, sys
sdk, image, lock_path, out = map(pathlib.Path, sys.argv[1:])
lock = json.loads(lock_path.read_text(encoding="utf-8"))
critical = [
    sdk / "platform-tools" / "adb",
    sdk / "emulator" / "emulator",
    sdk / "cmdline-tools" / "latest" / "bin" / "sdkmanager",
    sdk / "cmdline-tools" / "latest" / "bin" / "avdmanager",
]
critical += [sdk / pathlib.Path(*path.split(";")) / "package.xml" for path in lock["packages"]]
files = {}
for path in critical:
    if not path.is_file():
        raise SystemExit(f"critical SDK file missing after prepare: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    files[str(path)] = digest
json.dump({
    "status": "observed-after-prepare",
    "verification_method": "sdkmanager-repository-checksum-plus-local-critical-file-sha256",
    "metadata_sha256": lock["metadata_sha256"],
    "api": lock["api"],
    "tools": lock["tools"],
    "packages": lock["packages"],
    "critical_files_sha256": files,
}, open(out, "w", encoding="utf-8"), indent=2)
PY
  cat > "${RECEIPTS_DIR}/prepare.txt" <<EOF
profile=$(basename "$PROFILE_FILE")
workspace=$LAB_ROOT
sdk_root=$SDK_ROOT
system_image=$image
commandline_tools_sha256=7ec965280a073311c339e571cd5de778b9975026cfcbe79f2b1cdcb1e15317ee
network=official_google_https_only_during_prepare
EOF
  log "SDK prepared in $SDK_ROOT"
}

doctor() {
  setup_env
  assert_profile
  local sdk_lock="$(sdk_lock_path)"
  python3 - "$SDK_ROOT" "$AVD_HOME" "$AVD_NAME" "$sdk_lock" "$LAB_ROOT" "$EMULATOR_PORT" <<'PY'
import json, os, pathlib, sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
sdk, avd_home, lock, lab = map(pathlib.Path, (sys.argv[1], sys.argv[2], sys.argv[4], sys.argv[5]))
avd_name = sys.argv[3]
emulator_port = sys.argv[6]
checks = {
    "sdkmanager": os.access(sdk / "cmdline-tools/latest/bin/sdkmanager", os.X_OK),
    "avdmanager": os.access(sdk / "cmdline-tools/latest/bin/avdmanager", os.X_OK),
    "adb": os.access(sdk / "platform-tools/adb", os.X_OK),
    "emulator": os.access(sdk / "emulator/emulator", os.X_OK),
    "sdk_lock": lock.is_file(),
    "avd_marker": (avd_home / f"{avd_name}.lab-profile").is_file(),
    "avd_userdata": (avd_home / f"{avd_name}.avd").is_dir(),
    "kvm": pathlib.Path("/dev/kvm").exists(),
}
pid_file = pathlib.Path(lab) / "work/emulator.pid"
live = False
try:
    pid = int(pid_file.read_text(encoding="utf-8").strip())
    proc = pathlib.Path(f"/proc/{pid}")
    cmdline = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    live = proc.exists() and cmdline.find("-avd " + avd_name) >= 0 and cmdline.find("-port " + emulator_port) >= 0
except (OSError, ValueError):
    pass
checks["live_emulator"] = live
marker = avd_home / f"{avd_name}.lab-profile"
if marker.is_file():
    content = marker.read_text(encoding="utf-8")
    checks["avd_marker_binding"] = f"profile=android-arm64-v8a\n" in content and f"run={os.environ.get('AMNEZIA_ANDROID_LAB_RUN_ID', 'unassigned')}\n" in content
if checks["sdk_lock"]:
    try:
        locked = json.loads(lock.read_text(encoding="utf-8"))
        for package, item in locked["packages"].items():
            package_xml = sdk / pathlib.Path(*package.split(";")) / "package.xml"
            checks[f"locked_{package}"] = package_xml.is_file()
            if not package_xml.is_file():
                continue
            root = ET.parse(package_xml).getroot()
            rev = next(x for x in root.iter() if x.tag.endswith("revision"))
            parts = [next((y.text or "0" for y in rev.iter() if y.tag.endswith(k)), "0") for k in ("major", "minor", "micro")]
            while len(parts) > 1 and parts[-1] == "0": parts.pop()
            checks[f"locked_{package}"] = ".".join(parts) == item["revision"]
    except (KeyError, OSError, ValueError, StopIteration, ET.ParseError):
        checks["locked_packages"] = False
print(json.dumps({
    "status": "observed-ready" if all(checks.values()) else "pending",
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "lab_root": str(lab), "api": int(avd_name.rsplit("api", 1)[-1]) if "api" in avd_name else None,
    "checks": checks,
    "source": "filesystem-and-host-preflight",
}, sort_keys=True))
PY
}

create_avd() {
  setup_env
  assert_profile
  [[ -x "$(avdmanager_bin)" ]] || die "avdmanager is not installed; run prepare"
  [[ -x "$(emulator_bin)" ]] || die "emulator is not installed; run prepare"
  need_cmd setsid
  local image="system-images;android-${API_LEVEL};google_apis;x86_64"
  local sdk_lock="$(sdk_lock_path)"
  [[ -s "$sdk_lock" ]] || die "SDK/image lock is absent; run prepare"
  local image_xml="${SDK_ROOT}/system-images/android-${API_LEVEL}/google_apis/x86_64/package.xml"
  [[ -s "$image_xml" ]] || die "locked Google APIs system image is not installed"
  local image_revision image_sha
  image_revision="$(python3 - "$image_xml" <<'PY'
import sys, xml.etree.ElementTree as ET
r = ET.parse(sys.argv[1]).getroot()
v = next(x for x in r.iter() if x.tag.endswith("revision"))
p = [next((y.text or "0" for y in v.iter() if y.tag.endswith(k)), "0") for k in ("major", "minor", "micro")]
while len(p) > 1 and p[-1] == "0": p.pop()
print(".".join(p))
PY
  )"
  image_sha="$(sha256sum "$image_xml" | awk '{print tolower($1)}')"
  printf 'no\n' | "$(avdmanager_bin)" create avd --force --name "$AVD_NAME" \
    --package "$image" --device 'pixel_7' >/dev/null
  mkdir -p "${AVD_HOME}/${AVD_NAME}.avd"
  local nonce
  nonce="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  nonce="${nonce:0:8}-${nonce:8:4}-${nonce:12:4}-${nonce:16:4}-${nonce:20:12}"
  printf '%s\n' "$nonce" >"${WORK_HOME}/avd-identity.nonce"
  cat > "${AVD_HOME}/${AVD_NAME}.lab-profile" <<EOF
profile=android-arm64-v8a
run=$RUN_ID
avd_name=$AVD_NAME
api_level=$API_LEVEL
system_image=$image
image_revision=$image_revision
image_package_xml_sha256=$image_sha
host_abi=x86_64
guest_abi=arm64-v8a
native_bridge=required
network=offline-by-default
EOF
  chmod 600 "${AVD_HOME}/${AVD_NAME}.lab-profile" "${WORK_HOME}/avd-identity.nonce"
  log "created isolated AVD $AVD_NAME"
}

running_pid() {
  [[ -s "$PID_FILE" ]] || return 1
  local pid
  pid="$(<"$PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  printf '%s\n' "$pid"
}

assert_owned_emulator_process() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[0-9]+$ ]] || die "invalid emulator pid"
  local cmdline
  cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  local exe uid starttime expected_starttime
  exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
  [[ "$exe" == "${SDK_ROOT}/emulator/"* ]] || die "pid $pid is outside the isolated emulator executable subtree"
  uid="$(stat -c '%u' "/proc/${pid}" 2>/dev/null || true)"
  [[ "$uid" == "$(id -u)" ]] || die "pid $pid is owned by another UID"
  starttime="$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null || true)"
  expected_starttime="$(<"${WORK_HOME}/emulator.starttime")"
  [[ -n "$starttime" && "$starttime" == "$expected_starttime" ]] || die "emulator PID start-time ownership check failed"
  [[ "$cmdline" == *"-avd $AVD_NAME"* || "$cmdline" == *"-uuid $(<"${WORK_HOME}/avd-identity.nonce")"* ]] \
    || die "pid $pid does not own AVD $AVD_NAME/launch nonce"
  [[ "$cmdline" == *"-port $EMULATOR_PORT"* || "$cmdline" == *":$EMULATOR_PORT"* ]] \
    || die "pid $pid has unexpected emulator port"
}

assert_owned_launcher_process() {
  local pid="$1" cmdline uid
  [[ "$pid" =~ ^[0-9]+$ ]] || die "invalid launcher PID"
  kill -0 "$pid" 2>/dev/null || return 0
  uid="$(stat -c '%u' "/proc/${pid}" 2>/dev/null || true)"
  [[ "$uid" == "$(id -u)" ]] || die "launcher PID is owned by another UID"
  cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  [[ "$cmdline" == *"$(emulator_bin)"* && "$cmdline" == *"-avd $AVD_NAME"* && "$cmdline" == *"-port $EMULATOR_PORT"* ]] \
    || die "launcher PID does not own the requested emulator"
}

start_emulator() {
  setup_env
  assert_profile
  assert_wsl_kvm
  [[ -x "$(emulator_bin)" ]] || die "emulator is not installed; run prepare"
  [[ -f "${AVD_HOME}/${AVD_NAME}.lab-profile" ]] || die "AVD is not created; run create"
  [[ -s "${WORK_HOME}/avd-identity.nonce" ]] || die "AVD identity nonce is absent; recreate the owned AVD"
  if pid="$(running_pid)"; then
    assert_owned_emulator_process "$pid"
    log "emulator already owned by pid $pid"
    return
  fi
  rm -f -- "$PID_FILE" "$UUID_FILE" "$SERIAL_FILE" "${WORK_HOME}/emulator.starttime"
  # No -wipe-data here: update tests need persistent state. reset/create are explicit.
  nohup setsid --wait "$(emulator_bin)" -avd "$AVD_NAME" -port "$EMULATOR_PORT" \
    -no-window -no-audio -no-boot-anim -no-snapshot -no-snapshot-save \
    -gpu "$GPU_MODE" -no-metrics -accel on -qemu -uuid "$(<"${WORK_HOME}/avd-identity.nonce")" \
    </dev/null >"$LOG_FILE" 2>&1 &
  local launcher_pid=$! pid='' attempt
  printf '%s\n' "$launcher_pid" >"${WORK_HOME}/emulator-launcher.pid"
  for attempt in {1..100}; do
    pid="$(find_owned_emulator_pid "$(emulator_bin)" || true)"
    [[ -n "$pid" ]] && break
    sleep 0.2
  done
  [[ "$pid" =~ ^[0-9]+$ ]] || die "owned QEMU process did not appear under detached launcher"
  printf '%s\n' "$pid" >"$PID_FILE"
  awk '{print $22}' "/proc/${pid}/stat" >"${WORK_HOME}/emulator.starttime"
  printf '%s\n' "$(<"${WORK_HOME}/avd-identity.nonce")" >"$UUID_FILE"
  assert_owned_emulator_process "$pid"
  printf '%s\n' "$SERIAL" >"$SERIAL_FILE"
  start_dedicated_adb_server
  local deadline=$((SECONDS + 180)) state=''
  while (( SECONDS < deadline )); do
    state="$(adb_server_cmd devices | awk -v s="$SERIAL" '$1 == s {print $2}')"
    if [[ "$state" == device ]]; then
      log "emulator $SERIAL is online"
      break
    fi
    sleep 2
  done
  [[ "$state" == device ]] || die "owned emulator did not become online"
  adb_cmd wait-for-device >/dev/null
  local boot=''
  deadline=$((SECONDS + 180))
  while (( SECONDS < deadline )); do
    boot="$(adb_cmd shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
    [[ "$boot" == 1 ]] && break
    sleep 2
  done
  [[ "$boot" == 1 ]] || die "owned emulator did not finish boot"
  ensure_guest_offline
  capture_identity
}

start_dedicated_adb_server() {
  local adb="$(adb_bin)" server_pid='' attempt candidate
  [[ -x "$adb" ]] || die "isolated adb is not installed; run prepare"
  env -u ADB_SERVER_SOCKET ANDROID_ADB_SERVER_PORT="$ADB_SERVER_PORT" "$adb" start-server >/dev/null
  for attempt in {1..20}; do
    server_pid="$(find_owned_server_pid || true)"
    if [[ "$server_pid" =~ ^[0-9]+$ ]]; then
      break
    fi
    server_pid=''
    sleep 0.1
  done
  [[ "$server_pid" =~ ^[0-9]+$ ]] || die "could not identify dedicated ADB server"
  printf '%s\n' "$server_pid" >"$SERVER_PID_FILE"
  awk '{print $22}' "/proc/${server_pid}/stat" >"$SERVER_STARTTIME_FILE"
  assert_server_owner
}

capture_identity() {
  local out="${RECEIPTS_DIR}/identity-$(date -u +%Y%m%dT%H%M%SZ).txt"
  {
    printf 'serial=%s\n' "$SERIAL"
    printf 'avd=%s\n' "$AVD_NAME"
    printf 'pid=%s\n' "$(<"$PID_FILE")"
    adb_cmd shell getprop ro.boot.qemu.avd_name
    adb_cmd shell getprop ro.boot.qemu.uuid
    adb_cmd shell getprop ro.product.cpu.abilist
    adb_cmd shell getprop ro.dalvik.vm.native.bridge
    printf 'gpu_mode=%s\n' "$GPU_MODE"
  } >"$out"
  local qemu_avd qemu_uuid
  qemu_avd="$(adb_cmd shell getprop ro.boot.qemu.avd_name | tr -d '\r')"
  qemu_uuid="$(adb_cmd shell getprop ro.boot.qemu.uuid | tr -d '\r')"
  [[ -z "$qemu_avd" || "$qemu_avd" == "$AVD_NAME" ]] || die "qemu AVD identity mismatch: $qemu_avd"
  if [[ "$qemu_uuid" == unknown || ! "$qemu_uuid" =~ ^[[:alnum:]-]+$ ]]; then
    qemu_uuid="$(<"${WORK_HOME}/avd-identity.nonce")"
    local process_cmdline
    process_cmdline="$(tr '\0' ' ' < "/proc/$(<"$PID_FILE")/cmdline" 2>/dev/null || true)"
    [[ "$process_cmdline" == *"-uuid $qemu_uuid"* ]] || die "qemu UUID property absent and launch nonce is not present"
  fi
  [[ "$qemu_uuid" =~ ^[[:alnum:]-]+$ ]] || die "missing qemu UUID and launch nonce"
  printf '%s\n' "$qemu_uuid" >"$UUID_FILE"
}

verify_network_gate() {
  assert_owned_target
  local marker="${WORK_HOME}/network-gate.ok"
  [[ -s "$marker" ]] || die "network gate marker is absent; network scenarios remain pending"
  grep -Fxq "avd_name=$AVD_NAME" "$marker" || die "network gate AVD binding mismatch"
  grep -Fxq "qemu_uuid=$(<"$UUID_FILE")" "$marker" || die "network gate qemu UUID binding mismatch"
  grep -Fxq 'egress=deny' "$marker" || die "network gate is not fail-closed"
  grep -Fxq 'peer=controller-owned' "$marker" || die "network gate peer is not controller-owned"
  local peer4 peer6
  peer4="$(sed -n 's/^peer_ipv4=//p' "$marker")"
  peer6="$(sed -n 's/^peer_ipv6=//p' "$marker")"
  [[ "$peer4" =~ ^[0-9a-fA-F:.]+$ && "$peer6" =~ ^[0-9a-fA-F:.]+$ ]] || die "network gate peer addresses are absent"
  grep -Fxq 'allowlist=loopback,peer-only' "$marker" || die "network gate allowlist is not explicit"
  grep -Fxq 'rules=verified' "$marker" || die "network gate has no rule verification receipt"
  local rules4 rules6 line
  rules4="$(adb_cmd shell 'iptables -S OUTPUT' || true)"
  rules6="$(adb_cmd shell 'ip6tables -S OUTPUT' || true)"
  [[ "$rules4" == *'-P OUTPUT DROP'* && "$rules4" == *'-o lo -j ACCEPT'* ]] \
    || die "guest IPv4 deny/loopback policy was not observed inside the AVD"
  [[ "$rules6" == *'-P OUTPUT DROP'* && "$rules6" == *'-o lo -j ACCEPT'* ]] \
    || die "guest IPv6 deny/loopback policy was not observed inside the AVD"
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == *'-P OUTPUT DROP'* || "$line" == *'-o lo -j ACCEPT'* || "$line" == *"$peer4"* || "$line" == *ESTABLISHED* ]] \
      || die "guest IPv4 OUTPUT has an unallowlisted rule: $line"
  done <<<"$rules4"
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == *'-P OUTPUT DROP'* || "$line" == *'-o lo -j ACCEPT'* || "$line" == *"$peer6"* || "$line" == *ESTABLISHED* ]] \
      || die "guest IPv6 OUTPUT has an unallowlisted rule: $line"
  done <<<"$rules6"
  printf 'serial=%s\navd_name=%s\nqemu_uuid=%s\nrules=verified\n' \
    "$SERIAL" "$AVD_NAME" "$(<"$UUID_FILE")" | tee "${RECEIPTS_DIR}/network-gate-$(date -u +%Y%m%dT%H%M%SZ).txt"
}

enable_consumer_fixture_network() {
  assert_owned_target
  local host_port="${1:-}"
  [[ "$host_port" =~ ^[0-9]+$ && "$host_port" -ge 1024 && "$host_port" -le 65535 && "$host_port" != 5037 ]] \
    || die "fixture host port is invalid"
  adb_cmd root >/dev/null 2>&1 || die "guest cannot enter root mode for fixture network setup"
  adb_cmd wait-for-device >/dev/null
  adb_cmd shell 'iptables -F OUTPUT && iptables -P OUTPUT DROP && iptables -A OUTPUT -o lo -j ACCEPT && iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' \
    >/dev/null || die "failed to apply fixture IPv4 base policy"
  adb_cmd shell "iptables -A OUTPUT -d 10.0.2.2 -p tcp --dport ${host_port} -j ACCEPT && iptables -t nat -F OUTPUT && iptables -t nat -A OUTPUT -d 10.8.1.0/32 -p tcp --dport 17865 -j DNAT --to-destination 10.0.2.2:${host_port} && ip route replace 10.8.1.0/32 via 10.0.2.2" \
    >/dev/null || die "failed to apply fixture IPv4 DNAT policy"
  adb_cmd shell 'ip6tables -F OUTPUT && ip6tables -P OUTPUT DROP && ip6tables -A OUTPUT -o lo -j ACCEPT' \
    >/dev/null || die "failed to apply fixture IPv6 deny policy"
  local rules4 rules6 nat route
  rules4="$(adb_cmd shell iptables -S OUTPUT | tr -d '\r')"
  rules6="$(adb_cmd shell ip6tables -S OUTPUT | tr -d '\r')"
  nat="$(adb_cmd shell iptables -t nat -S OUTPUT | tr -d '\r')"
  route="$(adb_cmd shell ip route show 10.8.1.0/32 | tr -d '\r')"
  grep -Eq -- '^-P OUTPUT DROP(\r)?$' <<<"$rules4" \
    && grep -Eq -- "-d 10\\.0\\.2\\.2(/32)? .*--dport ${host_port} -j ACCEPT" <<<"$rules4" \
    || die "fixture IPv4 peer allowlist verification failed"
  grep -Eq -- '^-P OUTPUT DROP(\r)?$' <<<"$rules6" || die "fixture IPv6 deny verification failed"
  grep -Eq -- "-d 10\\.8\\.1\\.0/32 .*--dport 17865 -j DNAT --to-destination 10\\.0\\.2\\.2:${host_port}" <<<"$nat" \
    || die "fixture DNAT rule verification failed"
  [[ "$route" == *"via 10.0.2.2"* ]] || die "fixture route verification failed"
  python3 - "$WORK_HOME/fixture-network.json" "$RUN_ID" "$PROFILE_ID" "$host_port" <<'PY'
import json, pathlib, sys
out, run, profile, host_port = sys.argv[1:]
pathlib.Path(out).write_text(json.dumps({
    "status": "observed-guest-fixture-network",
    "run_id": run, "profile": profile, "host_port": int(host_port),
    "guest_endpoint": "10.8.1.0:17865",
    "dnat_target": f"10.0.2.2:{host_port}",
    "ipv4": "loopback-established-fixture-peer-only",
    "ipv6": "output-drop-loopback-only",
    "host_routes_or_firewall": False,
}, sort_keys=True) + "\n", encoding="utf-8")
PY
}

ensure_guest_network() {
  if [[ -s "${WORK_HOME}/fixture-network.json" ]]; then
    local fixture_port
    fixture_port="$(python3 - "${WORK_HOME}/fixture-network.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["host_port"])
PY
    )"
    enable_consumer_fixture_network "$fixture_port"
  else
    ensure_guest_offline
  fi
}

assert_owned_target() {
  setup_env
  [[ "$SERIAL" == emulator-* ]] || die "refusing non-emulator serial: $SERIAL"
  local state
  state="$(adb_cmd get-state 2>/dev/null | tr -d '\r')" || die "ADB target $SERIAL is unavailable"
  [[ "$state" == device ]] || die "ADB target $SERIAL is not online: $state"
  local qemu_avd qemu_uuid expected_uuid
  qemu_avd="$(adb_cmd shell getprop ro.boot.qemu.avd_name | tr -d '\r')"
  qemu_uuid="$(adb_cmd shell getprop ro.boot.qemu.uuid | tr -d '\r')"
  expected_uuid="$(<"$UUID_FILE")"
  local launch_nonce pid_cmdline
  launch_nonce="$(<"${WORK_HOME}/avd-identity.nonce")"
  pid_cmdline="$(tr '\0' ' ' < "/proc/$(<"$PID_FILE")/cmdline" 2>/dev/null || true)"
  [[ "$pid_cmdline" == *"-uuid $launch_nonce"* ]] || die "owned emulator launch nonce is not bound to PID"
  [[ -z "$qemu_avd" || "$qemu_avd" == "$AVD_NAME" ]] || die "target AVD mismatch"
  if [[ -n "$qemu_uuid" && "$qemu_uuid" != unknown ]]; then
    [[ "$qemu_uuid" == "$expected_uuid" ]] || die "qemu UUID ownership check failed"
  else
    [[ "$pid_cmdline" == *"-uuid $expected_uuid"* ]] || die "qemu UUID property absent and launch nonce is not owned"
  fi
}

ensure_guest_offline() {
  assert_owned_target
  local id4 id6
  adb_cmd root >/dev/null 2>&1 || die "guest cannot enter root mode for offline firewall setup"
  adb_cmd wait-for-device >/dev/null
  id4="$(adb_cmd shell id | tr -d '\r')"
  [[ "$id4" == uid=0* ]] || die "guest root mode was not verified"
  adb_cmd shell 'iptables -F OUTPUT && iptables -P OUTPUT DROP && iptables -A OUTPUT -o lo -j ACCEPT' \
    >/dev/null || die "failed to apply guest IPv4 offline policy"
  adb_cmd shell 'ip6tables -F OUTPUT && ip6tables -P OUTPUT DROP && ip6tables -A OUTPUT -o lo -j ACCEPT' \
    >/dev/null || die "failed to apply guest IPv6 offline policy"
  id4="$(adb_cmd shell iptables -S OUTPUT | tr -d '\r')"
  id6="$(adb_cmd shell ip6tables -S OUTPUT | tr -d '\r')"
  [[ "$id4" == *'-P OUTPUT DROP'* && "$id4" == *'-A OUTPUT -o lo -j ACCEPT'* ]] \
    || die "guest IPv4 offline policy verification failed"
  [[ "$id6" == *'-P OUTPUT DROP'* && "$id6" == *'-A OUTPUT -o lo -j ACCEPT'* ]] \
    || die "guest IPv6 offline policy verification failed"
  cat >"${WORK_HOME}/offline-gate.ok" <<EOF
avd_name=$AVD_NAME
qemu_uuid=$(<"$UUID_FILE")
mode=guest-offline
ipv4=output-drop-loopback-only
ipv6=output-drop-loopback-only
rules=verified
EOF
  python3 - "$WORK_HOME/offline-boot.json" "$RUN_ID" "$PROFILE_ID" "$AVD_NAME" "$UUID_FILE" <<'PY'
import json, pathlib, sys
out, run, profile, avd, uuid_file = sys.argv[1:]
uuid = pathlib.Path(uuid_file).read_text(encoding="utf-8").strip()
pathlib.Path(out).write_text(json.dumps({
    "status": "observed-after-boot",
    "run_id": run, "profile": profile, "avd": avd, "qemu_uuid": uuid,
    "ipv4": {"policy": "DROP", "allow": ["loopback"]},
    "ipv6": {"policy": "DROP", "allow": ["loopback"]},
    "host_routes_or_firewall": False,
    "verified_by": "adb-guest-iptables",
}, sort_keys=True) + "\n", encoding="utf-8")
PY
  chmod 600 "${WORK_HOME}/offline-gate.ok" "${WORK_HOME}/offline-boot.json"
}

probe() {
  assert_owned_target
  ensure_guest_network
  local abi bridge sdk package_dump
  abi="$(adb_cmd shell getprop ro.product.cpu.abilist | tr -d '\r')"
  bridge="$(adb_cmd shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
  sdk="$(adb_cmd shell getprop ro.build.version.sdk | tr -d '\r')"
  package_dump="$(adb_cmd shell dumpsys package "$PACKAGE" 2>/dev/null || true)"
  [[ "$abi" == *x86_64* ]] || die "host ABI is not x86_64: $abi"
  [[ "$bridge" == *libndk_translation* ]] || die "Native Bridge is not libndk_translation: $bridge"
  [[ "$sdk" == "$API_LEVEL" ]] || die "unexpected API level $sdk (expected $API_LEVEL)"
  [[ "$package_dump" == *"versionCode=$RELEASE_CODE"* || "$package_dump" == *"versionCode=$BASELINE_CODE"* || "$package_dump" == *"Unable to find package"* || -z "$package_dump" ]] || die "unexpected package version"
  {
    printf 'serial=%s\napi=%s\nhost_abi=%s\nnative_bridge=%s\n' "$SERIAL" "$sdk" "$abi" "$bridge"
    printf 'translation_required=true\nmetadata_only_pass=false\nnetwork_gate=pending\n'
  } | tee "${RECEIPTS_DIR}/probe-$(date -u +%Y%m%dT%H%M%SZ).txt"
}

resolve_apk() {
  local requested="${1:-}"
  if [[ -n "$requested" ]]; then
    [[ -f "$requested" ]] || die "APK does not exist: $requested"
    printf '%s\n' "$requested"
    return
  fi
  local default_path="${AMNEZIA_ANDROID_ARTIFACT_DIR:-${REPO_ROOT}/dist/selfhosted-local-artifacts/${RELEASE_VERSION}}/${RELEASE_APK_NAME}"
  [[ -f "$default_path" ]] || die "release APK not found; pass an explicit path: $default_path"
  printf '%s\n' "$default_path"
}

manifest_artifact_field() {
  local kind="$1" field="$2" manifest
  if [[ "$kind" == release ]]; then
    manifest="${AMNEZIA_ANDROID_RELEASE_MANIFEST:-}"
  else
    manifest="${AMNEZIA_ANDROID_BASELINE_MANIFEST:-}"
  fi
  [[ -n "$manifest" && -f "$manifest" ]] || return 1
  python3 - "$manifest" "$field" <<'PY'
import base64, json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
payload = doc.get("payload")
if payload:
    payload += "=" * (-len(payload) % 4)
    doc = json.loads(base64.b64decode(payload).decode("utf-8"))
artifact = doc["platforms"]["android-arm64-v8a"]
field = sys.argv[2]
if field == "version":
    print(artifact.get(field) or doc["version"])
else:
    print(artifact[field])
PY
}

artifact_hash() {
  local kind="$1" fallback value
  if [[ "$kind" == release ]]; then fallback="$RELEASE_SHA256"; else fallback="$BASELINE_SHA256"; fi
  value="$(manifest_artifact_field "$kind" sha256 || printf '%s\n' "$fallback")"
  [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]] || die "invalid $kind manifest SHA256"
  printf '%s\n' "${value,,}"
}

artifact_code() {
  local kind="$1" fallback value
  if [[ "$kind" == release ]]; then fallback="$RELEASE_CODE"; else fallback="$BASELINE_CODE"; fi
  value="$(manifest_artifact_field "$kind" versionCode || printf '%s\n' "$fallback")"
  [[ "$value" =~ ^[0-9]+$ ]] || die "invalid $kind manifest versionCode"
  printf '%s\n' "$value"
}

artifact_version() {
  local kind="$1" fallback value
  if [[ "$kind" == release ]]; then fallback="$RELEASE_VERSION"; else fallback="$BASELINE_VERSION"; fi
  value="$(manifest_artifact_field "$kind" version || printf '%s\n' "$fallback")"
  [[ "$value" =~ ^[A-Za-z0-9._+-]+$ ]] || die "invalid $kind manifest version"
  printf '%s\n' "$value"
}

assert_sha256() {
  local file="$1" expected="$2" got
  got="$(sha256sum "$file" | awk '{print tolower($1)}')"
  [[ "$got" == "$expected" ]] || die "APK checksum mismatch for $file (got $got)"
}

assert_apk_arm64_elf() {
  local apk="$1" member found=0
  need_cmd unzip
  while IFS= read -r member; do
    [[ "$member" == lib/arm64-v8a/*.so ]] || continue
    found=1
    unzip -p "$apk" "$member" | python3 -c 'import struct,sys; b=sys.stdin.buffer.read(); sys.exit(0 if len(b)>=20 and b[:4]==b"\x7fELF" and b[4]==2 and struct.unpack_from("<H",b,18)[0]==183 else 1)' \
      || die "ARM64 ELF header validation failed: $member"
  done < <(unzip -Z1 "$apk")
  (( found == 1 )) || die "APK has no lib/arm64-v8a ELF payload"
}

package_version_code() {
  adb_cmd shell dumpsys package "$PACKAGE" | sed -n 's/.*versionCode=\([0-9][0-9]*\).*/\1/p' | head -n1 | tr -d '\r'
}

assert_native_runtime() {
  local log_file="$1" pid maps package_dump deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    adb_cmd logcat -b all -d -t 5000 >"$log_file"
    pid="$(adb_cmd shell pidof "$PACKAGE" | tr -d '\r' | awk '{print $1}')"
    maps=""
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      maps="$(adb_cmd shell "cat /proc/${pid}/maps" 2>/dev/null || true)"
    fi
    if grep -Eiq 'libndk_translation|NativeBridge|nativeloader: Load .*\/lib\/arm64\/.*: ok' "$log_file" \
      && [[ "$pid" =~ ^[0-9]+$ && "$maps" == *'/lib/arm64/'* ]]; then
      break
    fi
    sleep 1
  done
  grep -Eiq 'libndk_translation|NativeBridge|nativeloader: Load .*\/lib\/arm64\/.*: ok' "$log_file" \
    || die "missing live Native Bridge evidence in $log_file"
  if grep -Eiq 'org\.amnezia\.vpn.*(FATAL EXCEPTION|SIGILL|dlopen failed|UnsatisfiedLinkError|signal 4)|(FATAL EXCEPTION|SIGILL|dlopen failed|UnsatisfiedLinkError|signal 4).*org\.amnezia\.vpn|/data/app/[^ ]*org\.amnezia\.vpn[^ ]*.*(dlopen failed|SIGILL)' "$log_file"; then
    die "fatal/native-loader failure observed in $log_file"
  fi
  [[ "$pid" =~ ^[0-9]+$ ]] || die "the Android app process did not remain alive after launch"
  package_dump="$(adb_cmd shell dumpsys package "$PACKAGE")"
  [[ "$package_dump" == *'primaryCpuAbi=arm64-v8a'* ]] || die "installed package primaryCpuAbi is not arm64-v8a"
  [[ "$package_dump" == *'legacyNativeLibraryDir='* ]] \
    || die "installed package native library metadata is not ARM64"
  maps="${maps:-$(adb_cmd shell "cat /proc/${pid}/maps" 2>/dev/null || true)}"
  [[ "$maps" == *'/lib/arm64/'* ]] || die "no exact ARM64 native library mapping observed in app process"
}

install_baseline() {
  assert_owned_target
  ensure_guest_network
  local apk="${1:-${AMNEZIA_ANDROID_BASELINE_APK:-}}"
  if [[ -z "$apk" ]]; then
    apk="${AMNEZIA_ANDROID_ARTIFACT_DIR:-${REPO_ROOT}/dist/selfhosted-local-artifacts/${BASELINE_VERSION}}/${BASELINE_APK_NAME}"
  fi
  [[ -f "$apk" ]] || die "baseline APK does not exist: $apk"
  local expected_hash expected_code expected_version
  expected_hash="$(artifact_hash baseline)"
  expected_code="$(artifact_code baseline)"
  expected_version="$(artifact_version baseline)"
  assert_sha256 "$apk" "$expected_hash"
  assert_apk_arm64_elf "$apk"
  # This is intentionally the only direct install path. It establishes state for the UI update.
  adb_cmd install --abi arm64-v8a "$apk" | tee "${RECEIPTS_DIR}/baseline-install-$(date -u +%Y%m%dT%H%M%SZ).txt"
  local code="$(package_version_code)"
  [[ "$code" == "$expected_code" ]] || die "baseline versionCode is $code, expected $expected_code"
  mkdir -p "${ARTIFACTS_DIR}/state"
  printf 'baseline=%s\npackage=%s\n' "$expected_version" "$PACKAGE" >"${ARTIFACTS_DIR}/state/marker.txt"
  adb_cmd shell "mkdir -p /sdcard/Android/data/${PACKAGE}/files/release-lab && printf '%s' baseline-${expected_code} > '${LAB_STATE_PATH}'"
  adb_cmd logcat -b all -c
  adb_cmd shell monkey -p "$PACKAGE" 1 >"${RECEIPTS_DIR}/baseline-launch-$(date -u +%Y%m%dT%H%M%SZ).txt" 2>&1
  local baseline_log="${RECEIPTS_DIR}/baseline-logcat-$(date -u +%Y%m%dT%H%M%SZ).txt"
  adb_cmd logcat -b all -d -t 2000 >"$baseline_log"
  assert_native_runtime "$baseline_log"
  local abi
  abi="$(adb_cmd shell dumpsys package "$PACKAGE" | grep -E 'primaryCpuAbi|legacyNativeLibraryDir' || true)"
  grep -q 'arm64-v8a' <<<"$abi" || log "package ABI is not exposed by dumpsys; Native Bridge evidence remains required"
  log "baseline installed; direct install is not updater evidence"
}

ui_dump() {
  local output="$1"
  adb_cmd shell uiautomator dump /sdcard/window.xml >/dev/null 2>&1 || return 1
  adb_cmd shell cat /sdcard/window.xml | tr -d '\r' >"$output"
  [[ -s "$output" ]]
}

ui_tap_text() {
  local text="$1" xml="$2" bounds x1 y1 x2 y2
  bounds="$(python3 - "$xml" "$text" <<'PY'
import html, re, sys
xml, wanted = open(sys.argv[1], encoding='utf-8').read(), sys.argv[2]
for m in re.finditer(r'<node\b[^>]*>', xml):
    tag = html.unescape(m.group(0))
    text_m = re.search(r'\btext="([^"]*)"', tag)
    b_m = re.search(r'\bbounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', tag)
    if text_m and b_m and text_m.group(1).strip().lower() == wanted.lower():
        print(' '.join(b_m.groups()))
        break
PY
  )"
  [[ -n "$bounds" ]] || return 1
  read -r x1 y1 x2 y2 <<<"$bounds"
  adb_cmd shell input tap "$(( (x1+x2) / 2 ))" "$(( (y1+y2) / 2 ))"
}

wait_ui_text() {
  local text="$1" xml="$2" deadline=$((SECONDS + ${3:-30}))
  while (( SECONDS < deadline )); do
    if ui_dump "$xml" && ui_tap_text "$text" "$xml"; then return 0; fi
    sleep 1
  done
  return 1
}

wait_ui_present() {
  local text="$1" xml="$2" deadline=$((SECONDS + ${3:-30}))
  while (( SECONDS < deadline )); do
    if ui_dump "$xml" && grep -Fq "text=\"$text\"" "$xml"; then return 0; fi
    sleep 1
  done
  return 1
}

ui_tap_checkable() {
  local xml="$1" bounds x1 y1 x2 y2
  bounds="$(python3 - "$xml" <<'PY'
import re, sys
xml = open(sys.argv[1], encoding="utf-8").read()
for match in re.finditer(r'<node\b[^>]*>', xml):
    tag = match.group(0)
    if 'checkable="true"' not in tag or 'checked="false"' not in tag or 'clickable="true"' not in tag:
        continue
    found = re.search(r'\bbounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', tag)
    if found:
        print(' '.join(found.groups()))
        break
PY
  )"
  [[ -n "$bounds" ]] || return 1
  read -r x1 y1 x2 y2 <<<"$bounds"
  adb_cmd shell input tap "$(( (x1+x2) / 2 ))" "$(( (y1+y2) / 2 ))"
}

test_update() {
  assert_owned_target
  ensure_guest_network
  local apk="$(resolve_apk "${1:-${AMNEZIA_ANDROID_RELEASE_APK:-}}")"
  local expected_hash expected_code expected_version baseline_code
  expected_hash="$(artifact_hash release)"
  expected_code="$(artifact_code release)"
  expected_version="$(artifact_version release)"
  baseline_code="$(artifact_code baseline)"
  assert_sha256 "$apk" "$expected_hash"
  assert_apk_arm64_elf "$apk"
  [[ "$(package_version_code)" == "$baseline_code" ]] || die "installer scenario requires baseline versionCode $baseline_code"
  local remote_apk='candidate.apk'
  local run_dir="${ARTIFACTS_DIR}/update-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$run_dir"
  adb_cmd shell "test -f '${LAB_STATE_PATH}'" || die "baseline persistent marker is missing"
  adb_cmd push "$apk" "/sdcard/Download/${remote_apk}" >"${run_dir}/push.txt"
  # Android's Downloads UI is the caller of the real package installer, so the
  # provider grant is created by the OS rather than injected from shell.
  adb_cmd shell am start -n com.google.android.documentsui/com.android.documentsui.ViewDownloadsActivity \
    >"${run_dir}/installer-start.txt"
  wait_ui_text "$remote_apk" "${run_dir}/documents-ui.xml" 30 \
    || die "DocumentsUI did not expose the pushed candidate APK"
  # On a fresh AVD PackageInstaller asks for the normal per-source permission.
  # Follow that visible Settings flow once, then return to the installer.
  if wait_ui_text 'Settings' "${run_dir}/unknown-source-dialog.xml" 5; then
    wait_ui_present 'Allow from this source' "${run_dir}/unknown-source-settings.xml" 15 \
      || die "unknown-source Settings page did not expose its toggle"
    ui_tap_checkable "${run_dir}/unknown-source-settings.xml" \
      || die "unknown-source Settings toggle is not a clickable checkable control"
    sleep 1
    ui_dump "${run_dir}/unknown-source-enabled.xml" || die "could not verify unknown-source toggle UI"
    grep -Eq 'package="com\.google\.android\.packageinstaller"' "${run_dir}/unknown-source-enabled.xml" \
      || die "unknown-source flow did not return to PackageInstaller"
  fi
  local xml="${run_dir}/ui.xml"
  wait_ui_text 'Install' "$xml" 45 || wait_ui_text 'Update' "$xml" 5 || die "package installer Install/Update control not visible"
  ui_dump "${run_dir}/ui-after-confirm.xml" || die "could not capture installer UI"
  wait_ui_text 'Done' "${run_dir}/ui-done.xml" 90 || die "package installer did not show Done"
  local code="$(package_version_code)"
  [[ "$code" == "$expected_code" ]] || die "installer did not produce versionCode $expected_code (got $code)"
  adb_cmd shell "test -f '${LAB_STATE_PATH}'" || die "external persistent state marker was lost during update"
  adb_cmd logcat -b all -c
  adb_cmd shell monkey -p "$PACKAGE" 1 >"${run_dir}/launch.txt" 2>&1
  adb_cmd logcat -b all -d -t 2000 >"${run_dir}/logcat.txt"
  assert_native_runtime "${run_dir}/logcat.txt"
  cat >"${run_dir}/result.txt" <<EOF
scenario=system-package-installer-smoke
real_app_server_update=pending
baseline_version=$(artifact_version baseline)
release_version=$expected_version
baseline_version_code=$baseline_code
release_version_code=$expected_code
apk_abi=arm64-v8a
native_bridge_evidence=required-and-checked-in-logcat
external_state=persisted
app_private_state=unavailable-without-supported-run-as-hook
network_gate=pending
EOF
  log "system package installer smoke passed: $run_dir (app/server update remains pending)"
}

collect() {
  assert_owned_target
  local out="${ARTIFACTS_DIR}/collect-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$out"
  adb_cmd logcat -b all -d -t 5000 >"${out}/logcat.txt"
  adb_cmd shell getprop >"${out}/getprop.txt"
  adb_cmd shell dumpsys package "$PACKAGE" >"${out}/package.txt" 2>&1 || true
  ui_dump "${out}/ui.xml" || true
  adb_cmd exec-out screencap -p >"${out}/screen.png"
  capture_identity >"${out}/identity.txt"
  if [[ -n "${AMNEZIA_ANDROID_BASELINE_MANIFEST:-}" && -n "${AMNEZIA_ANDROID_RELEASE_MANIFEST:-}" ]] \
    && [[ "$(package_version_code)" == "$(artifact_code release)" ]]; then
    write_controller_receipt installer-smoke-pass-real-update-pending
  fi
  log "collected $out"
}

write_controller_receipt() {
  local status="$1" baseline_sha candidate_sha baseline_code candidate_code baseline_version candidate_version
  baseline_sha="$(artifact_hash baseline)"
  candidate_sha="$(artifact_hash release)"
  baseline_code="$(artifact_code baseline)"
  candidate_code="$(artifact_code release)"
  baseline_version="$(artifact_version baseline)"
  candidate_version="$(artifact_version release)"
  python3 - "$CONTROLLER_RECEIPT" "$status" "${RUN_ARTIFACT:-candidate.apk}" "$baseline_version" "$baseline_code" "$baseline_sha" \
    "$candidate_version" "$candidate_code" "$candidate_sha" "$RUN_ID" "$PROFILE_ID" \
    "$AVD_NAME" "$SERIAL" "$(<"$PID_FILE")" "$(<"$UUID_FILE")" \
    "$(<"${WORK_HOME}/emulator.starttime")" "$(<"$SERVER_PID_FILE")" "$(<"$SERVER_STARTTIME_FILE")" \
    "$ADB_SERVER_SOCKET" <<'PY'
import json, pathlib, sys
from datetime import datetime, timezone
out, status, artifact, bv, bc, bs, cv, cc, cs, run, profile, avd, serial, pid, uuid, starttime, server_pid, server_starttime, socket = sys.argv[1:]
path = pathlib.Path(out)
path.parent.mkdir(parents=True, exist_ok=True)
doc = {
    "schema": 1,
    "run_id": run,
    "profile": profile,
    "artifact": artifact,
    "artifact_sha256": cs,
    "baseline_version": bv,
    "candidate_version": cv,
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "origin": "guest",
    "transport": "android-adapter",
    "injected": False,
    "status": status,
    "baseline": {"version": bv, "versionCode": int(bc), "sha256": bs},
    "candidate": {"version": cv, "versionCode": int(cc), "sha256": cs},
    "device_identity": {
        "avd": avd, "serial": serial, "pid": int(pid), "qemuUuid": uuid,
        "processStarttime": int(starttime), "adbServerPid": int(server_pid),
        "adbServerStarttime": int(server_starttime), "adbSocket": socket
    },
    "network": {
        "mode": "guest-offline",
        "ipv4": "output-drop-loopback-only",
        "ipv6": "output-drop-loopback-only",
        "hostRoutesOrFirewall": False,
        "production": False
    },
    "steps": [
        {"name": "start", "status": "observed"},
        {"name": "probe", "status": "observed"},
        {"name": "baselineInstall", "status": "observed"},
        {"name": "baselineLaunchNative", "status": "observed"},
        {"name": "offlineGuestFirewall", "status": "observed"},
        {"name": "systemPackageInstallerSmoke", "status": "observed"},
        {"name": "realAppServerUpdate", "status": "pending"},
        {"name": "collect", "status": "observed"},
        {"name": "reset", "status": "controller-required"}
    ]
}
path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

run_scenario() {
  # Controller entry point: APKs and signed manifest paths are mandatory so a
  # future release cannot silently fall back to the reference 5.0.1.37/38 pair.
  [[ "$#" -eq 4 ]] || die "run requires baseline-apk candidate-apk baseline-manifest candidate-manifest"
  [[ -f "$1" && -f "$2" && -f "$3" && -f "$4" ]] || die "run inputs must be existing APK and manifest files"
  export AMNEZIA_ANDROID_BASELINE_MANIFEST="$3"
  export AMNEZIA_ANDROID_RELEASE_MANIFEST="$4"
  RUN_ARTIFACT="$(basename -- "$2")"
  manifest_artifact_field baseline sha256 >/dev/null || die "baseline manifest has no Android ARM64 SHA256"
  manifest_artifact_field baseline versionCode >/dev/null || die "baseline manifest has no Android ARM64 versionCode"
  manifest_artifact_field release sha256 >/dev/null || die "candidate manifest has no Android ARM64 SHA256"
  manifest_artifact_field release versionCode >/dev/null || die "candidate manifest has no Android ARM64 versionCode"
  probe
  install_baseline "$1"
  test_update "$2"
  collect
  write_controller_receipt installer-smoke-pass-real-update-pending
}

reset_lab() {
  setup_env
  local pid
  if pid="$(running_pid)"; then
    assert_owned_emulator_process "$pid"
    local state
    state=""
    if [[ -s "$SERVER_PID_FILE" ]]; then
      state="$(adb_cmd get-state 2>/dev/null | tr -d '\r' || true)"
    fi
    if [[ "$state" == device ]]; then
      # emu kill addresses only this explicitly owned emulator; no global ADB shutdown.
      adb_cmd emu kill >/dev/null 2>&1 || true
      if kill -0 "$pid" 2>/dev/null; then
        # The same verified PID is the fallback when the emulator console is not responsive.
        kill -TERM "$pid"
      fi
    elif [[ ! -s "$SERVER_PID_FILE" ]]; then
      # A failed server bootstrap can leave the already-verified owned QEMU alive.
      # Stop that exact PID after the host ownership checks above.
      kill -TERM "$pid"
    fi
    local deadline=$((SECONDS + 30))
    while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 1; done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid"
      deadline=$((SECONDS + 15))
      while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 1; done
    fi
    kill -0 "$pid" 2>/dev/null && die "owned emulator did not stop after verified TERM/KILL escalation"
    if [[ -s "${WORK_HOME}/emulator-launcher.pid" ]]; then
      local launcher_pid="$(<"${WORK_HOME}/emulator-launcher.pid")"
      if kill -0 "$launcher_pid" 2>/dev/null; then
        assert_owned_launcher_process "$launcher_pid"
        kill -TERM "$launcher_pid" 2>/dev/null || true
      fi
    fi
  else
    local orphan
    orphan="$(find_owned_emulator_pid "$(emulator_bin)" || true)"
    [[ -z "$orphan" ]] || die "owned emulator process exists without a valid PID marker: $orphan"
  fi
  local adb="$(adb_bin)" server_pid
  server_pid="$(find_owned_server_pid || true)"
  if [[ "$server_pid" =~ ^[0-9]+$ ]] && kill -0 "$server_pid" 2>/dev/null; then
    local server_exe server_uid server_cmdline
    server_exe="$(readlink -f "/proc/${server_pid}/exe" 2>/dev/null || true)"
    server_uid="$(stat -c '%u' "/proc/${server_pid}" 2>/dev/null || true)"
    server_cmdline="$(tr '\0' ' ' < "/proc/${server_pid}/cmdline" 2>/dev/null || true)"
    [[ "$server_exe" == "${SDK_ROOT}/platform-tools/adb" && "$server_uid" == "$(id -u)" ]] \
      || die "refusing to stop an unowned ADB server during reset"
    [[ "$server_cmdline" == *"-L tcp:"*"${ADB_SERVER_PORT}"* ]] || die "refusing ADB server with unexpected socket during reset"
    env -u ADB_SERVER_SOCKET ANDROID_ADB_SERVER_PORT="$ADB_SERVER_PORT" "$adb" kill-server >/dev/null 2>&1 || true
    local deadline=$((SECONDS + 15))
    while kill -0 "$server_pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 1; done
    kill -0 "$server_pid" 2>/dev/null && die "owned ADB server did not stop"
  fi
  rm -f -- "$PID_FILE" "$UUID_FILE" "$SERIAL_FILE"
  rm -f -- "${AVD_HOME}/${AVD_NAME}.ini" "${AVD_HOME}/${AVD_NAME}.lab-profile" \
    "${WORK_HOME}/avd-identity.nonce" "${WORK_HOME}/network-gate.ok" \
    "${WORK_HOME}/offline-boot.json" "${WORK_HOME}/emulator.starttime" \
    "${WORK_HOME}/emulator-launcher.pid" \
    "${SERVER_PID_FILE}" "${SERVER_STARTTIME_FILE}"
  rm -rf -- "${AVD_HOME}/${AVD_NAME}.avd"
  log "reset completed for owned AVD userdata and metadata; global ADB and host networking were untouched"
}

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") <prepare|doctor|create|start|probe|network-gate|fixture-network|install-baseline|test-update|collect|reset> [apk]
       $(basename "$0") run baseline.apk candidate.apk baseline-manifest.json candidate-manifest.json
Environment: AMNEZIA_ANDROID_LAB_ROOT, AMNEZIA_ANDROID_AVD_NAME, AMNEZIA_ANDROID_API_LEVEL,
             AMNEZIA_ANDROID_ADB_PORT, AMNEZIA_ANDROID_SERIAL, AMNEZIA_ANDROID_EMULATOR_PORT
EOF
}

main() {
  local command="${1:-}"
  case "$command" in
    prepare) prepare ;;
    doctor) doctor ;;
    create) create_avd ;;
    start) start_emulator ;;
    probe) probe ;;
    network-gate) verify_network_gate ;;
    fixture-network) enable_consumer_fixture_network "${2:-}" ;;
    install-baseline) install_baseline "${2:-}" ;;
    test-update) test_update "${2:-}" ;;
    run) run_scenario "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
    collect) collect ;;
    reset) reset_lab ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
