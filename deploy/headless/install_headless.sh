#!/usr/bin/env bash
set -euo pipefail

# User-invoked provisioning flow for a freshly installed Ubuntu headless
# client.  The update tar remains binary-only; this script is deliberately a
# separate package step and never publishes or fetches release artifacts.
PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLIC_KEY="${1:-}"
EXPECTED_KEY_SHA256="${2:-${AMNEZIA_HEADLESS_UPDATE_PUBLIC_KEY_SHA256:-}}"
MODE="${3:-fresh}"
EXPECTED_MANIFEST_SHA256="${4:-${AMNEZIA_HEADLESS_PACKAGE_MANIFEST_SHA256:-}}"
EXPECTED_CHECKSUMS_SHA256="${5:-${AMNEZIA_HEADLESS_PACKAGE_CHECKSUMS_SHA256:-}}"
VERIFIED_RECEIPT="${6:-${AMNEZIA_HEADLESS_VERIFIED_RECEIPT:-}}"
if [[ -z "$PUBLIC_KEY" || ! -f "$PUBLIC_KEY" || ! "$EXPECTED_KEY_SHA256" =~ ^[[:xdigit:]]{64}$ \
    || ! "$EXPECTED_MANIFEST_SHA256" =~ ^[[:xdigit:]]{64}$ \
    || ! "$EXPECTED_CHECKSUMS_SHA256" =~ ^[[:xdigit:]]{64}$ \
    || -z "$VERIFIED_RECEIPT" || ! -f "$VERIFIED_RECEIPT" || -L "$VERIFIED_RECEIPT" \
    || ("$MODE" != "fresh" && "$MODE" != "upgrade") ]]; then
    echo "usage: $0 /path/to/update-public-key.pem expected-key-sha256 [fresh|upgrade] expected-package-manifest-sha256 expected-checksums-sha256 verified-receipt.json" >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "run this provisioning step as root" >&2
    exit 2
fi
if [[ "$(sha256sum "$PACKAGE_ROOT/package-manifest.json" | awk '{print tolower($1)}')" != "${EXPECTED_MANIFEST_SHA256,,}" ]]; then
    echo "package manifest fingerprint does not match the trusted release receipt" >&2
    exit 3
fi
if [[ "$(sha256sum "$PACKAGE_ROOT/SHA256SUMS" | awk '{print tolower($1)}')" != "${EXPECTED_CHECKSUMS_SHA256,,}" ]]; then
    echo "package checksums fingerprint does not match the trusted release receipt" >&2
    exit 3
fi
for required in python3 sha256sum awk openssl readelf readlink groupdel id; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "required bootstrap command is missing: $required" >&2
        exit 3
    fi
done
if [[ ! -r /etc/os-release ]]; then
    echo "Ubuntu release metadata is unavailable" >&2
    exit 3
fi
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" || -z "${VERSION_ID:-}" || -z "${VERSION_CODENAME:-}" ]]; then
    echo "headless provisioning requires supported Ubuntu metadata with VERSION_CODENAME" >&2
    exit 3
fi
SERVICE_PATH=""
SERVICE_COUNT=0
for candidate in /etc/systemd/system/amneziad.service /lib/systemd/system/amneziad.service; do
    if [[ -e "$candidate" || -L "$candidate" ]]; then
        if [[ -L "$candidate" && "$(readlink -f -- "$candidate" 2>/dev/null || true)" != "/dev/null" ]]; then
            echo "ambiguous installation identity: service is not a regular file: $candidate" >&2
            exit 4
        fi
        SERVICE_PATH="$candidate"
        SERVICE_COUNT=$((SERVICE_COUNT + 1))
    fi
done
if [[ "$SERVICE_COUNT" -gt 1 ]]; then
    # Refuse when the service exists in both /etc and /lib: the installation
    # identity is ambiguous and must be repaired by the operator first.
    echo "ambiguous installation: service unit exists in both /etc and /lib" >&2
    exit 4
fi
EXISTING_COMPONENTS="$SERVICE_COUNT"
for candidate in /usr/local/bin/amneziad /usr/local/bin/amnezia-cli /etc/amnezia/update-public-key.pem; do
    if [[ -e "$candidate" || -L "$candidate" ]]; then
        if [[ ! -f "$candidate" || -L "$candidate" ]]; then echo "ambiguous installation identity: non-regular component $candidate" >&2; exit 4; fi
        EXISTING_COMPONENTS=$((EXISTING_COMPONENTS + 1))
    fi
done
if [[ "$MODE" == "fresh" && "$EXISTING_COMPONENTS" -ne 0 ]]; then
    echo "a partial or complete installation already exists; pass 'upgrade' explicitly" >&2
    exit 4
fi
if [[ "$MODE" == "upgrade" && "$EXISTING_COMPONENTS" -ne 4 ]]; then
    echo "upgrade requires exactly one complete installation identity; partial or ambiguous state found" >&2
    exit 4
fi
SERVICE_TARGET="${SERVICE_PATH:-/etc/systemd/system/amneziad.service}"
if ! PACKAGE_VERSION="$(python3 - "$PACKAGE_ROOT" "$VERSION_ID" "$VERSION_CODENAME" <<'PY'
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
version_id, codename = sys.argv[2:4]
version_re = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
def load(name):
    path = root / name
    if not path.is_file() or path.is_symlink(): raise SystemExit(f"missing regular package file: {name}")
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error: raise SystemExit(f"invalid JSON package file: {name}") from error
manifest = load("package-manifest.json")
if set(manifest) != {"schema","version","platform","installModes","artifacts","service","servicePaths","trustAnchor","runtimeManifest","checksums","runtimeText"} or manifest["schema"] != 2 or not version_re.fullmatch(manifest["version"]): raise SystemExit("invalid package-manifest.json")
if manifest["platform"] != "linux-headless-x64" or manifest["installModes"] != ["fresh","upgrade"] or manifest["artifacts"] != ["amneziad","amnezia-cli","amneziad.service"] or manifest["servicePaths"] != ["/etc/systemd/system/amneziad.service","/lib/systemd/system/amneziad.service"]: raise SystemExit("invalid package artifact/service contract")
if manifest["service"] != "amneziad.service" or manifest["trustAnchor"] != "external-ed25519-sha256-receipt" or manifest["runtimeManifest"] != "runtime-dependencies.json" or manifest["checksums"] != "SHA256SUMS" or manifest["runtimeText"] != "runtime-dependencies.txt": raise SystemExit("invalid package references")
for name in ("install_headless.sh","amneziad","amnezia-cli","amneziad.service","package-manifest.json","runtime-dependencies.json","runtime-dependencies.txt","SHA256SUMS"):
    if not (root / name).is_file() or (root / name).is_symlink(): raise SystemExit(f"missing package member: {name}")
runtime = load("runtime-dependencies.json")
if set(runtime) != {"schema","distribution","architectures","releases","commands"} or runtime["schema"] != 2 or runtime["distribution"] != "ubuntu" or runtime["architectures"] != ["amd64"]: raise SystemExit("invalid runtime host contract")
release = next((item for item in runtime["releases"] if item.get("versionId") == version_id and codename in item.get("codenames", [])), None)
if not isinstance(release, dict): raise SystemExit(f"unsupported Ubuntu release/codename: {version_id}/{codename}")
commands = runtime["commands"]
if set(commands) != {"required","backendModes"} or not all(isinstance(x, str) and x for x in commands["required"]): raise SystemExit("invalid runtime command contract")
if not commands["backendModes"] or any(set(mode) != {"mode","alternatives"} or not isinstance(mode["mode"], str) or not mode["mode"] or not mode["alternatives"] or any(not isinstance(x, str) or not x for x in mode["alternatives"]) for mode in commands["backendModes"]): raise SystemExit("invalid backend mode contract")
for name in commands["required"]:
    if shutil.which(name) is None: raise SystemExit(f"required runtime command is missing: {name}")
if not any(any(shutil.which(name) for name in mode["alternatives"]) for mode in commands["backendModes"]): raise SystemExit("no declared VPN backend mode is installed")
for package in release["packages"]:
    if set(package) != {"alternatives","minimum","reason"} or not package["alternatives"] or not package["minimum"] or not package["reason"]:
        raise SystemExit("invalid runtime package entry")
    satisfied = False
    for name in package["alternatives"]:
        result = subprocess.run(["dpkg-query","-W",f"-f=${{Status}}\t${{Version}}",name], text=True, capture_output=True)
        if result.returncode == 0 and result.stdout.startswith("install ok installed\t") and subprocess.run(["dpkg","--compare-versions",result.stdout.split("\t",1)[1].strip(),"ge",package["minimum"]]).returncode == 0:
            satisfied = True; break
    if not satisfied: raise SystemExit("runtime dependency alternatives are not satisfied")
if subprocess.run(["dpkg","--print-architecture"], capture_output=True, text=True).stdout.strip() != "amd64": raise SystemExit("headless provisioning requires amd64")
print(manifest["version"])
PY
)"; then
    echo "strict provisioning metadata validation failed" >&2
    exit 3
fi
if ! (cd "$PACKAGE_ROOT" && sha256sum --strict --check SHA256SUMS); then
    echo "provisioning bundle integrity check failed" >&2
    exit 3
fi
if ! python3 - "$VERIFIED_RECEIPT" "$PACKAGE_ROOT" "$PUBLIC_KEY" "$EXPECTED_KEY_SHA256" "$EXPECTED_MANIFEST_SHA256" "$EXPECTED_CHECKSUMS_SHA256" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path
receipt_path, root_text, public_key_text, expected_key, expected_manifest, expected_checksums = sys.argv[1:]
root = Path(root_text)
expected_files = ["install_headless.sh", "amneziad", "amnezia-cli", "amneziad.service",
                  "package-manifest.json", "runtime-dependencies.json",
                  "runtime-dependencies.txt", "SHA256SUMS"]
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
receipt_file = Path(receipt_path)
if not receipt_file.is_file() or receipt_file.is_symlink(): raise SystemExit("verified receipt must be regular")
receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
required = {"schema","tool","verified","manifestSha256","publicKeySha256","archiveSha256","archiveSize",
            "version","packageVersion","packageFiles","packageManifestSha256","checksumsSha256"}
if set(receipt) != required or receipt["schema"] != 1 or receipt["tool"] != "amnezia-verify-provisioning-v1" or receipt["verified"] is not True: raise SystemExit("receipt is not trusted")
for key in ("manifestSha256", "publicKeySha256", "archiveSha256", "packageManifestSha256", "checksumsSha256"):
    if not isinstance(receipt[key], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt[key]): raise SystemExit("receipt digest is not canonical")
if receipt["publicKeySha256"] != expected_key.lower() or digest(Path(public_key_text)) != expected_key.lower() or not isinstance(receipt["archiveSize"], int) or receipt["archiveSize"] <= 0: raise SystemExit("receipt trust anchor or archive identity is invalid")
if receipt["packageFiles"] != expected_files or receipt["packageVersion"] != receipt["version"]: raise SystemExit("receipt package identity is not exact")
if receipt["packageManifestSha256"] != expected_manifest or receipt["checksumsSha256"] != expected_checksums: raise SystemExit("receipt inner hashes do not match trusted arguments")
if digest(root / "package-manifest.json") != expected_manifest or digest(root / "SHA256SUMS") != expected_checksums: raise SystemExit("package does not match verified receipt")
manifest = json.loads((root / "package-manifest.json").read_text(encoding="utf-8"))
if manifest.get("version") != receipt["version"] or manifest.get("artifacts") != ["amneziad", "amnezia-cli", "amneziad.service"]: raise SystemExit("package version/artifacts do not match receipt")
for name in expected_files:
    if not (root / name).is_file() or (root / name).is_symlink(): raise SystemExit("package member is not a regular file")
PY
then
    echo "verified provisioning receipt is missing or does not match this package" >&2
    exit 3
fi
if ! openssl pkey -pubin -in "$PUBLIC_KEY" -text -noout 2>/dev/null | grep -qi 'ED25519'; then
    echo "public key is not a readable Ed25519 PEM public key" >&2
    exit 3
fi
if [[ "$(sha256sum "$PUBLIC_KEY" | awk '{print tolower($1)}')" != "${EXPECTED_KEY_SHA256,,}" ]]; then
    echo "supplied trust anchor fingerprint does not match the expected receipt" >&2
    exit 3
fi
for binary in amneziad amnezia-cli; do
    if ! python3 - "$PACKAGE_ROOT/$binary" <<'PY'
import struct
import sys
from pathlib import Path
data = Path(sys.argv[1]).read_bytes()[:20]
if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] not in (1,2): raise SystemExit("not ELF64")
machine = struct.unpack("<H" if data[5] == 1 else ">H", data[18:20])[0]
if machine != 62: raise SystemExit("not x86_64")
PY
    then echo "headless binary is not an x86_64 ELF64 executable: $binary" >&2; exit 3; fi
    if ! elf_header="$(readelf -h "$PACKAGE_ROOT/$binary" 2>/dev/null)" \
        || ! grep -q 'Class:[[:space:]]*ELF64' <<< "$elf_header" \
        || ! grep -q 'Machine:[[:space:]]*Advanced Micro Devices X86-64' <<< "$elf_header"; then
        echo "static readelf validation failed for authenticated headless binary: $binary" >&2
        exit 3
    fi
    if ! ldd_output="$(ldd "$PACKAGE_ROOT/$binary" 2>&1)"; then echo "ldd failed for headless binary: $binary" >&2; exit 3; fi
    if grep -q 'not found' <<< "$ldd_output"; then echo "unresolved shared-library dependency: $binary" >&2; exit 3; fi
    if ! version_output="$("$PACKAGE_ROOT/$binary" --version 2>&1)" \
        || ! grep -Fq "$PACKAGE_VERSION" <<< "$version_output"; then
        echo "authenticated headless binary version does not match package version: $binary" >&2
        exit 3
    fi
done
if [[ "$MODE" == "fresh" ]]; then SERVICE_PATH=/etc/systemd/system/amneziad.service; fi
SERVICE_WAS_ACTIVE=""
SERVICE_WAS_ENABLED=""
if [[ "$MODE" == "upgrade" ]]; then
    SERVICE_WAS_ENABLED="$(systemctl is-enabled amneziad.service 2>/dev/null || true)"
    SERVICE_WAS_ACTIVE="$(systemctl is-active amneziad.service 2>/dev/null || true)"
    case "$SERVICE_WAS_ENABLED" in
        enabled|disabled|static|indirect|linked|linked-runtime|generated|transient|masked) ;;
        *) echo "ambiguous systemd enabled state: ${SERVICE_WAS_ENABLED:-empty}" >&2; exit 4 ;;
    esac
    case "$SERVICE_WAS_ACTIVE" in
        active|inactive|failed) ;;
        *) echo "ambiguous systemd runtime state: ${SERVICE_WAS_ACTIVE:-empty}" >&2; exit 4 ;;
    esac
fi
BACKUP_DIR=""
INSTALL_OK=0
BACKUP_DIR="$(mktemp -d /var/lib/amnezia-headless-transaction.XXXXXX)"
backup_file() {
    local item="$1" name="$2"
    if [[ -e "$item" || -L "$item" ]]; then
        if [[ -L "$item" ]]; then
            if [[ "$name" != "amneziad.service" || "$(readlink -f -- "$item" 2>/dev/null || true)" != "/dev/null" ]]; then
                echo "existing installation component is not a regular file: $item" >&2
                return 1
            fi
        elif [[ ! -f "$item" ]]; then
            echo "existing installation component is not a regular file: $item" >&2
            return 1
        fi
        cp -a -- "$item" "$BACKUP_DIR/$name"
    else
        touch "$BACKUP_DIR/.missing-$name"
    fi
}
backup_file /usr/local/bin/amneziad amneziad
backup_file /usr/local/bin/amnezia-cli amnezia-cli
backup_file "$SERVICE_TARGET" amneziad.service
backup_file /etc/amnezia/update-public-key.pem update-public-key.pem

restore_file() {
    local target="$1" name="$2"
    if [[ -f "$BACKUP_DIR/.missing-$name" ]]; then
        if [[ -e "$target" || -L "$target" ]]; then rm -f -- "$target" || return 1; fi
        return 0
    fi
    rm -f -- "$target" && cp -a -- "$BACKUP_DIR/$name" "$target" && cmp -s "$BACKUP_DIR/$name" "$target"
}

verify_active_health() {
    [[ -S /run/amnezia/amneziad.sock ]] && /usr/local/bin/amnezia-cli --socket /run/amnezia/amneziad.sock doctor --json >/dev/null
}

rollback_upgrade() {
    if [[ "$INSTALL_OK" -eq 1 ]]; then return 0; fi
    set +e
    local rollback_ok=1
    if systemctl is-active --quiet amneziad.service 2>/dev/null; then systemctl stop amneziad.service >/dev/null 2>&1 || rollback_ok=0; fi
    if [[ "$MODE" == "upgrade" ]]; then
        restore_file /usr/local/bin/amneziad amneziad || rollback_ok=0
        restore_file /usr/local/bin/amnezia-cli amnezia-cli || rollback_ok=0
        restore_file "$SERVICE_TARGET" amneziad.service || rollback_ok=0
        restore_file /etc/amnezia/update-public-key.pem update-public-key.pem || rollback_ok=0
    else
        if [[ -e "$SERVICE_TARGET" || -L "$SERVICE_TARGET" ]]; then
            systemctl disable amneziad.service >/dev/null 2>&1 || rollback_ok=0
        fi
        rm -f -- /usr/local/bin/amneziad || rollback_ok=0
        rm -f -- /usr/local/bin/amnezia-cli || rollback_ok=0
        rm -f -- "$SERVICE_TARGET" || rollback_ok=0
        rm -f -- /etc/amnezia/update-public-key.pem || rollback_ok=0
        if [[ "${GROUP_CREATED:-0}" -eq 1 ]] && getent group amnezia >/dev/null 2>&1; then
            groupdel --system amnezia >/dev/null 2>&1 || rollback_ok=0
        fi
    fi
    systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
    if [[ "$MODE" == "upgrade" ]]; then
        case "$SERVICE_WAS_ENABLED" in
            masked) systemctl mask amneziad.service >/dev/null 2>&1 || rollback_ok=0 ;;
            enabled) systemctl enable amneziad.service >/dev/null 2>&1 || rollback_ok=0 ;;
            disabled) systemctl disable amneziad.service >/dev/null 2>&1 || rollback_ok=0 ;;
            static|indirect|linked|linked-runtime|generated|transient) ;;
            *) rollback_ok=0 ;;
        esac
        if [[ "$SERVICE_WAS_ACTIVE" == "active" ]]; then
            systemctl start amneziad.service >/dev/null 2>&1 || rollback_ok=0
        elif [[ "$SERVICE_WAS_ACTIVE" == "inactive" ]]; then
            if systemctl is-active --quiet amneziad.service 2>/dev/null; then systemctl stop amneziad.service >/dev/null 2>&1 || rollback_ok=0; fi
        elif ! systemctl is-failed --quiet amneziad.service 2>/dev/null; then
            rollback_ok=0
        fi
        current_enabled="$(systemctl is-enabled amneziad.service 2>/dev/null || true)"
        current_active="$(systemctl is-active amneziad.service 2>/dev/null || true)"
        [[ "$current_enabled" == "$SERVICE_WAS_ENABLED" && "$current_active" == "$SERVICE_WAS_ACTIVE" ]] || rollback_ok=0
        if [[ "$SERVICE_WAS_ACTIVE" == "active" ]]; then verify_active_health || rollback_ok=0; fi
    elif systemctl is-active --quiet amneziad.service 2>/dev/null; then
        rollback_ok=0
    fi
    if [[ "$rollback_ok" -ne 1 ]]; then
        marker_ok=1
        install -d -m 0750 /var/lib/amnezia || marker_ok=0
        printf '%s\n' "provisioning rollback failed; manual recovery is required" > /var/lib/amnezia/headless-recovery-required || marker_ok=0
        chmod 0600 /var/lib/amnezia/headless-recovery-required || marker_ok=0
        if [[ "$marker_ok" -ne 1 ]]; then echo "durable provisioning recovery marker could not be written" >&2; fi
        echo "headless provisioning rollback failed; manual recovery is required (backup: $BACKUP_DIR)" >&2
        return 1
    fi
    if ! rm -rf -- "$BACKUP_DIR"; then
        echo "headless provisioning rollback completed but backup cleanup failed: $BACKUP_DIR" >&2
        return 1
    fi
    echo "headless provisioning failed; previous installation was restored" >&2
    return 0
}
on_exit() {
    local status=$?
    trap - EXIT
    if [[ "$INSTALL_OK" -ne 1 ]]; then rollback_upgrade || status=5; fi
    exit "$status"
}
trap on_exit EXIT

GROUP_CREATED=0
if ! getent group amnezia >/dev/null 2>&1; then
    groupadd --system amnezia
    GROUP_CREATED=1
fi
if [[ "$MODE" == "upgrade" && "$SERVICE_WAS_ENABLED" == "masked" ]]; then
    systemctl unmask amneziad.service
fi
if [[ "$MODE" == "upgrade" && "$SERVICE_WAS_ACTIVE" == "active" ]]; then
    systemctl stop amneziad.service
fi
install -d -o root -g root -m 0755 /usr/local/bin
install -d -o root -g amnezia -m 0750 /var/lib/amnezia /run/amnezia /etc/amnezia/profiles
install -o root -g root -m 0755 "$PACKAGE_ROOT/amneziad" /usr/local/bin/amneziad
install -o root -g root -m 0755 "$PACKAGE_ROOT/amnezia-cli" /usr/local/bin/amnezia-cli
install -D -o root -g root -m 0644 "$PACKAGE_ROOT/amneziad.service" "$SERVICE_TARGET"
install -o root -g root -m 0644 "$PUBLIC_KEY" /etc/amnezia/update-public-key.pem
chown root:amnezia /etc/amnezia/update-public-key.pem
chmod 0640 /etc/amnezia/update-public-key.pem
systemctl daemon-reload
if [[ "$MODE" == "fresh" ]]; then
    systemctl enable --now amneziad.service
elif [[ "$SERVICE_WAS_ENABLED" == "masked" ]]; then
    systemctl mask amneziad.service
elif [[ "$SERVICE_WAS_ENABLED" == "enabled" ]]; then
    systemctl enable amneziad.service
elif [[ "$SERVICE_WAS_ENABLED" == "disabled" ]]; then
    systemctl disable amneziad.service
fi
if [[ "$MODE" == "upgrade" ]]; then
    if [[ "$SERVICE_WAS_ACTIVE" == "active" ]]; then
        systemctl start amneziad.service
    elif [[ "$SERVICE_WAS_ACTIVE" == "inactive" ]]; then
        if systemctl is-active --quiet amneziad.service 2>/dev/null; then systemctl stop amneziad.service; fi
    elif ! systemctl is-failed --quiet amneziad.service; then
        echo "failed service state was not preserved" >&2
        exit 4
    fi
fi
current_enabled="$(systemctl is-enabled amneziad.service 2>/dev/null || true)"
current_active="$(systemctl is-active amneziad.service 2>/dev/null || true)"
if [[ "$MODE" == "fresh" ]]; then
    if [[ "$current_active" != "active" ]]; then echo "amneziad.service did not become active" >&2; exit 4; fi
elif [[ "$current_enabled" != "$SERVICE_WAS_ENABLED" || "$current_active" != "$SERVICE_WAS_ACTIVE" ]]; then
    echo "systemd enabled/active state was not preserved" >&2
    exit 4
fi
if [[ "$current_active" == "active" ]] && ! verify_active_health; then
    echo "headless daemon health check failed" >&2
    exit 4
fi
INSTALL_OK=1
if [[ -n "$BACKUP_DIR" ]]; then
    if ! rm -rf -- "$BACKUP_DIR"; then
        echo "installation completed but transaction backup cleanup failed: $BACKUP_DIR" >&2
        exit 5
    fi
fi
echo "headless provisioning complete: service, trust anchor and state directories installed"
