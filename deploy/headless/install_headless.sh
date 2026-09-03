#!/usr/bin/env bash
set -euo pipefail

# User-invoked provisioning flow for a freshly installed Ubuntu headless
# client.  The update tar remains binary-only; this script is deliberately a
# separate package step and never publishes or fetches release artifacts.
export LC_ALL=C
SOURCE_PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$SOURCE_PACKAGE_ROOT"
RECOVER_ONLY=0
if [[ "${1:-}" == "--recover" ]]; then
    RECOVER_ONLY=1
    shift
fi
PUBLIC_KEY="${1:-}"
EXPECTED_KEY_SHA256="${2:-${AMNEZIA_HEADLESS_UPDATE_PUBLIC_KEY_SHA256:-}}"
MODE="${3:-fresh}"
EXPECTED_MANIFEST_SHA256="${4:-${AMNEZIA_HEADLESS_PACKAGE_MANIFEST_SHA256:-}}"
EXPECTED_CHECKSUMS_SHA256="${5:-${AMNEZIA_HEADLESS_PACKAGE_CHECKSUMS_SHA256:-}}"
EXPECTED_SIGNED_MANIFEST_SHA256="${6:-${AMNEZIA_HEADLESS_SIGNED_MANIFEST_SHA256:-}}"
VERIFIED_RECEIPT="${7:-${AMNEZIA_HEADLESS_VERIFIED_RECEIPT:-}}"
if [[ "$RECOVER_ONLY" -eq 0 && ( -z "$PUBLIC_KEY" || -L "$PUBLIC_KEY" || ! -f "$PUBLIC_KEY" || ! "$EXPECTED_KEY_SHA256" =~ ^[[:xdigit:]]{64}$ \
    || ! "$EXPECTED_MANIFEST_SHA256" =~ ^[[:xdigit:]]{64}$ \
    || ! "$EXPECTED_CHECKSUMS_SHA256" =~ ^[[:xdigit:]]{64}$ \
    || ! "$EXPECTED_SIGNED_MANIFEST_SHA256" =~ ^[[:xdigit:]]{64}$ \
    || -z "$VERIFIED_RECEIPT" || ! -f "$VERIFIED_RECEIPT" || -L "$VERIFIED_RECEIPT" \
    || ("$MODE" != "fresh" && "$MODE" != "upgrade") ) ]]; then
    echo "usage: $0 /path/to/update-public-key.pem expected-key-sha256 [fresh|upgrade] expected-package-manifest-sha256 expected-checksums-sha256 expected-signed-manifest-sha256 verified-receipt.json" >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "run this provisioning step as root" >&2
    exit 2
fi
for required in python3 sha256sum awk openssl readelf readlink groupdel groupadd getent stat cmp mktemp id install flock cp touch rm rmdir mv chown chmod grep ldd dpkg dpkg-query systemctl dirname; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "required bootstrap command is missing: $required" >&2
        exit 3
    fi
done
TRANSACTION_ROOT="/var/lib/amnezia"
TRANSACTION_BASE="$TRANSACTION_ROOT/.headless-provisioning-transactions"
TRANSACTION_JOURNAL="$TRANSACTION_ROOT/.headless-provisioning-journal.json"
# Durable hard gate: the literal headless-recovery-required marker remains
# until an operator completes a verified recovery transaction.
RECOVERY_MARKER="$TRANSACTION_ROOT/.headless-provisioning-recovery-required"
 # The updater uses the same durable lock pathname.  Holding it with flock
 # makes provisioning and an in-process update mutually exclusive; never
 # install over binaries while the daemon owns the update transaction.
TRANSACTION_LOCK_PATH="$TRANSACTION_ROOT/updates/update.lock"
install -d -o root -g root -m 0755 /var/lib
if [[ -e "$TRANSACTION_ROOT" || -L "$TRANSACTION_ROOT" ]]; then
    if [[ -L "$TRANSACTION_ROOT" || ! -d "$TRANSACTION_ROOT" ]]; then
        echo "headless transaction root is not a regular directory" >&2
        exit 4
    fi
else
    install -d -o root -g root -m 0700 "$TRANSACTION_ROOT"
fi
install -d -o root -g root -m 0700 "$TRANSACTION_ROOT/updates"
if [[ -L "$TRANSACTION_LOCK_PATH" || -d "$TRANSACTION_LOCK_PATH" ]]; then
    echo "headless provisioning lock path is not a regular file" >&2
    exit 4
fi
if [[ -e "$TRANSACTION_LOCK_PATH" ]]; then
    echo "another headless update or provisioning transaction is already running" >&2
    exit 4
fi
# QLockFile uses this same path in amneziad.  Atomic no-clobber creation is
# required here; flock alone would not coordinate with Qt's lock-file
# protocol and a redirection could truncate an updater's lock identity.
set -o noclobber
if ! exec 9>"$TRANSACTION_LOCK_PATH"; then
    set +o noclobber
    echo "another headless update or provisioning transaction is already running" >&2
    exit 4
fi
set +o noclobber
chown root:root "$TRANSACTION_LOCK_PATH"
chmod 0600 "$TRANSACTION_LOCK_PATH"
if ! flock -n 9; then
    echo "another headless provisioning transaction is already running" >&2
    exit 4
fi
# Cover validation failures and --recover exits before the transaction trap is
# installed.  The descriptor remains open until shell exit, so this exact
# unlink cannot race another owner acquiring the path.
trap 'if [[ -e "$TRANSACTION_LOCK_PATH" && ! -L "$TRANSACTION_LOCK_PATH" ]]; then rm -f -- "$TRANSACTION_LOCK_PATH"; fi' EXIT
if [[ "$RECOVER_ONLY" -eq 1 && "$#" -ne 0 ]]; then
    echo "usage: $0 --recover" >&2
    exit 2
fi
if [[ "$RECOVER_ONLY" -eq 0 && ( -e "$RECOVERY_MARKER" || -L "$RECOVERY_MARKER" ) ]]; then
    echo "headless provisioning recovery marker exists; run '$0 --recover' before a new transaction" >&2
    exit 5
fi
verify_transaction_root() {
    local mode mode_bits
    [[ -d "$TRANSACTION_ROOT" && ! -L "$TRANSACTION_ROOT" ]] || return 1
    [[ "$(stat -c '%u' -- "$TRANSACTION_ROOT" 2>/dev/null || true)" == "0" ]] || return 1
    mode="$(stat -c '%a' -- "$TRANSACTION_ROOT" 2>/dev/null || true)"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    mode_bits=$((0$mode))
    (( mode_bits & 0022 )) && return 1
}
fsync_path_directory() {
    python3 - "$1" <<'PY'
import os
import sys
path = sys.argv[1]
fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}
fsync_regular_path() {
    python3 - "$1" <<'PY'
import os
import sys
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}
mark_recovery_required() {
    local temporary
    temporary="$(mktemp "$TRANSACTION_ROOT/.headless-provisioning-recovery-required.XXXXXX")" || return 1
    printf '%s\n' 'headless provisioning recovery is required' > "$temporary" || { rm -f -- "$temporary"; return 1; }
    chown root:root "$temporary" && chmod 0600 "$temporary" || { rm -f -- "$temporary"; return 1; }
    mv -f -- "$temporary" "$RECOVERY_MARKER" || { rm -f -- "$temporary"; return 1; }
    fsync_path_directory "$TRANSACTION_ROOT"
}
clear_recovery_required() {
    if [[ -e "$RECOVERY_MARKER" || -L "$RECOVERY_MARKER" ]]; then
        [[ ! -L "$RECOVERY_MARKER" && -f "$RECOVERY_MARKER" ]] || return 1
        rm -f -- "$RECOVERY_MARKER" || return 1
        fsync_path_directory "$TRANSACTION_ROOT"
    fi
}
write_transaction_journal() {
    local phase="$1"
    python3 - "$TRANSACTION_JOURNAL" "$phase" "${MODE:-}" "${BACKUP_DIR:-}" \
        "${SERVICE_TARGET:-/etc/systemd/system/amneziad.service}" \
        "${SERVICE_WAS_ENABLED:-not-found}" "${SERVICE_WAS_ACTIVE:-inactive}" \
        "${GROUP_WAS_PRESENT:-false}" "${GROUP_CREATED:-false}" <<'PY'
import hashlib
import os
import json
import stat
import sys
import tempfile
from pathlib import Path

target = Path(sys.argv[1])
phase, mode, backup_dir, service_target, service_enabled, service_active, group_present, group_created = sys.argv[2:]
payload = {
    "schema": 1,
    "phase": phase,
    "mode": mode,
    "backupDir": backup_dir,
    "serviceTarget": service_target,
    "serviceEnabled": service_enabled,
    "serviceActive": service_active,
    "groupPresent": group_present == "true",
    "groupCreated": group_created == "true",
}
managed_names = ("amneziad", "amnezia-cli", "amneziad.service", "update-public-key.pem")
backup_files = {}
for name in managed_names:
    item = target.parent / Path(backup_dir).name / name if backup_dir else None
    missing = target.parent / Path(backup_dir).name / (".missing-" + name) if backup_dir else None
    if item is not None and item.is_file() and not item.is_symlink():
        digest = hashlib.sha256(item.read_bytes()).hexdigest()
        stat_result = item.stat()
        backup_files[name] = {
            "present": True,
            "kind": "regular",
            "sha256": digest,
            "size": stat_result.st_size,
            "mode": stat.S_IMODE(stat_result.st_mode),
            "owner": stat_result.st_uid,
            "group": stat_result.st_gid,
        }
    elif item is not None and item.is_symlink():
        stat_result = item.lstat()
        backup_files[name] = {
            "present": True,
            "kind": "symlink",
            "target": os.readlink(item),
            "sha256": "",
            "size": 0,
            "mode": stat.S_IMODE(stat_result.st_mode),
            "owner": stat_result.st_uid,
            "group": stat_result.st_gid,
        }
    elif missing is not None and missing.is_file() and not missing.is_symlink():
        stat_result = missing.stat()
        backup_files[name] = {
            "present": False,
            "kind": "missing",
            "sha256": "",
            "size": 0,
            "mode": stat.S_IMODE(stat_result.st_mode),
            "owner": stat_result.st_uid,
            "group": stat_result.st_gid,
        }
payload["backupFiles"] = backup_files
target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
temporary_fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
os.close(temporary_fd)
temporary = Path(temporary_name)
try:
    with temporary.open("wb") as stream:
        data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
    descriptor = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
finally:
    temporary.unlink(missing_ok=True)
PY
}
restore_transaction_file() {
    local target="$1" name="$2" backup_dir="$3"
    if [[ -f "$backup_dir/.missing-$name" ]]; then
        if [[ -e "$target" || -L "$target" ]]; then
            [[ ! -d "$target" || -L "$target" ]] || return 1
            rm -f -- "$target" || return 1
        fi
        return 0
    fi
    [[ -f "$backup_dir/$name" || -L "$backup_dir/$name" ]] || return 1
    if [[ -e "$target" || -L "$target" ]]; then
        [[ ! -d "$target" || -L "$target" ]] || return 1
        rm -f -- "$target" || return 1
    fi
    cp -a -- "$backup_dir/$name" "$target" || return 1
    if [[ -f "$backup_dir/$name" ]]; then
        cmp -s "$backup_dir/$name" "$target" || return 1
    else
        [[ -L "$target" && "$(readlink -f -- "$target" 2>/dev/null || true)" == "/dev/null" ]] || return 1
    fi
}
verify_recovery_backup() {
    local backup_dir="$1" backup_entry backup_mode backup_mode_bits
    [[ -d "$backup_dir" && ! -L "$backup_dir" ]] || return 1
    [[ "$(stat -c '%u' -- "$backup_dir" 2>/dev/null || true)" == "0" ]] || return 1
    [[ "$(stat -c '%a' -- "$backup_dir" 2>/dev/null || true)" == "700" ]] || return 1
    for name in amneziad amnezia-cli amneziad.service update-public-key.pem; do
        if [[ ! -f "$backup_dir/$name" && ! -L "$backup_dir/$name" && ! -f "$backup_dir/.missing-$name" ]]; then
            return 1
        fi
        backup_entry="$backup_dir/$name"
        if [[ -f "$backup_dir/.missing-$name" ]]; then backup_entry="$backup_dir/.missing-$name"; fi
        [[ "$(stat -c '%u' -- "$backup_entry" 2>/dev/null || true)" == "0" ]] || return 1
        if [[ -L "$backup_dir/$name" ]]; then
            # A masked unit is the only supported symlink.  Symlink mode bits
            # are kernel-defined (often 0777), so do not apply regular-file
            # write-bit checks to the link itself.
            [[ "$name" == "amneziad.service" \
                && "$(readlink -f -- "$backup_dir/$name" 2>/dev/null || true)" == "/dev/null" ]] || return 1
            continue
        fi
        backup_mode="$(stat -c '%a' -- "$backup_entry" 2>/dev/null || true)"
        [[ "$backup_mode" =~ ^[0-7]{3,4}$ ]] || return 1
        backup_mode_bits=$((0$backup_mode))
        (( backup_mode_bits & 0022 )) && return 1
    done
    # The journal is the authority for the backup identity.  Verify every
    # entry (content, size, mode and numeric ownership) before any recovery
    # mutation; a merely complete-looking directory is not sufficient after
    # a crash or partial copy.
    python3 - "$TRANSACTION_JOURNAL" "$backup_dir" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

journal_path, backup_text = sys.argv[1:]
try:
    journal = json.loads(Path(journal_path).read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit("invalid headless provisioning journal") from error
metadata = journal.get("backupFiles")
names = ("amneziad", "amnezia-cli", "amneziad.service", "update-public-key.pem")
if not isinstance(metadata, dict) or set(metadata) != set(names):
    raise SystemExit("headless provisioning journal has incomplete backup metadata")
root = Path(backup_text)
for name in names:
    record = metadata[name]
    if not isinstance(record, dict) or set(record) not in (
        {"present", "kind", "sha256", "size", "mode", "owner", "group"},
        {"present", "kind", "target", "sha256", "size", "mode", "owner", "group"},
    ):
        raise SystemExit("headless provisioning journal has invalid backup metadata")
    present = record.get("present")
    kind = record.get("kind")
    if not isinstance(present, bool) or kind not in {"regular", "symlink", "missing"}:
        raise SystemExit("headless provisioning journal has invalid backup metadata")
    item = root / name
    missing = root / (".missing-" + name)
    if not present:
        if kind != "missing" or item.exists() or item.is_symlink() or not missing.is_file():
            raise SystemExit("backup presence metadata does not match backup files")
        actual = missing
    elif kind == "regular":
        if not item.is_file() or item.is_symlink() or missing.exists():
            raise SystemExit("regular backup metadata does not match backup files")
        actual = item
    elif kind == "symlink":
        if not item.is_symlink() or missing.exists() or record.get("target") != os.readlink(item):
            raise SystemExit("symlink backup metadata does not match backup files")
        actual = item
    else:
        raise SystemExit("backup kind is invalid")
    details = actual.lstat()
    if details.st_uid != record.get("owner") or details.st_gid != record.get("group"):
        raise SystemExit("backup ownership metadata does not match backup files")
    if stat.S_IMODE(details.st_mode) != record.get("mode"):
        raise SystemExit("backup mode metadata does not match backup files")
    if record.get("size") != (details.st_size if kind == "regular" else 0):
        raise SystemExit("backup size metadata does not match backup files")
    digest = hashlib.sha256(actual.read_bytes()).hexdigest() if kind in {"regular", "missing"} else ""
    if record.get("sha256") != digest:
        raise SystemExit("backup hash metadata does not match backup files")
PY
}
verify_active_health() {
    [[ -S /run/amnezia/amneziad.sock ]] && /usr/local/bin/amnezia-cli --socket /run/amnezia/amneziad.sock doctor --json >/dev/null
}
recover_transaction() {
    if [[ ! -e "$TRANSACTION_JOURNAL" && ! -L "$TRANSACTION_JOURNAL" ]]; then
        [[ ! -e "$RECOVERY_MARKER" && ! -L "$RECOVERY_MARKER" ]] && return 0
        echo "headless provisioning recovery marker exists without a durable journal" >&2
        return 1
    fi
    if [[ -L "$TRANSACTION_JOURNAL" || ! -f "$TRANSACTION_JOURNAL" \
        || "$(stat -c '%u' -- "$TRANSACTION_JOURNAL" 2>/dev/null || true)" != "0" \
        || "$(stat -c '%a' -- "$TRANSACTION_JOURNAL" 2>/dev/null || true)" != "600" ]]; then
        echo "headless provisioning journal is not a root-owned mode 0600 regular file" >&2
        return 1
    fi
    local journal_values
    if ! journal_values="$(python3 - "$TRANSACTION_JOURNAL" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit("invalid headless provisioning journal") from error
required = {"schema", "phase", "mode", "backupDir", "serviceTarget", "serviceEnabled", "serviceActive", "groupPresent", "groupCreated", "backupFiles"}
if set(value) != required or value["schema"] != 1:
    raise SystemExit("headless provisioning journal has an invalid schema")
if value["phase"] not in {"starting", "prepared", "stopping", "stopped", "replacing", "installed", "verified", "committing", "committed"}:
    raise SystemExit("headless provisioning journal has an invalid phase")
if value["mode"] not in {"fresh", "upgrade"} or not isinstance(value["groupPresent"], bool) or not isinstance(value["groupCreated"], bool) or not isinstance(value["backupFiles"], dict):
    raise SystemExit("headless provisioning journal has an invalid mode")
if (not isinstance(value["backupDir"], str)
        or not re.fullmatch(r"/var/lib/amnezia/\.headless-provisioning-transactions/transaction\.[A-Za-z0-9]+", value["backupDir"])):
    raise SystemExit("headless provisioning journal has an unsafe backup path")
allowed = {
    "/etc/systemd/system/amneziad.service",
    "/run/systemd/system/amneziad.service",
    "/usr/local/lib/systemd/system/amneziad.service",
    "/usr/lib/systemd/system/amneziad.service",
    "/lib/systemd/system/amneziad.service",
}
if value["serviceTarget"] not in allowed:
    raise SystemExit("headless provisioning journal has an unsafe service path")
if value["serviceEnabled"] not in {"enabled", "disabled", "static", "indirect", "linked", "linked-runtime", "generated", "transient", "masked", "not-found"}:
    raise SystemExit("headless provisioning journal has an invalid enabled state")
if value["serviceActive"] not in {"active", "inactive", "failed", "not-found"}:
    raise SystemExit("headless provisioning journal has an invalid active state")
print(value["phase"])
for key in ("mode", "backupDir", "serviceTarget", "serviceEnabled", "serviceActive"):
    print(value[key])
print("true" if value["groupPresent"] else "false")
print("true" if value["groupCreated"] else "false")
PY
)"; then
        echo "headless provisioning recovery cannot parse its durable journal" >&2
        return 1
    fi
    local -a journal=()
    mapfile -t journal <<< "$journal_values"
    [[ "${#journal[@]}" -eq 8 ]] || return 1
    local phase="${journal[0]}" journal_mode="${journal[1]}" backup_dir="${journal[2]}"
    local service_target="${journal[3]}" service_enabled="${journal[4]}" service_active="${journal[5]}"
    local group_present="${journal[6]}" group_created="${journal[7]}"
    if [[ "$phase" != "starting" && "$phase" != "committing" && "$phase" != "committed" ]]; then
        verify_recovery_backup "$backup_dir" || { echo "headless provisioning backup is not safe to recover" >&2; return 1; }
    fi
    local had_errexit=0 recovery_ok=1
    case "$-" in *e*) had_errexit=1;; esac
    set +e
    if [[ "$phase" == "starting" ]]; then
        : "no installation mutation is possible before the prepared phase"
    elif [[ "$phase" == "committing" || "$phase" == "committed" ]]; then
        : "verified state is committed; only durable transaction debris needs cleanup"
    elif [[ "$journal_mode" == "upgrade" ]]; then
        if systemctl is-active --quiet amneziad.service 2>/dev/null; then
            systemctl stop amneziad.service >/dev/null 2>&1 || recovery_ok=0
        fi
        restore_transaction_file /usr/local/bin/amneziad amneziad "$backup_dir" || recovery_ok=0
        restore_transaction_file /usr/local/bin/amnezia-cli amnezia-cli "$backup_dir" || recovery_ok=0
        restore_transaction_file "$service_target" amneziad.service "$backup_dir" || recovery_ok=0
        restore_transaction_file /etc/amnezia/update-public-key.pem update-public-key.pem "$backup_dir" || recovery_ok=0
    else
        if systemctl is-active --quiet amneziad.service 2>/dev/null; then
            systemctl stop amneziad.service >/dev/null 2>&1 || recovery_ok=0
        fi
        rm -f -- /usr/local/bin/amneziad /usr/local/bin/amnezia-cli "$service_target" /etc/amnezia/update-public-key.pem || recovery_ok=0
    fi
    if [[ "$phase" != "starting" ]]; then
        systemctl daemon-reload >/dev/null 2>&1 || recovery_ok=0
    fi
    if [[ "$phase" != "starting" && "$phase" != "committing" && "$phase" != "committed" ]]; then
        if [[ "$journal_mode" == "upgrade" ]]; then
            case "$service_enabled" in
                masked) ;;
                enabled) systemctl enable amneziad.service >/dev/null 2>&1 || recovery_ok=0 ;;
                disabled) systemctl disable amneziad.service >/dev/null 2>&1 || recovery_ok=0 ;;
                static|indirect|linked|linked-runtime|generated|transient) ;;
                *) recovery_ok=0 ;;
            esac
            if [[ "$service_active" == "active" ]]; then
                systemctl start amneziad.service >/dev/null 2>&1 || recovery_ok=0
            elif [[ "$service_active" == "inactive" ]] && systemctl is-active --quiet amneziad.service 2>/dev/null; then
                systemctl stop amneziad.service >/dev/null 2>&1 || recovery_ok=0
            elif [[ "$service_active" == "failed" ]] && ! systemctl is-failed --quiet amneziad.service 2>/dev/null; then
                recovery_ok=0
            fi
            [[ "$(systemctl is-enabled amneziad.service 2>/dev/null || true)" == "$service_enabled" ]] || recovery_ok=0
            [[ "$(systemctl is-active amneziad.service 2>/dev/null || true)" == "$service_active" ]] || recovery_ok=0
            if [[ "$service_active" == "active" ]]; then verify_active_health || recovery_ok=0; fi
        else
            case "$(systemctl is-enabled amneziad.service 2>/dev/null || true)" in
                enabled|linked|linked-runtime|generated|transient) systemctl disable amneziad.service >/dev/null 2>&1 || recovery_ok=0 ;;
                disabled|not-found|masked) ;;
                *) recovery_ok=0 ;;
            esac
            case "$(systemctl is-enabled amneziad.service 2>/dev/null || true)" in disabled|not-found|masked) ;; *) recovery_ok=0 ;; esac
            if systemctl is-active --quiet amneziad.service 2>/dev/null; then recovery_ok=0; fi
        fi
    fi
    if [[ "$journal_mode" == "fresh" && "$phase" != "starting" && "$phase" != "committing" && "$phase" != "committed" ]]; then
        for state_dir in /etc/amnezia/profiles /etc/amnezia /run/amnezia; do
            rmdir -- "$state_dir" >/dev/null 2>&1 || [[ ! -e "$state_dir" ]] || recovery_ok=0
        done
    fi
    if [[ "$group_created" == "true" && "$phase" != "starting" && "$phase" != "committing" && "$phase" != "committed" \
        && -n "$(getent group amnezia || true)" ]]; then
        groupdel --system amnezia >/dev/null 2>&1 || recovery_ok=0
    fi
    if [[ "$recovery_ok" -eq 1 ]]; then
        rm -rf -- "$backup_dir" || recovery_ok=0
        if [[ -e "$TRANSACTION_BASE" ]] && ! rmdir -- "$TRANSACTION_BASE" >/dev/null 2>&1; then
            recovery_ok=0
        fi
        if [[ "$recovery_ok" -eq 1 ]]; then
            rm -f -- "$TRANSACTION_JOURNAL" || recovery_ok=0
            fsync_path_directory "$TRANSACTION_ROOT" 2>/dev/null || recovery_ok=0
        fi
        if [[ "$recovery_ok" -eq 1 && "$journal_mode" == "fresh" ]]; then
            rmdir -- /var/lib/amnezia >/dev/null 2>&1 || true
        fi
    fi
    if [[ "$had_errexit" -eq 1 ]]; then set -e; fi
    if [[ "$recovery_ok" -ne 1 ]]; then
        mark_recovery_required || true
        echo "headless provisioning recovery is incomplete; refusing a new transaction" >&2
        return 1
    fi
    clear_recovery_required || {
        mark_recovery_required || true
        echo "headless provisioning recovery marker could not be retired" >&2
        return 1
    }
    echo "headless provisioning transaction recovered exactly" >&2
    return 0
}
if [[ "$RECOVER_ONLY" -eq 1 ]]; then
    if ! verify_transaction_root; then
        echo "headless provisioning transaction root is not a root-owned directory" >&2
        exit 5
    fi
    if recover_transaction; then
        exit 0
    fi
    mark_recovery_required || true
    exit 5
fi
if [[ -e "$TRANSACTION_JOURNAL" || -L "$TRANSACTION_JOURNAL" ]]; then
    if ! verify_transaction_root; then
        echo "headless provisioning transaction root is not a root-owned directory" >&2
        exit 5
    fi
    recover_transaction || exit 5
fi
PRIVATE_INPUTS_ROOT=""
if ! PRIVATE_INPUTS_ROOT="$(mktemp -d /tmp/amnezia-headless-inputs.XXXXXX)"; then
    echo "unable to create a private package-input directory" >&2
    exit 3
fi
if ! chmod 0700 "$PRIVATE_INPUTS_ROOT"; then
    echo "unable to protect the private package-input directory" >&2
    rm -rf -- "$PRIVATE_INPUTS_ROOT"
    exit 3
fi
cleanup_private_inputs() {
    if [[ -n "${PRIVATE_INPUTS_ROOT:-}" ]]; then
        rm -rf -- "$PRIVATE_INPUTS_ROOT"
    fi
}
release_shared_lock() {
    if [[ -e "$TRANSACTION_LOCK_PATH" && ! -L "$TRANSACTION_LOCK_PATH" ]]; then
        rm -f -- "$TRANSACTION_LOCK_PATH" || return 1
    fi
}
trap cleanup_private_inputs EXIT
if ! python3 - "$SOURCE_PACKAGE_ROOT" "$PRIVATE_INPUTS_ROOT" "$PUBLIC_KEY" "$VERIFIED_RECEIPT" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

source_root, private_root_text, public_key_text, receipt_text = sys.argv[1:]
private_root = Path(private_root_text)
package_root = private_root / "package"
package_root.mkdir(mode=0o700)
expected_names = (
    "install_headless.sh", "amneziad", "amnezia-cli", "amneziad.service",
    "package-manifest.json", "runtime-dependencies.json",
    "runtime-dependencies.txt", "SHA256SUMS",
)

def copy_exact(source: Path, target: Path, label: str) -> None:
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    target_fd = -1
    try:
        opened = os.fstat(source_fd)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_size != before.st_size):
            raise SystemExit(f"{label} changed while it was being copied")
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        source_hash = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            source_hash.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise SystemExit(f"unable to copy {label} to the private package-input directory")
                view = view[written:]
        os.fsync(target_fd)
        os.fchmod(target_fd, stat.S_IMODE(before.st_mode) & 0o777)
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        os.close(source_fd)
    copied = target.stat()
    if copied.st_size != before.st_size or hashlib.sha256(target.read_bytes()).hexdigest() != source_hash.hexdigest():
        raise SystemExit(f"private {label} copy has an unexpected hash or size")

private_stat = private_root.stat()
if private_stat.st_uid != 0 or (private_stat.st_mode & 0o777) != 0o700:
    raise SystemExit("private package-input directory must be root-owned and mode 0700")
for name in expected_names:
    copy_exact(Path(source_root) / name, package_root / name, name)
copy_exact(Path(public_key_text), private_root / "update-public-key.pem", "public key")
copy_exact(Path(receipt_text), private_root / "verified-receipt.json", "verified receipt")
PY
then
    echo "unable to copy authenticated package inputs into the private root-owned directory" >&2
    exit 3
fi
PACKAGE_ROOT="$PRIVATE_INPUTS_ROOT/package"
PUBLIC_KEY="$PRIVATE_INPUTS_ROOT/update-public-key.pem"
VERIFIED_RECEIPT="$PRIVATE_INPUTS_ROOT/verified-receipt.json"
if [[ "$(sha256sum "$PACKAGE_ROOT/package-manifest.json" | awk '{print tolower($1)}')" != "${EXPECTED_MANIFEST_SHA256,,}" ]]; then
    echo "package manifest fingerprint does not match the trusted release receipt" >&2
    exit 3
fi
if [[ "$(sha256sum "$PACKAGE_ROOT/SHA256SUMS" | awk '{print tolower($1)}')" != "${EXPECTED_CHECKSUMS_SHA256,,}" ]]; then
    echo "package checksums fingerprint does not match the trusted release receipt" >&2
    exit 3
fi
if [[ "$(sha256sum "$PUBLIC_KEY" | awk '{print tolower($1)}')" != "${EXPECTED_KEY_SHA256,,}" ]]; then
    echo "private trust-anchor fingerprint does not match the trusted release receipt" >&2
    exit 3
fi
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
declare -a SERVICE_CANONICAL_PATHS=()
STATE_DIR_COUNT=0
verify_root_private_directory() {
    local candidate="$1"
    local owner mode mode_bits
    if [[ -L "$candidate" || ! -d "$candidate" ]]; then
        echo "upgrade requires a regular directory: $candidate" >&2
        return 1
    fi
    owner="$(stat -c '%u' -- "$candidate" 2>/dev/null || true)"
    mode="$(stat -c '%a' -- "$candidate" 2>/dev/null || true)"
    if [[ "$owner" != "0" || ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
        echo "upgrade requires root-owned directory metadata: $candidate" >&2
        return 1
    fi
    mode_bits=$((0$mode))
    if (( mode_bits & 0022 )); then
        echo "upgrade rejects group/world-writable directory: $candidate" >&2
        return 1
    fi
}
verify_root_private_file() {
    local candidate="$1"
    local owner mode mode_bits
    if [[ -L "$candidate" || ! -f "$candidate" ]]; then
        echo "managed file must be a regular file: $candidate" >&2
        return 1
    fi
    owner="$(stat -c '%u' -- "$candidate" 2>/dev/null || true)"
    mode="$(stat -c '%a' -- "$candidate" 2>/dev/null || true)"
    if [[ "$owner" != "0" || ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
        echo "managed file must be root-owned: $candidate" >&2
        return 1
    fi
    mode_bits=$((0$mode))
    if (( mode_bits & 0022 )); then
        echo "managed file is group/world-writable: $candidate" >&2
        return 1
    fi
}
verify_root_private_tree() {
    python3 - "$1" <<'PY'
import os
import stat
import sys
import grp
from pathlib import Path

root = Path(sys.argv[1])
allowed_socket = root / "amneziad.sock"
def check(path: Path) -> None:
    metadata = path.lstat()
    if path == allowed_socket and stat.S_ISSOCK(metadata.st_mode):
        if (metadata.st_uid != 0 or metadata.st_gid != grp.getgrnam("amnezia").gr_gid
                or stat.S_IMODE(metadata.st_mode) != 0o660):
            raise SystemExit(f"managed runtime socket is not exactly root:amnezia 0660: {path}")
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"managed state contains a symlink: {path}")
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
        raise SystemExit(f"managed state contains an unsupported file: {path}")
    if metadata.st_uid != 0 or metadata.st_mode & 0o22:
        raise SystemExit(f"managed state path is not root-owned and private: {path}")

check(root)
pending = [root]
while pending:
    current = pending.pop()
    with os.scandir(current) as entries:
        for entry in entries:
            path = Path(entry.path)
            check(path)
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
PY
}
if [[ "$MODE" == "upgrade" ]]; then
    for candidate in /etc/amnezia/profiles /etc/amnezia /etc / /var/lib/amnezia /var/lib /var /run/amnezia /run /usr/local/bin /usr/local /usr; do
        verify_root_private_directory "$candidate" || exit 4
    done
fi
for candidate in /var/lib/amnezia /run/amnezia /etc/amnezia /etc/amnezia/profiles; do
    if [[ -e "$candidate" || -L "$candidate" ]]; then
        if [[ ! -d "$candidate" || -L "$candidate" ]]; then
            echo "ambiguous installation identity: state path is not a regular directory: $candidate" >&2
            exit 4
        fi
        STATE_DIR_COUNT=$((STATE_DIR_COUNT + 1))
    fi
done
for candidate in /etc/systemd/system/amneziad.service /run/systemd/system/amneziad.service /usr/local/lib/systemd/system/amneziad.service /usr/lib/systemd/system/amneziad.service /lib/systemd/system/amneziad.service; do
    if [[ -e "$candidate" || -L "$candidate" ]]; then
        if [[ -L "$candidate" && "$(readlink -f -- "$candidate" 2>/dev/null || true)" != "/dev/null" ]]; then
            echo "ambiguous installation identity: service is not a regular file: $candidate" >&2
            exit 4
        fi
        candidate_canonical="$(readlink -f -- "$candidate" 2>/dev/null || true)"
        if [[ -z "$candidate_canonical" ]]; then
            echo "ambiguous installation identity: service path cannot be canonicalized: $candidate" >&2
            exit 4
        fi
        candidate_seen=0
        for existing_canonical in "${SERVICE_CANONICAL_PATHS[@]}"; do
            if [[ "$existing_canonical" == "$candidate_canonical" ]]; then
                candidate_seen=1
                break
            fi
        done
        if [[ "$candidate_seen" -eq 0 ]]; then
            SERVICE_CANONICAL_PATHS+=("$candidate_canonical")
            SERVICE_PATH="$candidate"
            SERVICE_COUNT=$((SERVICE_COUNT + 1))
        fi
    fi
done
if [[ "$SERVICE_COUNT" -gt 1 ]]; then
    # Refuse when the service exists in multiple systemd unit roots: the installation
    # identity is ambiguous and must be repaired by the operator first.
    # In particular, service exists in both /etc and /lib is an ambiguous install.
    echo "ambiguous installation: service unit exists in multiple systemd unit roots" >&2
    exit 4
fi
EXISTING_COMPONENTS="$SERVICE_COUNT"
for candidate in /usr/local/bin/amneziad /usr/local/bin/amnezia-cli /etc/amnezia/update-public-key.pem; do
    if [[ -e "$candidate" || -L "$candidate" ]]; then
        if [[ ! -f "$candidate" || -L "$candidate" ]]; then echo "ambiguous installation identity: non-regular component $candidate" >&2; exit 4; fi
        EXISTING_COMPONENTS=$((EXISTING_COMPONENTS + 1))
    fi
done
if [[ "$MODE" == "upgrade" ]]; then
    for candidate in /var/lib/amnezia /run/amnezia /etc/amnezia /etc/amnezia/profiles; do
        verify_root_private_tree "$candidate" || exit 4
    done
    for candidate in /run/systemd/system /usr/local/lib/systemd/system; do
        if [[ -e "$candidate" || -L "$candidate" ]]; then
            verify_root_private_directory "$candidate" || exit 4
        fi
    done
    for candidate in /usr/local/bin/amneziad /usr/local/bin/amnezia-cli /etc/amnezia/update-public-key.pem; do
        if [[ -e "$candidate" || -L "$candidate" ]]; then
            verify_root_private_file "$candidate" || exit 4
        fi
    done
    if [[ -n "$SERVICE_PATH" && ! -L "$SERVICE_PATH" ]]; then
        verify_root_private_file "$SERVICE_PATH" || exit 4
    fi
fi
if [[ -e "$TRANSACTION_BASE" || -L "$TRANSACTION_BASE" ]]; then
    echo "headless provisioning refuses unresolved transaction backup state; recover it first" >&2
    exit 4
fi
if [[ "$MODE" == "fresh" && ("$EXISTING_COMPONENTS" -ne 0 || "$STATE_DIR_COUNT" -ne 0) ]]; then
    echo "a partial, complete, or preexisting-state installation already exists; pass 'upgrade' explicitly after adoption/backup" >&2
    exit 4
fi
AMNEZIA_GROUP_ENTRY="$(getent group amnezia || true)"
if [[ "$MODE" == "fresh" && -n "$AMNEZIA_GROUP_ENTRY" ]]; then
    echo "fresh installation refuses a preexisting amnezia group; use upgrade after adoption/backup" >&2
    exit 4
fi
if [[ "$MODE" == "upgrade" && -z "$AMNEZIA_GROUP_ENTRY" ]]; then
    echo "upgrade requires the existing amnezia group" >&2
    exit 4
fi
if [[ -n "$AMNEZIA_GROUP_ENTRY" ]]; then
    IFS=: read -r _ _ _ AMNEZIA_GROUP_MEMBERS <<< "$AMNEZIA_GROUP_ENTRY"
    if [[ -n "$AMNEZIA_GROUP_MEMBERS" ]]; then
        echo "installation refuses an amnezia group with preexisting members" >&2
        exit 4
    fi
fi
if [[ "$MODE" == "upgrade" && "$EXISTING_COMPONENTS" -ne 4 ]]; then
    echo "upgrade requires exactly one complete installation identity; partial or ambiguous state found" >&2
    exit 4
fi
SERVICE_TARGET="${SERVICE_PATH:-/etc/systemd/system/amneziad.service}"
SERVICE_FRAGMENT_PATH=""
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
if manifest["platform"] != "linux-headless-x64" or manifest["installModes"] != ["fresh","upgrade"] or manifest["artifacts"] != ["amneziad","amnezia-cli","amneziad.service"] or manifest["servicePaths"] != ["/etc/systemd/system/amneziad.service","/run/systemd/system/amneziad.service","/usr/local/lib/systemd/system/amneziad.service","/usr/lib/systemd/system/amneziad.service","/lib/systemd/system/amneziad.service"]: raise SystemExit("invalid package artifact/service contract")
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
if ! python3 - "$VERIFIED_RECEIPT" "$PACKAGE_ROOT" "$PUBLIC_KEY" "$EXPECTED_KEY_SHA256" "$EXPECTED_MANIFEST_SHA256" "$EXPECTED_CHECKSUMS_SHA256" "$EXPECTED_SIGNED_MANIFEST_SHA256" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path
receipt_path, root_text, public_key_text, expected_key, expected_manifest, expected_checksums, expected_signed_manifest = sys.argv[1:]
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
if receipt["publicKeySha256"] != expected_key.lower() or digest(Path(public_key_text)) != expected_key.lower() or receipt["manifestSha256"] != expected_signed_manifest.lower() or not isinstance(receipt["archiveSize"], int) or receipt["archiveSize"] <= 0: raise SystemExit("receipt trust anchor, signed manifest, or archive identity is invalid")
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
    SERVICE_FRAGMENT_PATH="$(systemctl show -p FragmentPath --value amneziad.service 2>/dev/null || true)"
    if [[ "$SERVICE_WAS_ENABLED" == "masked" ]]; then
        if [[ "$SERVICE_FRAGMENT_PATH" != "/dev/null" ]]; then
            echo "masked amneziad.service has an unexpected systemd FragmentPath" >&2
            exit 4
        fi
    else
        case "$SERVICE_FRAGMENT_PATH" in
            /etc/systemd/system/amneziad.service|/run/systemd/system/amneziad.service|/usr/local/lib/systemd/system/amneziad.service|/usr/lib/systemd/system/amneziad.service|/lib/systemd/system/amneziad.service) ;;
            *) echo "systemd FragmentPath is outside the supported unit load roots: ${SERVICE_FRAGMENT_PATH:-empty}" >&2; exit 4 ;;
        esac
        verify_root_private_file "$SERVICE_FRAGMENT_PATH" || exit 4
        if [[ "$(readlink -f -- "$SERVICE_FRAGMENT_PATH" 2>/dev/null || true)" != "$(readlink -f -- "$SERVICE_PATH" 2>/dev/null || true)" ]]; then
            echo "systemd FragmentPath does not identify the discovered installation unit" >&2
            exit 4
        fi
        SERVICE_TARGET="$SERVICE_FRAGMENT_PATH"
    fi
fi
BACKUP_DIR=""
TRANSACTION_ACTIVE=0
TRANSACTION_COMMITTED=0
GROUP_WAS_PRESENT=false
GROUP_CREATED=false
if [[ "$MODE" == "upgrade" ]]; then GROUP_WAS_PRESENT=true; fi
if [[ ! -e "$TRANSACTION_ROOT" ]]; then
    install -d -o root -g root -m 0700 "$TRANSACTION_ROOT"
fi
if [[ -L "$TRANSACTION_ROOT" || ! -d "$TRANSACTION_ROOT" \
    || "$(stat -c '%u' -- "$TRANSACTION_ROOT" 2>/dev/null || true)" != "0" ]]; then
    echo "transaction root must be a root-owned regular directory: $TRANSACTION_ROOT" >&2
    exit 4
fi
install -d -o root -g root -m 0700 "$TRANSACTION_BASE"
BACKUP_DIR="$(mktemp -d "$TRANSACTION_BASE/transaction.XXXXXX")"
chmod 0700 "$BACKUP_DIR"
fsync_path_directory "$TRANSACTION_BASE"
TRANSACTION_ACTIVE=1
on_exit() {
    local status=$?
    trap - EXIT
    if [[ "$TRANSACTION_ACTIVE" -eq 1 && "$TRANSACTION_COMMITTED" -ne 1 ]]; then
        if ! recover_transaction; then
            mark_recovery_required || true
            status=5
        fi
    fi
    if ! cleanup_private_inputs; then status=5; fi
    if ! release_shared_lock; then status=5; fi
    exit "$status"
}
trap on_exit EXIT
write_transaction_journal starting
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
    if [[ -f "$BACKUP_DIR/$name" ]]; then
        fsync_regular_path "$BACKUP_DIR/$name"
    elif [[ -f "$BACKUP_DIR/.missing-$name" ]]; then
        fsync_regular_path "$BACKUP_DIR/.missing-$name"
    fi
    fsync_path_directory "$BACKUP_DIR"
}
backup_file /usr/local/bin/amneziad amneziad
backup_file /usr/local/bin/amnezia-cli amnezia-cli
backup_file "$SERVICE_TARGET" amneziad.service
backup_file /etc/amnezia/update-public-key.pem update-public-key.pem
write_transaction_journal prepared

write_transaction_journal stopping
if [[ "$MODE" == "fresh" ]]; then
    groupadd --system amnezia
    GROUP_CREATED=true
fi
if [[ "$MODE" == "upgrade" && "$SERVICE_WAS_ENABLED" == "masked" ]]; then
    systemctl unmask amneziad.service
fi
if [[ "$MODE" == "upgrade" && "$SERVICE_WAS_ACTIVE" == "active" ]]; then
    systemctl stop amneziad.service
fi
write_transaction_journal stopped
write_transaction_journal replacing
install -d -o root -g root -m 0755 /usr/local/bin
for state_dir in /var/lib/amnezia /run/amnezia /etc/amnezia /etc/amnezia/profiles; do
    if [[ ! -e "$state_dir" ]]; then
        install -d -o root -g amnezia -m 0750 "$state_dir"
    fi
done
install -o root -g root -m 0755 "$PACKAGE_ROOT/amneziad" /usr/local/bin/amneziad
install -o root -g root -m 0755 "$PACKAGE_ROOT/amnezia-cli" /usr/local/bin/amnezia-cli
install -D -o root -g root -m 0644 "$PACKAGE_ROOT/amneziad.service" "$SERVICE_TARGET"
install -o root -g root -m 0644 "$PUBLIC_KEY" /etc/amnezia/update-public-key.pem
if [[ -L /etc/amnezia/update-public-key.pem || ! -f /etc/amnezia/update-public-key.pem \
    || "$(sha256sum /etc/amnezia/update-public-key.pem | awk '{print tolower($1)}')" != "${EXPECTED_KEY_SHA256,,}" ]]; then
    echo "installed trust anchor hash does not match the verified private source" >&2
    exit 4
fi
chown root:amnezia /etc/amnezia/update-public-key.pem
chmod 0640 /etc/amnezia/update-public-key.pem
write_transaction_journal installed
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
current_fragment="$(systemctl show -p FragmentPath --value amneziad.service 2>/dev/null || true)"
if [[ "$MODE" == "fresh" ]]; then
    if [[ "$current_active" != "active" ]]; then echo "amneziad.service did not become active" >&2; exit 4; fi
    case "$current_fragment" in
        /etc/systemd/system/amneziad.service|/run/systemd/system/amneziad.service|/usr/local/lib/systemd/system/amneziad.service|/usr/lib/systemd/system/amneziad.service|/lib/systemd/system/amneziad.service) ;;
        *) echo "fresh installation has an unexpected systemd FragmentPath" >&2; exit 4 ;;
    esac
    verify_root_private_file "$current_fragment" || exit 4
elif [[ "$current_enabled" != "$SERVICE_WAS_ENABLED" || "$current_active" != "$SERVICE_WAS_ACTIVE" ]]; then
    echo "systemd enabled/active state was not preserved" >&2
    exit 4
elif [[ "$SERVICE_WAS_ENABLED" == "masked" ]]; then
    [[ "$current_fragment" == "/dev/null" ]] || { echo "masked service has an unexpected systemd FragmentPath" >&2; exit 4; }
else
    case "$current_fragment" in
        /etc/systemd/system/amneziad.service|/run/systemd/system/amneziad.service|/usr/local/lib/systemd/system/amneziad.service|/usr/lib/systemd/system/amneziad.service|/lib/systemd/system/amneziad.service) ;;
        *) echo "upgraded service has an unexpected systemd FragmentPath" >&2; exit 4 ;;
    esac
    verify_root_private_file "$current_fragment" || exit 4
    [[ "$(readlink -f -- "$current_fragment" 2>/dev/null || true)" == "$(readlink -f -- "$SERVICE_TARGET" 2>/dev/null || true)" ]] || {
        echo "upgraded systemd FragmentPath does not match the installed unit" >&2
        exit 4
    }
fi
if [[ "$current_active" == "active" ]] && ! verify_active_health; then
    echo "headless daemon health check failed" >&2
    exit 4
fi
write_transaction_journal verified
write_transaction_journal committing
if ! rm -rf -- "$BACKUP_DIR"; then
    echo "installation completed but transaction backup cleanup failed: $BACKUP_DIR" >&2
    exit 5
fi
fsync_path_directory "$TRANSACTION_BASE"
if ! rmdir -- "$TRANSACTION_BASE" >/dev/null 2>&1; then
    echo "installation completed but transaction backup directory cleanup failed" >&2
    exit 5
fi
if [[ "$MODE" == "fresh" ]]; then
    chown root:amnezia "$TRANSACTION_ROOT"
    chmod 0750 "$TRANSACTION_ROOT"
fi
write_transaction_journal committed
rm -f -- "$TRANSACTION_JOURNAL"
fsync_path_directory "$TRANSACTION_ROOT"
TRANSACTION_COMMITTED=1
TRANSACTION_ACTIVE=0
echo "headless provisioning complete: service, trust anchor and state directories installed"
