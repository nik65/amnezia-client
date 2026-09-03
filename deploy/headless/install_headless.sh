#!/usr/bin/env bash
set -euo pipefail

# User-invoked provisioning flow for a freshly installed Ubuntu headless
# client.  The update tar remains binary-only; this script is deliberately a
# separate package step and never publishes or fetches release artifacts.
PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLIC_KEY="${1:-}"
EXPECTED_KEY_SHA256="${2:-${AMNEZIA_HEADLESS_UPDATE_PUBLIC_KEY_SHA256:-}}"
MODE="${3:-fresh}"
if [[ -z "$PUBLIC_KEY" || ! -f "$PUBLIC_KEY" || ! "$EXPECTED_KEY_SHA256" =~ ^[[:xdigit:]]{64}$ \
    || ("$MODE" != "fresh" && "$MODE" != "upgrade") ]]; then
    echo "usage: $0 /path/to/update-public-key.pem expected-key-sha256 [fresh|upgrade]" >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "run this provisioning step as root" >&2
    exit 2
fi
for required in systemctl systemd-run getent tar ip ldd sha256sum openssl python3 dpkg-query dpkg \
    groupadd install chown chmod mktemp grep awk; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "required runtime command is missing: $required" >&2
        exit 3
    fi
done
EXISTING_SERVICE=""
for candidate in /etc/systemd/system/amneziad.service /lib/systemd/system/amneziad.service; do
    if [[ -f "$candidate" ]]; then
        EXISTING_SERVICE="$candidate"
        break
    fi
done
EXISTING_COMPONENTS=0
for candidate in /usr/local/bin/amneziad /usr/local/bin/amnezia-cli \
    /etc/systemd/system/amneziad.service /lib/systemd/system/amneziad.service \
    /etc/amnezia/update-public-key.pem; do
    if [[ -e "$candidate" || -L "$candidate" ]]; then
        EXISTING_COMPONENTS=$((EXISTING_COMPONENTS + 1))
    fi
done
if [[ "$MODE" == "fresh" && "$EXISTING_COMPONENTS" -ne 0 ]]; then
    echo "a partial or complete installation already exists; pass 'upgrade' explicitly" >&2
    exit 4
fi
if [[ "$MODE" == "upgrade" && "$EXISTING_COMPONENTS" -eq 0 ]]; then
    echo "upgrade requested but no existing installation identity was found; use 'fresh'" >&2
    exit 4
fi
if [[ ! -f "$PACKAGE_ROOT/SHA256SUMS" ]] || ! (cd "$PACKAGE_ROOT" && sha256sum --strict --check SHA256SUMS); then
    echo "provisioning bundle integrity check failed" >&2
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
if ldd "$PACKAGE_ROOT/amneziad" "$PACKAGE_ROOT/amnezia-cli" 2>&1 | grep -q 'not found'; then
    echo "headless binaries have unresolved shared-library dependencies" >&2
    exit 3
fi
if [[ ! -f "$PACKAGE_ROOT/runtime-dependencies.txt" || ! -f "$PACKAGE_ROOT/runtime-dependencies.json" || ! -f "$PACKAGE_ROOT/package-manifest.json" ]]; then
    echo "provisioning bundle is missing runtime-dependencies.txt" >&2
    exit 3
fi
if ! { grep -q '"schema":1' "$PACKAGE_ROOT/package-manifest.json" \
    && grep -q '"platform":"linux-headless-x64"' "$PACKAGE_ROOT/package-manifest.json" \
    && grep -q '"installMode":"fresh-or-upgrade"' "$PACKAGE_ROOT/package-manifest.json" \
    && grep -q '"distribution":"ubuntu"' "$PACKAGE_ROOT/runtime-dependencies.json" \
     && grep -q '"architectures":\["amd64"\]' "$PACKAGE_ROOT/runtime-dependencies.json" \
     && grep -q '"amneziad"' "$PACKAGE_ROOT/package-manifest.json" \
     && grep -q '"amnezia-cli"' "$PACKAGE_ROOT/package-manifest.json" \
     && grep -q '"amneziad.service"' "$PACKAGE_ROOT/package-manifest.json"; }; then
    echo "provisioning package manifest is invalid" >&2
    exit 3
fi
if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
    echo "headless provisioning bundle is only supported on amd64 Ubuntu" >&2
    exit 3
fi
if [[ ! -r /etc/os-release ]]; then
    echo "Ubuntu release metadata is unavailable" >&2
    exit 3
fi
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" || ! "${VERSION_ID:-}" =~ ^[0-9]+\.[0-9]+$ \
    || "${VERSION_ID%%.*}" -lt 22 ]]; then
    echo "headless provisioning requires Ubuntu 22.04 or newer on amd64" >&2
    exit 3
fi
if ! python3 - "$PACKAGE_ROOT/runtime-dependencies.json" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("schema") != 1 or document.get("distribution") != "ubuntu" or not document.get("packages"):
    raise SystemExit("invalid runtime dependency manifest")
for entry in document["packages"]:
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not isinstance(entry.get("minimum"), str):
        raise SystemExit("invalid runtime dependency entry")
PY
then
    echo "runtime dependency manifest cannot be validated" >&2
    exit 3
fi
while IFS=$'\t' read -r package minimum; do
    installed="$(dpkg-query -W -f='${Status}\t${Version}' "$package" 2>/dev/null || true)"
    if [[ "$installed" != "install ok installed"$'\t'* ]]; then
        echo "declared runtime dependency is not installed: $package >= $minimum" >&2
        exit 3
    fi
    installed_version="${installed#*$'\t'}"
    if ! dpkg --compare-versions "$installed_version" ge "$minimum"; then
        echo "declared runtime dependency is too old: $package $installed_version < $minimum" >&2
        exit 3
    fi
done < <(python3 - "$PACKAGE_ROOT/runtime-dependencies.json" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("schema") != 1 or document.get("distribution") != "ubuntu":
    raise SystemExit("invalid runtime dependency manifest")
for entry in document.get("packages", []):
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not isinstance(entry.get("minimum"), str):
        raise SystemExit("invalid runtime dependency entry")
    print(entry["name"] + "\t" + entry["minimum"])
PY
)
if ! getent group amnezia >/dev/null 2>&1; then
    groupadd --system amnezia
fi

BACKUP_DIR=""
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=unknown
SERVICE_WAS_MASKED=0
INSTALL_OK=0
BACKUP_DIR="$(mktemp -d /var/lib/amnezia-headless-transaction.XXXXXX)"
if [[ "$MODE" == "upgrade" ]]; then
    SERVICE_WAS_ENABLED="$(systemctl is-enabled amneziad.service 2>/dev/null || true)"
    if [[ "$SERVICE_WAS_ENABLED" == "masked" ]]; then
        SERVICE_WAS_MASKED=1
        if ! systemctl unmask amneziad.service; then
            echo "masked amneziad.service could not be prepared for upgrade" >&2
            exit 4
        fi
    fi
fi
for item in /usr/local/bin/amneziad /usr/local/bin/amnezia-cli \
    /etc/systemd/system/amneziad.service /etc/amnezia/update-public-key.pem; do
    name="$(basename "$item")"
    if [[ -e "$item" || -L "$item" ]]; then
        cp -a -- "$item" "$BACKUP_DIR/$name"
    else
        touch "$BACKUP_DIR/.missing-$name"
    fi
done
if [[ "$MODE" == "upgrade" ]]; then
    if systemctl is-active --quiet amneziad.service; then
        SERVICE_WAS_ACTIVE=1
        systemctl stop amneziad.service
    fi
fi

rollback_upgrade() {
    if [[ "$INSTALL_OK" -eq 1 ]]; then return 0; fi
    set +e
    local rollback_ok=1
    systemctl stop amneziad.service >/dev/null 2>&1
    for pair in \
        "/usr/local/bin/amneziad amneziad" \
        "/usr/local/bin/amnezia-cli amnezia-cli" \
        "/etc/systemd/system/amneziad.service amneziad.service" \
        "/etc/amnezia/update-public-key.pem update-public-key.pem"; do
        target="${pair% *}"
        name="${pair#* }"
        if [[ -f "$BACKUP_DIR/.missing-$name" ]]; then
            rm -f -- "$target" || rollback_ok=0
        elif [[ -e "$BACKUP_DIR/$name" ]]; then
            install -D -m 0644 "$BACKUP_DIR/$name" "$target" || rollback_ok=0
            if [[ "$target" == /usr/local/bin/* ]]; then chmod 0755 "$target" || rollback_ok=0; fi
        fi
    done
    systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
    if [[ "$MODE" == "upgrade" ]]; then
        if [[ "$SERVICE_WAS_MASKED" -eq 1 ]]; then
            systemctl mask amneziad.service >/dev/null 2>&1 || rollback_ok=0
        elif [[ "$SERVICE_WAS_ENABLED" == "enabled" ]]; then
            systemctl enable amneziad.service >/dev/null 2>&1 || rollback_ok=0
        else
            systemctl disable amneziad.service >/dev/null 2>&1 || rollback_ok=0
        fi
    fi
    if [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then
        systemctl start amneziad.service >/dev/null 2>&1 || rollback_ok=0
    else
        systemctl stop amneziad.service >/dev/null 2>&1 || rollback_ok=0
    fi
    if [[ "$rollback_ok" -eq 1 ]] && systemctl is-active --quiet amneziad.service 2>/dev/null; then
        :
    elif [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then
        rollback_ok=0
    fi
    if [[ "$rollback_ok" -ne 1 ]]; then
        install -d -m 0750 /var/lib/amnezia
        printf '%s\n' "rollback failed; manual recovery is required" > /var/lib/amnezia/headless-recovery-required
        chmod 0600 /var/lib/amnezia/headless-recovery-required
        echo "headless upgrade rollback failed; manual recovery is required" >&2
        exit 5
    fi
    echo "headless upgrade failed; previous installation was restored" >&2
}
trap rollback_upgrade EXIT

install -d -o root -g root -m 0755 /usr/local/bin
install -d -o root -g amnezia -m 0750 /var/lib/amnezia /run/amnezia /etc/amnezia/profiles
install -o root -g root -m 0755 "$PACKAGE_ROOT/amneziad" /usr/local/bin/amneziad
install -o root -g root -m 0755 "$PACKAGE_ROOT/amnezia-cli" /usr/local/bin/amnezia-cli
install -o root -g root -m 0644 "$PACKAGE_ROOT/amneziad.service" /etc/systemd/system/amneziad.service
install -o root -g root -m 0644 "$PUBLIC_KEY" /etc/amnezia/update-public-key.pem
chown root:amnezia /etc/amnezia/update-public-key.pem
chmod 0640 /etc/amnezia/update-public-key.pem
systemctl daemon-reload
systemctl enable --now amneziad.service
if ! systemctl is-active --quiet amneziad.service; then
    echo "amneziad.service did not become active" >&2
    exit 4
fi
if [[ ! -S /run/amnezia/amneziad.sock ]]; then
    echo "amneziad control socket was not created" >&2
    exit 4
fi
if ! /usr/local/bin/amnezia-cli --socket /run/amnezia/amneziad.sock doctor --json >/dev/null; then
    echo "headless daemon doctor check failed" >&2
    exit 4
fi
INSTALL_OK=1
if [[ -n "$BACKUP_DIR" ]]; then
    rm -rf -- "$BACKUP_DIR"
fi
echo "headless provisioning complete: service, trust anchor and state directories installed"
