#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROFILE=''
IMAGE=''
OUTPUT=''
SSH_KEY=''
IMAGE_SHA256=''
BASE_FORMAT=qcow2
FORCE=0
die() { printf 'provision-linux: ERROR: %s\n' "$*" >&2; exit 1; }
usage() { cat <<'EOF'
Usage: provision_linux_guest.sh --profile PROFILE --image IMAGE --image-sha256 HEX --output DIR --ssh-public-key FILE

Prepares a qcow2 overlay and NoCloud seed media. It never starts QEMU. The
base image must already have passed images/verify_images.sh. PROFILE is one of
linux-headless, linux-gui, or server-router.
EOF
}
while (($#)); do
  case "$1" in
    --profile) PROFILE="${2:?}"; shift 2 ;;
    --image) IMAGE="${2:?}"; shift 2 ;;
    --image-sha256) IMAGE_SHA256="${2:?}"; shift 2 ;;
    --output) OUTPUT="${2:?}"; shift 2 ;;
    --ssh-public-key) SSH_KEY="${2:?}"; shift 2 ;;
    --base-format) BASE_FORMAT="${2:?}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$PROFILE" =~ ^(linux-headless|linux-headless-x64|linux-gui|linux-x64-gui|server-router)$ ]] || die 'unsupported Linux profile'
[[ -f "$IMAGE" ]] || die "base image not found: $IMAGE"
[[ "$IMAGE_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || die '--image-sha256 must be a 64-character SHA-256 from a verified receipt'
[[ -r "$SSH_KEY" ]] || die "SSH public key not readable: $SSH_KEY"
[[ -n "$OUTPUT" && "$OUTPUT" = /* ]] || die '--output must be an absolute path'
[[ ! -L "$OUTPUT" ]] || die '--output must not be a symlink'
command -v qemu-img >/dev/null || die 'qemu-img is required'
command -v cloud-localds >/dev/null || die 'cloud-localds is required'
[[ ! -e "$OUTPUT" || "$FORCE" -eq 1 ]] || die "output exists; use a new run directory or --force: $OUTPUT"
for generated in "$OUTPUT/disk.qcow2" "$OUTPUT/seed" "$OUTPUT/seed/user-data" "$OUTPUT/seed/meta-data" "$OUTPUT/seed/nocloud.iso"; do
  [[ ! -L "$generated" ]] || die "refusing symlink generated path: $generated"
done
mkdir -p "$OUTPUT/seed"
if ((FORCE)); then rm -f -- "$OUTPUT/disk.qcow2" "$OUTPUT/seed/user-data" "$OUTPUT/seed/meta-data" "$OUTPUT/seed/nocloud.iso"; fi

TEMPLATE_PROFILE="$PROFILE"
case "$PROFILE" in
  linux-headless-x64) TEMPLATE_PROFILE=linux-headless ;;
  linux-x64-gui) TEMPLATE_PROFILE=linux-gui ;;
esac
TEMPLATE="$SCRIPT_DIR/guest_templates/$TEMPLATE_PROFILE/user-data"
[[ -r "$TEMPLATE" ]] || die "template missing: $TEMPLATE"
PUBKEY="$(tr -d '\r\n' < "$SSH_KEY")"
KEY_TYPE="${PUBKEY%% *}"
[[ "$KEY_TYPE" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+)$ ]] || die 'unsupported SSH public key type'
command -v ssh-keygen >/dev/null || die 'ssh-keygen is required to validate the public key'
ssh-keygen -lf "$SSH_KEY" >/dev/null 2>&1 || die 'SSH public key failed ssh-keygen validation'
ACTUAL_IMAGE_SHA256="$(sha256sum "$IMAGE" | awk '{print $1}')"
[[ "${ACTUAL_IMAGE_SHA256,,}" == "${IMAGE_SHA256,,}" ]] || die "base image SHA-256 mismatch (expected $IMAGE_SHA256, got $ACTUAL_IMAGE_SHA256)"
INSTANCE_ID="amnezia-${PROFILE}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
HOSTNAME="amnezia-${PROFILE}"
python3 - "$TEMPLATE" "$OUTPUT/seed/user-data" "$PUBKEY" <<'PY'
from pathlib import Path
import sys
source, target = map(Path, sys.argv[1:3])
key = sys.argv[3]
text = source.read_text(encoding='utf-8').replace('__LAB_SSH_PUBLIC_KEY__', key)
target.write_text(text, encoding='utf-8')
PY
python3 - "$SCRIPT_DIR/guest_templates/common/meta-data" "$OUTPUT/seed/meta-data" "$INSTANCE_ID" "$HOSTNAME" <<'PY'
from pathlib import Path
import sys
source, target = map(Path, sys.argv[1:3])
text = source.read_text(encoding='utf-8').replace('__INSTANCE_ID__', sys.argv[3]).replace('__LOCAL_HOSTNAME__', sys.argv[4])
target.write_text(text, encoding='utf-8')
PY
chmod 0644 "$OUTPUT/seed/user-data" "$OUTPUT/seed/meta-data"
qemu-img create -f qcow2 -F "$BASE_FORMAT" -b "$IMAGE" "$OUTPUT/disk.qcow2" >/dev/null
cloud-localds "$OUTPUT/seed/nocloud.iso" "$OUTPUT/seed/user-data" "$OUTPUT/seed/meta-data" >/dev/null
SEED_SHA256="$(sha256sum "$OUTPUT/seed/nocloud.iso" | awk '{print $1}')"
TEMPLATE_SHA256="$(sha256sum "$TEMPLATE" | awk '{print $1}')"
cat > "$OUTPUT/provisioning-manifest.json" <<EOF
{
  "schema": 1,
  "profile": "$PROFILE",
  "base_image": "$(basename -- "$IMAGE")",
  "base_image_preverified": true,
  "base_image_sha256": "$ACTUAL_IMAGE_SHA256",
  "disk": "disk.qcow2",
  "seed": "seed/nocloud.iso",
  "seed_sha256": "$SEED_SHA256",
  "template": "guest_templates/$TEMPLATE_PROFILE/user-data",
  "template_sha256": "$TEMPLATE_SHA256",
  "qemu_started": false,
  "network": "NAT allowed only before seal; WAN must be detached before candidate credentials",
  "candidate_credentials": "absent",
  "instance_id": "$INSTANCE_ID"
}
EOF
chmod 0644 "$OUTPUT/provisioning-manifest.json"
printf 'prepared profile=%s output=%s (QEMU not started)\n' "$PROFILE" "$OUTPUT"
