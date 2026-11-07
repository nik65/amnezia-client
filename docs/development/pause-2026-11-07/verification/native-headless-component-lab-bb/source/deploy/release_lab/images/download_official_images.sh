#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DEFAULT_LOCK="$SCRIPT_DIR/lock.json"
readonly DEFAULT_CACHE="/var/lib/amnezia-release-lab/images"

die() { printf 'image-download: ERROR: %s\n' "$*" >&2; exit 1; }
usage() { cat <<'EOF'
Usage: download_official_images.sh --image NAME --cache-dir DIR [options]

Downloads only official Ubuntu cloud media. The cache must be outside the
repository. The command verifies the signed SHA256SUMS file before accepting
the image. Windows media remains a manual Microsoft download and is rejected
until its URL and SHA-256 are supplied in a private lock copy.

Options:
  --image NAME       ubuntu24-cloud-amd64 or windows11-25h2-evaluation-amd64
  --cache-dir DIR    external cache directory (default: /var/lib/.../images)
  --lock FILE        lock JSON (default: this directory/lock.json)
  --gpg-keyring FILE detached keyring for Ubuntu image-signing key
  --dry-run          print the plan without downloading
EOF
}

IMAGE=''
CACHE_DIR="$DEFAULT_CACHE"
LOCK="$DEFAULT_LOCK"
KEYRING=''
DRY_RUN=0
while (($#)); do
  case "$1" in
    --image) [[ $# -ge 2 ]] || die '--image needs a value'; IMAGE="$2"; shift 2 ;;
    --cache-dir) [[ $# -ge 2 ]] || die '--cache-dir needs a value'; CACHE_DIR="$2"; shift 2 ;;
    --lock) [[ $# -ge 2 ]] || die '--lock needs a value'; LOCK="$2"; shift 2 ;;
    --gpg-keyring) [[ $# -ge 2 ]] || die '--gpg-keyring needs a value'; KEYRING="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$IMAGE" ]] || { usage >&2; exit 2; }
command -v python3 >/dev/null || die 'python3 is required to read lock.json'
command -v curl >/dev/null || die 'curl is required'
command -v sha256sum >/dev/null || die 'sha256sum is required'
command -v gpgv >/dev/null || die 'gpgv is required for signed image verification'
[[ -r "$LOCK" ]] || die "lock file is not readable: $LOCK"
[[ "$CACHE_DIR" = /* ]] || die '--cache-dir must be absolute and external'
[[ "$CACHE_DIR" != *"$SCRIPT_DIR"* ]] || die '--cache-dir must be outside the source tree'
[[ ! -L "$CACHE_DIR" ]] || die '--cache-dir must not be a symlink'

lock_value() {
  python3 - "$LOCK" "$IMAGE" "$1" <<'PY'
import json, sys
path, name, key = sys.argv[1:]
with open(path, encoding='utf-8') as fh:
    item = json.load(fh).get('images', {}).get(name)
if not item:
    raise SystemExit(f'unknown image: {name}')
value = item.get(key)
if value is None:
    print('')
elif isinstance(value, bool):
    print(str(value).lower())
else:
    print(str(value))
PY
}
PLATFORM="$(lock_value platform)"
URL="$(lock_value url)"
SUMS_URL="$(lock_value checksums_url)"
SIG_URL="$(lock_value checksums_signature_url)"
FILENAME="$(lock_value filename)"
SIGNATURE_REQUIRED="$(lock_value signature_required)"
SHA256="$(lock_value sha256)"
SIGNING_FINGERPRINT="$(lock_value signing_key_fingerprint)"
VERIFICATION_BLOCKED="$(lock_value verification_blocked)"
[[ -n "$FILENAME" && "$FILENAME" == "$(basename -- "$FILENAME")" ]] || die 'lock filename must be a plain basename'
[[ "$VERIFICATION_BLOCKED" != true ]] || die "image $IMAGE is blocked until a trusted SHA-256/signature receipt is available"

[[ -n "$URL" ]] || die "image $IMAGE has no official URL"
mkdir -p "$CACHE_DIR"
TARGET="$CACHE_DIR/$FILENAME"
[[ ! -L "$TARGET" ]] || die "refusing symlink target: $TARGET"
if ((DRY_RUN)); then
  printf 'would-download image=%s url=%s target=%s\n' "$IMAGE" "$URL" "$TARGET"
  exit 0
fi

TMP="$TARGET.part.$$"
trap 'rm -f -- "$TMP" "$TARGET.sums.part.$$" "$TARGET.sig.part.$$"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error --output "$TMP" "$URL"

if [[ "$SIGNATURE_REQUIRED" == true ]]; then
  [[ -n "$SUMS_URL" && -n "$SIG_URL" ]] || die 'signed checksum URLs are missing'
  [[ -n "$KEYRING" && -r "$KEYRING" ]] || die '--gpg-keyring with the official Ubuntu signing keyring is required'
  SUMS="$TARGET.sums.part.$$"
  SIG="$TARGET.sig.part.$$"
  curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error --output "$SUMS" "$SUMS_URL"
  curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error --output "$SIG" "$SIG_URL"
  [[ "$SIGNING_FINGERPRINT" =~ ^[0-9A-Fa-f]{40}$ ]] || die 'lock signing key fingerprint is missing or malformed'
  STATUS="$(gpgv --status-fd=1 --keyring "$KEYRING" "$SIG" "$SUMS" 2>/dev/null)" || die 'Ubuntu checksum signature verification failed'
  grep -Fq "[GNUPG:] VALIDSIG ${SIGNING_FINGERPRINT^^} " <<<"$STATUS" || die 'checksum signature is valid but was made by an unexpected key'
  EXPECTED="$(awk -v f="$FILENAME" '$2 == f || $2 == "*" f {print $1; exit}' "$SUMS")"
  [[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] || die "no SHA-256 entry for $FILENAME in signed checksum file"
else
  EXPECTED="$SHA256"
  if [[ ! "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ && -n "$SUMS_URL" ]]; then
    SUMS="$TARGET.sums.part.$$"
    curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error --output "$SUMS" "$SUMS_URL"
    EXPECTED="$(python3 - "$SUMS" "$FILENAME" <<'PY'
import re, sys
path, name = sys.argv[1:]
for line in open(path, encoding='utf-8', errors='replace'):
    if name not in line:
        continue
    match = re.search(r'(?i)([0-9a-f]{64})', line)
    if match:
        print(match.group(1)); break
PY
    )"
  fi
  [[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] || die 'lock/published checksum must be a 64-character hex value'
fi
ACTUAL="$(sha256sum "$TMP" | awk '{print $1}')"
[[ "${ACTUAL,,}" == "${EXPECTED,,}" ]] || die "SHA-256 mismatch for $FILENAME (expected $EXPECTED, got $ACTUAL)"
mv -- "$TMP" "$TARGET"
if [[ "$SIGNATURE_REQUIRED" == true ]]; then
  mv -- "$SUMS" "$TARGET.SHA256SUMS"
  mv -- "$SIG" "$TARGET.SHA256SUMS.gpg"
elif [[ -n "${SUMS:-}" ]]; then
  mv -- "$SUMS" "$TARGET.CHECKSUM"
fi
printf '%s  %s\n' "$ACTUAL" "$TARGET"
