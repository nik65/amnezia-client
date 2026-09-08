#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$SCRIPT_DIR/lock.json"
CACHE_DIR=''
IMAGE=''
KEYRING=''
usage() { cat <<'EOF'
Usage: verify_images.sh --image NAME --cache-dir DIR [--lock FILE]
Verifies an already downloaded image against the lock. Ubuntu verification
requires a signed upstream SHA256SUMS receipt supplied with --gpg-keyring.
EOF
}
die() { printf 'image-verify: ERROR: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --image) IMAGE="${2:?}"; shift 2 ;;
    --cache-dir) CACHE_DIR="${2:?}"; shift 2 ;;
    --lock) LOCK="${2:?}"; shift 2 ;;
    --gpg-keyring) KEYRING="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$IMAGE" && -n "$CACHE_DIR" ]] || { usage >&2; exit 2; }
[[ -r "$LOCK" ]] || die "lock is not readable: $LOCK"
[[ -d "$CACHE_DIR" ]] || die "cache is not a directory: $CACHE_DIR"
[[ ! -L "$CACHE_DIR" ]] || die 'cache must not be a symlink'
command -v python3 >/dev/null || die 'python3 is required'
command -v sha256sum >/dev/null || die 'sha256sum is required'
command -v gpgv >/dev/null || die 'gpgv is required for signed verification'
readarray -t FIELDS < <(python3 - "$LOCK" "$IMAGE" <<'PY'
import json,sys
data=json.load(open(sys.argv[1],encoding='utf-8'))
item=data.get('images',{}).get(sys.argv[2])
if not item: raise SystemExit('unknown image')
for k in ('filename','sha256','signature_required','signing_key_fingerprint','verification_blocked'):
 value=item.get(k)
 print('' if value is None else str(value).lower() if isinstance(value,bool) else str(value))
PY
)
(( ${#FIELDS[@]} == 5 )) || die 'lock entry is incomplete'
filename="${FIELDS[0]}"
sha256="${FIELDS[1]}"
signature_required="${FIELDS[2]}"
signing_key_fingerprint="${FIELDS[3]}"
verification_blocked="${FIELDS[4]}"
[[ "$verification_blocked" != true ]] || die 'image is blocked until a trusted SHA-256/signature receipt is available'
[[ -n "$filename" && "$filename" == "$(basename -- "$filename")" ]] || die 'lock filename must be a plain basename'
TARGET="$CACHE_DIR/$filename"
[[ ! -L "$TARGET" ]] || die "refusing symlink target: $TARGET"
[[ -f "$TARGET" ]] || die "missing image: $TARGET"
if [[ "$signature_required" == true ]]; then
  [[ -n "$KEYRING" ]] || die 'Ubuntu verification requires --gpg-keyring and a separately downloaded signed checksum receipt'
  [[ -f "$TARGET.SHA256SUMS" && -f "$TARGET.SHA256SUMS.gpg" ]] || die "missing signed checksum receipt beside $TARGET"
  [[ "$signing_key_fingerprint" =~ ^[0-9A-Fa-f]{40}$ ]] || die 'lock signing key fingerprint is missing or malformed'
  status="$(gpgv --status-fd=1 --keyring "$KEYRING" "$TARGET.SHA256SUMS.gpg" "$TARGET.SHA256SUMS" 2>/dev/null)" || die 'checksum signature invalid'
  grep -Fq "[GNUPG:] VALIDSIG ${signing_key_fingerprint^^} " <<<"$status" || die 'checksum signature came from an unexpected key'
  expected="$(awk -v f="$filename" '$2 == f || $2 == "*" f {print $1; exit}' "$TARGET.SHA256SUMS")"
else
  expected="$sha256"
  if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ && -f "$TARGET.CHECKSUM" ]]; then
    expected="$(python3 - "$TARGET.CHECKSUM" "$filename" <<'PY'
import re,sys
path,name=sys.argv[1:]
for line in open(path,encoding='utf-8',errors='replace'):
    if name in line:
        m=re.search(r'(?i)([0-9a-f]{64})',line)
        if m:
            print(m.group(1)); break
PY
    )"
  fi
fi
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die 'no usable expected SHA-256 in lock/receipt'
actual="$(sha256sum "$TARGET" | awk '{print $1}')"
[[ "${actual,,}" == "${expected,,}" ]] || die "SHA-256 mismatch: expected $expected got $actual"
printf '{"image":"%s","path":"%s","sha256":"%s","verified":true}\n' "$IMAGE" "$TARGET" "$actual"
