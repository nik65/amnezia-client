#!/usr/bin/env bash
# One-call refresh of the self-hosted update manifest for a release bundle.
#
# What it does, in order:
#   1. regenerates the signed manifest with deploy/selfhosted_updates/make_manifest.py
#      and ALWAYS passes --auto-install (the release lab manifest contract in
#      lab.py:927-929 rejects a manifest whose payload or platform entry lacks
#      autoInstall=true, and the failure only shows up much later in the gate);
#   2. writes the headless provisioning receipt by verifying the published
#      provisioning bundle against the freshly signed manifest
#      (deploy/headless/verify_provisioning_bundle.py --receipt-out);
#   3. lays the result out into the requested directory:
#          <dir>/updates/manifest.json + updates/files/artifacts/<sha256>/...
#          <dir>/verification/headless-provisioning-verifier-receipt.json
#      optionally copying the input artifacts into <dir>/artifacts/ (--copy-artifacts).
#      The manifest directory is REPLACED atomically by make_manifest.py, so every
#      input (artifacts, provisioning bundle, keys) must live outside it; the
#      script refuses to run when an input would be destroyed.  Pass
#      --manifest-dir <dir> for a flat HTTP-root layout (manifest.json + files/
#      directly in <dir>), with the artifacts somewhere outside <dir>;
#   4. re-reads the produced manifest and asserts the lab contract
#      (version, autoInstall=true in payload AND in every platform entry,
#      relative artifact URLs, headlessProvisioning present for headless).
#
# Defaults are the ones actually used for the 5.0.1.39 release bundles:
#   private key  : C:/keys/selfhosted-update-private.pem
#   public key   : C:/keys/selfhosted-update-public.pem
#   pubkey b64   : base64 of the public-key PEM (same value used in the build logs)
#   policy       : --payload-schema 1 --channel stable --rollout-percentage 100
#                  --cohort-salt-id fleet-v1 --health-deadline-seconds 600
#                  --policy-valid-for-hours 168
#   base url     : http://10.8.1.0:17865
#
# Pitfalls (learned live):
#   * never redirect this script's own output into <dir> (or into --manifest-dir):
#     make_manifest.py replaces that whole tree, and on Windows an open log file
#     inside the replaced tree makes the replacement fail;
#   * the inputs must stay outside the manifest tree -- the script refuses to run
#     when an artifact, provisioning bundle or key would be destroyed.
#
# Examples:
#   Testing/refresh_manifest.sh --version 5.0.1.39 --dir dist/full-release-5.0.1.39-20260915
#   Testing/refresh_manifest.sh --version 5.0.1.39 --dir /tmp/update-host \
#       --base-url http://172.29.172.252:17865 --artifact linux-headless-x64=dist/x.tar.gz \
#       --provisioning dist/x_provisioning.tar.gz --manifest-dir /tmp/update-host
#
# Exit codes: 0 ok, 2 usage/input error, 3 manifest generation failed,
#             4 provisioning receipt failed, 5 contract verification failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION=""
DIR=""
BASE_URL="http://10.8.1.0:17865"
MANIFEST_DIR=""
RECEIPT_DIR=""
ARTIFACTS_DIR=""
KEYS_DIR="${KEYS_DIR:-C:/keys}"
PRIVATE_KEY="${SELFHOSTED_UPDATE_PRIVATE_KEY_PATH:-}"
PUBLIC_KEY=""
PUBLIC_KEY_BASE64=""
EXPECTED_PUBLIC_KEY_SHA256=""
PROVISIONING=""
ANDROID_VERSION_CODE=""
PAYLOAD_SCHEMA="1"
CHANNEL="stable"
ROLLOUT_PERCENTAGE="100"
COHORT_SALT_ID="fleet-v1"
HEALTH_DEADLINE_SECONDS="600"
POLICY_VALID_FOR_HOURS="168"
COPY_ARTIFACTS=0
ARTIFACT_ARGS=()

usage() { # optional exit code (default 2)
    # print the header comment block (everything between line 2 and usage())
    local last
    last="$(grep -n '^usage()' "${BASH_SOURCE[0]}" | head -n 1 | cut -d: -f1)"
    sed -n "2,$(( last - 1 ))p" "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  --version V            release version x.y.z.w (required)
  --dir DIR              bundle directory for the layout (required)
  --base-url URL         update host base URL (default: http://10.8.1.0:17865)
  --artifact PLATFORM=PATH   artifact to publish (repeatable; default: auto-discover)
  --provisioning PATH    headless provisioning bundle (default: auto-discover)
  --android-version-code N   required only for Android payload-schema 2 releases
  --manifest-dir DIR     where manifest.json + files/ land (default: <dir>/updates;
                         pass --manifest-dir <dir> for a flat HTTP root)
  --receipt-dir DIR      where the provisioning receipt lands (default: <dir>/verification)
  --artifacts-dir DIR    artifact discovery/copy root (default: <dir>/artifacts)
  --copy-artifacts       copy input artifacts into <artifacts-dir>
  --private-key PATH     Ed25519 private key PEM (default: C:/keys/selfhosted-update-private.pem)
  --public-key PATH      Ed25519 public key PEM (default: C:/keys/selfhosted-update-public.pem)
  --public-key-base64 S  public key PEM base64 as embedded in the manifest (default: derived)
  --expected-public-key-sha256 HEX  override the pinned key fingerprint (default: sha256 of --public-key)
  --payload-schema N     signed payload schema (default: 1)
  --channel NAME         release channel policy (default: stable)
  --rollout-percentage N rollout percentage (default: 100)
  --cohort-salt-id ID    cohort salt id (default: fleet-v1)
  --health-deadline-seconds N  (default: 600)
  --policy-valid-for-hours N   (default: 168)
EOF
    exit "${1:-2}"
}

die() { echo "refresh_manifest: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --dir) DIR="${2:?--dir needs a value}"; shift 2 ;;
        --base-url) BASE_URL="${2:?--base-url needs a value}"; shift 2 ;;
        --artifact) ARTIFACT_ARGS+=("${2:?--artifact needs a value}"); shift 2 ;;
        --provisioning) PROVISIONING="${2:?--provisioning needs a value}"; shift 2 ;;
        --android-version-code) ANDROID_VERSION_CODE="${2:?}"; shift 2 ;;
        --manifest-dir) MANIFEST_DIR="${2:?}"; shift 2 ;;
        --receipt-dir) RECEIPT_DIR="${2:?}"; shift 2 ;;
        --artifacts-dir) ARTIFACTS_DIR="${2:?}"; shift 2 ;;
        --copy-artifacts) COPY_ARTIFACTS=1; shift ;;
        --private-key) PRIVATE_KEY="${2:?}"; shift 2 ;;
        --public-key) PUBLIC_KEY="${2:?}"; shift 2 ;;
        --public-key-base64) PUBLIC_KEY_BASE64="${2:?}"; shift 2 ;;
        --expected-public-key-sha256) EXPECTED_PUBLIC_KEY_SHA256="${2:?}"; shift 2 ;;
        --payload-schema) PAYLOAD_SCHEMA="${2:?}"; shift 2 ;;
        --channel) CHANNEL="${2:?}"; shift 2 ;;
        --rollout-percentage) ROLLOUT_PERCENTAGE="${2:?}"; shift 2 ;;
        --cohort-salt-id) COHORT_SALT_ID="${2:?}"; shift 2 ;;
        --health-deadline-seconds) HEALTH_DEADLINE_SECONDS="${2:?}"; shift 2 ;;
        --policy-valid-for-hours) POLICY_VALID_FOR_HOURS="${2:?}"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

[[ -n "$VERSION" ]] || die "--version is required"
[[ -n "$DIR" ]] || die "--dir is required"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die "--version must be x.y.z.w, got: $VERSION"
[[ -n "$BASE_URL" ]] || die "--base-url must not be empty"

# git-bash/MSYS: native python needs C:/... paths, not /c/... or relative MSYS paths.
is_msys() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*) return 0 ;;
        *) return 1 ;;
    esac
}
to_native() {
    local value="$1"
    if is_msys && command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$value"
    else
        printf '%s' "$value"
    fi
}
abs_path() {
    local value="$1"
    [[ "$value" = /* || "$value" =~ ^[A-Za-z]:[/\\] ]] || value="$REPO_ROOT/$value"
    # normalize git-bash drive paths (C:\x\y -> C:/x/y) so reported paths stay readable
    if [[ "$value" =~ ^[A-Za-z]:[\\/] ]]; then
        value="$(printf '%s' "$value" | sed 's#\\#/#g')"
    fi
    printf '%s' "$value"
}

sha_of() { # hash of a file, immune to sha256sum filename escaping
    sha256sum < "$1" | awk '{print $1}'
}

canon() { # physical path of an existing file/dir (best effort)
    local path="$1"
    if [ -d "$path" ]; then
        ( cd "$path" && pwd -P )
    elif [ -f "$path" ]; then
        printf '%s/%s' "$( cd "$(dirname "$path")" && pwd -P )" "$(basename "$path")"
    else
        printf '%s' "$path"
    fi
}

within() { # $1 path, $2 directory: is the path inside the directory?
    local target parent
    target="$(canon "$1")"
    parent="$(canon "$2")"
    case "$target" in
        "$parent"|"$parent"/*) return 0 ;;
    esac
    return 1
}

PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
    for candidate in python3 python; do
        command -v "$candidate" >/dev/null 2>&1 || continue
        # git-bash exposes a broken WindowsApps python3 alias that exits 49
        resolved="$(command -v "$candidate")"
        case "$resolved" in
            *WindowsApps*) continue ;;
        esac
        if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
            PYTHON="$candidate"
            break
        fi
    done
fi
[[ -n "$PYTHON" ]] || die "no working python3/python on PATH (set PYTHON=...)"
if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    die "PYTHON=$PYTHON is not a working Python >= 3.8"
fi

DIR="$(abs_path "$DIR")"
MANIFEST_DIR="${MANIFEST_DIR:-$DIR/updates}"
RECEIPT_DIR="${RECEIPT_DIR:-$DIR/verification}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$DIR/artifacts}"
MANIFEST_DIR="$(abs_path "$MANIFEST_DIR")"
RECEIPT_DIR="$(abs_path "$RECEIPT_DIR")"
ARTIFACTS_DIR="$(abs_path "$ARTIFACTS_DIR")"
# WSL sees the Windows key directory under /mnt/c; prefer whichever exists.
if [[ ! -f "$KEYS_DIR/selfhosted-update-private.pem" && -f "/mnt/c/keys/selfhosted-update-private.pem" ]]; then
    KEYS_DIR="/mnt/c/keys"
fi
PRIVATE_KEY="${PRIVATE_KEY:-$KEYS_DIR/selfhosted-update-private.pem}"
PUBLIC_KEY="${PUBLIC_KEY:-$KEYS_DIR/selfhosted-update-public.pem}"

[[ -f "$PRIVATE_KEY" ]] || die "private key not found: $PRIVATE_KEY"
[[ -f "$PUBLIC_KEY" ]] || die "public key not found: $PUBLIC_KEY"
MAKE_MANIFEST="$REPO_ROOT/deploy/selfhosted_updates/make_manifest.py"
VERIFY_BUNDLE="$REPO_ROOT/deploy/headless/verify_provisioning_bundle.py"
[[ -f "$MAKE_MANIFEST" ]] || die "make_manifest.py not found: $MAKE_MANIFEST"
[[ -f "$VERIFY_BUNDLE" ]] || die "verify_provisioning_bundle.py not found: $VERIFY_BUNDLE"

if [[ -z "$PUBLIC_KEY_BASE64" ]]; then
    PUBLIC_KEY_BASE64="$(base64 -w0 "$(to_native "$PUBLIC_KEY")" 2>/dev/null || base64 "$PUBLIC_KEY" | tr -d '\n')"
fi
if [[ -z "$EXPECTED_PUBLIC_KEY_SHA256" ]]; then
    EXPECTED_PUBLIC_KEY_SHA256="$(sha_of "$PUBLIC_KEY")"
fi

mkdir -p "$MANIFEST_DIR" "$RECEIPT_DIR" "$ARTIFACTS_DIR"

discover_artifact() {
    # $1 = platform, remaining args = candidate patterns, best first.
    # A pattern without '*' is matched exactly; with '*' the shortest name wins
    # (e.g. the thin windows installer beats ..._windows_x64_selfhosted.exe).
    local platform="$1"; shift
    local pattern match chosen
    for pattern in "$@"; do
        match=""
        case "$pattern" in
            *'*')
                match="$(find "$ARTIFACTS_DIR" -maxdepth 1 -type f -name "$pattern" ! -name '*provisioning*' 2>/dev/null | sort | awk '{ print length($0), $0 }' | sort -n | head -n 1 | cut -d' ' -f2-)"
                ;;
            *)
                if [ -f "$ARTIFACTS_DIR/$pattern" ]; then
                    match="$ARTIFACTS_DIR/$pattern"
                fi
                ;;
        esac
        if [ -n "$match" ]; then
            ARTIFACT_ARGS+=("$platform=$match")
            echo "    discovered $platform -> $match"
            return 0
        fi
    done
    return 1
}

if [[ ${#ARTIFACT_ARGS[@]} -eq 0 ]]; then
    echo "==> no --artifact given; discovering in $ARTIFACTS_DIR"
    discover_artifact windows-x64 \
        "AmneziaVPN_${VERSION}_windows_x64.exe" \
        "AmneziaVPN_${VERSION}_windows_x64*.exe" || true
    discover_artifact linux-x64 \
        "AmneziaVPN_${VERSION}_linux_x64.run" \
        "AmneziaVPN_${VERSION}_linux_x64*.run" || true
    discover_artifact android-arm64-v8a \
        "AmneziaVPN_${VERSION}_android9+_arm64-v8a.apk" \
        "AmneziaVPN_${VERSION}_*arm64-v8a*.apk" || true
    discover_artifact linux-headless-x64 \
        "AmneziaHeadless_${VERSION}_linux_x64.tar.gz" \
        "AmneziaHeadless_${VERSION}_linux_x64*.tar.gz" || true
    [[ ${#ARTIFACT_ARGS[@]} -gt 0 ]] || die "no artifacts found for $VERSION in $ARTIFACTS_DIR (pass --artifact)"
else
    for entry in "${ARTIFACT_ARGS[@]}"; do
        [[ "$entry" == *=* ]] || die "--artifact must be PLATFORM=PATH, got: $entry"
        file="${entry#*=}"
        [[ -f "$(abs_path "$file")" ]] || die "artifact file not found: $file"
    done
fi

HEADLESS_ARTIFACT=""
PLATFORMS=()
for entry in "${ARTIFACT_ARGS[@]}"; do
    platform="${entry%%=*}"
    PLATFORMS+=("$platform")
    if [[ "$platform" == "linux-headless-x64" ]]; then
        HEADLESS_ARTIFACT="${entry#*=}"
    fi
done

if [[ -z "$PROVISIONING" && -n "$HEADLESS_ARTIFACT" ]]; then
    PROVISIONING="$(find "$ARTIFACTS_DIR" -maxdepth 1 -type f -name "*provisioning*.tar.gz" 2>/dev/null | sort | tail -n 1)"
fi
if [[ -n "$PROVISIONING" ]]; then
    [[ -f "$(abs_path "$PROVISIONING")" ]] || die "provisioning bundle not found: $PROVISIONING"
elif [[ -n "$HEADLESS_ARTIFACT" ]]; then
    die "linux-headless-x64 is present but no provisioning bundle was found (--provisioning)"
fi

if [[ "$COPY_ARTIFACTS" -eq 1 ]]; then
    for entry in "${ARTIFACT_ARGS[@]}"; do
        source_file="$(abs_path "${entry#*=}")"
        target_file="$ARTIFACTS_DIR/$(basename "$source_file")"
        if [[ "$source_file" != "$target_file" ]]; then
            cp -f "$source_file" "$target_file"
        fi
    done
    if [[ -n "$PROVISIONING" ]]; then
        source_file="$(abs_path "$PROVISIONING")"
        target_file="$ARTIFACTS_DIR/$(basename "$source_file")"
        [[ "$source_file" == "$target_file" ]] || cp -f "$source_file" "$target_file"
    fi
fi

# make_manifest.py replaces its --out-dir atomically: it renames the previous
# tree away and deletes it afterwards.  Anything stored inside the manifest
# directory is therefore destroyed by a refresh, so refuse when an input lives
# there instead of silently deleting release artifacts.
if [[ "$(canon "$MANIFEST_DIR")" == "$(canon "$ARTIFACTS_DIR")" ]]; then
    die "--manifest-dir and --artifacts-dir must differ: the manifest directory is replaced atomically (point --artifacts-dir at a sibling directory)"
fi
if [[ "$(canon "$MANIFEST_DIR")" == "$(canon "$RECEIPT_DIR")" ]]; then
    die "--manifest-dir and --receipt-dir must differ: the manifest directory is replaced atomically"
fi
for input in "$PRIVATE_KEY" "$PUBLIC_KEY"; do
    if within "$input" "$MANIFEST_DIR"; then
        die "input $input lives inside the manifest directory $MANIFEST_DIR, which make_manifest.py replaces atomically; keep inputs outside it"
    fi
done
if [[ -n "$PROVISIONING" ]] && within "$(abs_path "$PROVISIONING")" "$MANIFEST_DIR"; then
    die "provisioning bundle lives inside the manifest directory $MANIFEST_DIR, which is replaced atomically; move it outside (e.g. --artifacts-dir)"
fi
for entry in "${ARTIFACT_ARGS[@]}"; do
    input="$(abs_path "${entry#*=}")"
    if within "$input" "$MANIFEST_DIR"; then
        die "artifact $input lives inside the manifest directory $MANIFEST_DIR, which make_manifest.py replaces atomically; move the artifacts outside it (e.g. --artifacts-dir <dir>/artifacts)"
    fi
done

echo "==> manifest refresh for $VERSION"
echo "    dir        : $DIR"
echo "    manifest   : $MANIFEST_DIR/manifest.json (this tree is replaced atomically)"
echo "    receipt    : $RECEIPT_DIR/headless-provisioning-verifier-receipt.json"
echo "    private key: $PRIVATE_KEY"
echo "    public key : $PUBLIC_KEY (sha256 $EXPECTED_PUBLIC_KEY_SHA256)"

make_args=(
    "$(to_native "$MAKE_MANIFEST")"
    --version "$VERSION"
    --base-url "$BASE_URL"
    --private-key "$(to_native "$PRIVATE_KEY")"
    --public-key-base64 "$PUBLIC_KEY_BASE64"
    --out-dir "$(to_native "$MANIFEST_DIR")"
    --auto-install
    --payload-schema "$PAYLOAD_SCHEMA"
    --channel "$CHANNEL"
    --rollout-percentage "$ROLLOUT_PERCENTAGE"
    --cohort-salt-id "$COHORT_SALT_ID"
    --health-deadline-seconds "$HEALTH_DEADLINE_SECONDS"
    --policy-valid-for-hours "$POLICY_VALID_FOR_HOURS"
)
if [[ -n "$ANDROID_VERSION_CODE" ]]; then
    make_args+=(--android-version-code "$ANDROID_VERSION_CODE")
fi
if [[ -n "$PROVISIONING" ]]; then
    make_args+=(--headless-provisioning "$(to_native "$(abs_path "$PROVISIONING")")")
fi
for entry in "${ARTIFACT_ARGS[@]}"; do
    platform="${entry%%=*}"
    file="$(to_native "$(abs_path "${entry#*=}")")"
    make_args+=(--require-platform "$platform" --artifact "$platform=$file")
done

echo "==> [1/3] regenerating signed manifest (--auto-install)"
if ! "$PYTHON" "${make_args[@]}"; then
    echo "refresh_manifest: manifest generation failed" >&2
    exit 3
fi
MANIFEST_PATH="$MANIFEST_DIR/manifest.json"
[[ -f "$MANIFEST_PATH" ]] || { echo "refresh_manifest: manifest.json was not produced" >&2; exit 3; }

PROVISIONING_RECEIPT=""
if [[ -n "$PROVISIONING" ]]; then
    PROVISIONING_RECEIPT="$RECEIPT_DIR/headless-provisioning-verifier-receipt.json"
    echo "==> [2/3] verifying provisioning bundle and writing receipt"
    if ! "$PYTHON" "$(to_native "$VERIFY_BUNDLE")" \
        --manifest "$(to_native "$MANIFEST_PATH")" \
        --public-key "$(to_native "$PUBLIC_KEY")" \
        --expected-public-key-sha256 "$EXPECTED_PUBLIC_KEY_SHA256" \
        --provisioning "$(to_native "$(abs_path "$PROVISIONING")")" \
        --receipt-out "$(to_native "$PROVISIONING_RECEIPT")"; then
        echo "refresh_manifest: provisioning receipt failed" >&2
        exit 4
    fi
else
    echo "==> [2/3] no provisioning bundle in this release; receipt skipped"
fi

echo "==> [3/3] verifying the lab manifest contract"
CONTRACT_OUTPUT="$("$PYTHON" - "$(to_native "$MANIFEST_PATH")" "$VERSION" "$PAYLOAD_SCHEMA" <<'PY'
import base64, json, sys
path, version, schema = sys.argv[1], sys.argv[2], sys.argv[3]
doc = json.load(open(path, encoding="utf-8"))
if doc.get("schema") != "amnezia-selfhosted-update-v1" or doc.get("signatureAlgorithm") != "Ed25519":
    raise SystemExit("manifest envelope schema/signature algorithm is invalid")
encoded = str(doc.get("payload") or "")
payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8"))
problems = []
if payload.get("version") != version:
    problems.append("payload version %r != %r" % (payload.get("version"), version))
if str(payload.get("schema")) != schema:
    problems.append("payload schema %r != %r" % (payload.get("schema"), schema))
if payload.get("autoInstall") is not True:
    problems.append("payload autoInstall is not true (lab.py:927 contract)")
platforms = payload.get("platforms") or {}
if not platforms:
    problems.append("no platform entries")
for name, item in sorted(platforms.items()):
    if not isinstance(item, dict):
        problems.append("%s entry is not an object" % name)
        continue
    if item.get("openExternal") is True:
        continue
    if item.get("autoInstall") is not True:
        problems.append("%s autoInstall is not true (lab.py:929 contract)" % name)
    if not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64:
        problems.append("%s sha256 is missing" % name)
    if not isinstance(item.get("size"), int) or isinstance(item.get("size"), bool) or item["size"] <= 0:
        problems.append("%s size is missing" % name)
    if name.endswith("linux-headless-x64") or "headless" in name:
        if isinstance(item.get("format"), str) is False or not item.get("format"):
            problems.append("%s format is missing" % name)
    url = item.get("url")
    if not isinstance(url, str) or not url:
        problems.append("%s url is missing" % name)
    elif url.startswith("/") or ".." in url.split("/"):
        problems.append("%s url is not a safe relative path: %s" % (name, url))
if "linux-headless-x64" in platforms and not isinstance(payload.get("headlessProvisioning"), dict):
    problems.append("headlessProvisioning metadata is missing")
if problems:
    print("CONTRACT_PROBLEMS " + " | ".join(problems))
    raise SystemExit(1)
summary = ", ".join(
    "%s=%s" % (name, (platforms[name] or {}).get("sha256", "")[:12]) for name in sorted(platforms)
)
print("CONTRACT_OK version=%s schema=%s autoInstall=%s platforms=[%s]" % (version, payload.get("schema"), payload.get("autoInstall"), summary))
PY
)" || {
    echo "$CONTRACT_OUTPUT" >&2
    echo "refresh_manifest: produced manifest violates the lab contract" >&2
    exit 5
}

echo ""
echo "=== refresh_manifest summary ==="
echo "version    : $VERSION"
echo "base url   : $BASE_URL"
( cd "$(dirname "$MANIFEST_PATH")" && echo "manifest   : $MANIFEST_PATH ($(wc -c < "$MANIFEST_PATH" | tr -d ' ') bytes)" )
echo "manifest sha256: $(sha_of "$MANIFEST_PATH")"
[[ -n "$PROVISIONING_RECEIPT" ]] && echo "receipt    : $PROVISIONING_RECEIPT"
for entry in "${ARTIFACT_ARGS[@]}"; do
    file="$(abs_path "${entry#*=}")"
    printf 'artifact   : %s %s %s\n' "${entry%%=*}" "$(sha_of "$file")" "$file"
done
echo "$CONTRACT_OUTPUT" | sed 's/^/contract   : /'
echo "OK"
