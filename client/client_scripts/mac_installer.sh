#!/bin/bash

set -euo pipefail

INSTALLER_PATH="${1:-}"
EXPECTED_SHA256="${2:-}"
EXPECTED_SIZE="${3:-}"

if [[ "$INSTALLER_PATH" != /* || ! -f "$INSTALLER_PATH" || -L "$INSTALLER_PATH" ]]; then
    echo "[AmneziaVPN] ERROR: invalid installer package path" >&2
    exit 1
fi
if [[ ! "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "[AmneziaVPN] ERROR: invalid installer SHA-256" >&2
    exit 1
fi
if [[ ! "$EXPECTED_SIZE" =~ ^[0-9]+$ ]]; then
    echo "[AmneziaVPN] ERROR: invalid installer size" >&2
    exit 1
fi

# The privileged process copies the package into a root-owned private directory
# and verifies the signed identity again there. The unprivileged source path is
# never passed directly to installer(8).
ROOT_SCRIPT=$(/bin/cat <<'ROOT_SCRIPT_END'
set -eu
umask 077
source_path=$1
expected_sha=$2
expected_size=$3
root_dir=$(/usr/bin/mktemp -d /private/var/tmp/com.amnezia.vpn.update.XXXXXX)
root_pkg=$root_dir/payload.pkg
sha_file=$root_dir/payload.sha256
cleanup() {
    status=$1
    trap - EXIT HUP INT TERM
    set +e
    /bin/rm -f "$root_pkg" "$sha_file"
    /bin/rmdir "$root_dir"
    exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
/usr/bin/install -o root -g wheel -m 0600 "$source_path" "$root_pkg"
/usr/bin/test -f "$root_pkg"
/usr/bin/test ! -L "$root_pkg"
/usr/bin/test "$(/usr/bin/stat -f %u "$root_pkg")" = 0
actual_size=$(/usr/bin/stat -f %z "$root_pkg")
/usr/bin/test "$actual_size" = "$expected_size"
/usr/bin/shasum -a 256 "$root_pkg" > "$sha_file"
actual_sha=$(/usr/bin/awk '{print $1}' "$sha_file")
/usr/bin/test "$actual_sha" = "$expected_sha"
/usr/sbin/pkgutil --check-signature "$root_pkg"
/usr/sbin/spctl --assess --type install "$root_pkg"
/usr/sbin/installer -pkg "$root_pkg" -target /
ROOT_SCRIPT_END
)

/usr/bin/osascript - "$INSTALLER_PATH" "$EXPECTED_SHA256" "$EXPECTED_SIZE" "$ROOT_SCRIPT" <<'APPLESCRIPT_END'
on run argv
    if (count of argv) is not 4 then error "invalid updater arguments"
    set sourcePath to item 1 of argv
    set expectedSha to item 2 of argv
    set expectedSize to item 3 of argv
    set rootScript to item 4 of argv
    set rootCommand to "/bin/sh -c " & quoted form of rootScript & " amnezia-root " & quoted form of sourcePath & " " & quoted form of expectedSha & " " & quoted form of expectedSize
    do shell script rootCommand with administrator privileges
end run
APPLESCRIPT_END
