#!/bin/sh
# This trusted helper is sent inline over SSH; the installer being checked is never
# sourced and is executed only after an immutable, root-owned copy matches exactly.
set -eu

UPLOADED_INSTALLER="${1:-}"
SEALED_INSTALLER="${2:-}"
EXPECTED_SHA256="${3:-}"
EXPECTED_SIZE="${4:-}"
HOST_DIRECTORY="${5:-}"
SEALED_CREATED=0
INSTALL_TIMEOUT_SECONDS=900

die() {
    printf '%s\n' "$1" >&2
    exit 65
}

as_root() {
    sudo -n -- "$@"
}

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$SEALED_CREATED" = "1" ]; then
        as_root rm -f -- "$SEALED_INSTALLER" >/dev/null 2>&1 || true
    fi
    exit "$status"
}

case "$UPLOADED_INSTALLER" in
    /*) ;;
    *) die "Uploaded installer path must be absolute" ;;
esac
case "$SEALED_INSTALLER" in
    /*) ;;
    *) die "Sealed installer path must be absolute" ;;
esac
case "$HOST_DIRECTORY" in
    /*) ;;
    *) die "Update host directory must be absolute" ;;
esac
[ "${#EXPECTED_SHA256}" -eq 64 ] || die "Expected installer sha256 is invalid"
case "$EXPECTED_SHA256" in
    *[!0-9a-f]*) die "Expected installer sha256 is invalid" ;;
esac
case "$EXPECTED_SIZE" in
    ""|*[!0-9]*) die "Expected installer size is invalid" ;;
esac
[ "$EXPECTED_SIZE" -gt 0 ] 2>/dev/null || die "Expected installer size is invalid"
command -v timeout >/dev/null 2>&1 || die "Required installer timeout tool is missing"
as_root true || die "Passwordless noninteractive sudo is required"

trap cleanup EXIT HUP INT TERM

[ -f "$UPLOADED_INSTALLER" ] && [ ! -L "$UPLOADED_INSTALLER" ] \
    || die "Uploaded installer is not a regular file"
[ "$(stat -c %s -- "$UPLOADED_INSTALLER")" = "$EXPECTED_SIZE" ] \
    || die "Uploaded installer size mismatch"
[ "$(sha256sum -- "$UPLOADED_INSTALLER" | awk '{print $1}')" = "$EXPECTED_SHA256" ] \
    || die "Uploaded installer sha256 mismatch"

if as_root test -e "$SEALED_INSTALLER" || as_root test -L "$SEALED_INSTALLER"; then
    die "Sealed installer path already exists"
fi
SEALED_CREATED=1
as_root install -o 0 -g 0 -m 0444 -- "$UPLOADED_INSTALLER" "$SEALED_INSTALLER"
as_root test -f "$SEALED_INSTALLER" && ! as_root test -L "$SEALED_INSTALLER" \
    || die "Sealed installer is not a regular file"
[ "$(as_root stat -c %u:%g:%a -- "$SEALED_INSTALLER")" = "0:0:444" ] \
    || die "Sealed installer ownership or mode mismatch"
[ "$(as_root stat -c %s -- "$SEALED_INSTALLER")" = "$EXPECTED_SIZE" ] \
    || die "Sealed installer size mismatch"
[ "$(as_root sha256sum -- "$SEALED_INSTALLER" | awk '{print $1}')" = "$EXPECTED_SHA256" ] \
    || die "Sealed installer sha256 mismatch"

timeout --signal=TERM --kill-after=60s "${INSTALL_TIMEOUT_SECONDS}s" \
    sh "$SEALED_INSTALLER" "$HOST_DIRECTORY"
as_root rm -f -- "$SEALED_INSTALLER"
SEALED_CREATED=0
trap - EXIT HUP INT TERM
