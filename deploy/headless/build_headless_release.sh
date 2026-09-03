#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${1:-}"
OUT_DIR="${2:-$ROOT_DIR/dist/headless-updates}"

if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "usage: $0 x.y.z.w [output-directory]" >&2
    exit 2
fi
fsync_output_directory() {
    python3 - "$1" <<'PY'
import os
import sys
fd = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

BUILD_DIR="$ROOT_DIR/build-headless-release-$VERSION"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amnezia-headless-stage.XXXXXX")"
cleanup() {
    if [[ -n "${ARCHIVE_TMP:-}" ]]; then rm -f -- "$ARCHIVE_TMP"; fi
    if [[ -n "${PACKAGE_ARCHIVE_TMP:-}" ]]; then rm -f -- "$PACKAGE_ARCHIVE_TMP"; fi
    rm -rf -- "$STAGE_DIR"
}
trap cleanup EXIT

cmake_args=(
    -S "$ROOT_DIR/headless"
    -B "$BUILD_DIR"
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_INSTALL_PREFIX=/usr/local
    -DBUILD_TESTING=OFF
    -DHEADLESS_BUILD_VERSION="$VERSION"
)
# Keep the normal build on the system OpenSSL, while allowing hermetic release
# runners to point at a staged development package without changing the repo's
# dependency policy or requiring root inside WSL/CI.
if [[ -n "${AMNEZIA_HEADLESS_OPENSSL_INCLUDE_DIR:-}" ]]; then
    cmake_args+=("-DOPENSSL_INCLUDE_DIR=${AMNEZIA_HEADLESS_OPENSSL_INCLUDE_DIR}")
fi
if [[ -n "${AMNEZIA_HEADLESS_OPENSSL_CRYPTO_LIBRARY:-}" ]]; then
    cmake_args+=("-DOPENSSL_CRYPTO_LIBRARY=${AMNEZIA_HEADLESS_OPENSSL_CRYPTO_LIBRARY}")
fi

cmake "${cmake_args[@]}"
cmake --build "$BUILD_DIR" --target amneziad amnezia-cli --parallel
DESTDIR="$STAGE_DIR" cmake --install "$BUILD_DIR" --prefix /usr/local --strip

mkdir -p "$OUT_DIR"
ARCHIVE_MTIME="${SOURCE_DATE_EPOCH:-0}"
ARCHIVE="$OUT_DIR/AmneziaHeadless_${VERSION}_linux_x64.tar.gz"
ARCHIVE_TMP="$(mktemp "$OUT_DIR/.AmneziaHeadless_${VERSION}_linux_x64.tar.gz.XXXXXX")"
UPDATE_DIR="$STAGE_DIR/headless-update"
mkdir -p "$UPDATE_DIR"
install -m 0755 "$STAGE_DIR/usr/local/bin/amneziad" "$UPDATE_DIR/amneziad"
install -m 0755 "$STAGE_DIR/usr/local/bin/amnezia-cli" "$UPDATE_DIR/amnezia-cli"
GZIP=-n tar --create --gzip --file "$ARCHIVE_TMP" --directory "$UPDATE_DIR" \
    --owner=0 --group=0 --numeric-owner --sort=name \
    --mtime="@${ARCHIVE_MTIME}" \
    amneziad amnezia-cli
mv -f -- "$ARCHIVE_TMP" "$ARCHIVE"
chmod 0644 "$ARCHIVE"
fsync_output_directory "$OUT_DIR"
sha256sum "$ARCHIVE"
echo "headless artifact: $ARCHIVE"

# Publish a separate, operator-invoked provisioning bundle.  The service unit
# is intentionally part of the provisioning contract only.  The automatic
# updater accepts exactly the two daemon binaries above; changing a systemd
# unit is an operator-controlled installation action.
PACKAGE_DIR="$STAGE_DIR/headless-package"
mkdir -p "$PACKAGE_DIR"
install -m 0755 "$ROOT_DIR/deploy/headless/install_headless.sh" "$PACKAGE_DIR/install_headless.sh"
install -m 0755 "$STAGE_DIR/usr/local/bin/amneziad" "$PACKAGE_DIR/amneziad"
install -m 0755 "$STAGE_DIR/usr/local/bin/amnezia-cli" "$PACKAGE_DIR/amnezia-cli"
install -m 0644 "$STAGE_DIR/usr/local/lib/systemd/system/amneziad.service" "$PACKAGE_DIR/amneziad.service"
cat > "$PACKAGE_DIR/package-manifest.json" <<EOF
{"schema":2,"version":"$VERSION","platform":"linux-headless-x64","installModes":["fresh","upgrade"],"artifacts":["amneziad","amnezia-cli","amneziad.service"],"service":"amneziad.service","servicePaths":["/etc/systemd/system/amneziad.service","/run/systemd/system/amneziad.service","/usr/local/lib/systemd/system/amneziad.service","/usr/lib/systemd/system/amneziad.service","/lib/systemd/system/amneziad.service"],"trustAnchor":"external-ed25519-sha256-receipt","runtimeManifest":"runtime-dependencies.json","checksums":"SHA256SUMS","runtimeText":"runtime-dependencies.txt"}
EOF
cat > "$PACKAGE_DIR/runtime-dependencies.json" <<'EOF'
{"schema":2,"distribution":"ubuntu","architectures":["amd64"],"releases":[
 {"versionId":"22.04","codenames":["jammy"],"packages":[
  {"alternatives":["libc6"],"minimum":"2.35","reason":"glibc runtime"},
  {"alternatives":["libssl3"],"minimum":"3.0","reason":"OpenSSL crypto runtime"},
  {"alternatives":["libqt6core6"],"minimum":"6.2","reason":"Qt6 Core runtime"},
  {"alternatives":["libqt6network6"],"minimum":"6.2","reason":"Qt6 Network runtime"},
  {"alternatives":["systemd"],"minimum":"245","reason":"service and restart supervision"},
  {"alternatives":["iproute2"],"minimum":"5.10","reason":"policy routing"},
  {"alternatives":["tar"],"minimum":"1.30","reason":"update extraction"}
 ]},
 {"versionId":"24.04","codenames":["noble"],"packages":[
  {"alternatives":["libc6"],"minimum":"2.35","reason":"glibc runtime"},
  {"alternatives":["libssl3t64","libssl3"],"minimum":"3.0","reason":"OpenSSL crypto runtime"},
  {"alternatives":["libqt6core6t64","libqt6core6"],"minimum":"6.4","reason":"Qt6 Core runtime"},
  {"alternatives":["libqt6network6t64","libqt6network6"],"minimum":"6.4","reason":"Qt6 Network runtime"},
  {"alternatives":["systemd"],"minimum":"255","reason":"service and restart supervision"},
  {"alternatives":["iproute2"],"minimum":"6.1","reason":"policy routing"},
  {"alternatives":["tar"],"minimum":"1.34","reason":"update extraction"}
 ]}
] ,"commands":{"required":["systemctl","systemd-run","getent","ip","resolvectl","readlink","readelf","ldd","sha256sum","openssl","python3","dpkg-query","dpkg","groupadd","groupdel","install","chown","chmod","mktemp","grep","awk","cmp","flock"],"backendModes":[{"mode":"native-tunnel","alternatives":["wg-quick","awg-quick","openvpn"]},{"mode":"proxy","alternatives":["xray"]}]}}
EOF
cat > "$PACKAGE_DIR/runtime-dependencies.txt" <<'EOF'
# Runtime requirements for dynamically linked headless binaries.
# The provisioning preflight validates commands and shared libraries.
Qt6 Core and Network runtime libraries
OpenSSL libcrypto runtime compatible with the build
systemd (systemctl, systemd-run)
util-linux (flock)
iproute2 (ip)
tar (gzip support)
WireGuard/AmneziaWG/OpenVPN/XRay backend binaries as used by imported profiles
EOF
(cd "$PACKAGE_DIR" && sha256sum install_headless.sh amneziad amnezia-cli amneziad.service package-manifest.json runtime-dependencies.json runtime-dependencies.txt > SHA256SUMS)
echo "headless package manifest sha256: $(sha256sum "$PACKAGE_DIR/package-manifest.json" | awk '{print $1}')"
echo "headless package checksums sha256: $(sha256sum "$PACKAGE_DIR/SHA256SUMS" | awk '{print $1}')"
PACKAGE_ARCHIVE="$OUT_DIR/AmneziaHeadless_${VERSION}_linux_x64_provisioning.tar.gz"
PACKAGE_ARCHIVE_TMP="$(mktemp "$OUT_DIR/.AmneziaHeadless_${VERSION}_linux_x64_provisioning.tar.gz.XXXXXX")"
GZIP=-n tar --create --gzip --file "$PACKAGE_ARCHIVE_TMP" --directory "$STAGE_DIR" \
    --owner=0 --group=0 --numeric-owner --sort=name \
    --mtime="@${ARCHIVE_MTIME}" headless-package
mv -f -- "$PACKAGE_ARCHIVE_TMP" "$PACKAGE_ARCHIVE"
chmod 0644 "$PACKAGE_ARCHIVE"
fsync_output_directory "$OUT_DIR"
sha256sum "$PACKAGE_ARCHIVE"
echo "headless provisioning bundle: $PACKAGE_ARCHIVE"
