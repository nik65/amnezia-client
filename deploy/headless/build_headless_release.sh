#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${1:-}"
OUT_DIR="${2:-$ROOT_DIR/dist/headless-updates}"

if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "usage: $0 x.y.z.w [output-directory]" >&2
    exit 2
fi

BUILD_DIR="$ROOT_DIR/build-headless-release-$VERSION"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amnezia-headless-stage.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

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
ARCHIVE="$OUT_DIR/AmneziaHeadless_${VERSION}_linux_x64.tar.gz"
tar --create --gzip --file "$ARCHIVE" --directory "$STAGE_DIR/usr/local/bin" \
    --owner=0 --group=0 --numeric-owner --sort=name amneziad amnezia-cli
sha256sum "$ARCHIVE"
echo "headless artifact: $ARCHIVE"

# Publish a separate, operator-invoked provisioning bundle.  The updater
# archive above intentionally stays restricted to the two replaceable
# binaries; this bundle carries the service unit and provisioning contract.
PACKAGE_DIR="$STAGE_DIR/headless-package"
mkdir -p "$PACKAGE_DIR"
install -m 0755 "$ROOT_DIR/deploy/headless/install_headless.sh" "$PACKAGE_DIR/install_headless.sh"
install -m 0755 "$STAGE_DIR/usr/local/bin/amneziad" "$PACKAGE_DIR/amneziad"
install -m 0755 "$STAGE_DIR/usr/local/bin/amnezia-cli" "$PACKAGE_DIR/amnezia-cli"
install -m 0644 "$STAGE_DIR/usr/local/lib/systemd/system/amneziad.service" "$PACKAGE_DIR/amneziad.service"
cat > "$PACKAGE_DIR/package-manifest.json" <<EOF
{"schema":1,"version":"$VERSION","platform":"linux-headless-x64","artifacts":["amneziad","amnezia-cli"],"service":"amneziad.service","trustAnchor":"external-ed25519-sha256-receipt","runtimeManifest":"runtime-dependencies.txt"}
EOF
cat > "$PACKAGE_DIR/runtime-dependencies.txt" <<'EOF'
# Runtime requirements for dynamically linked headless binaries.
# The provisioning preflight validates commands and shared libraries.
Qt6 Core and Network runtime libraries
OpenSSL libcrypto runtime compatible with the build
systemd (systemctl, systemd-run)
iproute2 (ip)
tar (gzip support)
WireGuard/AmneziaWG/OpenVPN/XRay backend binaries as used by imported profiles
EOF
(cd "$PACKAGE_DIR" && sha256sum amneziad amnezia-cli amneziad.service package-manifest.json runtime-dependencies.txt > SHA256SUMS)
PACKAGE_ARCHIVE="$OUT_DIR/AmneziaHeadless_${VERSION}_linux_x64_provisioning.tar.gz"
tar --create --gzip --file "$PACKAGE_ARCHIVE" --directory "$STAGE_DIR" \
    --owner=0 --group=0 --numeric-owner --sort=name headless-package
sha256sum "$PACKAGE_ARCHIVE"
echo "headless provisioning bundle: $PACKAGE_ARCHIVE"
