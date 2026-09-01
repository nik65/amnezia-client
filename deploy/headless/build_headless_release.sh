#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${1:-}"
OUT_DIR="${2:-$ROOT_DIR/dist/headless-updates}"

if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "usage: $0 x.y.z.w [output-directory]" >&2
    exit 2
fi

BUILD_DIR="$ROOT_DIR/build-headless-release"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amnezia-headless-stage.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

cmake_args=(
    -S "$ROOT_DIR/headless"
    -B "$BUILD_DIR"
    -DCMAKE_BUILD_TYPE=Release
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
