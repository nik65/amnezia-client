#!/usr/bin/env bash
set -euo pipefail

# User-invoked provisioning flow for a freshly installed Ubuntu headless
# client.  The update tar remains binary-only; this script is deliberately a
# separate package step and never publishes or fetches release artifacts.
PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLIC_KEY="${1:-}"
EXPECTED_KEY_SHA256="${2:-${AMNEZIA_HEADLESS_UPDATE_PUBLIC_KEY_SHA256:-}}"
if [[ -z "$PUBLIC_KEY" || ! -f "$PUBLIC_KEY" || ! "$EXPECTED_KEY_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "usage: $0 /path/to/update-public-key.pem expected-key-sha256" >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "run this provisioning step as root" >&2
    exit 2
fi
for required in systemctl systemd-run getent tar ip ldd sha256sum openssl; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "required runtime command is missing: $required" >&2
        exit 3
    fi
done
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
    && grep -q '"installMode":"fresh-only"' "$PACKAGE_ROOT/package-manifest.json" \
    && grep -q '"distribution":"ubuntu"' "$PACKAGE_ROOT/runtime-dependencies.json" \
    && grep -q '"architectures":\["amd64"\]' "$PACKAGE_ROOT/runtime-dependencies.json" \
    && grep -q '"amneziad"' "$PACKAGE_ROOT/package-manifest.json" \
    && grep -q '"amnezia-cli"' "$PACKAGE_ROOT/package-manifest.json"; }; then
    echo "provisioning package manifest is invalid" >&2
    exit 3
fi
if ! getent group amnezia >/dev/null 2>&1; then
    groupadd --system amnezia
fi

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
echo "headless provisioning complete: service, trust anchor and state directories installed"
