# Build a local server-native resource bundle

The resource bundle contains `collector`, `collector-route` and `awg-feed` for
both `x86_64` and `aarch64`. Build the existing Linux CMake projects below;
the resource importer deliberately does not build or download executables.

| Role | Source directory | Executable target |
|---|---|---|
| collector | `client/server_scripts/client_logs/native` | `amnezia-client-logs-collector` |
| collector-route | `client/server_scripts/client_logs/native_route` | `amnezia-collector-route` |
| awg-feed | `client/server_scripts/awg_migration/native` | `awg_feed_server` |

Use an owned Ubuntu 24.04 build container, with the checkout mounted read-only
and a separate writable output directory. The validated local build used:

```text
ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
```

Preserve the managed proxy configuration. For HTTPS APT, mount the supplied
public CA bundle read-only and pass its container path through
`-o Acquire::https::CaInfo=...`. Keep TLS and APT signature verification enabled.
After `dpkg --add-architecture arm64`, scope the ordinary Noble archive/security
sources to `amd64`; add `arm64` Noble, Noble updates and Noble security sources
from `https://ports.ubuntu.com/ubuntu-ports`. Use the image's Ubuntu archive
keyring for both, with `main universe` components. Install:

```sh
apt-get update
apt-get install -y --no-install-recommends \
  cmake ninja-build g++ g++-aarch64-linux-gnu \
  binutils binutils-aarch64-linux-gnu \
  libssl-dev:amd64 libssl-dev:arm64 \
  libsqlite3-dev:amd64 libsqlite3-dev:arm64 \
  libjson-c-dev:amd64 libjson-c-dev:arm64 rapidjson-dev python3
```

Record the image digest, package versions, compiler/linker versions, static
library hashes and exact commands. APT updates can change inputs: retaining
this inventory and the prepared toolchain is necessary for exact reproduction.

Freeze the actual working-tree bytes before compilation, including new headers;
`git archive HEAD` does not capture uncommitted work. Hash all three source
directories and `client/core/utils/constants/protocolConstants.h`, copy them
with their relative hierarchy, and compare hashes before and after copying.

For each table row and architecture, configure Release with `BUILD_TESTING=OFF`
and build only the named target using `--parallel 1`. Supply these settings:

```text
CMAKE_EXE_LINKER_FLAGS=-static -no-pie
CMAKE_CXX_STANDARD_LIBRARIES=-ldl -lm -lpthread
OPENSSL_USE_STATIC_LIBS=ON
OPENSSL_INCLUDE_DIR=/usr/include
OPENSSL_CRYPTO_LIBRARY=/usr/lib/<triplet>/libcrypto.a
SQLite3_LIBRARY=/usr/lib/<triplet>/libsqlite3.a
JSON_C_LIBRARY=/usr/lib/<triplet>/libjson-c.a
JSON_C_INCLUDE_DIR=/usr/include
RAPIDJSON_INCLUDE_DIR=/usr/include
```

Native uses triplet `x86_64-linux-gnu`. Cross-compilation uses
`CMAKE_SYSTEM_NAME=Linux`, `CMAKE_SYSTEM_PROCESSOR=aarch64`, compiler
`aarch64-linux-gnu-g++`, triplet `aarch64-linux-gnu`, and include directory
`/usr/include/aarch64-linux-gnu`. Add `-Wl,-z,max-page-size=65536` to the cross
linker flags. Keep source/build prefix maps and `SOURCE_DATE_EPOCH` stable when
comparing independent builds. Strip copies with the matching architecture's
`strip`; keep unstripped build outputs and logs separately. Compilation must
not execute the generated server programs.

Place the stripped files at `<architecture>/<role>` beneath the bundle root.
Generate `manifest.json` as compact, sorted-key JSON with one trailing newline:

```python
json.dumps({"binaries": rows, "schema": 1}, sort_keys=True, separators=(",", ":")) + "\n"
```

Each row has exactly `architecture`, `path`, `role`, `sha256` and integer `size`;
`path` is `<architecture>/<role>`. Include all six unique pairs. Compute hashes
from the final bytes, use ordinary files without symlinks, and keep each file
within 32 MiB.

Validate through `client/cmake/serverNativeBundle.cmake` using a CMake script
that includes that file and calls `amnezia_import_server_native_bundle(qrc)`
with `AMNEZIA_SERVER_NATIVE_BUNDLE_DIR` set to the absolute bundle directory.
Run the script from a separate build directory. The same importer runs during
client configuration and checks canonical JSON, hashes, sizes, ELF64 machine,
ET_EXEC, executable entry/load mapping and absence of PT_INTERP/PT_DYNAMIC.

The local six-artifact build passed this importer. Its final x86_64 awg-feed
also passed the offline topology/stopped-topology corpora and config parser
suite; an independently rebuilt x86_64 collector was byte-identical. AArch64
was compiled and inspected only. Static OpenSSL emitted glibc warnings for
dynamic extension and resolver symbols: static ELF acceptance does not prove
provider/resolver compatibility, target-container activation or VPN behavior.
Owned-guest/device acceptance and release publication remain separate gates.
