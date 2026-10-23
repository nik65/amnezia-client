# Native Linux server resource bundle

`AMNEZIA_SERVER_NATIVE_BUNDLE_DIR` is an optional CMake cache PATH. An empty
value preserves existing resources. A supplied invalid bundle stops configuration;
it never silently selects the Python fallback. This importer only reads supplied
reviewed files. It does not build, download, execute, install or publish binaries.

The root contains `manifest.json` and files named `<architecture>/<role>`, where
architecture is `x86_64` or `aarch64` and role is `collector`, `collector-route`
or `awg-feed`. Between one and six unique architecture/role pairs are allowed.
The manifest is canonical Qt compact JSON with sorted object keys, optionally
followed by one LF. Example structure (replace the hash and size with actual
reviewed artifact values):

```json
{"binaries":[{"architecture":"x86_64","path":"x86_64/collector","role":"collector","sha256":"<actual lowercase SHA-256>","size":12345}],"schema":1}
```

Do not use the example as an artifact manifest. Unknown fields, duplicate keys,
duplicate identities, noncanonical JSON, traversal, symlink path components,
missing files, directories, sizes outside 64..33554432 bytes and hash mismatches
are rejected. Manifest input is limited to 16384 bytes. Only immutable, regular
files in an owner-controlled directory are supported: CMake has no portable
atomic no-follow file descriptor or hard-link-count API. Its path checks are
configure-time checks, not protection against a hostile concurrent filesystem
writer. Zero-sized special files are rejected before content reads; do not supply
special files. The embedded runtime independently validates bounded resource bytes.

The importer validates ELF64 little endian Linux/System V ABI version zero,
ET_EXEC, machine type, bounded program table (1..128 headers), all file ranges,
no PT_INTERP or PT_DYNAMIC, executable file-backed entry point, PT_LOAD file size
versus memory size, load page congruence (4096 x86_64, 65536 aarch64), and power-of-two
alignment/congruence. Unlike the runtime uint64 parser, CMake conservatively rejects
coordinates above signed 63 bits and load memory end above INT64_MAX. Static PIE
and dynamically linked executables are intentionally unsupported.

The generated `serverNativeBundle.qrc` embeds the manifest as
`:/server_native/manifest.json` and binaries as `:/server_native/<architecture>/<role>`.
XML paths are escaped, including spaces and ampersands. Inputs are registered as
configuration dependencies. Hash validation is repeated by the runtime validator;
ELF validation is structural and does not prove behavior or acceptance on a server.

Source wiring does not establish production activation. Supplying and accepting
reviewed static Linux artifacts remains a separate task; no digest, binary or
production deployment is synthesized by this import. Existing Python components
remain available when no native bundle is supplied, according to caller policy.
