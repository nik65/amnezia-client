# Native client-log collector (standalone)

This Linux C++17 executable implements the working collector runtime: bounded HTTP,
authentication and scoped legacy bootstrap, durable files plus SQLite batch receipts,
replay/body conflict checks, process locks, health probes and retention. It uses
OpenSSL Crypto, SQLite3 and POSIX sockets/filesystem APIs; no Python runtime is used
by the executable. Python remains a test driver.

The exporter has an optional reviewed static-bundle source path for this
collector and its route helper. Without that bundle, legacy Python remains the
default; invalid supplied bundles fail closed. No real static bundle, server
deployment or application release was made. See docs/python-runtime-migration.md.

Build on Linux with CMake 3.20+, a C++17 compiler, OpenSSL development files and
SQLite3 development files:

```sh
cmake -S client/server_scripts/client_logs/native -B /tmp/collector-build -DBUILD_TESTING=ON
cmake --build /tmp/collector-build -j4
ctest --test-dir /tmp/collector-build --output-on-failure
```

Run only in a deliberately selected data root. Defaults match the existing server
contract: `/data`, port 17866, `/logs`, `/bootstrap`; `--root`, `--bind`, `--port`,
`--upload-path`, `--bootstrap-path` customize those deployment coordinates.
`AMNEZIA_CLIENT_LOGS_BOOTSTRAP=1` plus `AMNEZIA_CLIENT_LOGS_SCOPE` enables scoped
bootstrap. Ordinary bridge startup keeps bootstrap disabled. Tokens and legacy
mapping files keep their existing names and formats. The executable creates and
protects its owned data root and children; it is not a read-only inspection tool.

Defaults retain 4096 log files / 30 MiB per client, 8192 / 512 MiB globally,
30-day log age and 35-day receipt age. These are bounded quotas, not a guarantee
of arbitrary 24-hour retention. Receipts survive file pruning. A 204 response is
sent only after durable receipt/file handling; a repeated batch with different
body bytes receives 409. Header authentication precedes upload body materialization.
The HTTP server bounds handlers (16), simultaneous body buffers (4), header/body
size and elapsed read time, and closes each connection after one request.

Tests exercise real temporary files and SQLite, concurrent commits and global
quotas, the observed 1706+1687 small-chunk cadence, schema/recovery/replay paths,
legacy duplicate-IP/extra-column compatibility and invalid locks. Socket tests
cover framing, deadlines, admission limits and shutdown. Six blackbox tests run
the actual executable on loopback and verify ACK persistence and rejected requests.
Stored-file crash recovery hashes with a fixed 64 KiB buffer, including a 15 MiB regression, rather than duplicating the upload payload in memory. Global receipt age/count pruning also runs every 256 receipt-record calls, matching the existing collector. They do not exercise production Docker/network namespaces or power-loss hardware. Compatibility with the current 96 MiB container memory budget remains pending actual image-level stress tests.

Before activating delivery:

1. Build Linux architecture-specific binaries in a reviewed builder image pinned
   to a verified digest. Select the real builder/runtime image and record its
   provenance; no digest is assumed here. Verify libc/OpenSSL/SQLite compatibility
   (the current Python Alpine image uses musl, unlike this local Ubuntu build).
2. Package the binary and required runtime libraries, or a reviewed static build,
   through CMake and Qt resources/source assets. Bind every deployed byte to a
   manifest and preserve current pinned image and ownership checks.
3. Update exporter startup, entrypoint and route-helper process identity together.
   The separate native route helper has its own json-c dependency. Keep the old
   path until this complete delivery has passed disposable-container parity,
   restart/crash, storage permission and namespace/ownership tests.
4. Only then switch production generation under a separate reviewed change.
   Never silently compile on or modify the production server during export.

A later owned-process stress found allocator retention across 16 workers: four
simultaneous 15 MiB uploads followed by recovery/replay waves reached 138944 KiB
RSS. The HTTP server now reuses exactly four server-owned payload buffers,
retaining exclusive ownership through the synchronous handler and response. The
same baseline scenario measured 80880 KiB after the fix. A permanent loopback
CTest repeats multi-wave payloads, health and receipt maintenance and requires
the child process RSS below 96 MiB. This does not replace container aggregate
memory/ABI validation or authorize production delivery.

The 2026-10-21 audit also reproduced per-authentication materialization of large
allowlists: four rejected requests could exceed the 96 MiB process RSS budget.
Authentication, legacy resolution and health validation now scan bounded rows,
without a persistent map cache; the 16 MiB file allowance and duplicate semantics
remain. A 200,004-row / 15,800,316-byte allowlist plus rejected requests, twelve
15 MiB uploads and health probes measured 81,656 KiB (final optimized standalone check) child RSS. Image/cgroup
aggregate acceptance remains pending. Evidence:
`dist/diagnostics/python-native-resume-20261021/audit/`.

## Unresolved bootstrap memory finding (2026-10-21)

The passing upload/authentication stress does not cover scoped legacy bootstrap.
One legitimate loopback bootstrap with a 15,800,079-byte / 200,001-row allowlist
returned HTTP 200 but reached 99,828 KiB child VmHWM, above the 98,304 KiB process
budget. Bootstrap still materializes the allowlist and serialized replacement;
this path is not fixed and must not be reported as memory acceptance. The probe
used only an owned temporary root and process; no image/cgroup or production
runtime was tested. Evidence and source/binary hashes:
`dist/diagnostics/python-native-journal-20261021/collector-bootstrap/receipt.json`.
No runtime source or deployment change is implied by this finding.
