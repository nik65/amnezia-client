# Read-only native ready attestation

`validateReadyTarget` ports the runtime dump/showconf/engine comparisons from
`ready_validation.validate_ready_target`. `validateExistingTarget` also checks
generation and endpoint mappings, exact source SHA-256, source and target
configuration bytes, peer IP mappings and approved running-engine identity.
All process execution is injected through `ProcessRunner`; these functions never
invoke a shell or Docker themselves. The fixed engine-proof shell fragment is
passed as one argument to the same container command as the Python oracle.
No runner implementation is supplied here, and the standalone probe only accepts
synthetic FakeRunner answers. This is not activated in production recipes.

Interface: `ready_attestation.h`; library sources `ready_attestation.cpp` and
`ready_config.cpp`; dependencies json-c and OpenSSL Crypto. Linux C++17.
Test-only probe: `test_ready_attestation_probe.cpp`. Run differential tests with
`python3 test_ready_attestation_parity.py --probe /path/to/probe`.

Explicit stricter boundaries relative to Python:

- A target directory must be an absolute path without trailing `/`, empty, `.`
  or `..` components. Every directory ancestor is traversed with descriptor-relative
  `openat(O_DIRECTORY|O_NOFOLLOW)` from a pinned `/` descriptor; ancestor and final
  symlinks are rejected.
- The target configuration is opened relative to a pinned directory with
  `O_NOFOLLOW|O_NONBLOCK`, must be a single-link regular file at most 1 MiB,
  and must preserve device/inode/size/mtime/ctime during the descriptor read.
  Its final pathname must still identify that inode after the read. Every pinned
  ancestor edge is checked again against its parent descriptor, and the absolute
  path is reopened without following symlinks to verify the leaf directory still
  has the same device/inode. A directory rename/replacement during the config
  read therefore fails instead of validating the detached old directory.
- Source configuration is bounded to 1 MiB, dump/showconf to 16 MiB each,
  and engine proof to 4096 bytes. Runner-level allocation/time limits are still
  required because returned process output is already materialized.
- Duplicate observed parameter entries fail instead of Python's last-value-wins.
- Contract identities and parameter values must be NUL-free JSON strings; request port
  accepts a JSON integer or string. Both generation fields must be exact JSON
  integers in `1..9007199254740991`, equal to one another. Booleans, floats,
  strings, zero, negatives and values above the interoperable integer range fail.
- Runtime `showconf` trimming handles ASCII whitespace; persisted configuration
  parsing retains the Unicode behavior of the shared `parseConfig` parser.

Pinned directory traversal rejects all symlink ancestors; callers must still
provide the intended generation path. This does not claim to freeze files
against a privileged writer after the attestation returns.

The 40 differential/strict cases include valid automatic/manual attestation,
private key/address/PSK/route/parameter/port/server-key drift, absent or additional
peers, boolean and default-zero padding handling, native-engine proof mismatch,
source hash/generation/endpoint/peer mapping drift, wrong target bytes, missing
symlink destination and the stricter duplicate-parameter/hardlink rejection,
ancestor symlink/traversal rejection and generation type/range boundaries.
The fortieth case uses a test-only `LD_PRELOAD` read interposer, limited to an
explicit owned temporary fixture path, to replace its parent directory after
the configuration descriptor opens. The probe must reject the detached snapshot.
Build `test_ready_attestation_read_swap.cpp` as a shared library linked with `dl`
and pass `--swap-library /path/to/library.so` to enable that deterministic case.
Only isolated temporary fixture files and FakeRunner answers are used.
