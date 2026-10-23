# Native transaction ownership core

`transaction_journal.{h,cpp}` is a C++17 library using json-c and OpenSSL Crypto.
It has **no default process runner**, executable entry point, Docker connection,
installation path or deployment activation. Production Python is retained.

Implemented from `journal.py`:

- atomic private `transaction.json` snapshots with same-directory exclusive
  staging, full writes, file fsync, rename and directory fsync;
- migration-root-global `.prepare.lock`, held across each journal lifetime;
- typed owner/source/request/generation/image/ID metadata, exact request and
  SHA256 source-byte equality for reuse;
- plan, immutable-ID record and reverse-order owned cleanup, including the
  precise existing source-rule deletion commands;
- ready-generation target/helper restart decisions after parent epoch drift;
  the old source VPN is never started, stopped or restarted;
- injected read-only listener attestation for a source-control helper. Omitting
  that dependency fails before any mutation. Attestation failures do not persist
  new epochs. Serialized writes share the reader's 4 MiB bound and reject
  oversized growth before any staging file, preserving the previous snapshot.
  Production integration must supply the full reviewed PID1/socket
  ownership attestor, not a success callback.

`JournalRunner` receives argument vectors and returns separate status, stdout and
stderr. It is the **only** route to hypothetical Docker mutations; every test
injects fake results. Private command output is never included in exceptions.

Additional fail-closed checks compared with the Python implementation:

- walk every path ancestor from `/` with `openat(O_NOFOLLOW)`, then open
  root/scope/generation by directory descriptors; reject symlinks and
  unsafe owners/permissions, private single-link regular journal/lock files;
  regular-file read opens use `O_NONBLOCK` before `fstat`, so FIFO metadata
  cannot block constructor validation;
- never replace an existing generation by supplying an initial JSON value;
- reject unscoped component names, source-VPN ID aliases, invalid phases,
  mismatched source interface, mutable image identifiers and malformed types;
- preflight the complete owned set before cleanup or ready mutations, then
  inspect each immutable ID again immediately before its operation;
- reject generic cleanup/recovery while `controlMaintenance` intent exists.

Existing Python installations can have a more permissive `.prepare.lock` mode
because `open(..., 'a')` uses the process umask. Such a generation is rejected;
this library never silently changes permissions, copies/adopts state, creates a
second lock or falls back to Python after native failure.

Not implemented here: `maintain_controls`, `recover_control_maintenance`, recipe
backup/hash pinning and Python PID1 loaded-recipe receipts. These are a separate
control-backend port. This library must not replace `journal.py` until those
contracts, architecture/package delivery and full preparation integration are
complete. In particular no `.py` artifact is replaced with ELF bytes, and no
readiness or release PASS is inferred from these tests.

Tests:

- `test_transaction_journal.cpp`: nine groups; exclusive locking, strict types
  and identity, ownership collisions, private paths, symlink rejection, all five
  durable-save transition faults, cleanup/start/rejoin retry, helper attestation
  and source epoch recovery. Negative cases include an ancestor symlink alias
  above the migration root and a FIFO journal (bounded owned fork with alarm).
  Runs without Docker or any external process runner.
- `test_transaction_journal_parity.py` and test-only
  `transaction_journal_probe.cpp`: eight comparisons against actual `journal.py`
  over owned temporary paths and fake Docker inspect results; snapshots and
  mutating command argument vectors match. Native additional preflight reads
  are intentionally not required to equal the weaker legacy read sequence.

The parity driver contains no live runner and is not a runtime deliverable.
