# Durable provisioning journal

Linux C++17/QtCore implementation of the installer's schema1 journal, linked
into the authenticated `amnezia-headless-fs` executable. It uses Qt's JSON
parser and SHA256 implementation; no custom JSON/crypto implementation.

The production dispatcher accepts only uid0 and a fixed `/var/lib/amnezia`
root. `journal-write` takes phase, mode, backup directory, service target,
enabled/active states and two strict boolean strings. `journal-recovery-read`
emits eight validated lines, verifying rollback backups for mutable phases.
`journal-validate-backup` verifies the entire backup receipt. No CLI root, UID,
output path, fault injection, shell, service, route or installer option exists.
The library's `Policy` root/UID override is for owned unit fixtures only.

All calls run under the installer's existing exclusive transaction flock.
The module does not acquire that same lock recursively. JSON is bounded64KiB;
root/backup directories use nofollow descriptor opens and ownership/mode checks.
Only the four managed names and supported systemd service paths are accepted.
Backup identity includes kind, size, ownership, permissions and streamed SHA256.
Only the service may be a symlink resolving exactly `/dev/null`. Resolution is
relative to our pinned directory FD through `/proc/self/fd`, never another PID.
Relative legacy mask aliases and nonempty legacy missing markers preserve the
reference contract. Marker bytes are hashed, not treated as installation data.

Writes use exclusive0600 temporary files, full writes, filefsync, atomic rename
and directoryfsync. Failure before rename preserves the previous journal;
directoryfsync failure after rename reports failure with the new journal
possibly visible. It never falsely reports successful durability. A committed
journal may have an already removed backup directory, as in the original flow.

The shell chooses these commands only after its private input snapshot,
authenticated manifest/checksums/key and helper receipt validation. Every native
error returns immediately. Pre-authentication `--recover` and legacy bundles
without an authenticated native helper retain the Python reference; unverified
source helper bytes must never be executed for recovery. Python receipt,
manifest/archive validation and private-input copying remain separate work.

Focused tests compile independently with CMake/QtCore and run on temporary
fixtures only. They include injected write/fsync/rename failure points, schema,
path/type/hash/mode failures, native/Python writer-validator interoperability
using the extracted reference blocks, and actual shell dispatch failure without
Python fallback. No product/installer or service is launched by the tests.
