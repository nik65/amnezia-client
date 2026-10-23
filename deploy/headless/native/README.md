# Native provisioning filesystem helper

`amnezia-headless-fs` is a Linux C++17 executable. Its filesystem commands are
`fsync-directory`, `fsync-file`, `verify-elf64-x86-64`, and
`verify-root-private-tree`; its journal commands are described below. The linked
QtCore journal reads and writes JSON. The helper contains no shell execution,
service management, installer launch, network access, signature or archive parser.
Failure is nonzero and cannot trigger a Python retry after native activation.

The regular headless CMake build has a target for the helper. The provisioning
packager includes it as mode0755, adds `nativeHelper` to schema2 metadata and
includes the file in authenticated SHA256SUMS. The automatic two-binary update
archive remains unchanged. No new runtime helper is installed globally.

The installer first copies optional helper bytes into its root-owned0700 private
snapshot without executing them. Native activation follows metadata, exact
receipt membership, checksums and public-key fingerprint validation. Tree checks
then run before any installation transaction. A present-but-invalid helper is a
hard error. Native checks reject final symlinks and unsupported file types;
directory recursion uses descriptor-relative nofollow opens.

Legacy bundles have no nativeHelper field and retain the previous Python path.
Pre-authentication transaction recovery/fsync also retains Python, because a
helper from untrusted input must never be executed for recovery.
Post-authentication durable journal write/read/backup validation now uses the
QtCore C++ journal module linked into the same authenticated helper. Its fixed
root commands are `journal-write`, `journal-recovery-read`, and
`journal-validate-backup`. Receipt, manifest, secure copying and the standalone
signed archive verifier remain Python; complete migration is **not claimed**.
Python is still required by provisioning. References and tests remain.

Standalone verification (only temporary test files, no installer/service):

```
cmake -S deploy/headless/native -B /tmp/amnezia-native-test -DBUILD_TESTING=ON
cmake --build /tmp/amnezia-native-test
ctest --test-dir /tmp/amnezia-native-test --output-on-failure
```

The positive root-owned-tree test runs only if the test runner already has uid0;
tests never create groups or request privilege elevation. Full provisioning and
rollback acceptance in owned guests is still required before delivery.
