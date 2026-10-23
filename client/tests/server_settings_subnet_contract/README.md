# Server subnet deployment contract

Standalone QtCore regression tests extract the actual production model
comparators and JSON serialization methods, using their real model headers.
No application, networking, SSH or deployment target is built or executed.

Configure this directory with CMake and Qt6 Core, build its single test target,
then run `ctest --test-dir <build-directory> --output-on-failure`.
Python3 is configure-time test tooling only. The generated C++ fixture lives
in the build directory.

Tests cover changed CIDR/netmask requiring a deployment identity change,
serialization roundtrips, unchanged identity, symmetry, existing port-change
behavior, and unused WireGuard mask metadata preserving no-op behavior.
InstallController relies on these comparators; this test does not execute the
controller or claim deployment/runtime acceptance.

The parent agent ran these tests against the original production methods:
configure/build passed and CTest failed with exactly 11 missing CIDR/netmask
checks. The minimal production patch adds WG/AWG CIDR and OpenVPN CIDR/mask.
Post-patch execution is owned by the parent agent.
