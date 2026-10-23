# Staged native namespace policy

`policy.h/.cpp` ports the pure policy contract. `Runner` receives an argument
vector and returns captured stdout; the library never creates a process. The
filesystem epoch overload only reads the supplied directory. Production callers
remain on Python until separate security/integration approval.

API coverage: MTU validation, standard filter rules, POSIX shlex-compatible
normalization, hook allowlisting, complete Docker embedded DNS recognition,
complete ServerX proxy recognition with preserved dispatch order, namespace
snapshot with runner, firewall script generation, and client policy epoch.
Docker ephemeral listener ports are excluded from replay. ServerX destinations
and ordering remain evidence; they are never retargeted.

`Snapshot` holds typed MTU/filter/NAT/routes/egress/Docker-DNS state. `Epoch`
uses signed int64 revision and a validated hash. Unlike Python's unbounded
integer type, revisions outside this explicit domain are rejected; they are
never rounded or clamped. json-c parses the JSON, including strict UTF-8.
Explicit operational rejection codes match Python; malformed shell/address/
JSON shape failures use stable generic categories without reflecting input.

Files owned by this port: policy.h, policy.cpp, policy_probe.cpp, test_policy.cpp,
and test_policy_parity.py. The probe accepts synthetic JSON fixtures and uses
an in-memory fake runner; it is a test tool, not a deployment entry point.

Integrator CMake targets (CMakeLists is intentionally not edited here):

- library `awg_policy` from policy.cpp, C++17, include this directory and the
  approved json-c include directory, link json-c.
- executable `awg_policy_tests` from test_policy.cpp linked to awg_policy.
- executable `awg_policy_probe` from policy_probe.cpp linked to awg_policy.
- CTest native unit and Python3 test_policy_parity.py --probe
  $<TARGET_FILE:awg_policy_probe>.

Validation: strict g++ -Wall -Wextra -Wpedantic -Werror standalone compilation;
136 Python/native differential fixtures compare complete results and exact
FakeRunner command order, including negative firewall/DNS/hook/route/MTU cases.
Five native-only oversized epoch cases verify explicit range rejection. Native
typed API tests also pass with UndefinedBehaviorSanitizer. Tests do not execute
Docker, iptables, ip, a VPN, an installer, or an application build.

Filesystem adapter hardening (independent owned-fixture defect reproduced):
Python and C++ now walk and pin each parent directory with O_NOFOLLOW, open
rules.json O_NOFOLLOW|O_NONBLOCK, require a regular inode with exactly one link,
and cap the source at1MiB. They compare stat identity/metadata before and after,
verify the current file and directory names still bind to the pinned source,
and independently re-read all bounded bytes. The second read catches same-size
rewrites on filesystems with coarsened timestamps; metadata alone was shown
insufficient on the owned drvfs fixture. Unsafe sources fail policy_source_untrusted.
Missing directory remains absent; a missing rules file remains not-ready.

Additional test-only targets: policy_file_probe.cpp links awg_policy;
test_policy_fs_hook.cpp builds a separate LD_PRELOAD shared library linked dl.
The hook only acts on POLICY_TEST_DIRECTORY/rules.json in explicit owned fixtures
and must never be linked/installed with production. Run test_policy_filesystem.py
--probe <file-probe> --hook <test-hook.so>. Fourteen native filesystem fixtures
pass, including deterministic replacement, in-place rewrite and parent rename.
Python test_policy.py includes equivalent filesystem/race tests (13 total tests).

Pure decoder correctness follow-up (21 October): epoch selected fields now come
from exact-length RapidJSON object names, after the existing json-c syntax/depth
and global ERANGE precheck. Full input consumption rejects raw NUL suffixes.
Duplicate exact names retain Python last-wins semantics; unknown fields including
decoded-NUL names/values and literal backslash-u0000 are preserved. Unknown alias
names alongside legitimate fields do not override the exact required fields.
The signed-int64 domain and malformed-shape stable error categories are unchanged.

The pure address helper rejects NUL only in host/mask passed to inet_pton. IPv6
scope text remains governed by prior Python semantics. Current production policy
request text already rejects decoded NUL address inputs; no live incident cause
is claimed. The test-only policy_probe text accessor now preserves explicit
string lengths, making these pure-core differential fixtures faithful.

Owned standalone checks: thirteen new typed boundary checks, maintained163-case
Python/native parity plus five pre-existing out-of-int64 negatives, and eight
confirmed malformed inputs RED before / GREEN after. Automatic pure selection
and serialization80/80 matches; no automatic source patch. No live networking,
process adapter, filesystem epoch or app/release validation is implied. Evidence:
dist/diagnostics/native-calculation-audit-20261021/automatic-policy/.
