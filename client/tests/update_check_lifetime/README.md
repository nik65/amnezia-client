# Updater async lifetime and byte-budget regressions

This standalone QtCore/QtNetwork fixture extracts the actual manifest GET,
legacy metadata GET, gateway future continuation and bundled-publication completion
callback from source. The gateway promise/network backend, manifest signature and
release interpretation, installer scheduling and publication work are inert seams.
It opens no real network connection and launches no application, installer, updater
or publication flow. No app/release/delivery build is required.

The 22 scenarios cover old gateway completions during a newer check, invalidated
delayed starts, exact/overflow/declared metadata bounds, finished-only data, reply
and controller destruction, the pending reply set and synchronous emitter deletion.
Both Retry and Exhausted post-signal branches are covered; ordinary Success and
non-deleting receivers retain their behavior. The current production publication
receiver does not delete its emitter, so this is a component lifetime regression,
not an established production incident.

Use AUDIT_UPDATE_SOURCE and AUDIT_BOOTSTRAP_SOURCE CMake cache paths to test exact
before copies. UPDATE_CHECK_ENABLE_ASAN=ON enables ASAN/LSAN on this owned fixture.
Qt6::Core and Qt6::Network are the only Qt runtime dependencies. Generated source
comments record SHA256 of each actual input; its business seams are explicit.

The 2026-10-21 baseline run built successfully after correcting a missing fixture
lambda closing brace. It had 14 failures of 22: real ASAN heap-use-after-free on
Retry/Exhausted direct emitter deletion, LSAN 32793 bytes in 3 manifest-state allocations,
stale gateway progression and byte/ownership boundary failures. The initial fixture
compile failure and actual RED logs remain under
dist/diagnostics/python-native-client-review-20261021/update-red/.

The source patch preserves manifest fallback/order, HTTP status/pinned URL/redirect
checks and the existing artifact download behavior. Both metadata paths use the
shared 1 MiB bounded RAII body and own their reply; finished-only bytes are drained.
Gateway start/completion check the captured generation; publication completion
checks a QPointer after emitting its notification. Parent's final 2026-10-21 GREEN
run passed 22/22 with ASAN/LSAN; the prior artifact-download lifetime suite also
passed 11/11 with ASAN. These are owned component fixtures, not application or
release acceptance. CMake tracks every extracted source/header and the generator
with CMAKE_CONFIGURE_DEPENDS so a later build regenerates the actual-source fixture.
