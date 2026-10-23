# Actual Android discovery worker contract

Standalone QtCore-only fixture extracts seven current production VpnConnection methods plus the actual main-controller refusal and UI state/error handlers at configure time. QObject, QSharedPointer and the actual six-second QTimer watchdog run locally. A counted inert wrapper replaces the VPN protocol: its stop method is never called. Signal sinks record worker/cache-facing visible state and errors; disconnectSlots is an inert subscription counter. No Activity/JNI, app, native service, route, device or network code is executed.

Checks cover exact one-shot rejection, explicit dispatched/uncertain retention, worker epoch and replacement fences, native704 precedence including observation arriving after admission registration, refresh ACK/timeout, stale/repeated reconnect terminal, watchdog retention and a late authoritative rejection after timeout; post-cleanup reconnect refresh timeout, native observation arriving during that wait, and actual cached705/704 propagation into UI state/error methods. This does not prove full app linkage, Android runtime or route/DNS behavior. The controller/UI signal connections use direct inert forwarding of the actual method bodies; Qt production queued delivery is not replicated. Assertions ensure no native stop; Error cleanup is excluded by extracting these methods, but the complete route side-effect path remains an integration review obligation.

Run in WSL with Qt 6.10.1:

```sh
cmake -S client/tests/android_service_discovery/worker -B dist/diagnostics/android-service-discovery-20261021/cpp/workerfixture/build -DCMAKE_PREFIX_PATH=/home/ivano/Qt/6.10.1/gcc_64
cmake --build dist/diagnostics/android-service-discovery-20261021/cpp/workerfixture/build -j2
ctest --test-dir dist/diagnostics/android-service-discovery-20261021/cpp/workerfixture/build --output-on-failure
```

Observed 2026-10-21: configure/build exit0, CTest1/1 PASS, actual-worker checks68, native-stops0. Prior113/11 regression suites are owned by the root and were not run here. Initial compile exposed a missing Disconnecting value in the inert enum seam; the seam was corrected without changing production.


## Fresh entry guard ordering regression

A second target extracts the actual `connectToVpn` prefix through its first `beginManagedRouteReconnectSession` side-effect marker, the actual classifier, and actual `rejectNativeRestoreConnect`. The remaining production tail is excluded; the marker increments an inert mutation counter. Native refusal signal/subscription methods are inert, while Pending and discovery Coordinator are the maintained real helpers. Cases prove stale expected epoch/server and pending/recovery teardown consume no EMPTY grant; a valid fresh entry consumes once; stale queue entries preserve the existing Pending token; valid current native observation still refuses with no side effects. This tests source entry ordering, not complete app startup.

Before production reorder: initial 14 checks had4 failures; enhanced25 checks against preserved v1 source had8 failures (four original grant failures, two stale-token failures, two repeated stale-grant failures). Configure/build passed. After production reorder: worker68 + entry25 checks, CTest2/2 PASS onQt6.10.1. Red snapshot and logs are in cpp/entryfixture. Use a separate cache with `-DAUDIT_ENTRY_SOURCE=<absolute preserved source>` to reproduce RED; normal cache extracts current source.
