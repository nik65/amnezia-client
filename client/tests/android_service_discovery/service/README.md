# Service discovery source fixture

Run `python -B client/tests/android_service_discovery/service/run_tests.py OUTPUT`.

Uses cached Kotlin/JDK only, with actual extracted Service discovery methods, actual job-completion predicate and bind/unbind/rebind callbacks. Android Messenger, JSON parser and backend native reads are inert stubs; this is no Android runtime or whole-application compilation claim.

Cases cover both initialized native owners, ACTIVE despite UNKNOWN service state, uncertain native close, retained exact retired identity, cancelled-but-not-completed jobs, stale/consumed/duplicate grants, wrong component configuration, promotion, and passive observation group callbacks. Negative-control execution replacing the job predicate with the earlier draft `!isActive` fails at the real cancelled-job regression; this is explicitly a synthetic negative control, not a replay against initial repository source (which lacked these methods).

Current stage logs: `dist/diagnostics/android-service-discovery-20261021/kotlin/service-jvm/`; review/final integration pending. No app/Gradle/device/network operations.

Completion-order regression: confirmed retired descriptor plus DISCONNECTED may precede disconnectionJob completion. Actual request method now joins captured jobs and performs native IO within one 2000ms budget. Tests require no early UNKNOWN, eventual IDLE/grant after completion, timeout UNKNOWN without grant, and changed lifecycle UNKNOWN. Actual prior ce6ca source RED compile0/test1 is preserved in service-completion-red; current GREEN compile0/test0 in service-completion-green.
