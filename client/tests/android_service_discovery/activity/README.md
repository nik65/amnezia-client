# Activity discovery standalone source regression

Run `python -B client/tests/android_service_discovery/activity/run_tests.py OUTPUT_DIRECTORY`.
An optional second argument selects a preserved Activity source for RED checks.
Only cached standalone Kotlin/JVM tools run; no Gradle, application, JNI, Android device or network effects.

The generator extracts the actual discovery fields/methods, start admission API,
per-binding control callbacks, doBindService, doUnbindService, and admission reply
branch. Android inventory, bind/send/start operations are inert counters. Existing
bound-restore tests separately compile actual shared adoption and control callbacks.

Cases cover empty cold start, consumed grants, permission and lifecycle cancellation,
permission-dialog inventory change, bound-only HOLD, no AUTO_CREATE on observational
binds, late observational callbacks, existing control refresh, and uncertain dispatch.
Pending-control refresh retains the exact connection with zero unbind effects, then
its real callback checks renewed inventory and requests the current-generation probe.
A real 4000ms timeout yields uncertainty without releasing possible ownership, and
late callback cannot reopen that terminal outcome. Missing/mistyped admission ACK
cannot prove rejection; only actual Boolean false does. Serializer corpus uses the
real finite six-key/five-key producer.

Tests stub service proof and permission framework effects. They do not establish
real-device lifecycle behavior, native ownership, global exclusivity, or a full
Android/JNI compile. Test-only confirmedStop models already proven retirement for
independent admission cases; it does not claim to test native cleanup.
