# Pending Android stop consumer regression

This offline JVM suite extracts the current Activity dispatch, stop, Binder,
adoption and unbind methods plus the service registration, DISCONNECT branch and
disconnect implementation. It also extracts complete Wireguard and DNS stop
methods with explicit inert native and relay seams. It compiles the real `IpcMessage`, `IpcMessenger` and
`NativeSessionBinding` sources. Android IPC delivery and native effects have inert
test-owned seams; there is no device, Android service, JNI load or VPN operation.

Run with an existing Kotlin 2.1 Gradle cache (no downloads):

```sh
python3 -B client/tests/android_pending_stop/run_tests.py /tmp/pending-stop \
  --cache /path/to/gradle/caches/modules-2/files-2.1
```

Optional `--java`, `--activity-source` and `--service-source` select a local JVM
or immutable source copies for a negative control. Output contains source/tool
hashes, compilation and test logs. An old implementation must fail the same
first assertion after issuing a start, stopping before bind and binding late.

Active native stop seams deliberately never call `confirmedCleanup`. Separate
pre-init cases extract the real Wireguard and DNS retirement methods and receipt
getters, exercising the real pristine monitor transition. They require an exact
receipt before testing that the monitor admits a new owner. Android main-loop
dispatch uses an explicit synchronous dispatcher seam; JSON input/output uses a
literal-field stub. These tests prove delivery, owner fences and pre-init
retirement, not active native TUN cleanup. A startup without any service session
still has no cleanup confirmation; device acceptance remains required.
