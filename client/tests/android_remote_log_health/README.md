# Android remote-log host checks

`run_sanitizer_contract.py` extracts the production Kotlin sanitizer and runs
its complete self-contract with a host JVM. Add `--orchestration` to execute
the actual cursor preparation, recovery and ACK construction with in-memory
preferences and logging stubs. It does not start an Android device or VPN.

```powershell
python client/tests/android_remote_log_health/run_sanitizer_contract.py `
  --compiler-classpath $kotlinCompilerClasspath `
  --output dist/android-remote-log-contract --orchestration
```

Supply a classpath containing the Kotlin compiler and its dependencies. The
output directory contains generated Kotlin, compiler output, execution output
and a source-hash-bound JSON receipt.

The orchestration checks cover full-prefix confirmation and rewrite recovery,
secret-set changes, pending uploads and structural sanitizer state. Batch
boundary regressions also cover ordinary multi-record backlogs exceeding
1 MiB, an exact-limit record, UTF-8 records, immutable pending extent/body/id
on retries, oversized records, quoted and structured secrets and PEM blocks
spanning record boundaries, partial EOF, and an already fail-closed cursor.

Ordinary batches end at a complete record when one fits within the raw budget.
Cutting a benign record mid-line would otherwise persist terminal fail-closed
state and hide subsequent batches. A pending batch keeps its original boundary
for replay consistency. Oversized records and partial EOF remain fail-closed;
these checks do not reset an existing fail-closed cursor.

The suite also checks reduced redaction diagnostics: both 25-byte and 26-byte
whole-placeholder bodies are classified as redacted, transition quarantine
keeps its category, and readable payloads keep category zero. The classifier
compares complete byte bodies and does not trim or decode uploaded logs.
