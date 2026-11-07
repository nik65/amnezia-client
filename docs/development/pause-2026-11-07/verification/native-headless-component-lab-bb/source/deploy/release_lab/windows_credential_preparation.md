# Owned Windows guest credential preparation

`PreparedWindowsController` is a reviewed subclass of the existing canonical
`lab.LabController`. Use a **fresh run** created through this subclass; its
`create()` records exact hashes of the canonical controller, preparation module,
PowerShell helper, installed Tesseract executable and English language data.
Every preparation action rechecks those hashes. Existing product files and the
sealed Windows parent are unchanged by this module.

After the canonical adapter creates and starts each case, preparation first
tries the existing private runtime credential. If it works, no password is
changed. If PowerShell Direct reports an invalid credential, the module reads
only the owned VM's console. It enters the known old password only after local
OCR recognizes the `labadmin` password screen, and changes it only after the
exact Windows expiry message and the normal change form are observed. Unknown
screens stop without additional credential input. Authentication, rather than
screen appearance alone, must succeed with the new password.

The helper checks the exact run/case/VM ID, actual case-owned VM configuration
directory and differencing disk, zero guest NICs, and the sealed parent marker
and Off state. It supports only bounded credential UI input, capture and
authenticated guest clock correction. It exposes no installer or host network
action. The canonical start already verifies the real parent disk hash before
this hook runs under the same controller mutation lock.

New credentials are separate, exclusively created `0600` files owned by
`amnezia-lab` under the existing controller root. They are passed only over
private stdin. Original credentials remain unchanged. Password-entry actions do
not produce screenshots or OCR text; captures occur before entry and on the
expiry/change-completed dialogs. Only state classifications and image hashes
are retained in the preparation receipt. Errors suppress subprocess streams.

Preparation has a total 240-second deadline. Each helper call is limited to the
remaining deadline and at most 45 seconds; each OCR call is limited to at most
20 seconds. Failure returns to the canonical case cleanup. Preparation receipts
always have `release_passed=false` and do not replace probe, artifact, runtime,
service, UI/UAC or publication checks.

The subclass delegates the entire existing `run_steps()` matrix to its parent.
It selects the child-specific credential for subsequent canonical operations.
For trusted live acquisition, attach the reviewed
`controller._trusted_acquisition_session` before runtime execution. Passed cases
are captured through `capture_windows_case(case_id)` immediately before the
real reset; `record_windows_cleanup(case_id, result)` receives the real reset
result. A capture error still allows canonical cleanup and then fails closed.
`verify_acquisition_provenance(run_id)` verifies the recorded source capsule.

Tests: `python3 -m unittest deploy.release_lab.test_windows_credential_preparation`.
They exercise the actual orchestration with fake guest transports; no VM is
started and they cannot issue release evidence. Actual Tesseract recognition of
the earlier captured expiry screen was also checked through WSL stdin.

Live validation of the new hook remains required before claiming this matrix
path works. The previous manual owned-child recovery proves the underlying
normal authentication method, not this new implementation.
