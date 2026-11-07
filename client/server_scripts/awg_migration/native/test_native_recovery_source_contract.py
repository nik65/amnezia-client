"""Source-only recovery invariants; native execution remains explicitly deferred.

This module does not configure or compile code, spawn helpers, use Docker, SSH,
or touch an installer/VM. The native critical fixture supplies the later runtime
negative cases once the user authorizes the build/acceptance lane.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = (ROOT / "maintenance_runtime.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "maintenance_runtime.h").read_text(encoding="utf-8")
RECOVER = SOURCE.split("if (request.mode == Mode::Recover) {", 1)[1].split(
    "if (result.pendingRecovery) fail", 1)[0]


class NativeRecoverySourceContract(unittest.TestCase):
    def test_live_marker_is_false_by_default_and_serialized(self):
        self.assertIn("bool liveVerified = false;", HEADER)
        self.assertIn('"liveVerified", json_object_new_boolean(result.liveVerified)', SOURCE)
        status = SOURCE.split("if (request.mode == Mode::Status) {", 1)[1].split(
            "if (request.mode == Mode::Cleanup)", 1)[0]
        self.assertNotIn("liveVerified = true", status)

    def test_scope_and_current_old_pin_are_checked_before_recovery(self):
        first_effect = RECOVER.index("recoverNativeControlMaintenance(journal")
        before = RECOVER[:first_effect]
        for field in ['"phase"', '"source"', '"generation"', '"containerId"', '"targetContainer"']:
            self.assertIn(field, before)
        self.assertIn("readNativeTransaction(journal).oldPayload != request.nativeControlSha256", before)

    def test_final_binding_comes_from_independent_request_pin(self):
        final = RECOVER.split("Json latest = parseJson(journal.snapshot());")[-1]
        self.assertIn("controlBinding(journal, request.nativeControlSha256)", final)
        self.assertNotIn('controlBinding(journal, text(control.get(), "sha256"))', final)
        self.assertIn('text(latest.get(), "phase") != "ready"', final)
        self.assertIn('text(latest.get(), "source") != request.source', final)
        self.assertIn('"controlMaintenance", &pending', final)

    def test_both_live_controls_and_target_pass_before_success_marker(self):
        final = RECOVER.split("const ControlBinding recovered =", 1)[1]
        marker = final.index("result.liveVerified = true;")
        for call in ["controlHelpers(journal, recovered)",
                     "checkControlState(journal, directory, ops, nativeProtected)",
                     "checkLoadedControls(journal, recovered, nativePayloadHashes(recovered), request.nativeControlSha256, ops)",
                     "validateExistingTarget(journal, request.source, latest.get(), nativeReady.get(), ops)"]:
            self.assertLess(final.index(call), marker)
        self.assertLess(marker, final.index("result.ok = true"))

    def test_final_proof_applies_to_both_helper_roles(self):
        checker = SOURCE.split("void checkLoadedControls(", 1)[1].split(
            "void restartControls(", 1)[0]
        self.assertIn("for (const auto& helper : controlHelpers(journal, binding))", checker)
        self.assertIn("verifyLoaded(binding, helper", checker)
        roles = SOURCE.split("std::vector<Helper> controlHelpers(", 1)[1].split(
            "std::map<std::string,std::string> protectedState", 1)[0]
        self.assertIn('{"-control","target"}', roles)
        self.assertIn('{"-source-control","source"}', roles)


if __name__ == "__main__":
    unittest.main()
