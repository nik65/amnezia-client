"""Source-only read-only authority verification gates; no native build or Docker.

The deferred test_consumers.cpp cases exercise actual C++ behavior in a later
build turn. These source assertions do not establish native runtime acceptance.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent


class VerifySourceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "maintenance_runtime.cpp").read_text(encoding="utf-8")
        cls.header = (ROOT / "maintenance_runtime.h").read_text(encoding="utf-8")
        cls.dispatch = (ROOT / "orchestration_entry.cpp").read_text(encoding="utf-8")
        cls.branch_start = cls.source.index("    if (request.mode == Mode::Verify) {")
        cls.branch_end = cls.source.index("    std::map<std::string,std::string> candidate;", cls.branch_start)
        cls.branch = cls.source[cls.branch_start:cls.branch_end]

    def test_production_dispatch_and_parse_reach_verify(self):
        self.assertIn('mode == "--maintenance-verify"', self.dispatch)
        self.assertIn('argv[0] == "--maintenance-verify") request.mode = Mode::Verify;', self.source)
        self.assertIn('case Mode::Verify: return "verify";', self.source)
        self.assertIn("Maintain, Verify", self.header)

    def test_native_ready_scope_and_required_state_precede_verification(self):
        prelude = self.source[self.source.index("    // Verify shares"):self.branch_start]
        self.assertIn('request.mode == Mode::Verify && !native', prelude)
        self.assertIn('text(value.get(), "phase") != "ready"', prelude)
        self.assertIn('text(value.get(), "source") != request.source', prelude)
        self.assertIn('integerAt(ready.get(), "generation") != request.generation', prelude)
        self.assertIn('text(ready.get(), "targetContainer") != target', prelude)
        self.assertIn('requireRegular(directory / name, "maintenance required state")', prelude)
        self.assertIn("controlHelpers(journal, binding);", prelude)
        self.assertIn("validateExistingTarget(journal, request.source, value.get(), ready.get(), ops);", prelude)

    def test_both_live_helpers_use_independent_caller_digest(self):
        self.assertIn("checkLoadedControls(journal, binding, nativePayloadHashes(binding), request.nativeControlSha256, ops);", self.branch)
        loaded = self.source[self.source.index("void checkLoadedControls("):self.source.index("void restartControls(")]
        self.assertIn("for (const auto& helper : controlHelpers(journal, binding))", loaded)
        self.assertIn("verifyLoaded(binding, helper, expected, operatorSha, ops)", loaded)

    def test_no_recipe_or_mutating_consumer_in_verify_branch(self):
        for forbidden in ("recipeDirectory", "runNativeControlMaintenance", "recoverReady",
                          "restartControls", "journal.cleanup", "journal.save", "ops.run("):
            self.assertNotIn(forbidden, self.branch)

    def test_live_success_follows_stable_journal_and_protected_state(self):
        marker = self.branch.index("result.liveVerified = true;")
        self.assertLess(self.branch.index("checkControlState(journal, directory, ops, protectedHashes);"), marker)
        self.assertLess(self.branch.index("!sameMap(protectedState(directory, true), protectedHashes)"), marker)
        self.assertLess(self.branch.index('!= request.expectedJournalSha256'), marker)
        self.assertLess(self.branch.index("validateExistingTarget("), marker)
        self.assertLess(marker, self.branch.index("result.ok = true;"))

    def test_client_nonce_is_canonical_and_owner_has_compatible_shape(self):
        helper = (ROOT / "client_operation.h").read_text(encoding="utf-8")
        self.assertIn('value.size() != 36', helper)
        self.assertIn('00000000-0000-0000-0000-000000000000', helper)
        self.assertIn("value[i] >= 'a' && value[i] <= 'f'", helper)
        self.assertIn("if (character != '-') result.push_back(character);", helper)
        self.assertIn("if (!validClientOperationId(value)) return {};", helper)

    def test_prepare_persists_nonce_and_uses_existing_live_owner_labels(self):
        prepare = (ROOT / "prepare_sequencer.cpp").read_text(encoding="utf-8")
        parser = (ROOT / "prepare_entry.cpp").read_text(encoding="utf-8")
        self.assertIn('seen.count("--client-operation-id")', parser)
        self.assertIn('!parsed.request.nativeControl || !validClientOperationId(parsed.request.clientOperationId)', parser)
        self.assertEqual(prepare.count('"clientOperationId", json_object_new_string(request.clientOperationId.c_str())'), 3)
        owner = prepare.index("std::string ownership = clientOperationOwner(request.clientOperationId);")
        self.assertLess(owner, prepare.index("journalInitial(request, observed, ownership, target, sourceDigest)"))
        self.assertIn("if (ownership.empty()) {", prepare[owner:])
        self.assertIn("RAND_priv_bytes(ownerBytes", prepare[owner:])
        self.assertIn('"amnezia.migration.owner=" + ownership', prepare)

    def test_causal_guard_precedes_metadata_live_and_mutating_paths(self):
        guard = self.source.index('fail("maintenance client operation binding");')
        guard_body = self.source[self.source.rfind("if (!request.clientOperationId.empty())", 0, guard):guard]
        self.assertIn('"clientOperationId") != request.clientOperationId', guard_body)
        self.assertIn('text(value.get(), "owner") != clientOperationOwner(request.clientOperationId)', guard_body)
        self.assertIn("!native || !validClientOperationId(request.clientOperationId)", guard_body)
        for following in ("if (request.mode == Mode::Status)", "if (request.mode == Mode::Recover)",
                          "if (request.mode == Mode::Verify) {"):
            self.assertLess(guard, self.source.index(following, guard))
        self.assertIn("result.clientOperationId = request.clientOperationId;", self.source[guard:])
        self.assertIn('if (!result.clientOperationId.empty())', self.source)

    def test_partial_prepare_admission_is_separate_and_before_control_fallback(self):
        start = self.source.index("    if (request.mode == Mode::InspectPrepare || request.mode == Mode::AbortPrepare) {")
        end = self.source.index("    // The journal variant is authoritative.", start)
        partial = self.source[start:end]
        self.assertLess(start, self.source.index("const ControlBinding binding = controlBinding(journal, request.nativeControlSha256);", start))
        for gate in ('has(snapshot, "nativeControl")', 'has(snapshot, "controlMaintenance")',
                     'text(snapshot, "source") != request.source',
                     '"generation") != request.generation',
                     '"clientOperationId") != request.clientOperationId',
                     'text(snapshot, "owner") != clientOperationOwner(request.clientOperationId)',
                     'optionalText(snapshot, "nativeFeedSha256") != request.nativeControlSha256'):
            self.assertIn(gate, partial)
        self.assertIn('phase != "preparing" && phase != "creating" && phase != "activating" && phase != "aborted"', partial)

    def test_partial_inspect_has_no_mutation_or_retirement_claim(self):
        start = self.source.index("    if (request.mode == Mode::InspectPrepare || request.mode == Mode::AbortPrepare) {")
        before_abort = self.source[start:self.source.index("        if (request.mode == Mode::AbortPrepare) {", start)]
        self.assertIn("journal.ownedSnapshot(name)", before_abort)
        self.assertNotIn("journal.cleanup()", before_abort)
        self.assertNotIn("ops.run(", before_abort)
        self.assertNotIn("retiredVerified = true", before_abort)

    def test_partial_retirement_marker_requires_absence_and_persisted_proof(self):
        start = self.source.index("        if (request.mode == Mode::AbortPrepare) {")
        end = self.source.index("    // The journal variant is authoritative.", start)
        abort = self.source[start:end]
        marker = abort.index("partial.retiredVerified = request.mode == Mode::AbortPrepare;")
        for proof in ("journal.cleanup();", "validatePartial(retired.get());",
                      'text(retired.get(), "phase") != "aborted"',
                      'booleanAt(retired.get(), "sourceRules")',
                      'journal.ownedSnapshot(name) != "null"',
                      'persisted != journal.snapshot()'):
            self.assertLess(abort.index(proof), marker)
        self.assertLess(marker, abort.index("partial.ok = true;"))

    def test_partial_modes_are_reachable_and_retired_is_default_false(self):
        self.assertIn("bool retiredVerified = false;", self.header)
        for mode in ("--maintenance-inspect-prepare", "--maintenance-abort-prepare"):
            self.assertIn(mode, self.dispatch)
            self.assertIn(mode, self.source)
        self.assertIn('case Mode::InspectPrepare: return "inspect-prepare";', self.source)
        self.assertIn('case Mode::AbortPrepare: return "abort-prepare";', self.source)


if __name__ == "__main__":
    unittest.main()
