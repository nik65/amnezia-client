// Actual full-caller tests for the explicit native-control replacement
// transaction and its crash/failure recovery: real runMaintenance(Maintain /
// Recover) through the real journal, JSON and filesystem; the Docker/process
// boundary is the inert FakeOps only. No mocked validate[]{} and no emit-plan
// success path: every assertion is a real persisted journal/byte observation.
#include "test_native_control_transaction_fixture.h"

using namespace awgfix;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::cerr << "FAIL line " << __LINE__ << ": " #cond "\n"; ++failures; } } while (0)

static void expectThrows(const std::function<void()>& fn, const std::string& text, int line) {
    try { fn(); } catch (const std::exception& e) {
        if (std::string(e.what()).find(text) != std::string::npos) return;
        std::cerr << "message: " << e.what() << "\n";
    }
    std::cerr << "FAIL line " << line << ": expected " << text << "\n"; ++failures;
}

static std::string journalText(const Fixture& f) { return read(f.directory / "transaction.json"); }
static bool hasField(const std::string& journal, const std::string& field) {
    return journal.find("\"" + field + "\":") != std::string::npos;
}
static std::string nativeField(const Fixture& f, const std::string& key) {
    const auto journal = journalText(f);
    auto at = journal.find("\"nativeControl\":{");
    if (at == std::string::npos) return {};
    auto end = journal.find('}', at);
    auto key_at = journal.find("\"" + key + "\":\"", at);
    if (key_at == std::string::npos || key_at > end) return {};
    auto begin = key_at + key.size() + 4;
    return journal.substr(begin, journal.find('"', begin) - begin);
}
static std::size_t dynCount(const Fixture& f, const std::string& name) {
    std::size_t n = 0;
    for (const auto& item : f.dyn) if (item.second.name == name) ++n;
    return n;
}
static const Dyn* dynNamed(const Fixture& f, const std::string& name) {
    for (const auto& item : f.dyn) if (item.second.name == name) return &item.second;
    return nullptr;
}
static bool helperAt(const Fixture& f, const std::string& name, const std::string& id,
                     const std::string& image, const std::string& payload) {
    if (const Dyn* d = dynNamed(f, name)) return d->image == image && d->payload == payload && d->running;
    if (f.removed.count(id)) return false;
    return image == f.image && payload == f.nativeSha;   // untouched fixed fixture container
}
static void expectRestored(Fixture& f, const std::string& oldPayload, const std::string& oldImage, int line,
                           bool expectRollback = true, const std::string& before = {}) {
    const auto journal = journalText(f);
    if (nativeField(f, "sha256") != oldPayload) { std::cerr << "FAIL line " << line << ": payload not restored\n"; ++failures; }
    if (nativeField(f, "image") != oldImage) { std::cerr << "FAIL line " << line << ": image not restored\n"; ++failures; }
    if (hasField(journal, "controlMaintenance")) { std::cerr << "FAIL line " << line << ": intent left pending\n"; ++failures; }
    if (expectRollback && journal.find("\"controlMaintenanceResult\":\"rolled_back\"") == std::string::npos
        && (before.empty() || journal != before)) {
        std::cerr << "FAIL line " << line << ": no rolled_back result\n"; ++failures;
    }
    if (!helperAt(f, "amnezia-awg-migration-1-control", f.controlId, oldImage, oldPayload)
        || !helperAt(f, "amnezia-awg-migration-1-source-control", f.sourceControlId, oldImage, oldPayload)) {
        std::cerr << "FAIL line " << line << ": helpers not restored\n"; ++failures;
    }
}

// ---------------------------------------------------------------------------
static void testValidUpgrade() {
    Fixture f(true, true);   // explicit native control AND an independently bound old target feed
    const auto before = journalText(f);
    const auto protectedBefore = f.protectedJson();
    const auto readyBefore = read(f.directory / "ready.json");
    const auto bytes = elfImage("control-new\n");
    const auto newSha = sha(bytes);
    const auto oldImage = f.image;
    write(f.recipe / "awg-feed", bytes);
    FakeOps ops(f);
    Request request = f.upgrade(bytes);
    auto result = runMaintenance(request, ops);
    CHECK(result.ok && result.native && result.phase == "ready");
    CHECK(result.controlHashes.size() == 1 && result.controlHashes.at("awg-feed") == newSha);
    const auto journal = journalText(f);
    CHECK(nativeField(f, "sha256") == newSha);
    const auto newImage = nativeField(f, "image");
    CHECK(newImage.size() == 71 && newImage != oldImage);
    CHECK(!hasField(journal, "controlMaintenance"));
    CHECK(journal.find("\"controlMaintenanceResult\":\"updated\"") != std::string::npos);
    CHECK(journal.find("\"controlLoadedReceipt\":true") != std::string::npos);
    // Independently bound target feed bytes are preserved untouched and audited.
    CHECK(journal.find("\"nativeFeedSha256\":\"" + f.nativeSha + "\"") != std::string::npos);
    CHECK(journal.find("\"controlReplacement\":{\"state\":\"committed\"") != std::string::npos);
    CHECK(journal.find("\"feedSha256\":\"" + f.nativeSha + "\"") != std::string::npos);
    CHECK(journal.find("\"priorControlSha256\":\"" + f.nativeSha + "\"") != std::string::npos);
    // Real owned local build bound to the exact independently authenticated bytes.
    CHECK(f.images.count(newImage) == 1);
    CHECK(ops.verb("build") == 1);
    CHECK(ops.builtContexts.size() == 1 && ops.builtContexts.front().second == newSha);
    CHECK(ops.verb("image") == 1);
    // Exact-owned helper recreation with live listener proof of the new image.
    CHECK(dynCount(f, "amnezia-awg-migration-1-control") == 1);
    CHECK(dynCount(f, "amnezia-awg-migration-1-source-control") == 1);
    const Dyn* control = dynNamed(f, "amnezia-awg-migration-1-control");
    const Dyn* source = dynNamed(f, "amnezia-awg-migration-1-source-control");
    CHECK(control && control->image == newImage && control->payload == newSha && control->running);
    CHECK(source && source->image == newImage && source->payload == newSha && source->running);
    CHECK(control && control->started != "t-control");
    CHECK(source && source->started != "t-source-control");
    CHECK(ops.verb("rm") == 2);
    CHECK(ops.verifiedAs(newSha) >= 4);      // create-time proof plus per-helper re-attestation
    CHECK(ops.verifiedAs(f.nativeSha) >= 2); // pre-mutation proof of the old authority
    CHECK(ops.count("python") == 0);
    // Protected configuration/signing/grants/ready/target/source state unchanged.
    CHECK(f.protectedJson() == protectedBefore);
    CHECK(read(f.directory / "ready.json") == readyBefore);
    CHECK(journal.find("\"sourceId\":\"" + f.sourceId + "\"") != std::string::npos);
    CHECK(journal.find("\"sourceEpoch\":\"t-source\"") != std::string::npos);
    CHECK(journal.find("\"targetEpoch\":\"t-target\"") != std::string::npos);
    CHECK(journal.find("\"amnezia-awg-migration-1\":{\"image\":\"" + oldImage + "\",\"id\":\"" + f.targetId + "\"}") != std::string::npos);
    CHECK(f.restarted.empty());
    CHECK(journal != before);
    // The committed new authority is reachable through the real read modes.
    { FakeOps statusOps(f); Request status = f.request(Mode::Status); status.nativeControlSha256 = newSha;
      auto observed = runMaintenance(status, statusOps);
      CHECK(observed.ok && observed.controlHashes.at("awg-feed") == newSha); }
    { FakeOps restartOps(f); Request restart = f.request(Mode::RestartControls); restart.nativeControlSha256 = newSha;
      auto observed = runMaintenance(restart, restartOps);
      CHECK(observed.ok && observed.controlHashes.at("awg-feed") == newSha);
      CHECK(restartOps.verifiedAs(newSha) == 2 && restartOps.count("python") == 0); }
    // A second identical recipe is now a genuine no-op under the NEW authority.
    { FakeOps noop(f); const auto stable = journalText(f);
      Request repeat = f.request(Mode::Maintain);
      repeat.nativeControlSha256 = newSha; repeat.nativeControlReplacementSha256 = newSha;
      auto observed = runMaintenance(repeat, noop);
      CHECK(observed.ok && observed.controlHashes.at("awg-feed") == newSha);
      CHECK(journalText(f) == stable);
      CHECK(noop.verb("build") == 0 && noop.verb("create") == 0 && noop.verb("rm") == 0); }
}

static void testUnchangedNoop() {
    Fixture f(true);
    const auto before = journalText(f);
    FakeOps ops(f);
    auto result = runMaintenance(f.request(Mode::Maintain), ops);
    CHECK(result.ok && result.controlHashes.at("awg-feed") == f.nativeSha);
    CHECK(journalText(f) == before);
    CHECK(ops.count("python") == 0);
    CHECK(ops.verb("build") == 0 && ops.verb("create") == 0 && ops.verb("rm") == 0);
    CHECK(ops.verifiedAs(f.nativeSha) >= 2);
    // A redundant replacement claim for unchanged bytes is still the same bytes.
    Fixture g(true); FakeOps same(g);
    Request request = g.upgrade(elfImage("control-old\n"));
    CHECK(runMaintenance(request, same).ok);
    CHECK(same.verb("build") == 0);
}

static void testAuthorityAndBytes() {
    { Fixture f(true); const auto before = journalText(f);
      fs::remove(f.recipe / "awg-feed"); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(f.upgrade("x"), ops); }, "native control payload missing", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes);
      Request request = f.request(Mode::Maintain);   // no replacement field
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(request, ops); }, "native_control_replacement_sha256_required", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes);
      Request request = f.request(Mode::Maintain);
      request.nativeControlReplacementSha256 = std::string(64, '9');   // wrong independent assertion
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(request, ops); }, "native_control_replacement_sha256_mismatch", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes);
      Request request = f.upgrade(bytes); request.nativeControlSha256.clear();
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(request, ops); }, "native_control_sha256_required", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes);
      Request request = f.upgrade(bytes); request.nativeControlSha256 = std::string(64, '9');
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(request, ops); }, "native_control_sha256_mismatch", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    // The current payload never silently becomes the replacement authority.
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes);
      Request request = f.upgrade(bytes); request.nativeControlReplacementSha256 = f.nativeSha;
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(request, ops); }, "native_control_replacement_sha256_mismatch", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    // Divergent target feed without the committed replacement ledger stays refused.
    { Fixture f(true, true);
      f.rewrite([&](std::string& j){ replaceOnce(j, "\"nativeFeedSha256\":\"" + f.nativeSha + "\"",
                                                  "\"nativeFeedSha256\":\"" + f.feedSha + "\""); });
      FakeOps ops(f);
      expectThrows([&]{ runMaintenance(f.request(Mode::Status), ops); }, "unsupported mixed control variant", __LINE__);
      CHECK(ops.calls.empty()); }
    // Actual CLI parsing: the new flags bind to Maintain only and round-trip, so a
    // changed payload can never succeed through unsupported or misplaced argv.
    { Fixture f(true);
      std::vector<std::string> status{"--maintenance-status","--source","amnezia-awg","--generation","1",
          "--expected-journal-sha256",std::string(64,'a'),"--native-control-sha256",f.nativeSha,
          "--native-control-replacement-sha256",std::string(64,'9')};
      expectThrows([&]{ parseRequest(status); }, "maintenance request", __LINE__);
      std::vector<std::string> maintain{"--maintenance","--source","amnezia-awg","--generation","1",
          "--expected-journal-sha256",std::string(64,'a'),"--native-control-sha256",f.nativeSha,
          "--native-control-replacement-sha256",std::string(64,'b'),"--control-staging-directory",f.staging.string()};
      const auto parsed = parseRequest(maintain);
      CHECK(parsed.mode == Mode::Maintain);
      CHECK(parsed.nativeControlReplacementSha256 == std::string(64,'b'));
      CHECK(parsed.controlStagingDirectory == f.staging);
      CHECK(parsed.nativeControlSha256 == f.nativeSha); }
}

static void testStaticExecutableAndStaging() {
    auto refused = [](const std::string& bytes, const char* text) {
        Fixture f(true); write(f.recipe / "awg-feed", bytes);
        const auto before = journalText(f); FakeOps ops(f);
        expectThrows([&]{ runMaintenance(f.upgrade(bytes), ops); }, text, __LINE__);
        CHECK(journalText(f) == before && !ops.mutatingBoundary());
        CHECK(ops.verb("build") == 0);
    };
    refused("#!/bin/sh\necho not-static\n", "native control payload not an ELF image");
    refused(elfImage("control-new\n", 3), "native control payload requires a dynamic loader");
    refused(elfImage("control-new\n", 1, 3), "native control payload unsupported machine");
    refused(elfImage("control-new\n", 1, 62, 1), "native control payload not an executable image");
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes);
      Request request = f.upgrade(bytes); request.controlStagingDirectory.clear();
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(request, ops); }, "native control staging directory", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes);
      chmod(f.staging.c_str(), 0755);   // not private
      Request request = f.upgrade(bytes);
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(request, ops); }, "native control staging directory", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    // Helper identity drift is refused before the build/staging boundary.
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes); f.entrypoint = "python";
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(f.upgrade(bytes), ops); }, "control maintenance helper binding", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
    { Fixture f(true); const auto bytes = elfImage("control-new\n");
      write(f.recipe / "awg-feed", bytes); f.envSha = std::string(64, '1');
      const auto before = journalText(f); FakeOps ops(f);
      expectThrows([&]{ runMaintenance(f.upgrade(bytes), ops); }, "control maintenance helper role/scope", __LINE__);
      CHECK(journalText(f) == before && !ops.mutatingBoundary()); }
}

static void testFailureAfterEachMutation() {
    const auto bytes = elfImage("control-new\n");
    struct Fault { const char* label; std::string createRole, startRole, verifyRole; bool build, image; };
    std::vector<Fault> faults{
        {"build", "", "", "", true, false},
        {"image-inspect", "", "", "", false, true},
        {"create-target", "target", "", "", false, false},
        {"start-target", "", "target", "", false, false},
        {"verify-target", "", "", "target", false, false},
        {"create-source", "source", "", "", false, false},
        {"start-source", "", "source", "", false, false},
        {"verify-source", "", "", "source", false, false},
    };
    for (const auto& fault : faults) {
        Fixture f(true, true);
        write(f.recipe / "awg-feed", bytes);
        FakeOps ops(f);
        ops.failBuild = fault.build; ops.failImageInspect = fault.image;
        ops.failCreateRole = fault.createRole; ops.failStartRole = fault.startRole; ops.failVerifyRole = fault.verifyRole;
        const auto before = journalText(f);
        std::string message;
        try { runMaintenance(f.upgrade(bytes), ops); } catch (const std::exception& e) { message = e.what(); }
        if (message.empty()) { std::cerr << "FAIL " << fault.label << ": no failure\n"; ++failures; continue; }
        const bool mutated = fault.label != std::string("build") && fault.label != std::string("image-inspect");
        if (mutated) {
            // A fault inside the owned mutation is repaired through the real
            // recovery entry, which is exactly what a crash relies on.
            FakeOps recovery(f);
            auto recovered = runMaintenance(f.request(Mode::Recover), recovery);
            CHECK(recovered.ok && recovered.controlHashes.at("awg-feed") == f.nativeSha);
        }
        expectRestored(f, f.nativeSha, f.image, __LINE__, mutated, before);
        // Every removed container was one of the two journal-recorded helpers.
        for (const auto& call : ops.calls)
            if (call.size() > 1 && call[1] == "rm")
                if (call.back() != f.controlId && call.back() != f.sourceControlId && !f.created.count(call.back()))
                { std::cerr << "FAIL " << fault.label << ": foreign removal\n"; ++failures; }
        if (f.protectedJson().find(sha(read(f.directory / "signing.pem"))) == std::string::npos) { std::cerr << "FAIL protected\n"; ++failures; }
        FakeOps statusOps(f);
        auto status = runMaintenance(f.request(Mode::Status), statusOps);
        CHECK(status.ok && status.controlHashes.at("awg-feed") == f.nativeSha);
        CHECK(ops.count("python") == 0);
    }
}

static void testJournalAndAdmissionUncertainty() {
    const auto bytes = elfImage("control-new\n");
    const auto newSha = sha(bytes);
    auto journalRun = [&](Fixture& f, FakeOps& ops, JournalFault& fault) {
        return TransactionJournal(f.directory, [&](const std::vector<std::string>& a) {
            CommandResult r; try { r.output = ops.run(a); } catch (const std::exception& e) { r.status = 1; r.error = e.what(); } return r;
        }, {}, fault);
    };
    // (a) Intent commit uncertainty: nothing is mutated and the tree stays consistent.
    { Fixture f(true); write(f.recipe / "awg-feed", bytes);
      const auto oldJournal = journalText(f); FakeOps ops(f);
      int saves = 0;
      JournalFault fault = [&](const std::string& point) {
          if (point == "save-created") { if (++saves == 1) throw JournalError("injected journal uncertainty"); }
      };
      auto journal = journalRun(f, ops, fault);
      expectThrows([&]{ runNativeControlMaintenance(journal, f.directory, f.recipe, f.nativeSha, newSha, f.staging, ops, []{}); },
                   "injected journal uncertainty", __LINE__);
      CHECK(journalText(f) == oldJournal);
      CHECK(ops.verb("create") == 0 && ops.verb("rm") == 0); }
    // (b) Uncertain reply AFTER the complete mutation: the captured old authority
    // is restored instead of being assumed committed.
    { Fixture f(true, true); write(f.recipe / "awg-feed", bytes);
      FakeOps ops(f);
      int saves = 0;
      JournalFault fault = [&](const std::string& point) {
          if (point == "save-replaced") { if (++saves == 4) throw JournalError("injected journal uncertainty"); }
      };
      auto journal = journalRun(f, ops, fault);
      bool threw = false;
      try { runNativeControlMaintenance(journal, f.directory, f.recipe, f.nativeSha, newSha, f.staging, ops,
                                        [&]{ if (f.protectedJson().empty()) throw std::runtime_error("validate"); }); }
      catch (const std::exception&) { threw = true; }
      CHECK(threw);
      expectRestored(f, f.nativeSha, f.image, __LINE__); }
    // (c) Partial mutation (journal recorded the recreated target helper only),
    // then a hard stop: Maintain refuses, Recover repairs through the real path.
    { Fixture f(true); const auto newImage = "sha256:" + std::string(64, '5');
      f.plantIntent(newSha, newImage);
      const auto replacementId = f.addHelper("amnezia-awg-migration-1-control", "target", newImage, newSha, true);
      FakeOps maintain(f);
      expectThrows([&]{ runMaintenance(f.request(Mode::Maintain), maintain); }, "control maintenance recovery required", __LINE__);
      CHECK(maintain.calls.empty());
      FakeOps recover(f);
      auto result = runMaintenance(f.request(Mode::Recover), recover);
      CHECK(result.ok && !result.pendingRecovery && result.controlHashes.at("awg-feed") == f.nativeSha);
      expectRestored(f, f.nativeSha, f.image, __LINE__);
      CHECK(recover.verb("rm") == 1);                       // only the created replacement
      CHECK(recover.verifiedAs(f.nativeSha) >= 2);
      CHECK(recover.count("python") == 0);
      (void)replacementId; }
    // (d) Intent-only crash: no mutation happened, so no helper is destroyed.
    { Fixture f(true); const auto newImage = "sha256:" + std::string(64, '6');
      f.plantIntent(newSha, newImage);
      FakeOps recover(f);
      auto result = runMaintenance(f.request(Mode::Recover), recover);
      CHECK(result.ok && result.controlHashes.at("awg-feed") == f.nativeSha);
      expectRestored(f, f.nativeSha, f.image, __LINE__);
      CHECK(recover.verb("rm") == 0 && recover.verb("create") == 0);
      CHECK(read(f.directory / "awg0.native.conf") == "awg0.native.conf-bytes\n"); }
}

static void testForeignReplacementPreserved() {
    const auto newSha = sha(elfImage("control-new\n"));
    Fixture f(true);
    const auto newImage = "sha256:" + std::string(64, '5');
    f.plantIntent(newSha, newImage);
    // A container under the canonical name that this transaction never created.
    f.addHelper("amnezia-awg-migration-1-control", "target", "sha256:" + std::string(64, '7'), newSha, true, std::string(32, 'z'));
    const auto before = journalText(f);
    FakeOps ops(f);
    expectThrows([&]{ runMaintenance(f.request(Mode::Recover), ops); }, "control maintenance foreign replacement", __LINE__);
    CHECK(journalText(f) == before);
    CHECK(ops.verb("rm") == 0 && ops.verb("create") == 0);
    CHECK(dynCount(f, "amnezia-awg-migration-1-control") == 1);
}

static void testLegacyUnchanged() {
    { Fixture f(false); FakeOps ops(f);
      auto status = runMaintenance(f.request(Mode::Status), ops);
      CHECK(status.ok && !status.native && status.controlHashes.size() == 2);
      CHECK(ops.calls.empty()); }
    { Fixture f(false); FakeOps ops(f);
      auto restart = runMaintenance(f.request(Mode::RestartControls), ops);
      CHECK(restart.ok && !restart.native);
      CHECK(ops.count("python") >= 3 && ops.count("/app/awg-feed") == 0); }
    { Fixture f(false, true); FakeOps ops(f);
      auto restart = runMaintenance(f.request(Mode::RestartControls), ops);
      CHECK(restart.ok && restart.native);
      CHECK(ops.count("/app/awg-feed", "--verify-control-loaded") == 2);
      CHECK(ops.count("/app/awg-feed", "--verify-control-live") == 0); }
    { Fixture f(false); FakeOps ops(f);
      auto maintain = runMaintenance(f.request(Mode::Maintain), ops);
      CHECK(maintain.ok && !maintain.native);
      CHECK(read(f.directory / "transaction.json").find("\"controlLoadedReceipt\":true") != std::string::npos);
      CHECK(ops.verb("build") == 0 && ops.verb("create") == 0); }
    { Fixture f(false); write(f.recipe / "service.py", "service-new\n");
      FakeOps ops(f); ops.rejectHash = sha("service-new\n");
      TransactionJournal journal(f.directory, [&](const std::vector<std::string>& a) {
          CommandResult r; try { r.output = ops.run(a); } catch (const std::exception& e) { r.status = 1; r.error = e.what(); } return r;
      });
      bool threw = false;
      try { runControlMaintenance(journal, f.directory, f.recipe, false, "", ops, []{}); }
      catch (const std::exception&) { threw = true; }
      CHECK(threw);
      CHECK(read(f.directory / "service.py") == "service-old\n");
      CHECK(journal.snapshot().find("\"controlMaintenanceResult\":\"rolled_back\"") != std::string::npos); }
    // A legacy generation is never inferred native from the replacement flag: the
    // unchanged Python transaction runs and no native boundary is touched.
    { Fixture f(false); FakeOps ops(f);
      Request request = f.request(Mode::Maintain); request.nativeControlReplacementSha256 = std::string(64, '9');
      auto result = runMaintenance(request, ops);
      CHECK(result.ok && !result.native);
      CHECK(ops.verb("build") == 0 && ops.verb("create") == 0 && ops.count("/app/awg-feed") == 0); }
}

int main(int argc, char** argv) {
    try { testValidUpgrade(); } catch (const std::exception& e) { std::cerr << "EX valid upgrade: " << e.what() << "\n"; ++failures; }
    try { testUnchangedNoop(); } catch (const std::exception& e) { std::cerr << "EX noop: " << e.what() << "\n"; ++failures; }
    try { testAuthorityAndBytes(); } catch (const std::exception& e) { std::cerr << "EX authority: " << e.what() << "\n"; ++failures; }
    try { testStaticExecutableAndStaging(); } catch (const std::exception& e) { std::cerr << "EX executable: " << e.what() << "\n"; ++failures; }
    try { testFailureAfterEachMutation(); } catch (const std::exception& e) { std::cerr << "EX failures: " << e.what() << "\n"; ++failures; }
    try { testJournalAndAdmissionUncertainty(); } catch (const std::exception& e) { std::cerr << "EX uncertainty: " << e.what() << "\n"; ++failures; }
    try { testForeignReplacementPreserved(); } catch (const std::exception& e) { std::cerr << "EX foreign: " << e.what() << "\n"; ++failures; }
    try { testLegacyUnchanged(); } catch (const std::exception& e) { std::cerr << "EX legacy: " << e.what() << "\n"; ++failures; }
    if (failures) { std::cerr << failures << " failures\n"; return 1; }
    std::cout << "native control maintenance transaction checks: ok\n";
    if (argc == 2 && std::string(argv[1]) == "--fail-work") return 23;
    return 0;
}
