// AA inert witness: can an AUTOMATIC CURRENT control authority be produced and
// accepted by the UNCHANGED strict CURRENT consumer? Subject bytes are the
// frozen product snapshot in this directory (hashes in INPUT_SNAPSHOT.json); the
// Docker/process boundary is FakeOps only. No product binary, guest, network,
// secret or host control is reachable.
#include "test_fixture.h"
using namespace awgfix;
static int failures = 0, checks = 0, works = 0, workFailures = 0;
#define CHECK(cond) do { ++checks; if (!(cond)) { std::cerr << "FAIL line " << __LINE__ << ": " #cond "\n"; ++failures; } } while (0)
static int workBase = 0;
static void workBegin(const char* n) { ++works; workBase = failures; std::cout << "work " << works << " " << n << "\n"; }
static void workEnd() { if (failures != workBase) ++workFailures; }
static void expectThrow(const std::function<void()>& fn, const std::string& text, int line) {
    try { fn(); } catch (const std::exception& e) {
        if (std::string(e.what()).find(text) != std::string::npos) { ++checks; return; }
        std::cerr << "wrong refusal: " << e.what() << " (wanted " << text << ")\n";
    }
    std::cerr << "FAIL line " << line << ": expected refusal " << text << "\n"; ++failures; ++checks;
}
static std::string journalText(const Fixture& f) { return read(f.directory / "transaction.json"); }
static std::string nativeField(const Fixture& f, const std::string& key) {
    const auto j = journalText(f); auto at = j.find("\"nativeControl\":{");
    if (at == std::string::npos) return {};
    auto end = j.find('}', at); auto k = j.find("\"" + key + "\":\"", at);
    if (k == std::string::npos || k > end) return {};
    auto b = k + key.size() + 4; return j.substr(b, j.find('"', b) - b);
}

// WORK 1: the explicit operator CURRENT path is preserved unchanged (read modes
// go through the same strict controlBinding; mutation is owned by the accepted
// R lane and is not re-driven here).
static void work1() {
    workBegin("operator-current-preserved");
    Fixture f(true, true); const auto before = journalText(f);
    { FakeOps s(f); auto st = f.request(Mode::Status); st.nativeControlSha256 = f.nativeSha;
      auto o = runMaintenance(st, s);
      CHECK(o.ok && o.native && o.controlHashes.size() == 1 && o.controlHashes.at("awg-feed") == f.nativeSha);
      CHECK(s.verb("build") == 0 && s.verb("create") == 0); CHECK(s.count("python") == 0); CHECK(!s.mutatingBoundary()); }
    { FakeOps r(f); auto rs = f.request(Mode::RestartControls); rs.nativeControlSha256 = f.nativeSha;
      auto o = runMaintenance(rs, r);
      CHECK(o.ok && o.native && o.controlHashes.at("awg-feed") == f.nativeSha);
      CHECK(r.verifiedAs(f.nativeSha) == 2 && r.count("python") == 0); }
    CHECK(journalText(f) == before);
    workEnd();
}

// WORK 2: an automatic release-archive style authority label is not CURRENT
// authority; the unchanged consumer refuses it and nothing is mutated.
static void work2() {
    workBegin("automatic-release-authority-refused");
    Fixture f(true); const auto before = journalText(f);
    f.rewrite([](std::string& t) { replaceOnce(t, "authenticated-operator-sha256", "authenticated-release-archive"); });
    const auto forged = journalText(f); FakeOps ops(f);
    auto r = f.request(Mode::Maintain); r.nativeControlSha256 = f.nativeSha;
    expectThrow([&] { runMaintenance(r, ops); }, "unsupported control variant", __LINE__);
    CHECK(!ops.mutatingBoundary());
    CHECK(journalText(f) == forged && forged != before);
    workEnd();
}

// WORK 3: a self-reported loaded receipt alone is not CURRENT authority.
static void work3() {
    workBegin("automatic-receipt-only-refused");
    Fixture f(true); const auto before = journalText(f);
    f.rewrite([](std::string& t) { replaceOnce(t, "\"controlLoadedReceipt\":true", "\"controlLoadedReceipt\":false"); });
    const auto forged = journalText(f); FakeOps ops(f);
    auto r = f.request(Mode::Maintain);
    expectThrow([&] { runMaintenance(r, ops); }, "native_control_not_ready", __LINE__);
    CHECK(!ops.mutatingBoundary());
    CHECK(journalText(f) == forged && forged != before);
    workEnd();
}

// WORK 4: the automatic caller has no operator value -> required, and the
// explicit operator path still works afterwards (recovery intact).
static void work4() {
    workBegin("automatic-missing-operator-refused");
    Fixture f(true, true); const auto before = journalText(f); FakeOps ops(f);
    auto r = f.request(Mode::Maintain); r.nativeControlSha256.clear();
    expectThrow([&] { runMaintenance(r, ops); }, "native_control_sha256_required", __LINE__);
    CHECK(!ops.mutatingBoundary()); CHECK(journalText(f) == before);
    { FakeOps ops2(f); auto ok = f.request(Mode::Status); ok.nativeControlSha256 = f.nativeSha;
      auto o = runMaintenance(ok, ops2);
      CHECK(o.ok && o.native && o.controlHashes.at("awg-feed") == f.nativeSha);
      CHECK(!ops2.mutatingBoundary()); }
    CHECK(journalText(f) == before);
    workEnd();
}

// WORK 5: neither the replacement bundle SHA nor an unsigned journal/ledger
// value can stand in for CURRENT authority.
static void work5() {
    workBegin("replacement-or-ledger-not-current");
    { Fixture f(true, true); const auto before = journalText(f); FakeOps ops(f);
      const auto bytes = elfImage("control-new\n"); const auto newSha = sha(bytes);
      auto r = f.request(Mode::Maintain); r.nativeControlSha256 = newSha;          // replacement as CURRENT
      r.nativeControlReplacementSha256 = newSha;
      expectThrow([&] { runMaintenance(r, ops); }, "native_control_sha256_mismatch", __LINE__);
      CHECK(!ops.mutatingBoundary()); CHECK(journalText(f) == before); }
    { Fixture f(true, true); const auto before = journalText(f); FakeOps ops(f);
      auto r = f.request(Mode::Maintain); r.nativeControlSha256 = std::string(64, '9'); // journal/ledger value
      expectThrow([&] { runMaintenance(r, ops); }, "native_control_sha256_mismatch", __LINE__);
      CHECK(!ops.mutatingBoundary()); CHECK(journalText(f) == before); }
    workEnd();
}

int main(int argc, char** argv) {
    for (auto fn : {work1, work2, work3, work4, work5}) {
        const int before = failures;

        try { fn(); } catch (const std::exception& e) { std::cerr << "EX work: " << e.what() << "\n"; ++failures; }
    }
    std::cout << "works=" << works << " checks=" << checks << " failures=" << failures
              << " workFailures=" << workFailures << "\n";
    if (failures) return 1;
    if (argc == 2 && std::string(argv[1]) == "--outer-fail-work") return 23;
    return 0;
}
