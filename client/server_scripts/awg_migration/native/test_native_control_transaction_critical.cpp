#include "test_native_control_transaction_fixture.h"
// Deferred native regressions: do not execute until the user authorizes builds.
static void recoveryBoundaryCases() {
    using namespace awgfix;
    {
        Fixture f(true);
        FakeOps status(f);
        const auto observed = runMaintenance(f.request(Mode::Status), status);
        if (!observed.ok || observed.liveVerified || status.mutatingBoundary()
            || resultJson(observed).find("\"liveVerified\":false") == std::string::npos)
            throw std::runtime_error("status claimed live recovery evidence");
        FakeOps recover(f);
        const auto verified = runMaintenance(f.request(Mode::Recover), recover);
        if (!verified.ok || !verified.liveVerified || verified.pendingRecovery
            || verified.phase != "ready" || verified.controlHashes.at("awg-feed") != f.nativeSha
            || recover.verifiedAs(f.nativeSha) < 3)
            throw std::runtime_error("recovery did not verify both live helper roles");
    }
    for (const auto& role : {std::string("target"), std::string("source")}) {
        Fixture f(true);
        FakeOps rejected(f);
        rejected.failVerifyRole = role;
        bool refused = false;
        try { (void)runMaintenance(f.request(Mode::Recover), rejected); }
        catch (const std::exception&) { refused = true; }
        if (!refused) throw std::runtime_error("recovery ignored failed live helper proof");
    }
    {
        Fixture f(true);
        auto raw = read(f.directory / "ready.json");
        replaceOnce(raw, "\"generation\":1", "\"generation\":2");
        write(f.directory / "ready.json", raw);
        FakeOps rejected(f);
        bool refused = false;
        try { (void)runMaintenance(f.request(Mode::Recover), rejected); }
        catch (const std::exception&) { refused = true; }
        if (!refused || !rejected.calls.empty())
            throw std::runtime_error("recovery mutated before checking ready generation");
    }
    {
        Fixture f(true);
        const auto replacement = sha(elfImage("unknown-rollback-authority\n"));
        const auto newImage = "sha256:" + std::string(64, '5');
        f.plantIntent(replacement, newImage);
        f.rewrite([&](std::string& raw) {
            replaceOnce(raw, "\"sha256\":\"" + f.nativeSha + "\"",
                        "\"sha256\":\"" + replacement + "\"");
        });
        auto request = f.request(Mode::Recover);
        request.nativeControlSha256 = replacement;
        const auto before = read(f.directory / "transaction.json");
        FakeOps rejected(f);
        bool refused = false;
        try { (void)runMaintenance(request, rejected); }
        catch (const std::exception&) { refused = true; }
        if (!refused || !rejected.calls.empty() || before != read(f.directory / "transaction.json"))
            throw std::runtime_error("replacement authority authorized unknown old rollback");
    }
    std::cout << "native recovery source/generation/pin/live boundaries: PASS\n";
}

int main(int argc, char **argv) {
    using namespace awgfix;
    try {
        recoveryBoundaryCases();
        Fixture f(true, true);
        const auto bytes = elfImage("parent-first-update\n");
        write(f.recipe / "awg-feed", bytes);
        FakeOps ops(f);
        Request request = f.upgrade(bytes);
        const auto result = runMaintenance(request, ops);
        if (!result.ok || result.controlHashes.at("awg-feed") != sha(bytes))
            throw std::runtime_error("actual replacement did not commit");
        std::cout << "actual native create argv and committed consumer: PASS\n";
        const auto protectedBefore = f.protectedJson();
        const auto second = elfImage("parent-second-update\n");
        write(f.recipe / "awg-feed", second);
        Request upgrade = f.upgrade(second);
        upgrade.nativeControlSha256 = sha(bytes); // Independent known current authority.
        FakeOps failed(f);
        failed.failStartRole = "target";
        bool refused = false;
        try { runMaintenance(upgrade, failed); }
        catch (const std::exception &) { refused = true; }
        if (!refused) throw std::runtime_error("injected second update did not fail");
        Request recovery = f.request(Mode::Recover);
        recovery.nativeControlSha256 = sha(bytes);
        FakeOps recovering(f);
        const auto restored = runMaintenance(recovery, recovering);
        if (!restored.ok || !restored.liveVerified || restored.pendingRecovery || restored.controlHashes.at("awg-feed") != sha(bytes)
            || f.protectedJson() != protectedBefore)
            throw std::runtime_error("second-update rollback lost prior authority");
        std::cout << "successive update failure and recovery: PASS\n";
        Request retry = f.upgrade(second);
        retry.nativeControlSha256 = sha(bytes);
        FakeOps retrying(f);
        const auto committed = runMaintenance(retry, retrying);
        if (!committed.ok || committed.controlHashes.at("awg-feed") != sha(second)
            || f.protectedJson() != protectedBefore)
            throw std::runtime_error("successive update retry did not commit");
        std::cout << "successive distinct update retry: PASS\n";
        Request committedRecovery = f.request(Mode::Recover);
        committedRecovery.nativeControlSha256 = sha(second);
        FakeOps committedVerifier(f);
        const auto recoveredCommit = runMaintenance(committedRecovery, committedVerifier);
        if (!recoveredCommit.ok || !recoveredCommit.liveVerified
            || recoveredCommit.controlHashes.at("awg-feed") != sha(second))
            throw std::runtime_error("committed replacement could not be verified under new authority");

        if (argc == 2 && std::string(argv[1]) == "--fail-work") return 23;
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
