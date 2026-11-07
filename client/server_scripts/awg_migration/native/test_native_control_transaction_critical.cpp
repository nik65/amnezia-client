#include "test_native_control_transaction_fixture.h"
int main(int argc, char **argv) {
    using namespace awgfix;
    try {
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
        if (!restored.ok || restored.pendingRecovery || restored.controlHashes.at("awg-feed") != sha(bytes)
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
        if (argc == 2 && std::string(argv[1]) == "--fail-work") return 23;
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
