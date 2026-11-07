#include "orchestration_entry.h"
#include "prepare_entry.h"
#include "maintenance_runtime.h"
#include <iostream>
#include <string>
#include <vector>
namespace {
unsigned prepares = 0, maintains = 0, failures = 0;
std::vector<std::string> observed;
void capture(int argc, char **argv) {
    observed.clear();
    for (int i = 0; i < argc; ++i) observed.emplace_back(argv[i]);
}
}
namespace amnezia::awgMigration::prepareEntry {
int productionMain(int argc, char **argv) { ++prepares; capture(argc, argv); return 23; }
}
namespace amnezia::awgMigration::maintenance {
int maintenanceMain(int argc, char **argv) { ++maintains; capture(argc, argv); return 37; }
}
int main() {
    using amnezia::awgMigration::orchestration::runOrchestrationArgv;
    const std::vector<std::string> modes{"--prepare", "--maintenance", "--maintenance-status",
        "--maintenance-cleanup", "--maintenance-recover", "--maintenance-restart-controls", "--maintenance-verify",
        "--maintenance-inspect-prepare", "--maintenance-abort-prepare"};
    for (const auto &mode : modes) {
        std::vector<std::string> values{"/unchanged/awg-feed", mode, "--source", "amnezia-awg", "--opaque", "not-a-normalized token"};
        std::vector<char *> argv;
        for (auto &value : values) argv.push_back(value.data());
        int status = 99;
        const unsigned before = prepares + maintains;
        bool handled = runOrchestrationArgv(static_cast<int>(argv.size()), argv.data(), status);
        const std::vector<std::string> expected(values.begin() + 1, values.end());
        const bool good = handled && prepares + maintains == before + 1 && observed == expected
            && status == (mode == "--prepare" ? 23 : 37);
        std::cout << (good ? "PASS " : "FAIL ") << mode << '\n';
        if (!good) ++failures;
    }
    for (const auto *mode : {"--serve", "--control-pid1", "--maintenance-bogus", "--prepare-extra"}) {
        std::vector<std::string> values{"awg-feed", mode};
        std::vector<char *> argv{values[0].data(), values[1].data()};
        int status = 99;
        const unsigned before = prepares + maintains;
        if (runOrchestrationArgv(2, argv.data(), status) || status != 99 || prepares + maintains != before) ++failures;
    }
    int status = 99;
    if (runOrchestrationArgv(0, nullptr, status) || status != 99) ++failures;
    std::cout << "argv_failures=" << failures << '\n';
    return failures ? 1 : 0;
}
