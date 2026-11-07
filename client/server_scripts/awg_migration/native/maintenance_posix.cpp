#include "maintenance_runtime.h"
#include "bounded_docker.h"
#include "docker_absence.h"
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <vector>

namespace amnezia::awgMigration::maintenance {
namespace {
class PosixOps final : public Ops {
public:
    std::string run(const std::vector<std::string>& argv) override {
        if (argv.empty() || argv[0] != "docker") throw std::runtime_error("maintenance command rejected");
        try { return runBoundedDockerWithBudget(argv, 1024u * 1024u, 180); }
        catch (const BoundedDockerError& error) {
            if (error.kind == BoundedDockerFailureKind::Exit
                && verifiedDockerInspectAbsence(argv, [](const auto& inventory) {
                    return runBoundedDockerWithBudget(inventory,1024u*1024u,10);
                })) throw std::runtime_error("No such object");
            throw;
        }
    }
    std::uint32_t euid() override { return static_cast<std::uint32_t>(geteuid()); }
    void sleepSeconds(unsigned seconds) override { ::sleep(seconds); }
};
}

// Proposed constructor for the copied awg-feed main:
//   argv[0] == "--maintenance" (or one of the four read/recovery mode flags)
// New flags only. Existing argv has no meaning change; until wiring is applied
// this symbol is unreachable from the deployed feed.
int maintenanceMain(int argc, char** argv) {
    try {
        std::vector<std::string> args;
        for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
        Request request = parseRequest(args);
        PosixOps ops;
        if (ops.euid() != 0) throw std::runtime_error("administrator required");
        Result result = runMaintenance(request, ops);
        std::cout << resultJson(result) << std::endl;
        return 0;
    } catch (const std::exception&) {
        // Never leak private subprocess output or server configuration.
        std::cout << "{\"ok\":false,\"reason\":\"migration_control_maintenance_failed\"}" << std::endl;
        return 1;
    }
}
}
