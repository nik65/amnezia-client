#include "orchestration_entry.h"
#include "prepare_entry.h"
#include "maintenance_runtime.h"
#include <string>
namespace amnezia::awgMigration::orchestration {
bool runOrchestrationArgv(int argc, char **argv, int &status) {
    if (argc < 2 || !argv || !argv[1]) return false;
    const std::string mode = argv[1];
    if (mode == "--prepare") {
        status = prepareEntry::productionMain(argc - 1, argv + 1);
        return true;
    }
    if (mode == "--maintenance" || mode == "--maintenance-status"
        || mode == "--maintenance-cleanup" || mode == "--maintenance-recover"
        || mode == "--maintenance-restart-controls") {
        status = maintenance::maintenanceMain(argc - 1, argv + 1);
        return true;
    }
    return false;
}
}
