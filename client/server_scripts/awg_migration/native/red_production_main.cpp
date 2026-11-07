#include "prepare_entry.h"
#include "production_ports.h"
#include <unistd.h>
#include <iostream>

namespace amnezia::awgMigration::prepareEntry {
int productionMain(int argc, char **argv) {
    const Parsed parsed = parseArgv(argc, argv);
    prepareProduction::ProductionPorts ports("/opt/amnezia/awg-migration", parsed.nativeFeed,
                                             parsed.request.nativeFeedSha256);
    if (parsed.help || !parsed.valid) return run(parsed, "/opt/amnezia/awg-migration", ports, ports);
    // The canonical operation is an administrator action. This check is in the
    // production entry only; inert CLI-boundary tests inject inert ports.
    if (geteuid() != 0) {
        std::cout << "{\"error\":\"administrator/source required\"}\n";
        return 1;
    }
    return run(parsed, "/opt/amnezia/awg-migration", ports, ports);
}
} // namespace amnezia::awgMigration::prepareEntry
