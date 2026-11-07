#include "prepare_entry.h"
#include "production_ports.h"
#include <cstdio>

// Link-only proof: takes addresses, never calls. No process/Docker boundary is
// crossed by this probe.
int main() {
    auto entry = &amnezia::awgMigration::prepareEntry::productionMain;
    auto command = &amnezia::awgMigration::prepareProduction::ProductionPorts::command;
    auto observe = &amnezia::awgMigration::prepareProduction::ProductionPorts::observe;
    std::printf("entry=%d command=%d observe=%d\n", entry != nullptr, command != nullptr, observe != nullptr);
    return (entry && command && observe) ? 0 : 1;
}
