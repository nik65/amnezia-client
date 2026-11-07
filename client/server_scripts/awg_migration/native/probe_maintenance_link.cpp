#include "maintenance_runtime.h"
int main() {
    const auto entry = &amnezia::awgMigration::maintenance::maintenanceMain;
    return entry ? 0 : 1;
}
