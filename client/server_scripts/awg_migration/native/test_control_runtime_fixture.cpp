#include "control_runtime.h"
#include <filesystem>
#include <string>

int main(int argc, char **argv) {
    // Test-only state root is the caller's explicitly owned cwd. Production's
    // --control-json dispatch never accepts or derives its root from cwd/JSON/env.
    if (argc == 2 && std::string(argv[1]) == "--control-json")
        return amnezia::awgMigration::controlJsonMain(std::filesystem::current_path());
    return 2;
}
