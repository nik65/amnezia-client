#include "control_pid1.h"

#include <stdexcept>
#include <utility>

namespace amnezia::awgMigration::controlPid1 {
NativeArgv parseNativeControlArgv(int argc, char **argv, std::string &role,
                                  std::string &sha256, std::string &receiptPath) {
    if (argc < 2 || !argv || !argv[1]) return NativeArgv::NotNative;
    const std::string mode(argv[1]);
    if (mode != "--control-pid1" && mode != "--verify-control-loaded") return NativeArgv::NotNative;
    if (mode == "--control-pid1") return argc == 2 ? NativeArgv::ControlPid1 : NativeArgv::Invalid;
    if (argc != 5 || !argv[2] || !argv[3] || !argv[4]) return NativeArgv::Invalid;
    // Bounds are the same as the receipt/sha checks; the entrypoint repeats them
    // against its own trusted inputs rather than trusting argv alone.
    const std::string candidate(argv[2]);
    if ((candidate != "source" && candidate != "target")
        || std::string(argv[3]).size() != 64 || std::string(argv[4]).empty()) return NativeArgv::Invalid;
    role = candidate;
    sha256 = argv[3];
    receiptPath = argv[4];
    return NativeArgv::VerifyLoaded;
}

int controlPid1Run(const ControlPid1Config &config, ControlPid1Deps &deps) {
    if ((config.role != "source" && config.role != "target")
        || (config.scope != "amnezia-awg" && config.scope != "amnezia-awg2")
        || config.executable.empty() || config.directory.empty() || !deps.processStart) return 2;
    ExecutableImage image;
    try {
        image = captureExecutable(config.executable, config.expectedSha256, deps.capture);
    } catch (...) {
        return 2;
    }
    if (image.fd < 0) return 2;
    try {
        const auto start = deps.processStart();
        if (start.empty() || start.size() > 64) throw std::runtime_error("native_control_rejected");
        deps.sink.commit(config.directory, config.role,
                         receiptJson({config.role, start, image.sha256, image.fd}));
    } catch (...) {
        deps.capture.close(image.fd);
        image.fd = -1;
        return 2;
    }
    try {
        ControlConfig control{config.directory, config.role, config.scope};
        return serveControl(control, deps.hooks, deps.transport);
    } catch (...) {
        deps.capture.close(image.fd);
        image.fd = -1;
        return 2;
    }
}
} // namespace amnezia::awgMigration::controlPid1
