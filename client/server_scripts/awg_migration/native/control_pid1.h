#pragma once
#include "control_http.h"
#include "control_loaded.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

namespace amnezia::awgMigration::controlPid1 {
// argv dispatch owned by feed_server.cpp. `NotNative` keeps every existing mode
// byte-for-byte unchanged; a malformed native invocation is `Invalid` (exit 2)
// and never falls through to the feed listener.
enum class NativeArgv { NotNative, ControlPid1, VerifyLoaded, Invalid };
NativeArgv parseNativeControlArgv(int argc, char **argv, std::string &role,
                                  std::string &sha256, std::string &receiptPath);

struct ControlPid1Config {
    std::filesystem::path executable; // /app/awg-feed
    std::filesystem::path directory;  // /migration, trusted transport only
    std::string expectedSha256;       // image/meta authority, never the receipt
    std::string role, scope;
};
struct ControlPid1Deps {
    CaptureOps &capture;
    ReceiptSink &sink;
    ControlTransport &transport;
    std::function<std::string()> processStart;
    ControlHooks hooks;
};

// Bounded native PID1 entrypoint. Order is capture -> seal -> receipt finalize ->
// serve. Returns 0 after a clean listener stop and 2 for every startup/capture/
// receipt failure; a request that fails dispatch is answered 403 and does not
// terminate the listener.
int controlPid1Run(const ControlPid1Config &config, ControlPid1Deps &deps);

// Production entrypoints, defined only in control_pid1_posix.cpp. They wire the
// real adapters into controlPid1Run / verifyLoadedControl; they add no trust
// decision of their own.
int controlPid1Main();
int verifyLoadedControlMain(const std::string &role, const std::string &expectedSha256,
                            const std::string &receiptPath);

// Constructs the actual production POSIX pool transport without starting any OS
// work. Narrow seam for the inert boundary runner; serving begins only when
// controlPid1Run/serveControl hands it the request handler. controlPid1Main uses
// the same type directly.
std::unique_ptr<ControlTransport> makePosixPoolTransport(std::uint16_t port);
} // namespace amnezia::awgMigration::controlPid1
