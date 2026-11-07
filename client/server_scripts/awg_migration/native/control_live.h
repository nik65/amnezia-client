#pragma once
#include <cstdint>
#include <string>

namespace amnezia::awgMigration::controlPid1 {
// Port of the existing Python CONTROL_LISTENER_PROBE predicate that S2 still
// runs unconditionally: TCP IPv4 0.0.0.0:18082 (00000000:46A2), state LISTEN.
inline constexpr std::uint16_t liveControlPort = 18082;

// Distinct native live-control gate. First re-runs the unchanged
// verifyLoadedControlMain (same receipt/FD/incarnation semantics and exit
// codes); only on success additionally proves that PID1 is still the captured
// incarnation across that verification and owns the fixed IPv4 LISTEN socket.
// 0 = attested, 2 = invalid arguments, 3 = loaded receipt/FD gate failed,
// 4 = live incarnation/listener attestation failed or /proc data malformed.
int verifyLiveControlMain(const std::string &role, const std::string &expectedSha256,
                          const std::string &receiptPath);

// Narrow, separately implemented dispatcher input for feed_server main().
// NotLive means every existing argument mode keeps its current meaning.
enum class LiveArgv { NotLive, VerifyLive, Invalid };
LiveArgv parseVerifyControlLiveArgv(int argc, char **argv, std::string &role,
                                    std::string &sha256, std::string &receiptPath);
// Consumes only the exact --verify-control-live command. Returns false for any
// other argv so the existing dispatcher continues byte-for-byte unchanged.
bool runVerifyControlLiveArgv(int argc, char **argv, int &status);
} // namespace amnezia::awgMigration::controlPid1
