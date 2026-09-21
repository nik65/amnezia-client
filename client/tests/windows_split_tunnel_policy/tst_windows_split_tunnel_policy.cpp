#include <cstddef>
#include <cstdint>
#include <iostream>

#include "platforms/windows/daemon/windowssplittunnelpolicy.h"

namespace {
class TestRunner {
 public:
  void check(bool condition, const char* expression, int line) {
    ++assertions;
    if (!condition) {
      ++failures;
      std::cerr << "FAIL line " << line << ": " << expression << '\n';
    }
  }

  int finish() const {
    std::cout << (failures == 0 ? "PASS" : "FAIL") << ": " << assertions
              << " assertions, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
  }

 private:
  int assertions = 0;
  int failures = 0;
};
}  // namespace

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main() {
  TestRunner runner;
  constexpr std::uint32_t success = 0;
  constexpr std::size_t ready = 3;

  CHECK(!windowsSplitTunnelPolicy::helperExitNeedsIsolatedCleanup(
      true, success, success));
  CHECK(windowsSplitTunnelPolicy::helperExitNeedsIsolatedCleanup(
      true, 4, success));
  CHECK(windowsSplitTunnelPolicy::helperExitNeedsIsolatedCleanup(
      true, 6, success));
  CHECK(!windowsSplitTunnelPolicy::helperExitNeedsIsolatedCleanup(
      false, 6, success));
  // A commit-wait timeout keeps the helper quarantined; once it exits without
  // its own verified cleanup, the parent must perform isolated cleanup.
  CHECK(windowsSplitTunnelPolicy::quarantinedExitNeedsIsolatedCleanup(
      true, false));
  CHECK(!windowsSplitTunnelPolicy::quarantinedExitNeedsIsolatedCleanup(
      true, true));
  CHECK(!windowsSplitTunnelPolicy::quarantinedExitNeedsIsolatedCleanup(
      false, false));
  CHECK(windowsSplitTunnelPolicy::cleanupHelperWaitNeedsQuarantine(
      true, false, false));
  CHECK(windowsSplitTunnelPolicy::cleanupHelperWaitNeedsQuarantine(
      false, true, false));
  CHECK(windowsSplitTunnelPolicy::cleanupHelperWaitNeedsQuarantine(
      false, false, true) == false);
  CHECK(windowsSplitTunnelPolicy::failedHelperLaunchNeedsQuarantine(false));
  CHECK(!windowsSplitTunnelPolicy::failedHelperLaunchNeedsQuarantine(true));

  CHECK(windowsSplitTunnelPolicy::exactReadyStateReadback(
      true, sizeof(std::size_t), sizeof(std::size_t), ready, ready));
  CHECK(!windowsSplitTunnelPolicy::exactReadyStateReadback(
      true, sizeof(std::size_t) - 1, sizeof(std::size_t), ready, ready));
  CHECK(!windowsSplitTunnelPolicy::exactReadyStateReadback(
      true, sizeof(std::size_t) + 1, sizeof(std::size_t), ready, ready));
  CHECK(!windowsSplitTunnelPolicy::exactReadyStateReadback(
      true, sizeof(std::size_t), sizeof(std::size_t), 4, ready));
  CHECK(!windowsSplitTunnelPolicy::exactReadyStateReadback(
      false, sizeof(std::size_t), sizeof(std::size_t), ready, ready));

  windowsSplitTunnelPolicy::CleanupGate gate;
  CHECK(gate.allowsMutation());
  gate.markFailure();
  CHECK(!gate.allowsMutation());
  gate.markVerified();
  CHECK(gate.allowsMutation());

  return runner.finish();
}
