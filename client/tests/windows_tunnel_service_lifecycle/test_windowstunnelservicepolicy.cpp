#include "platforms/windows/daemon/windowstunnelservicepolicy.h"

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using amnezia::windowsTunnel::StartAttempt;

void retryAfterOwnedCleanup() {
  int attempts = 0;
  int cleanupCalls = 0;
  int backoffs = 0;
  bool cancelled = false;
  const std::string ownedService = "attempt-service";
  const std::string unrelatedService = "unrelated-service";
  std::vector<std::string> cleaned;

  const auto result = amnezia::windowsTunnel::runStartLifecycle(
      [&] {
        ++attempts;
        if (attempts == 1) {
          return StartAttempt{false, true, 1066, 3};
        }
        return StartAttempt{true, true, 0, 0};
      },
      [&] {
        ++cleanupCalls;
        cleaned.push_back(ownedService);
        return true;
      },
      [&] { ++backoffs; }, [&] { return cancelled; });

  assert(result.started);
  assert(result.cleanupConfirmed);
  assert(result.attempts == 2);
  assert(attempts == 2);
  assert(cleanupCalls == 1);
  assert(backoffs == 1);
  assert(cleaned.size() == 1 && cleaned.front() == ownedService);
  assert(unrelatedService != cleaned.front());
}

void permanentFailureIsCleanedWithoutRetry() {
  int attempts = 0;
  int cleanupCalls = 0;
  int backoffs = 0;

  const auto result = amnezia::windowsTunnel::runStartLifecycle(
      [&] {
        ++attempts;
        return StartAttempt{false, true, 1066, 7};
      },
      [&] {
        ++cleanupCalls;
        return true;
      },
      [&] { ++backoffs; }, [] { return false; });

  assert(!result.started);
  assert(result.cleanupConfirmed);
  assert(result.attempts == 1);
  assert(attempts == 1);
  assert(cleanupCalls == 1);
  assert(backoffs == 0);
}

void cancellationPreventsRetryAfterCleanup() {
  int attempts = 0;
  int cleanupCalls = 0;
  int backoffs = 0;

  const auto result = amnezia::windowsTunnel::runStartLifecycle(
      [&] {
        ++attempts;
        return StartAttempt{false, true, 1066, 3};
      },
      [&] {
        ++cleanupCalls;
        return true;
      },
      [&] { ++backoffs; }, [] { return true; });

  assert(!result.started);
  assert(result.cleanupConfirmed);
  assert(result.attempts == 1);
  assert(attempts == 1);
  assert(cleanupCalls == 1);
  assert(backoffs == 0);
}

void exhaustedBudgetDuringCleanupPreventsRetry() {
  int attempts = 0;
  int cleanupCalls = 0;
  int backoffs = 0;
  bool budgetExhausted = false;

  const auto result = amnezia::windowsTunnel::runStartLifecycle(
      [&] {
        ++attempts;
        return StartAttempt{false, true, 1066, 3};
      },
      [&] {
        ++cleanupCalls;
        budgetExhausted = true;
        return true;
      },
      [&] { ++backoffs; }, [&] { return budgetExhausted; });

  assert(!result.started);
  assert(result.cleanupConfirmed);
  assert(result.attempts == 1);
  assert(attempts == 1);
  assert(cleanupCalls == 1);
  assert(backoffs == 0);
}

void cleanupFailurePreventsRetry() {
  int attempts = 0;
  int cleanupCalls = 0;
  int backoffs = 0;

  const auto result = amnezia::windowsTunnel::runStartLifecycle(
      [&] {
        ++attempts;
        return StartAttempt{false, true, 1066, 3};
      },
      [&] {
        ++cleanupCalls;
        return false;
      },
      [&] { ++backoffs; }, [] { return false; });

  assert(!result.started);
  assert(!result.cleanupConfirmed);
  assert(result.attempts == 1);
  assert(attempts == 1);
  assert(cleanupCalls == 1);
  assert(backoffs == 0);
}

void retryFailureIsCleanedWithoutLeavingOwnedService() {
  int attempts = 0;
  int cleanupCalls = 0;
  int backoffs = 0;

  const auto result = amnezia::windowsTunnel::runStartLifecycle(
      [&] {
        ++attempts;
        return StartAttempt{false, true, 1066, attempts == 1 ? 3u : 7u};
      },
      [&] {
        ++cleanupCalls;
        return true;
      },
      [&] { ++backoffs; }, [] { return false; });

  assert(!result.started);
  assert(result.cleanupConfirmed);
  assert(result.attempts == 2);
  assert(attempts == 2);
  assert(cleanupCalls == 2);
  assert(backoffs == 1);
}

void firstErrorIsRetainedAfterRetryFailure() {
  int attempts = 0;
  int cleanupCalls = 0;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> errorHistory;

  const auto result = amnezia::windowsTunnel::runStartLifecycle(
      [&] {
        ++attempts;
        const StartAttempt outcome =
            attempts == 1 ? StartAttempt{false, true, 1066, 3}
                          : StartAttempt{false, true, 1066, 7};
        errorHistory.emplace_back(outcome.win32ExitCode,
                                  outcome.serviceSpecificExitCode);
        return outcome;
      },
      [&] {
        ++cleanupCalls;
        return true;
      },
      [] {}, [] { return false; });

  assert(!result.started);
  assert(result.attempts == 2);
  assert(attempts == 2);
  assert(cleanupCalls == 2);
  assert(errorHistory.size() == 2);
  assert(errorHistory.front() == std::make_pair(1066u, 3u));
  assert(errorHistory.back() == std::make_pair(1066u, 7u));
}

void unownedFailureCannotTriggerCleanupOrRetry() {
  int attempts = 0;
  int cleanupCalls = 0;
  int backoffs = 0;

  const auto result = amnezia::windowsTunnel::runStartLifecycle(
      [&] {
        ++attempts;
        return StartAttempt{false, false, 1066, 3};
      },
      [&] {
        ++cleanupCalls;
        return true;
      },
      [&] { ++backoffs; }, [] { return false; });

  assert(!result.started);
  assert(result.cleanupConfirmed);
  assert(result.attempts == 1);
  assert(attempts == 1);
  assert(cleanupCalls == 0);
  assert(backoffs == 0);
}

}  // namespace

int main() {
  retryAfterOwnedCleanup();
  permanentFailureIsCleanedWithoutRetry();
  cancellationPreventsRetryAfterCleanup();
  exhaustedBudgetDuringCleanupPreventsRetry();
  cleanupFailurePreventsRetry();
  retryFailureIsCleanedWithoutLeavingOwnedService();
  firstErrorIsRetainedAfterRetryFailure();
  unownedFailureCannotTriggerCleanupOrRetry();
  return 0;
}
