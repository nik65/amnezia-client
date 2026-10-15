/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <cstdint>

namespace amnezia::windowsTunnel {

inline constexpr std::uint32_t kServiceSpecificError = 1066;
inline constexpr std::uint32_t kWinTunDeviceCreationError = 3;

struct StartAttempt {
  bool started = false;
  bool ownsService = false;
  std::uint32_t win32ExitCode = 0;
  std::uint32_t serviceSpecificExitCode = 0;
};

struct StartLifecycleResult {
  bool started = false;
  bool cleanupConfirmed = true;
  unsigned attempts = 0;
};

inline bool isWinTunDeviceCreationFailure(const StartAttempt& attempt) {
  return attempt.win32ExitCode == kServiceSpecificError &&
         attempt.serviceSpecificExitCode == kWinTunDeviceCreationError;
}

// This policy owns only the service returned by attempt(). A failed attempt
// must be cleaned before a retry, and exactly one retry is permitted for the
// service-specific WinTun device-creation failure.
template <typename AttemptFn, typename CleanupFn, typename BackoffFn,
          typename CancelledFn>
StartLifecycleResult runStartLifecycle(AttemptFn&& attempt,
                                       CleanupFn&& cleanup,
                                       BackoffFn&& backoff,
                                       CancelledFn&& cancelled) {
  constexpr unsigned kMaxAttempts = 2;
  StartLifecycleResult result;

  while (result.attempts < kMaxAttempts) {
    ++result.attempts;
    const StartAttempt outcome = attempt();
    if (outcome.started) {
      result.started = true;
      return result;
    }

    if (!outcome.ownsService || !cleanup()) {
      result.cleanupConfirmed = !outcome.ownsService;
      return result;
    }

    if (cancelled() || result.attempts >= kMaxAttempts ||
        !isWinTunDeviceCreationFailure(outcome)) {
      return result;
    }

    backoff();
  }

  return result;
}

}  // namespace amnezia::windowsTunnel
