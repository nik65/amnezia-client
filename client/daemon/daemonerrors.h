/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <cmath>
#include <cstdint>
#include <limits>

enum class DaemonError : uint8_t {
  ERROR_NONE = 0u,
  ERROR_FATAL = 1u,
  ERROR_SPLIT_TUNNEL_INIT_FAILURE = 2u,
  ERROR_SPLIT_TUNNEL_START_FAILURE = 3u,
  ERROR_SPLIT_TUNNEL_EXCLUDE_FAILURE = 4u,
  ERROR_SPLIT_TUNNEL_CONFIG_TIMEOUT = 5u,
  ERROR_SPLIT_TUNNEL_CONFIG_WAIT_FAILED = 6u,
  ERROR_SPLIT_TUNNEL_CONFIG_CLEANUP_FAILED = 7u,

  DAEMON_ERROR_MAX = 8u,
};

enum class QuarantineCleanup : uint8_t {
  Pending = 0u,
  Failed = 1u,
  Verified = 2u,
};

inline bool isDaemonFailureIpcValue(int value) {
  return value >= static_cast<int>(DaemonError::ERROR_FATAL)
      && value < static_cast<int>(DaemonError::DAEMON_ERROR_MAX);
}

inline bool isValidDaemonFailureNumber(double value) {
  return std::isfinite(value) && std::floor(value) == value
      && value >= std::numeric_limits<int>::min()
      && value <= std::numeric_limits<int>::max();
}

inline DaemonError daemonErrorFromIpcValue(int value) {
  return isDaemonFailureIpcValue(value)
      ? static_cast<DaemonError>(value)
      : DaemonError::ERROR_FATAL;
}

inline bool mayReleaseQuarantine(bool processExited,
                                 QuarantineCleanup cleanup) {
  return processExited && cleanup == QuarantineCleanup::Verified;
}
