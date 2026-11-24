#ifndef WINDOWSSPLITTUNNELPOLICY_H
#define WINDOWSSPLITTUNNELPOLICY_H

#include <cstddef>
#include <cstdint>

namespace windowsSplitTunnelPolicy {

inline bool helperExitNeedsIsolatedCleanup(bool processExited,
                                           std::uint32_t exitCode,
                                           std::uint32_t successCode) {
  return processExited && exitCode != successCode;
}

inline bool quarantinedExitNeedsIsolatedCleanup(bool processExited,
                                                bool helperVerifiedCleanup) {
  return processExited && !helperVerifiedCleanup;
}

inline bool cleanupHelperWaitNeedsQuarantine(bool timedOut,
                                             bool waitFailed,
                                             bool processExited) {
  return timedOut || waitFailed || !processExited;
}

inline bool failedHelperLaunchNeedsQuarantine(bool terminationConfirmed) {
  return !terminationConfirmed;
}

inline bool exactReadyStateReadback(bool ioctlSucceeded,
                                    std::size_t returnedBytes,
                                    std::size_t expectedBytes,
                                    std::size_t observedState,
                                    std::size_t readyState) {
  return ioctlSucceeded && returnedBytes == expectedBytes
      && observedState == readyState;
}

// CLEAR_CONFIGURATION is not a valid control while the driver is only
// initialized. In that state no configuration can have been applied yet, so
// a verified INITIALIZED readback is already a successful no-op cleanup.
inline bool cleanupStateAllowsInitializedNoop(std::size_t ioctlSucceeded,
                                              std::size_t returnedBytes,
                                              std::size_t expectedBytes,
                                              std::size_t observedState,
                                              std::size_t initializedState) {
  return ioctlSucceeded != 0 && returnedBytes == expectedBytes
      && observedState == initializedState;
}

// Give the helper time to observe its cooperative abort. A termination
// request does not establish process exit or driver cleanup.
class QuarantineTermination {
 public:
  void begin(std::uint64_t now) {
    m_startedAt = now;
    m_requested = false;
  }

  bool requestIfOverdue(std::uint64_t now) {
    constexpr std::uint64_t graceMs = 5000;
    if (m_requested || now - m_startedAt < graceMs) {
      return false;
    }
    m_requested = true;
    return true;
  }

 private:
  std::uint64_t m_startedAt = 0;
  bool m_requested = false;
};

class CleanupGate {
 public:
  bool allowsMutation() const { return !m_failed; }
  void markFailure() { m_failed = true; }
  void markVerified() { m_failed = false; }

 private:
  bool m_failed = false;
};

}  // namespace windowsSplitTunnelPolicy

#endif  // WINDOWSSPLITTUNNELPOLICY_H
