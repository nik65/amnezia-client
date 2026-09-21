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
