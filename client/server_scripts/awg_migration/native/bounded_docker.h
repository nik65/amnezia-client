#pragma once
#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace amnezia::awgMigration {
enum class BoundedDockerFailureKind { Exit, Timeout, Os, Other };
class BoundedDockerError final : public std::runtime_error {
public:
    BoundedDockerFailureKind kind;
    explicit BoundedDockerError(BoundedDockerFailureKind reason = BoundedDockerFailureKind::Other)
        : std::runtime_error("read_only_process_failed"), kind(reason) {}
};
// Internal transport only. Callers must validate the complete permitted argv.
// Existing Docker/ss operations retain their fixed three-second budget.
std::string runBoundedDocker(const std::vector<std::string> &, std::size_t outputLimit);
// Exact read-only ss inventory command; executable and arguments are not supplied.
std::string runBoundedSs(std::size_t outputLimit);
// Internal catalog adapter only; its CLI accepts no executable, argv or budget.
// The caller first validates its exact pinned-image command and selects10/30/180s.
std::string runBoundedDockerWithBudget(const std::vector<std::string> &, std::size_t outputLimit, unsigned timeoutSeconds);
}
