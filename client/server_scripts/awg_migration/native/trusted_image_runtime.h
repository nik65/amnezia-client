#pragma once
#include "trusted_image.h"

namespace amnezia::awgMigration {
struct TrustedImageCommandLimits {
    std::size_t outputLimit;
    unsigned timeoutSeconds;
};
class TrustedImageRuntimeError final : public std::runtime_error {
public:
    explicit TrustedImageRuntimeError(const std::string &code) : std::runtime_error(code) {}
};
// No caller-supplied command/image/architecture is accepted by the CLI.
// The injected runner is a C++ test seam only.
TrustedImageCommandLimits trustedImageCommandLimits(const ProcessArgs &);
std::string trustedImageRuntimeRequest(const std::string &, ProcessRunner &);
int trustedImageJsonMain();
}
