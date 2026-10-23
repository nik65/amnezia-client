#pragma once
#include "automatic_plan.h"

namespace amnezia::awgMigration {
class AutomaticRuntimeError final : public std::runtime_error {
public:
    explicit AutomaticRuntimeError(const std::string &code) : std::runtime_error(code) {}
};
// Explicit dependency seams belong to C++ tests, never the production JSON protocol.
std::string automaticRuntimeRequest(const std::string &, ProcessRunner &, PortProbe &);
int automaticJsonMain();
}
