#pragma once
#include "trusted_image.h"

namespace amnezia::awgMigration {
inline constexpr const char *ReadyInspectFormat =
    "{\"id\":{{json .Id}},\"name\":{{json .Name}},\"image\":{{json .Image}},"
    "\"owner\":{{json (index .Config.Labels \"amnezia.migration.owner\")}},"
    "\"running\":{{json .State.Running}},\"startedAt\":{{json .State.StartedAt}}}";
inline constexpr const char *ReadyEngineProbe =
    "set -eu; engine=$(cat /migration/engine.pid); case \"$engine\" in \"\"|*[!0-9]*) exit 1;; esac; "
    "kill -0 \"$engine\"; sha256sum \"/proc/$engine/exe\"";
class ReadyRuntimeError final : public std::runtime_error {
public:
    explicit ReadyRuntimeError(const std::string &code) : std::runtime_error(code) {}
};
// Dependency-injected runner is a C++ test seam, never a production CLI option.
// Successful output contains a boolean only; all failures use fixed public codes.
std::string readyRuntimeRequest(const std::string &, ProcessRunner &);
int readyJsonMain();
}
