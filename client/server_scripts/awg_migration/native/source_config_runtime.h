#pragma once
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace amnezia::awgMigration {
using SourceConfigRunner = std::function<std::string(const std::vector<std::string> &)>;
class SourceConfigRuntimeError final : public std::runtime_error {
public:
    SourceConfigRuntimeError() : std::runtime_error("native_source_config_rejected") {}
};
// Private read-only capture. No fixture, executable, path or deadline input fields.
std::string sourceConfigRuntimeRequest(const std::string &, const SourceConfigRunner &);
std::string sourceConfigRuntimeRequest(const std::string &);
int sourceConfigJsonMain(const SourceConfigRunner &);
int sourceConfigJsonMain();
SourceConfigRunner productionSourceConfigRunner();
}
