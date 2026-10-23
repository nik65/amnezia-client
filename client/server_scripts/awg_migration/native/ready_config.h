#pragma once
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
namespace amnezia::awgMigration {
using ConfigFields = std::map<std::string, std::string>;
struct ReadyConfig { ConfigFields Interface; std::vector<ConfigFields> Peers; };
class ConfigError final : public std::runtime_error {
public:
 explicit ConfigError(const std::string &code) : std::runtime_error(code) {}
 const char *code() const noexcept { return what(); }
};
// Pure parser. Explicit validation errors match ready_validation.parse_config.
// Python KeyError/UnicodeDecodeError/ipaddress exceptions map to missing field,
// invalid UTF-8/configuration address respectively; no secrets appear in errors.
ReadyConfig parseConfig(std::string_view raw);
}
