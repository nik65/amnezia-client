#pragma once
#include "ready_config.h"
#include <array>
#include <functional>

namespace amnezia::awgMigration {
using GenerationEntropy = std::array<unsigned char, 32>;
// The injected callback is a component-test seam, never accepted by the CLI.
using GenerationRandom = std::function<bool(GenerationEntropy &)>;
struct GeneratedConfig {
    ConfigFields parameters, interface;
    std::string config, nativeConfig;
};
class GenerationError final : public std::runtime_error {
public:
    GenerationError() : std::runtime_error("native_generation_rejected") {}
};
GeneratedConfig generateConfig(std::string_view source, unsigned port, unsigned mtu,
                               const GenerationRandom &random);
GeneratedConfig generateConfig(std::string_view source, unsigned port, unsigned mtu);
}
