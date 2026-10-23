#include "ready_config.h"
#include <array>
#include <iostream>
#include <string>

// Public read-only validator: unlike the differential fixture probe, no key or
// config field is echoed, even on parse failure.
int main() {
    std::string bytes;
    std::array<char, 4096> block{};
    while (std::cin) {
        std::cin.read(block.data(), block.size());
        bytes.append(block.data(), static_cast<std::size_t>(std::cin.gcount()));
        if (bytes.size() > 1024 * 1024) {
            std::cout << "{\"valid\":false,\"error\":\"input_limit\"}\n";
            return 2;
        }
    }
    if (!std::cin.eof()) return 2;
    try {
        const auto config = amnezia::awgMigration::parseConfig(bytes);
        std::cout << "{\"valid\":true,\"peers\":" << config.Peers.size() << "}\n";
        return 0;
    } catch (...) {
        std::cout << "{\"valid\":false,\"error\":\"configuration_rejected\"}\n";
        return 1;
    }
}
