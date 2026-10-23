#include "feed_file.h"
#include <iostream>
#include <string_view>

// Read-only inspection CLI: deliberately emits no file contents or private path.
int main(int argc, char **argv) {
    if (argc != 4 || (std::string_view(argv[1]) != "routing" && std::string_view(argv[1]) != "updates")) {
        std::cerr << "usage: awg_feed_probe routing|updates ROOT REQUEST\n";
        return 2;
    }
    try {
        const auto file = amnezia::awgMigration::openFeed(argv[2], argv[3], std::string_view(argv[1]) == "routing");
        std::cout << "{\"accepted\":true,\"bytes\":" << file.size() << "}\n";
        return 0;
    } catch (...) {
        std::cout << "{\"accepted\":false,\"error\":\"feed_rejected\"}\n";
        return 1;
    }
}
