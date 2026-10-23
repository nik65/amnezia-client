// Owned-fixture-only adapter probe: explicit directory argument is mandatory.
#include "policy.h"
#include <iostream>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    try {
        auto value = amnezia::awgMigration::policy::clientPolicyEpoch(std::string(argv[1]));
        std::cout << (value ? "epoch" : "absent") << '\n';
        return 0;
    } catch (const std::exception &error) {
        std::cout << error.what() << '\n';
        return 3;
    }
}
