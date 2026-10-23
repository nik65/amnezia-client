#include "control_service.h"
#include <iostream>
#include <iterator>
int main(int argc, char **argv)
{
    try {
        std::string raw((std::istreambuf_iterator<char>(std::cin)), { });
        if (argc == 2 && std::string(argv[1]) == "canonical")
            std::cout << amnezia::awgMigration::controlCanonical(raw);
        else if (argc == 2 && std::string(argv[1]) == "grant")
            std::cout << amnezia::awgMigration::controlBootstrapGrant("public-test-secret", raw);
        else if (argc == 3 && std::string(argv[1]) == "sign")
            std::cout << amnezia::awgMigration::controlSign(raw, argv[2]);
        else if ((argc == 8 || argc == 9) && std::string(argv[1]) == "dispatch") {
            amnezia::awgMigration::ControlOptions o;
            o.directory = argv[2];
            o.role = argv[3];
            o.scope = "amnezia-awg2";
            auto now = std::stoll(argv[7]);
            o.clock = [now]() { return now; };
            amnezia::awgMigration::ControlRequest r;
            r.path = argv[4];
            r.peerAddress = argv[5];
            r.body = raw;
            r.headers["content-length"] = std::to_string(raw.size());
            if (argc == 9)
                r.headers["x-amnezia-migration-grant"] = argv[8];
            auto out = amnezia::awgMigration::ControlService(o).dispatch(r, [&]() { return std::string(argv[6]); });
            std::cout << out.status << "\n" << out.body;
        } else
            return 2;
        return 0;
    } catch (...) {
        return 1;
    }
}
