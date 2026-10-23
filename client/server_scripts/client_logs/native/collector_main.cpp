#include "collector_http.h"
#include "collector_store.h"
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <thread>
namespace
{
    std::atomic<bool> stopped { false };
    void signal_stop(int)
    {
        stopped.store(true);
    }
}
int main(int argc, char **argv)
{
    try {
        amnezia::collector::CollectorOptions collector;
        amnezia::collector::HttpServerOptions http;
        http.bind_address = "0.0.0.0";
        http.port = 17866;
        if (const char *e = std::getenv("AMNEZIA_CLIENT_LOGS_BOOTSTRAP"))
            collector.allow_bootstrap = std::string(e) == "1";
        if (const char *e = std::getenv("AMNEZIA_CLIENT_LOGS_SCOPE"))
            collector.scope = e;
        for (int i = 1; i < argc; ++i) {
            std::string key = argv[i];
            if (i + 1 >= argc)
                throw std::runtime_error("missing option value");
            std::string value = argv[++i];
            if (key == "--root")
                collector.root = value;
            else if (key == "--bind")
                http.bind_address = value;
            else if (key == "--port") {
                std::size_t end = 0;
                auto n = std::stoul(value, &end);
                if (end != value.size() || n < 1 || n > 65535)
                    throw std::runtime_error("invalid port");
                http.port = int(n);
                collector.port = int(n);
            } else if (key == "--upload-path")
                collector.upload_path = value;
            else if (key == "--bootstrap-path")
                collector.bootstrap_path = value;
            else
                throw std::runtime_error("unknown option");
        }
        std::signal(SIGTERM, signal_stop);
        std::signal(SIGINT, signal_stop);
        std::signal(SIGPIPE, SIG_IGN);
        amnezia::collector::Collector store(collector);
        http.header_handler = [&](const auto &request) { return store.preflight(request); };
        std::thread retention([&] {
            unsigned ticks = 0;
            while (!stopped.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                if (++ticks == 240) {
                    ticks = 0;
                    try {
                        store.maintenance();
                    } catch (...) { /* Health remains fail-closed; never log private paths/tokens. */
                    }
                }
            }
        });
        try {
            amnezia::collector::run_http_server(http, [&](const auto &request) { return store.handle(request); }, stopped);
        } catch (...) {
            stopped = true;
            retention.join();
            throw;
        }
        stopped = true;
        retention.join();
        return 0;
    } catch (...) {
        std::cerr << "collector startup or runtime failure\n";
        return 1;
    }
}
