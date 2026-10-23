#pragma once
#include "collector_http.h"
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
namespace amnezia::collector
{
    struct CollectorOptions
    {
        std::filesystem::path root = "/data";
        std::string scope;
        bool allow_bootstrap = false;
        int port = 17866;
        std::string upload_path = "/logs", bootstrap_path = "/bootstrap";
        std::uint64_t upload_bytes = 15 * 1024 * 1024, client_bytes = 30 * 1024 * 1024;
        std::uint64_t client_files = 4096, total_bytes = 512 * 1024 * 1024, total_files = 8192;
        std::int64_t log_age = 30 * 86400, tmp_age = 3600, receipt_age = 35 * 86400;
        std::uint64_t client_receipts = 131072, total_receipts = 1048576;
    };
    class Collector
    {
    public:
        explicit Collector(CollectorOptions options);
        HttpResponse handle(const HttpRequest &request);
        HttpResponse preflight(const HttpRequest &request);
        void maintenance(bool force = false);
        bool healthy();

    private:
        CollectorOptions options_;
        std::mutex storage_mutex_, token_mutex_, health_mutex_;
        std::atomic<unsigned> uploads_ { 0 }, health_requests_ { 0 };
        double health_expires_ = 0;
        bool health_ready_ = false;
        void invalidate_health();
        HttpResponse upload(const HttpRequest &request);
        HttpResponse bootstrap(const HttpRequest &request);
        int authenticate(const HttpRequest &request, std::string &id);
        std::string resolve_legacy(const std::string &peer);
    };
}
