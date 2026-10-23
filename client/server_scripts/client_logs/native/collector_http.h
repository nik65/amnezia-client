#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace amnezia::collector {
struct HttpRequest {
    std::string method, target, peer;
    std::map<std::string, std::string> headers; // Lower-case names, no duplicates.
    std::string body;
};
struct HttpResponse {
    int status = 500;
    std::map<std::string, std::string> headers;
    std::string body;
};
using Handler = std::function<HttpResponse(const HttpRequest &)>;
struct HttpServerOptions {
    std::string bind_address = "0.0.0.0";
    std::uint16_t port = 17866;
    std::size_t max_handlers = 16;
    std::size_t max_body_readers = 4;
    unsigned header_timeout_seconds = 10;
    unsigned body_timeout_seconds = 30;
    std::size_t max_body_bytes = 15 * 1024 * 1024;
    std::size_t max_header_bytes = 32 * 1024;
    std::size_t max_response_bytes = 1024 * 1024;
    // Runs after framing/length validation, before any body allocation/read.
    // status == 0 continues; any final response rejects immediately.
    Handler header_handler;
    // Optional fixed startup observer, called after listen; useful with port 0.
    std::function<void(std::uint16_t)> on_listening;
};
// One request per connection. Throws on invalid options/bind/startup; handler
// failures return a bounded 500 without disclosing exception contents. Stop
// interrupts socket waits; shutdown joins every worker (no detached threads).
void run_http_server(const HttpServerOptions &, const Handler &, std::atomic<bool> &stop);
}
