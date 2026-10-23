#include "collector_http.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <unistd.h>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <future>
#include <iostream>
#include <mutex>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace amnezia::collector;
using namespace std::chrono_literals;
namespace {
void require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
struct Client {
    int fd = -1;
    explicit Client(std::uint16_t port) {
        fd = ::socket(AF_INET, SOCK_STREAM, 0); require(fd >= 0, "client socket");
        timeval timeout {3, 0}; ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        sockaddr_in address {}; address.sin_family = AF_INET; address.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        if (::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
            ::close(fd); fd = -1; throw std::runtime_error("loopback connect");
        }
    }
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;
    ~Client() { if (fd >= 0) ::close(fd); }
    void send(const std::string &bytes) {
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const auto sent = ::send(fd, bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
            require(sent > 0, "client send"); offset += std::size_t(sent);
        }
    }
    std::string read_all() {
        std::string bytes; char buffer[4096];
        while (true) {
            const auto count = ::recv(fd, buffer, sizeof(buffer), 0);
            if (count == 0) return bytes;
            require(count > 0, "client receive deadline"); bytes.append(buffer, std::size_t(count));
            const auto header_end = bytes.find("\r\n\r\n"), length = bytes.find("content-length: ");
            if (header_end != std::string::npos && length != std::string::npos && length < header_end) {
                const auto size = std::stoull(bytes.substr(length + 16));
                if (bytes.size() >= header_end + 4 + size) return bytes.substr(0, header_end + 4 + size);
            }
        }
    }
    std::string read_interim() {
        std::string bytes; char c;
        while (bytes.find("\r\n\r\n") == std::string::npos) {
            require(::recv(fd, &c, 1, 0) == 1, "continue response"); bytes += c;
        }
        return bytes;
    }
};
struct Server {
    std::atomic<bool> stop {false};
    std::thread thread;
    std::uint16_t port = 0;
    std::exception_ptr failure;
    Server(HttpServerOptions options, Handler handler) {
        options.bind_address = "127.0.0.1"; options.port = 0;
        auto listening = std::make_shared<std::promise<std::uint16_t>>(); auto ready = listening->get_future();
        options.on_listening = [listening](std::uint16_t value) { listening->set_value(value); };
        thread = std::thread([this, options, handler, listening]() {
            try { run_http_server(options, handler, stop); }
            catch (...) { failure = std::current_exception(); try { listening->set_exception(failure); } catch (...) {} }
        });
        try { port = ready.get(); }
        catch (...) { stop = true; thread.join(); throw; }
    }
    ~Server() { stop = true; if (thread.joinable()) thread.join(); }
    std::string exchange(const std::string &request) {
        Client client(port); client.send(request); ::shutdown(client.fd, SHUT_WR); return client.read_all();
    }
};
int status(const std::string &response) {
    require(response.rfind("HTTP/1.1 ", 0) == 0, "response protocol");
    return std::stoi(response.substr(9, 3));
}
HttpServerOptions options() {
    HttpServerOptions value; value.max_handlers = 8; value.max_body_readers = 4;
    value.max_header_bytes = 4096; value.max_body_bytes = 32;
    value.header_timeout_seconds = 1; value.body_timeout_seconds = 1; return value;
}
}
int main() {
    try {
        std::atomic<int> calls {0};
        Server server(options(), [&](const HttpRequest &request) -> HttpResponse {
            ++calls;
            require(request.peer == "127.0.0.1", "peer cannot come from forwarded headers");
            if (request.target == "/throw") throw std::runtime_error("private-exception-content");
            if (request.target == "/bad-response") return {200, {{"X-Unsafe", "bad\r\nx-injected: yes"}}, "unsafe"};
            if (request.method == "POST") return {201, {{"Content-Type", "application/octet-stream"}}, request.body};
            return {200, {{"Connection", "keep-alive"}}, "healthy\n"};
        });
        const auto get = [](const std::string &path) { return "GET " + path + " HTTP/1.1\r\nHost: test\r\n\r\n"; };
        require(status(server.exchange(get("/healthz"))) == 200, "health succeeds");
        const std::string binary("a\0b", 3);
        auto response = server.exchange("POST /logs HTTP/1.1\r\nHost: test\r\nContent-Length: 3\r\nX-Forwarded-For: 203.0.113.1\r\n\r\n" + binary);
        require(status(response) == 201 && response.substr(response.find("\r\n\r\n") + 4) == binary, "exact binary body");
        const std::vector<std::pair<std::string, int>> invalid {
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n", 400},
            {"GET /healthz HTTP/1.1\r\nHost: t\r\nX-Token: a\r\nx-token: b\r\n\r\n", 400},
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n", 400},
            {"GET /healthz HTTP/1.1\r\nHost: t\r\n folded: a\r\n\r\n", 400},
            {"GET http://example/ HTTP/1.1\r\nHost: t\r\n\r\n", 400},
            {"GET /healthz HTTP/1.1\r\n\r\n", 400},
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: -1\r\n\r\n", 400},
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: +1\r\n\r\n", 400},
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 1,1\r\n\r\n", 400},
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 9999999999999999999999999999999\r\n\r\n", 413},
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 33\r\n\r\n", 413},
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nab", 400},
            {"GET /healthz HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\n\r\nx", 400},
            {"HEAD /healthz HTTP/1.1\r\nHost: t\r\n\r\n", 405},
            {"POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nExpect: other\r\n\r\n", 417},
            {"GET /healthz HTTP/1.1\r\nHost: t\r\nX: " + std::string(4100, 'x') + "\r\n\r\n", 431},
            {get("/healthz") + get("/healthz"), 400}
        };
        for (const auto &item : invalid) {
            const int before = calls;
            require(status(server.exchange(item.first)) == item.second, "invalid framing rejected with expected status");
            require(calls == before, "invalid request never reaches handler");
        }
        require(status(server.exchange("POST /bootstrap HTTP/1.1\r\nHost: t\r\n\r\n")) == 201, "missing length is bounded zero for bootstrap compatibility");
        require(status(server.exchange("GET /healthz HTTP/1.0\r\n\r\n")) == 200, "HTTP1.0 close semantics");
        response = server.exchange(get("/throw"));
        require(status(response) == 500 && response.find("private-exception-content") == std::string::npos, "exceptions do not leak");
        response = server.exchange(get("/bad-response"));
        require(status(response) == 500 && response.find("x-injected") == std::string::npos, "response header injection rejected");
        response = server.exchange(get("/healthz")); require(response.find("connection: close") != std::string::npos && response.find("keep-alive") == std::string::npos, "one request per connection");
        std::vector<std::unique_ptr<Client>> bodies;
        for (int i = 0; i < 4; ++i) {
            auto client = std::make_unique<Client>(server.port);
            client->send("POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n");
            require(status(client->read_interim()) == 100, "bounded body reader acquired before continue");
            bodies.push_back(std::move(client));
        }
        require(status(server.exchange("POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\n\r\n")) == 503, "fifth body denied before allocation");
        require(status(server.exchange(get("/healthz"))) == 200, "health does not consume body permits");
        for (auto &client : bodies) { client->send("x"); require(status(client->read_all()) == 201, "body permit request completes"); }
        bodies.clear();
        Client slow_header(server.port); slow_header.send("GET /healthz HTTP/1.1\r\nHost:");
        require(status(slow_header.read_all()) == 408, "absolute header deadline");
        Client slow_body(server.port); slow_body.send("POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\na");
        require(status(slow_body.read_all()) == 408, "absolute body deadline");
        // Saturate handlers with deterministic in-handler barriers rather than sleeps.
        std::mutex mutex; std::condition_variable changed; int entered = 0; bool release = false;
        auto small_options = options(); small_options.max_handlers = 2; small_options.max_body_readers = 1;
        Server small(small_options, [&](const HttpRequest &) {
            std::unique_lock<std::mutex> lock(mutex); ++entered; changed.notify_all();
            changed.wait(lock, [&]() { return release; }); return HttpResponse {200, {}, "ok"};
        });
        Client first(small.port), second(small.port); first.send(get("/block")); second.send(get("/block"));
        bool two_entered;
        { std::unique_lock<std::mutex> lock(mutex); two_entered = changed.wait_for(lock, 2s, [&]() { return entered == 2; }); }
        int overloaded = 0;
        try { overloaded = status(small.exchange(get("/healthz"))); }
        catch (...) { { std::lock_guard<std::mutex> lock(mutex); release = true; } changed.notify_all(); throw; }
        { std::lock_guard<std::mutex> lock(mutex); release = true; } changed.notify_all();
        require(two_entered && overloaded == 503, "total handler count is bounded");
        require(status(first.read_all()) == 200 && status(second.read_all()) == 200, "all workers remain joinable");
        // A server failure is joined/rethrown by construction/startup; avoid
        // unsynchronized reads of the diagnostic exception pointer here.
        std::atomic<int> preflight_calls {0}, body_calls {0};
        auto auth_options = options();
        auth_options.header_handler = [&](const HttpRequest &request) {
            ++preflight_calls;
            return HttpResponse {request.headers.count("x-auth") ? 0 : 401, {}, ""};
        };
        Server auth(auth_options, [&](const HttpRequest &) { ++body_calls; return HttpResponse {200, {}, "ok"}; });
        Client unauthorized(auth.port);
        unauthorized.send("POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 32\r\nExpect: 100-continue\r\n\r\n");
        require(status(unauthorized.read_all()) == 401 && body_calls == 0, "auth rejected before body and 100 Continue");
        require(status(auth.exchange("POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\nX-Auth: yes\r\n\r\nx")) == 200, "accepted preflight dispatches body");
        require(preflight_calls == 2 && body_calls == 1, "preflight and body validation phases distinct");
        // Four actual maximum-size requests; keep buffers alive at a barrier.
        std::mutex large_mutex; std::condition_variable large_changed; int large_entered = 0; bool large_release = false;
        auto large_options = options(); large_options.max_body_bytes = 15 * 1024 * 1024; large_options.body_timeout_seconds = 10;
        Server large(large_options, [&](const HttpRequest &request) {
            if (request.method == "GET") return HttpResponse {200, {}, "ok"};
            require(request.body.size() == large_options.max_body_bytes, "exact maximum body received");
            std::unique_lock<std::mutex> lock(large_mutex); ++large_entered; large_changed.notify_all();
            large_changed.wait(lock, [&]() { return large_release; }); return HttpResponse {201, {}, "ok"};
        });
        struct ReleaseLarge {
            std::mutex &mutex; std::condition_variable &cv; bool &flag;
            ~ReleaseLarge() { { std::lock_guard<std::mutex> lock(mutex); flag = true; } cv.notify_all(); }
        } release_large {large_mutex, large_changed, large_release};
        std::string maximum(large_options.max_body_bytes, 'x');
        std::vector<std::unique_ptr<Client>> maximum_clients;
        for (int i = 0; i < 4; ++i) {
            auto client = std::make_unique<Client>(large.port);
            client->send("POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: " + std::to_string(maximum.size()) + "\r\nExpect: 100-continue\r\n\r\n");
            require(status(client->read_interim()) == 100, "maximum body admission"); client->send(maximum);
            maximum_clients.push_back(std::move(client));
        }
        bool all_large;
        { std::unique_lock<std::mutex> lock(large_mutex); all_large = large_changed.wait_for(lock, 3s, [&]() { return large_entered == 4; }); }
        require(all_large, "all four maximum buffers reached handler");
        require(status(large.exchange(get("/healthz"))) == 200, "health remains available with maximum bodies");
        require(status(large.exchange("POST /logs HTTP/1.1\r\nHost: t\r\nContent-Length: 15728640\r\n\r\n")) == 503, "maximum memory admission bounded four");
        { std::lock_guard<std::mutex> lock(large_mutex); large_release = true; } large_changed.notify_all();
        for (auto &client : maximum_clients) require(status(client->read_all()) == 201, "maximum body acknowledged");
        rusage usage {}; ::getrusage(RUSAGE_SELF, &usage);
        std::cout << "maxBodyBytes=" << maximum.size() << " concurrentBodies=4 processPeakRssKiB=" << usage.ru_maxrss << " (includes test client buffer)\n";
        auto stop_options = options(); stop_options.header_timeout_seconds = 30;
        Server stopping(stop_options, [](const HttpRequest &) { return HttpResponse {200, {}, "ok"}; });
        Client interrupted(stopping.port); interrupted.send("GET /healthz HTTP/1.1\r\nHost:");
        const auto stop_start = std::chrono::steady_clock::now(); stopping.stop = true; stopping.thread.join();
        require(std::chrono::steady_clock::now() - stop_start < 2s, "stop interrupts socket deadlines and joins workers");

        std::cout << "HTTP framing/security/deadline/configured-handler-cap/body4 contracts PASS; loopback only\n";
        return 0;
    } catch (const std::exception &error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
