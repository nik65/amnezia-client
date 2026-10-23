#include "ready_config_runtime.h"
#include "source_config_runtime.h"
#include "ready_runtime.h"
#include "automatic_runtime.h"
#include "trusted_image_runtime.h"
#include "config_generation_runtime.h"
#include "control_runtime.h"
#include "network_topology_runtime.h"
#include "policy_runtime.h"
#include "routed_policy_epoch.h"
#include "feed_file.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <deque>
#include <fcntl.h>
#include <iostream>
#include <mutex>
#include <memory>
#include <set>
#include <openssl/evp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
std::atomic<bool> stopping{false};
static_assert(std::atomic<bool>::is_always_lock_free, "signal stop requires a lock-free atomic");
void signalStop(int) { stopping.store(true); }
struct Socket {
    int fd = -1;
    explicit Socket(int value = -1) : fd(value) {}
    ~Socket() { if (fd >= 0) ::close(fd); }
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
};
struct Route { int listener; std::string root; bool routing; };
struct Job { int fd; std::string root; bool routing; };
bool waitFor(int fd, short events, Clock::time_point deadline) {
    while (!stopping.load() && Clock::now() < deadline) {
        pollfd p{fd, events, 0};
        const int result = ::poll(&p, 1, 100);
        if (result < 0 && errno != EINTR) return false;
        if (result > 0) return (p.revents & events) != 0;
    }
    return false;
}
bool sendBytes(int fd, const char *data, std::size_t length, Clock::time_point deadline) {
    while (length && waitFor(fd, POLLOUT, deadline)) {
        const auto n = ::send(fd, data, length, MSG_NOSIGNAL);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return false;
        data += n; length -= static_cast<std::size_t>(n);
    }
    return length == 0;
}
bool sendText(int fd, const std::string &text, Clock::time_point deadline) {
    return sendBytes(fd, text.data(), text.size(), deadline);
}
void error(int fd, int status, bool head = false) {
    const char *reason = status == 400 ? "Bad Request" : status == 403 ? "Forbidden"
        : status == 408 ? "Request Timeout" : status == 431 ? "Request Header Fields Too Large"
        : status == 501 ? "Not Implemented" : "Service Unavailable";
    const std::string body = "feed request rejected\n";
    const auto deadline = Clock::now() + std::chrono::seconds(2);
    if (sendText(fd, "HTTP/1.0 " + std::to_string(status) + " " + reason
                 + "\r\nContent-Length: " + std::to_string(body.size())
                 + "\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n", deadline) && !head)
        sendText(fd, body, deadline);
}
bool validHeaderName(const std::string &name) {
    if (name.empty()) return false;
    for (unsigned char c : name)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || std::string("!#$%&'*+-.^_`|~").find(char(c)) != std::string::npos)) return false;
    return true;
}
void serve(const Job &job) {
    Socket client(job.fd);
    const auto headerDeadline = Clock::now() + std::chrono::seconds(10);
    std::string headers;
    // Consume one byte at a time only until the header terminator. This avoids
    // allocating a body and leaves pipelined bytes ignored on connection close.
    while (headers.size() < 16384 && headers.find("\r\n\r\n") == std::string::npos) {
        if (!waitFor(client.fd, POLLIN, headerDeadline)) { error(client.fd, 408); return; }
        char c;
        const auto n = ::recv(client.fd, &c, 1, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n != 1) return;
        if (c == '\0') { error(client.fd, 400); return; }
        headers.push_back(c);
    }
    if (headers.find("\r\n\r\n") == std::string::npos) { error(client.fd, 431); return; }
    const auto requestEnd = headers.find("\r\n");
    std::istringstream request(headers.substr(0, requestEnd));
    std::string method, target, version, extra;
    const bool parsed = bool(request >> method >> target >> version) && !(request >> extra);
    const bool head = method == "HEAD";
    if (!parsed || (version != "HTTP/1.0" && version != "HTTP/1.1")) { error(client.fd, 400, head); return; }
    if (method != "GET" && !head) { error(client.fd, 501); return; }
    bool lengthSeen = false;
    for (std::size_t offset = requestEnd + 2; offset + 2 < headers.size();) {
        const auto end = headers.find("\r\n", offset);
        if (end == offset) break;
        auto line = headers.substr(offset, end - offset);
        const auto colon = line.find(':');
        if (colon == std::string::npos || !validHeaderName(line.substr(0, colon))) { error(client.fd, 400, head); return; }
        auto name = line.substr(0, colon), value = line.substr(colon + 1);
        for (char &c : name) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
        for (unsigned char c : value) if ((c < 32 && c != '\t') || c == 127) { error(client.fd, 400, head); return; }
        const auto first = value.find_first_not_of(" \t");
        value = first == std::string::npos ? "" : value.substr(first, value.find_last_not_of(" \t") - first + 1);
        if (name == "transfer-encoding" || (name == "content-length" && (lengthSeen || value != "0"))) {
            error(client.fd, 400, head); return;
        }
        if (name == "content-length") lengthSeen = true;
        offset = end + 2;
    }
    try {
        auto file = amnezia::awgMigration::openFeed(job.root, target, job.routing);
        const bool json = file.isJson();
        const auto deadline = Clock::now() + std::chrono::minutes(5);
        if (!sendText(client.fd, "HTTP/1.0 200 OK\r\nContent-Length: " + std::to_string(file.size())
                      + "\r\nContent-Type: " + (json ? "application/json" : "application/octet-stream")
                      + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", deadline) || head) return;
        std::array<char, 128 * 1024> buffer{};
        auto remaining = file.size();
        while (remaining && !stopping.load()) {
            const auto count = ::read(file.descriptor(), buffer.data(), std::min<std::uint64_t>(buffer.size(), remaining));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0 || !sendBytes(client.fd, buffer.data(), static_cast<std::size_t>(count), deadline)) return;
            remaining -= static_cast<std::uint64_t>(count);
        }
    } catch (...) { error(client.fd, 403, head); }
}
// Read-only namespace-local readiness: fixed allowlisted URL, bounded body,
// absolute deadline, exact framing and expected authenticated source digest.
bool checkFeed(const std::string &kind, const std::string &portText, const std::string &expected) {
    if ((kind != "routing" && kind != "updates") || portText.empty()
        || portText.find_first_not_of("0123456789") != std::string::npos
        || expected.size() != 64 || expected.find_first_not_of("0123456789abcdef") != std::string::npos) return false;
    const auto port = std::stoul(portText);
    if (port == 0 || port > 65535) return false;
    Socket socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (socket.fd < 0) return false;
    sockaddr_in endpoint{}; endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(static_cast<std::uint16_t>(port));
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const auto deadline = Clock::now() + std::chrono::seconds(5);
    if (::connect(socket.fd, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) != 0) {
        if (errno != EINPROGRESS || !waitFor(socket.fd, POLLOUT, deadline)) return false;
        int error = 0; socklen_t length = sizeof(error);
        if (::getsockopt(socket.fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0) return false;
    }
    const std::string path = kind == "routing" ? "/rules.json" : "/manifest.json";
    if (!sendText(socket.fd, "GET " + path + " HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", deadline)) return false;
    std::string header, prefix;
    std::array<char, 8192> buffer{};
    while (true) {
        if (!waitFor(socket.fd, POLLIN, deadline)) return false;
        const auto count = ::recv(socket.fd, buffer.data(), buffer.size(), 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return false;
        header.append(buffer.data(), static_cast<std::size_t>(count));
        const auto end = header.find("\r\n\r\n");
        if (end != std::string::npos) {
            if (end + 4 > 8192) return false;
            prefix = header.substr(end + 4); header.resize(end + 2); break;
        }
        if (header.size() > 8192) return false;
    }
    const auto statusEnd = header.find("\r\n");
    const auto status = header.substr(0, statusEnd);
    if (status != "HTTP/1.0 200 OK" && status != "HTTP/1.1 200 OK") return false;
    bool hasLength = false; std::uint64_t length = 0;
    std::set<std::string> names;
    for (std::size_t position = statusEnd + 2; position < header.size();) {
        const auto end = header.find("\r\n", position);
        if (end == std::string::npos) return false;
        const auto line = header.substr(position, end - position); position = end + 2;
        const auto colon = line.find(':');
        if (colon == std::string::npos) return false;
        auto name = line.substr(0, colon);
        if (!validHeaderName(name)) return false;
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!names.insert(name).second || name == "transfer-encoding") return false;
        auto value = line.substr(colon + 1);
        const auto first = value.find_first_not_of(" \t"), last = value.find_last_not_of(" \t");
        value = first == std::string::npos ? "" : value.substr(first, last - first + 1);
        if (value.find_first_of("\r\n") != std::string::npos || value.find('\0') != std::string::npos) return false;
        if (name == "content-length") {
            if (value.empty() || value.size() > 7 || value.find_first_not_of("0123456789") != std::string::npos) return false;
            length = std::stoull(value); hasLength = true;
        }
    }
    if (!hasLength || length > 1024 * 1024 || prefix.size() > length) return false;
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!digest || EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1
        || EVP_DigestUpdate(digest.get(), prefix.data(), prefix.size()) != 1) return false;
    std::uint64_t received = prefix.size();
    while (received < length) {
        if (!waitFor(socket.fd, POLLIN, deadline)) return false;
        const auto count = ::recv(socket.fd, buffer.data(), std::min<std::uint64_t>(buffer.size(), length - received), 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0 || EVP_DigestUpdate(digest.get(), buffer.data(), static_cast<std::size_t>(count)) != 1) return false;
        received += static_cast<std::uint64_t>(count);
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{}; unsigned int size = 0;
    if (EVP_DigestFinal_ex(digest.get(), bytes.data(), &size) != 1 || size != 32) return false;
    std::string actual;
    for (unsigned int i = 0; i < size; ++i) { actual += "0123456789abcdef"[bytes[i] >> 4]; actual += "0123456789abcdef"[bytes[i] & 15]; }
    return actual == expected;
}

int listenOn(const std::string &address, unsigned port) {
    Socket socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (socket.fd < 0) throw std::runtime_error("listen failed");
    int reuse = 1;
    if (::setsockopt(socket.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) throw std::runtime_error("listen failed");
    sockaddr_in endpoint{}; endpoint.sin_family = AF_INET; endpoint.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, address.c_str(), &endpoint.sin_addr) != 1
        || ::bind(socket.fd, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) < 0
        || ::listen(socket.fd, 32) < 0) throw std::runtime_error("listen failed");
    socklen_t size = sizeof(endpoint);
    if (::getsockname(socket.fd, reinterpret_cast<sockaddr *>(&endpoint), &size) != 0) throw std::runtime_error("listen failed");
    std::cout << "{\"listening\":" << ntohs(endpoint.sin_port) << "}" << std::endl;
    const int fd = socket.fd; socket.fd = -1; return fd;
}
} // namespace

int main(int argc, char **argv) {
    if (argc >= 2 && std::string(argv[1]) == "--policy-epoch-capability")
        return argc == 2 ? amnezia::awgMigration::routedPolicyEpochCapabilityMain() : 2;
    if (argc >= 2 && std::string(argv[1]) == "--check-policy-epoch")
        return argc == 4 ? amnezia::awgMigration::checkRoutedPolicyEpochMain(argv[2], argv[3]) : 2;
    if (argc == 2 && std::string(argv[1]) == "--source-config-json")
        return amnezia::awgMigration::sourceConfigJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--network-json")
        return amnezia::awgMigration::networkTopologyJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--automatic-json")
        return amnezia::awgMigration::automaticJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--trusted-image-json")
        return amnezia::awgMigration::trustedImageJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--ready-json")
        return amnezia::awgMigration::readyJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--generate-config-json")
        return amnezia::awgMigration::generationJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--control-json")
        return amnezia::awgMigration::controlJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--config-json")
        return amnezia::awgMigration::configJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--policy-json")
        return amnezia::awgMigration::policy::policyJsonMain();
    std::signal(SIGINT, signalStop); std::signal(SIGTERM, signalStop);
    std::vector<Route> routes;
    try {
        if (argc == 5 && std::string(argv[1]) == "--check-feed")
            return checkFeed(argv[2], argv[3], argv[4]) ? 0 : 3;
        if (argc == 6 && std::string(argv[1]) == "--single"
            && (std::string(argv[2]) == "routing" || std::string(argv[2]) == "updates")) {
            const std::string portText(argv[5]);
            if (portText.empty() || portText.find_first_not_of("0123456789") != std::string::npos) throw std::runtime_error("port");
            const auto port = std::stoul(portText);
            if (port > 65535) throw std::runtime_error("port");
            routes.push_back({listenOn(argv[4], static_cast<unsigned>(port)), argv[3], std::string(argv[2]) == "routing"});
        } else if (argc == 1 || (argc == 2 && std::string(argv[1]) == "--serve")) {
            std::istringstream ports(std::getenv("AMNEZIA_FEED_PORTS") ? std::getenv("AMNEZIA_FEED_PORTS") : "");
            std::string port;
            bool routing = false, updates = false;
            while (std::getline(ports, port, ',')) { routing |= port == "17864"; updates |= port == "17865"; }
            if (routing) routes.push_back({listenOn("0.0.0.0", 17864), "/routing", true});
            if (updates) routes.push_back({listenOn("0.0.0.0", 17865), "/updates", false});
            if (routes.empty()) throw std::runtime_error("no feed requested");
        } else throw std::runtime_error("arguments");
    } catch (...) {
        for (const auto &route : routes) ::close(route.listener);
        std::cerr << "feed startup rejected\n"; return 2;
    }
    std::mutex mutex;
    std::condition_variable changed;
    std::deque<Job> jobs;
    std::vector<std::thread> workers;
    try {
        for (int i = 0; i < 16; ++i) workers.emplace_back([&] {
            while (true) {
                Job job;
                {
                    std::unique_lock<std::mutex> lock(mutex);
                    changed.wait_for(lock, std::chrono::milliseconds(100), [&] { return stopping.load() || !jobs.empty(); });
                    if (stopping.load()) return;
                    if (jobs.empty()) continue;
                    job = std::move(jobs.front()); jobs.pop_front();
                }
                try { serve(job); } catch (...) { /* Socket RAII already closed the failed request. */ }
            }
        });
        while (!stopping.load()) {
            std::vector<pollfd> ready;
            for (const auto &route : routes) ready.push_back({route.listener, POLLIN, 0});
            if (::poll(ready.data(), ready.size(), 100) <= 0) continue;
            for (std::size_t i = 0; i < ready.size(); ++i) {
                if (!(ready[i].revents & POLLIN)) continue;
                const int fd = ::accept4(routes[i].listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (fd < 0) continue;
                std::lock_guard<std::mutex> lock(mutex);
                if (jobs.size() >= 32) { ::close(fd); continue; }
                jobs.push_back({fd, routes[i].root, routes[i].routing}); changed.notify_one();
            }
        }
    } catch (...) { stopping.store(true); }
    stopping.store(true); changed.notify_all();
    for (const auto &route : routes) ::close(route.listener);
    for (auto &worker : workers) worker.join();
    for (const auto &job : jobs) ::close(job.fd);
    return 0;
}
