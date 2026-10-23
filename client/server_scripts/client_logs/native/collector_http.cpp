#include "collector_http.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace amnezia::collector
{
    namespace
    {
        using Clock = std::chrono::steady_clock;
        using Deadline = Clock::time_point;
        struct Socket
        {
            int value = -1;
            explicit Socket(int fd = -1) : value(fd)
            {
            }
            ~Socket()
            {
                if (value >= 0)
                    ::close(value);
            }
            Socket(const Socket &) = delete;
            Socket &operator=(const Socket &) = delete;
        };
        struct HttpError
        {
            int status;
        };
        std::string lower(std::string text)
        {
            for (char &c : text)
                if (c >= 'A' && c <= 'Z')
                    c = char(c - 'A' + 'a');
            return text;
        }
        bool token(const std::string &value)
        {
            if (value.empty())
                return false;
            for (unsigned char c : value) {
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
                    continue;
                if (std::string("!#$%&'*+-.^_`|~").find(char(c)) == std::string::npos)
                    return false;
            }
            return true;
        }
        bool field_value(const std::string &value)
        {
            for (unsigned char c : value)
                if ((c < 32 && c != '\t') || c == 127)
                    return false;
            return true;
        }
        std::string trim(std::string value)
        {
            const auto first = value.find_first_not_of(" \t");
            if (first == std::string::npos)
                return { };
            return value.substr(first, value.find_last_not_of(" \t") - first + 1);
        }
        void nonblocking(int fd)
        {
            const int flags = ::fcntl(fd, F_GETFL, 0);
            if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || ::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
                throw std::runtime_error("socket flags failed");
        }
        bool wait_socket(int fd, short event, Deadline until, const std::atomic<bool> &stop)
        {
            while (!stop.load(std::memory_order_relaxed)) {
                const auto remaining =
                        std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count();
                if (remaining <= 0)
                    return false;
                pollfd item { fd, event, 0 };
                const int result = ::poll(&item, 1, int(std::min<long long>(remaining, 100)));
                if (result < 0) {
                    if (errno == EINTR)
                        continue;
                    return false;
                }
                if (result > 0)
                    return (item.revents & event) != 0;
            }
            return false;
        }
        bool send_all(int fd, const std::string &data, Deadline until, const std::atomic<bool> &stop)
        {
            std::size_t offset = 0;
            while (offset < data.size()) {
                if (!wait_socket(fd, POLLOUT, until, stop))
                    return false;
                const ssize_t written = ::send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
                if (written < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                    continue;
                if (written <= 0)
                    return false;
                offset += std::size_t(written);
            }
            return true;
        }
        std::string reason(int status)
        {
            switch (status) {
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 204: return "No Content";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 408: return "Request Timeout";
            case 409: return "Conflict";
            case 411: return "Length Required";
            case 413: return "Payload Too Large";
            case 417: return "Expectation Failed";
            case 429: return "Too Many Requests";
            case 431: return "Request Header Fields Too Large";
            case 500: return "Internal Server Error";
            case 503: return "Service Unavailable";
            default: return "Status";
            }
        }
        void reply(int fd, HttpResponse response, const HttpServerOptions &options, const std::atomic<bool> &stop)
        {
            bool valid = response.status >= 200 && response.status <= 599
                    && response.body.size() <= options.max_response_bytes;
            std::size_t header_size = 0;
            std::map<std::string, std::string> headers;
            for (const auto &entry : response.headers) {
                const std::string name = lower(entry.first);
                header_size += entry.first.size() + entry.second.size() + 4;
                if (!token(entry.first) || !field_value(entry.second) || !headers.emplace(name, entry.second).second)
                    valid = false;
            }
            if (!valid || headers.size() > 100 || header_size > options.max_header_bytes) {
                response = { 500, { }, "internal server error\n" };
                headers.clear();
            }
            headers.erase("content-length");
            headers.erase("transfer-encoding");
            headers.erase("connection");
            if (!headers.count("content-type"))
                headers["content-type"] = "text/plain; charset=utf-8";
            if (response.status == 204 || response.status == 304)
                response.body.clear();
            std::string wire = "HTTP/1.1 " + std::to_string(response.status) + " " + reason(response.status) + "\r\n";
            for (const auto &entry : headers)
                wire += entry.first + ": " + entry.second + "\r\n";
            wire += "content-length: " + std::to_string(response.body.size()) + "\r\nconnection: close\r\n\r\n";
            const auto deadline = Clock::now() + std::chrono::seconds(options.body_timeout_seconds);
            if (send_all(fd, wire, deadline, stop))
                send_all(fd, response.body, deadline, stop);
        }
        // Buffers belong to the server rather than worker allocators. Reusing four
        // fixed-capacity strings bounds retained payload memory across successive waves
        // dispatched to different workers (freeing per-worker allocations may retain
        // them in allocator arenas until process exit).
        struct BodyPool
        {
            struct Buffer
            {
                std::string bytes;
                bool used = false;
            };
            std::mutex mutex;
            std::vector<Buffer> buffers;
            BodyPool(std::size_t count, std::size_t capacity) : buffers(count)
            {
                for (auto &buffer : buffers)
                    buffer.bytes.reserve(capacity);
            }
        };
        struct BodyLease
        {
            BodyPool &pool;
            std::string &body;
            std::size_t index;
            BodyLease(BodyPool &p, std::string &b) : pool(p), body(b), index(p.buffers.size())
            {
            }
            bool acquire()
            {
                std::lock_guard<std::mutex> lock(pool.mutex);
                for (std::size_t i = 0; i < pool.buffers.size(); ++i) {
                    if (!pool.buffers[i].used) {
                        pool.buffers[i].used = true;
                        index = i;
                        body.swap(pool.buffers[i].bytes);
                        return true;
                    }
                }
                return false;
            }
            ~BodyLease()
            {
                if (index == pool.buffers.size())
                    return;
                body.clear();
                std::lock_guard<std::mutex> lock(pool.mutex);
                body.swap(pool.buffers[index].bytes);
                pool.buffers[index].used = false;
            }
        };
        void handle(int fd, const std::string &peer, const HttpServerOptions &options, const Handler &handler,
                    BodyPool &bodies, const std::atomic<bool> &stop)
        {
            HttpRequest request;
            BodyLease body_lease(bodies, request.body); // Hold until handler/response/request memory is released.
            try {
                const auto header_deadline = Clock::now() + std::chrono::seconds(options.header_timeout_seconds);
                std::string incoming;
                std::array<char, 8192> buffer { };
                std::size_t end = std::string::npos;
                while ((end = incoming.find("\r\n\r\n")) == std::string::npos) {
                    if (incoming.size() >= options.max_header_bytes)
                        throw HttpError { 431 };
                    if (!wait_socket(fd, POLLIN, header_deadline, stop))
                        throw HttpError { 408 };
                    const ssize_t count = ::recv(fd, buffer.data(), buffer.size(), 0);
                    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                        continue;
                    if (count <= 0)
                        throw HttpError { 400 };
                    incoming.append(buffer.data(), std::size_t(count));
                }
                end += 4;
                if (end > options.max_header_bytes)
                    throw HttpError { 431 };
                const std::size_t first_line = incoming.find("\r\n");
                if (first_line == std::string::npos || first_line > 8192)
                    throw HttpError { 400 };
                const std::string request_line = incoming.substr(0, first_line);
                const auto first_space = request_line.find(' '),
                           second_space = request_line.find(' ', first_space == std::string::npos ? 0 : first_space + 1);
                if (first_space == std::string::npos || second_space == std::string::npos
                    || request_line.find(' ', second_space + 1) != std::string::npos)
                    throw HttpError { 400 };
                request.method = request_line.substr(0, first_space);
                request.target = request_line.substr(first_space + 1, second_space - first_space - 1);
                request.peer = peer;
                const std::string version = request_line.substr(second_space + 1);
                if (!token(request.method) || (version != "HTTP/1.1" && version != "HTTP/1.0") || request.target.empty()
                    || request.target.size() > 4096 || request.target.front() != '/'
                    || request.target.find('#') != std::string::npos)
                    throw HttpError { 400 };
                for (unsigned char c : request.target)
                    if (c <= 32 || c >= 127)
                        throw HttpError { 400 };
                std::size_t position = first_line + 2;
                while (position < end - 2) {
                    const auto next = incoming.find("\r\n", position);
                    if (next == std::string::npos || next - position > 8192)
                        throw HttpError { 431 };
                    const std::string line = incoming.substr(position, next - position);
                    const auto colon = line.find(':');
                    if (colon == std::string::npos)
                        throw HttpError { 400 };
                    const std::string name = line.substr(0, colon), value = trim(line.substr(colon + 1));
                    if (!token(name) || !field_value(value) || request.headers.size() >= 100
                        || !request.headers.emplace(lower(name), value).second)
                        throw HttpError { 400 };
                    position = next + 2;
                }
                if (version == "HTTP/1.1" && (!request.headers.count("host") || request.headers.at("host").empty()))
                    throw HttpError { 400 };
                if (request.headers.count("transfer-encoding"))
                    throw HttpError { 400 };
                if (request.method != "GET" && request.method != "POST")
                    throw HttpError { 405 };
                std::size_t length = 0;
                const auto content_length = request.headers.find("content-length");
                if (content_length != request.headers.end()) {
                    if (content_length->second.empty())
                        throw HttpError { 400 };
                    for (unsigned char c : content_length->second) {
                        if (c < '0' || c > '9')
                            throw HttpError { 400 };
                        const std::size_t digit = c - '0';
                        if (length > (std::numeric_limits<std::size_t>::max() - digit) / 10)
                            throw HttpError { 413 };
                        length = length * 10 + digit;
                    }
                }
                if (request.method == "GET" && length != 0)
                    throw HttpError { 400 };
                if (incoming.size() - end > length)
                    throw HttpError { 400 };
                if (options.header_handler) {
                    HttpResponse preliminary = options.header_handler(request);
                    if (preliminary.status != 0) {
                        reply(fd, std::move(preliminary), options, stop);
                        return;
                    }
                }
                if (length > options.max_body_bytes)
                    throw HttpError { 413 };
                if (length && !body_lease.acquire())
                    throw HttpError { 503 };
                const auto expect = request.headers.find("expect");
                if (expect != request.headers.end()) {
                    if (lower(expect->second) != "100-continue" || request.method != "POST")
                        throw HttpError { 417 };
                    if (!send_all(fd, "HTTP/1.1 100 Continue\r\n\r\n", header_deadline, stop))
                        return;
                }
                const auto body_deadline = Clock::now() + std::chrono::seconds(options.body_timeout_seconds);
                request.body.reserve(length);
                request.body.append(incoming.data() + end, incoming.size() - end);
                incoming.clear();
                while (request.body.size() < length) {
                    if (!wait_socket(fd, POLLIN, body_deadline, stop))
                        throw HttpError { 408 };
                    const ssize_t count =
                            ::recv(fd, buffer.data(), std::min(buffer.size(), length - request.body.size()), 0);
                    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                        continue;
                    if (count <= 0)
                        throw HttpError { 400 };
                    request.body.append(buffer.data(), std::size_t(count));
                }
                reply(fd, handler(request), options, stop);
            } catch (const HttpError &error) {
                reply(fd, { error.status, { }, reason(error.status) + "\n" }, options, stop);
            } catch (...) {
                reply(fd, { 500, { }, "internal server error\n" }, options, stop);
            }
        }
    }

    void run_http_server(const HttpServerOptions &options, const Handler &handler, std::atomic<bool> &stop)
    {
        if (!handler || !options.max_handlers || options.max_handlers > 64 || !options.max_body_readers
            || options.max_body_readers > options.max_handlers || !options.header_timeout_seconds
            || !options.body_timeout_seconds || !options.max_body_bytes || options.max_body_bytes > 15 * 1024 * 1024
            || options.max_header_bytes < 64 || options.max_header_bytes > 64 * 1024
            || options.max_response_bytes > 15 * 1024 * 1024)
            throw std::invalid_argument("invalid HTTP server options");
        addrinfo hints { };
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        addrinfo *address = nullptr;
        if (::getaddrinfo(options.bind_address.c_str(), std::to_string(options.port).c_str(), &hints, &address) != 0)
            throw std::invalid_argument("bind address must be numeric");
        const int listener_fd = ::socket(address->ai_family, SOCK_STREAM, 0);
        Socket listener(listener_fd);
        if (listener_fd < 0) {
            ::freeaddrinfo(address);
            throw std::runtime_error("socket failed");
        }
        const int enabled = 1;
        ::setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
        if (address->ai_family == AF_INET6)
            ::setsockopt(listener_fd, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled));
        const int bound = ::bind(listener_fd, address->ai_addr, address->ai_addrlen);
        ::freeaddrinfo(address);
        if (bound < 0 || ::listen(listener_fd, int(options.max_handlers)) < 0)
            throw std::runtime_error("bind/listen failed");
        nonblocking(listener_fd);
        sockaddr_storage local { };
        socklen_t local_size = sizeof(local);
        if (::getsockname(listener_fd, reinterpret_cast<sockaddr *>(&local), &local_size) != 0)
            throw std::runtime_error("socket name failed");
        const auto port = ntohs(local.ss_family == AF_INET ? reinterpret_cast<sockaddr_in *>(&local)->sin_port
                                                           : reinterpret_cast<sockaddr_in6 *>(&local)->sin6_port);
        std::mutex mutex;
        std::condition_variable ready;
        std::deque<std::pair<int, std::string>> queue;
        std::size_t active = 0;
        bool finishing = false;
        BodyPool bodies(options.max_body_readers, options.max_body_bytes);
        std::vector<std::thread> workers;
        const auto finish = [&]() {
            {
                std::lock_guard<std::mutex> lock(mutex);
                finishing = true;
                for (const auto &item : queue)
                    ::close(item.first);
                active -= queue.size();
                queue.clear();
            }
            ready.notify_all();
            for (auto &worker : workers)
                if (worker.joinable())
                    worker.join();
        };
        try {
            for (std::size_t i = 0; i < options.max_handlers; ++i)
                workers.emplace_back([&]() {
                    while (true) {
                        std::pair<int, std::string> item;
                        {
                            std::unique_lock<std::mutex> lock(mutex);
                            ready.wait(lock, [&]() { return finishing || !queue.empty(); });
                            if (queue.empty())
                                return;
                            item = std::move(queue.front());
                            queue.pop_front();
                        }
                        {
                            Socket client(item.first);
                            handle(item.first, item.second, options, handler, bodies, stop);
                        }
                        {
                            std::lock_guard<std::mutex> lock(mutex);
                            --active;
                        }
                    }
                });
            if (options.on_listening)
                options.on_listening(port);
            while (!stop.load(std::memory_order_relaxed)) {
                pollfd event { listener_fd, POLLIN, 0 };
                const int observed = ::poll(&event, 1, 100);
                if (observed < 0) {
                    if (errno == EINTR)
                        continue;
                    throw std::runtime_error("accept poll failed");
                }
                if (observed == 0)
                    continue;
                if (!(event.revents & POLLIN))
                    throw std::runtime_error("listener failed");
                sockaddr_storage remote { };
                socklen_t remote_size = sizeof(remote);
                Socket accepted(::accept(listener_fd, reinterpret_cast<sockaddr *>(&remote), &remote_size));
                if (accepted.value < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                        continue;
                    throw std::runtime_error("accept failed");
                }
                nonblocking(accepted.value);
                char peer[NI_MAXHOST] { };
                if (::getnameinfo(reinterpret_cast<sockaddr *>(&remote), remote_size, peer, sizeof(peer), nullptr, 0,
                                  NI_NUMERICHOST)
                    != 0)
                    continue;
                bool admitted = false;
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    if (active < options.max_handlers) {
                        queue.emplace_back(accepted.value, peer);
                        ++active;
                        accepted.value = -1;
                        admitted = true;
                    }
                }
                if (admitted)
                    ready.notify_one();
                else
                    send_all(accepted.value,
                             "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                             Clock::now() + std::chrono::milliseconds(100), stop);
            }
        } catch (...) {
            stop.store(true);
            finish();
            throw;
        }
        finish();
    }
}
