// Actual production controlPid1Run -> serveControl -> PosixPoolTransport worker
// path under link-time fake syscall boundaries. Never opens a proc file, a real
// socket, a service, a namespace or a product artifact.
#include "control_http.h"
#include "control_loaded.h"
#include "control_pid1.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace amnezia::awgMigration::controlPid1;

namespace {
constexpr int listenerFd = 9;

std::mutex g_ioMutex;
std::condition_variable g_ioCv;
std::deque<int> g_acceptQueue;
std::map<int, std::string> g_requests;
std::map<int, std::size_t> g_offsets;
std::map<int, std::string> g_sent;
std::map<int, int> g_closedCount;
std::atomic<int> g_unexpected{0};

std::mutex g_gateMutex;
std::condition_variable g_gateCv;
int g_active = 0, g_maxActive = 0, g_dispatches = 0;
bool g_release = false, g_abort = false;

std::string requestFor(const std::string &path) {
    return "POST " + path + " HTTP/1.1\r\nHost: control\r\nContent-Length: 2\r\n\r\n{}";
}
std::string malformedRequest() {
    return "POST /migration/v1/x HTTP/1.1\r\nHost: control\r\n\r\n";
}
void ioChanged() { g_ioCv.notify_all(); }
} // namespace

extern "C" {
int __wrap_socket(int, int, int) { return listenerFd; }
int __wrap_setsockopt(int, int, int, const void *, socklen_t) { return 0; }
int __wrap_bind(int, const struct sockaddr *, socklen_t) { return 0; }
int __wrap_listen(int, int) { return 0; }
int __wrap_accept4(int, struct sockaddr *peer, socklen_t *size, int) {
    std::lock_guard<std::mutex> lock(g_ioMutex);
    if (g_acceptQueue.empty()) {
        errno = EAGAIN;
        return -1;
    }
    const int fd = g_acceptQueue.front();
    g_acceptQueue.pop_front();
    if (peer && size && *size >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        std::memset(peer, 0, sizeof(sockaddr_in));
        auto *address = reinterpret_cast<sockaddr_in *>(peer);
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        *size = sizeof(sockaddr_in);
    }
    return fd;
}
int __wrap_poll(struct pollfd *descriptors, nfds_t count, int timeout) {
    if (!descriptors || count == 0) return 0;
    for (nfds_t index = 0; index < count; ++index) {
        if (descriptors[index].fd != listenerFd) continue;
        {
            std::lock_guard<std::mutex> lock(g_ioMutex);
            if (!g_acceptQueue.empty()) {
                descriptors[index].revents = POLLIN;
                return 1;
            }
        }
        if (timeout > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout, 1)));
        return 0;
    }
    for (nfds_t index = 0; index < count; ++index) {
        if (descriptors[index].fd == listenerFd) continue;
        descriptors[index].revents = static_cast<short>(descriptors[index].events & (POLLIN | POLLOUT));
        return 1;
    }
    return 0;
}
ssize_t __wrap_read(int fd, void *buffer, size_t size) {
    std::lock_guard<std::mutex> lock(g_ioMutex);
    const auto request = g_requests.find(fd);
    if (request == g_requests.end()) {
        errno = EBADF;
        return -1;
    }
    auto &offset = g_offsets[fd];
    const auto begin = std::min(offset, request->second.size());
    const auto count = std::min(size, request->second.size() - begin);
    std::memcpy(buffer, request->second.data() + begin, count);
    offset += count;
    return static_cast<ssize_t>(count);
}
ssize_t __wrap_send(int fd, const void *buffer, size_t size, int) {
    std::lock_guard<std::mutex> lock(g_ioMutex);
    g_sent[fd].append(static_cast<const char *>(buffer), size);
    ioChanged();
    return static_cast<ssize_t>(size);
}
int __wrap_shutdown(int, int) { return 0; }
int __wrap_close(int fd) {
    std::lock_guard<std::mutex> lock(g_ioMutex);
    ++g_closedCount[fd];
    ioChanged();
    return 0;
}
int __wrap_open(const char *, int, ...) { ++g_unexpected; errno = EPERM; return -1; }
int __wrap_fstat(int, struct stat *) { ++g_unexpected; errno = EPERM; return -1; }
ssize_t __wrap_pread(int, void *, size_t, off_t) { ++g_unexpected; errno = EPERM; return -1; }
uid_t __wrap_geteuid() { ++g_unexpected; errno = EPERM; return static_cast<uid_t>(-1); }
int __wrap_fcntl(int, int, ...) { ++g_unexpected; errno = EPERM; return -1; }
int __wrap_uname(void *) { ++g_unexpected; errno = EPERM; return -1; }
int __wrap_memfd_create(const char *, unsigned) { ++g_unexpected; errno = EPERM; return -1; }
int __wrap_fsync(int) { ++g_unexpected; errno = EPERM; return -1; }
int __wrap_fchmod(int, unsigned) { ++g_unexpected; errno = EPERM; return -1; }
int __wrap_unlink(const char *) { ++g_unexpected; errno = EPERM; return -1; }
int __wrap_rename(const char *, const char *) { ++g_unexpected; errno = EPERM; return -1; }
ssize_t __wrap_write(int, const void *, size_t) { ++g_unexpected; errno = EPERM; return -1; }
int __wrap_dup(int) { ++g_unexpected; errno = EPERM; return -1; }
}

namespace {
std::string sha(const std::string &bytes) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> guard(ctx, EVP_MD_CTX_free);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1
        || EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) != 1
        || EVP_DigestFinal_ex(ctx, digest.data(), &length) != 1) throw std::runtime_error("sha");
    static const char *digits = "0123456789abcdef";
    std::string result;
    for (unsigned index = 0; index < length; ++index) {
        result.push_back(digits[digest[index] >> 4]);
        result.push_back(digits[digest[index] & 0x0f]);
    }
    return result;
}
void put16(std::string &raw, std::size_t at, unsigned value) {
    raw[at] = static_cast<char>(value & 0xff);
    raw[at + 1] = static_cast<char>((value >> 8) & 0xff);
}
void put32(std::string &raw, std::size_t at, unsigned value) {
    for (int index = 0; index < 4; ++index)
        raw[at + static_cast<std::size_t>(index)] = static_cast<char>((value >> (8 * index)) & 0xff);
}
void put64(std::string &raw, std::size_t at, std::uint64_t value) {
    for (int index = 0; index < 8; ++index)
        raw[at + static_cast<std::size_t>(index)] = static_cast<char>((value >> (8 * index)) & 0xff);
}
std::string elfFixture() {
    std::string raw(512, '\0');
    raw[0] = '\x7f'; raw[1] = 'E'; raw[2] = 'L'; raw[3] = 'F';
    raw[4] = 2; raw[5] = 1; raw[6] = 1;
    put16(raw, 16, 2);
    put16(raw, 18, 62);
    put32(raw, 20, 1);
    put64(raw, 24, 0x1000);
    put64(raw, 32, 64);
    put16(raw, 52, 64);
    put16(raw, 54, 56);
    put16(raw, 56, 1);
    put32(raw, 64, 1);
    put32(raw, 68, 5);
    put64(raw, 72, 0);
    put64(raw, 80, 0x1000);
    put64(raw, 88, 0x1000);
    put64(raw, 96, 512);
    put64(raw, 104, 512);
    put64(raw, 112, 4096);
    return raw;
}

struct FakeFile {
    std::string bytes;
    FileIdentity identity;
    std::size_t offset = 0;
};
class FakeCapture final : public CaptureOps {
public:
    std::map<int, FakeFile> files;
    int nextFd = 10, nextMemfd = 100;
    std::vector<int> closed;
    void add(int fd, const std::string &bytes) {
        FakeFile file;
        file.bytes = bytes;
        file.identity.regular = true;
        file.identity.mode = 0100755;
        file.identity.uid = 1000;
        file.identity.nlink = 1;
        file.identity.device = 7;
        file.identity.inode = 11;
        file.identity.size = bytes.size();
        file.identity.mtimeNs = 1000;
        file.identity.ctimeNs = 2000;
        files[fd] = file;
    }
    int openNoFollow(const std::filesystem::path &) override { return files.empty() ? -1 : nextFd; }
    FileIdentity identify(int fd) override { return files.at(fd).identity; }
    std::string readChunk(int fd, std::size_t limit) override {
        auto &file = files.at(fd);
        const auto count = std::min(limit, file.bytes.size() - file.offset);
        std::string chunk = file.bytes.substr(file.offset, count);
        file.offset += count;
        return chunk;
    }
    bool hasExtraByte(int) override { return false; }
    int createSealedMemfd() override { return nextMemfd++; }
    bool writeAll(int, const std::string &) override { return true; }
    bool setMode0500(int) override { return true; }
    bool sealAndVerify(int) override { return true; }
    std::uint32_t currentUid() override { return 1000; }
    std::string machine() override { return "x86_64"; }
    void close(int fd) override { closed.push_back(fd); }
};
class FakeSink final : public ReceiptSink {
public:
    int commits = 0;
    std::string bytes;
    void commit(const std::filesystem::path &, const std::string &, const std::string &content) override {
        ++commits;
        bytes = content;
    }
};

bool waitForGate(int target, int milliseconds) {
    std::unique_lock<std::mutex> lock(g_gateMutex);
    return g_gateCv.wait_for(lock, std::chrono::milliseconds(milliseconds),
                             [target] { return g_maxActive >= target; });
}
bool waitForIo(const std::function<bool()> &predicate, int milliseconds) {
    // Polling keeps every predicate free to take g_ioMutex itself; a
    // condition_variable predicate would re-enter the non-recursive mutex.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}
int sentCount(int first, int last) {
    std::lock_guard<std::mutex> lock(g_ioMutex);
    int count = 0;
    for (int fd = first; fd <= last; ++fd) if (g_sent.count(fd)) ++count;
    return count;
}
int responseStatus(int fd) {
    std::lock_guard<std::mutex> lock(g_ioMutex);
    const auto entry = g_sent.find(fd);
    if (entry == g_sent.end() || entry->second.size() < 12) return -1;
    return std::stoi(entry->second.substr(9, 3));
}
bool sentOn(int fd) {
    std::lock_guard<std::mutex> lock(g_ioMutex);
    return g_sent.count(fd) != 0;
}
int closeCount(int fd) {
    std::lock_guard<std::mutex> lock(g_ioMutex);
    const auto entry = g_closedCount.find(fd);
    return entry == g_closedCount.end() ? 0 : entry->second;
}
} // namespace

int main(int argc, char **argv) {
    const bool failWork = argc == 2 && std::string(argv[1]) == "--fail-work";
    int failures = 0;
    FakeCapture capture;
    const std::string elf = elfFixture();
    capture.add(capture.nextFd, elf);
    FakeSink sink;
    auto transport = makePosixPoolTransport(18082);
    if (!transport) {
        std::cerr << "production pool transport factory returned null\n";
        return 1;
    }
    ControlHooks hooks;
    hooks.allowPeer = [](const std::string &) { return true; };
    hooks.authenticate = [](const std::string &, const std::string &, std::string &) { return false; };
    hooks.dispatch = [](const std::string &frame, const std::filesystem::path &) -> std::string {
        {
            std::unique_lock<std::mutex> lock(g_gateMutex);
            ++g_active;
            ++g_dispatches;
            g_maxActive = std::max(g_maxActive, g_active);
            g_gateCv.notify_all();
            g_gateCv.wait(lock, [] { return g_release || g_abort; });
            --g_active;
        }
        if (frame.find("throw") != std::string::npos)
            throw std::runtime_error("native_control_rejected");
        return "{\"result\":{\"handled\":true,\"status\":200,\"body\":\"{}\",\"authenticate\":false}}";
    };
    ControlPid1Deps deps{capture, sink, *transport, [] { return std::string("12345"); }, hooks};
    ControlPid1Config config{"/app/awg-feed", "/migration", sha(elf), "target", "amnezia-awg"};
    {
        std::lock_guard<std::mutex> lock(g_ioMutex);
        for (int fd = 100; fd <= 116; ++fd) {
            g_acceptQueue.push_back(fd);
            g_requests[fd] = requestFor("/migration/v1/native-control-capability");
        }
        g_requests[118] = malformedRequest();
        g_requests[119] = requestFor("/migration/v1/throw");
    }
    int runResult = -1;
    std::thread server([&] {
        try {
            runResult = controlPid1Run(config, deps);
        } catch (...) {
            runResult = -2;
        }
    });
    const auto stopServer = [&] {
        transport->requestStop();
        if (server.joinable()) server.join();
    };
    if (!waitForGate(16, 3000)) {
        {
            std::lock_guard<std::mutex> lock(g_gateMutex);
            g_abort = true;
        }
        g_gateCv.notify_all();
        stopServer();
        std::cout << "concurrent handlers max=" << g_maxActive << " expected=16\n";
        return 1;
    }
    if (g_maxActive != static_cast<int>(controlSlotLimit)) {
        std::cerr << "handler concurrency exceeded or missed slot limit: " << g_maxActive << "\n";
        ++failures;
    }
    const bool refusedClosed = waitForIo([] { return closeCount(116) == 1; }, 2000);
    if (!refusedClosed) {
        std::cerr << "17th concurrent connection was not closed\n";
        ++failures;
    }
    if (closeCount(116) != 1) {
        std::cerr << "17th concurrent connection close count=" << closeCount(116) << "\n";
        ++failures;
    }
    if (sentOn(116)) {
        std::cerr << "17th concurrent connection received a response\n";
        ++failures;
    }
    {
        std::lock_guard<std::mutex> lock(g_gateMutex);
        g_release = true;
    }
    g_gateCv.notify_all();
    const bool firstWave = waitForIo([] { return sentCount(100, 115) == 16; }, 5000);
    if (!firstWave) {
        std::cerr << "not all sixteen concurrent handlers responded\n";
        ++failures;
    }
    for (int fd = 100; fd <= 115; ++fd) {
        if (responseStatus(fd) != 200) {
            std::cerr << "concurrent handler fd " << fd << " status=" << responseStatus(fd) << "\n";
            ++failures;
        }
    }
    const auto serveNext = [&](int fd, const std::string &raw, int expected) {
        {
            std::lock_guard<std::mutex> lock(g_ioMutex);
            if (!raw.empty()) g_requests[fd] = raw;
            g_acceptQueue.push_back(fd);
        }
        if (!waitForIo([fd] { return sentOn(fd); }, 5000)) {
            std::cerr << "no response after admission for fd " << fd << "\n";
            ++failures;
            return;
        }
        if (responseStatus(fd) != expected) {
            std::cerr << "fd " << fd << " status=" << responseStatus(fd) << " expected=" << expected << "\n";
            ++failures;
        }
    };
    serveNext(117, requestFor("/migration/v1/native-control-capability"), 200);
    serveNext(118, std::string(), 403);
    serveNext(119, std::string(), 403);
    serveNext(120, requestFor("/migration/v1/native-control-capability"), 200);
    stopServer();
    if (runResult != 0) {
        std::cerr << "controlPid1Run returned " << runResult << "\n";
        ++failures;
    }
    for (int fd = 100; fd <= 115; ++fd) if (closeCount(fd) != 1) {
        std::cerr << "handler fd " << fd << " close count=" << closeCount(fd) << "\n";
        ++failures;
    }
    for (const int fd : {117, 118, 119, 120}) if (closeCount(fd) != 1) {
        std::cerr << "cleanup fd " << fd << " close count=" << closeCount(fd) << "\n";
        ++failures;
    }
    if (closeCount(116) != 1) {
        std::cerr << "refused fd 116 close count=" << closeCount(116) << "\n";
        ++failures;
    }
    if (g_dispatches != 19) {
        std::cerr << "dispatcher calls=" << g_dispatches << " expected=19\n";
        ++failures;
    }
    if (g_unexpected.load() != 0) {
        std::cerr << "unexpected real OS boundary calls=" << g_unexpected.load() << "\n";
        ++failures;
    }
    transport.reset();
    if (closeCount(listenerFd) != 1) {
        std::cerr << "listener close count=" << closeCount(listenerFd) << "\n";
        ++failures;
    }
    std::cout << "control pool concurrency checks: 25 max_concurrent=" << g_maxActive
              << " dispatched=" << g_dispatches << " failures=" << failures << "\n";
    if (failWork) return 23;
    return failures ? 1 : 0;
}
