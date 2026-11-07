#include "control_http.h"
#include "control_loaded.h"
#include "control_pid1.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace amnezia::awgMigration::controlPid1 {
namespace {
class PosixCaptureOps final : public CaptureOps {
public:
    int openNoFollow(const std::filesystem::path &path) override {
        return ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    }
    FileIdentity identify(int fd) override {
        struct stat info {};
        if (::fstat(fd, &info) != 0) throw std::runtime_error("native_control_rejected");
        FileIdentity identity;
        identity.regular = S_ISREG(info.st_mode);
        identity.mode = static_cast<std::uint32_t>(info.st_mode);
        identity.uid = info.st_uid;
        identity.nlink = static_cast<std::uint32_t>(info.st_nlink);
        identity.device = info.st_dev;
        identity.inode = info.st_ino;
        identity.size = static_cast<std::uint64_t>(info.st_size);
        identity.mtimeNs = static_cast<std::uint64_t>(info.st_mtim.tv_sec) * 1000000000ull + static_cast<std::uint64_t>(info.st_mtim.tv_nsec);
        identity.ctimeNs = static_cast<std::uint64_t>(info.st_ctim.tv_sec) * 1000000000ull + static_cast<std::uint64_t>(info.st_ctim.tv_nsec);
        return identity;
    }
    std::string readChunk(int fd, std::size_t limit) override {
        std::vector<char> buffer(limit);
        ssize_t count = -1;
        do {
            count = ::read(fd, buffer.data(), buffer.size());
        } while (count < 0 && errno == EINTR);
        if (count < 0) throw std::runtime_error("native_control_rejected");
        return std::string(buffer.data(), static_cast<std::size_t>(count));
    }
    bool hasExtraByte(int fd) override {
        std::array<char, 1> extra{};
        ssize_t count = -1;
        do {
            count = ::read(fd, extra.data(), 1);
        } while (count < 0 && errno == EINTR);
        if (count < 0) throw std::runtime_error("native_control_rejected");
        return count != 0;
    }
    int createSealedMemfd() override {
        return ::memfd_create("amnezia-control", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    }
    bool writeAll(int fd, const std::string &bytes) override {
        const int duplicate = ::dup(fd);
        if (duplicate < 0) return false;
        std::size_t written = 0;
        while (written < bytes.size()) {
            const auto count = ::write(duplicate, bytes.data() + written, bytes.size() - written);
            if (count <= 0) {
                ::close(duplicate);
                return false;
            }
            written += static_cast<std::size_t>(count);
        }
        ::close(duplicate);
        return true;
    }
    bool setMode0500(int fd) override { return ::fchmod(fd, 0500) == 0; }
    bool sealAndVerify(int fd) override {
        const int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
        return ::fcntl(fd, F_ADD_SEALS, seals) == 0 && ::fcntl(fd, F_GET_SEALS) == seals;
    }
    std::uint32_t currentUid() override { return ::geteuid(); }
    std::string machine() override {
        struct utsname value {};
        if (::uname(&value) != 0) throw std::runtime_error("native_control_rejected");
        return value.machine;
    }
    void close(int fd) override {
        if (fd >= 0) ::close(fd);
    }
};

class PosixReceiptSink final : public ReceiptSink {
public:
    void commit(const std::filesystem::path &directory, const std::string &role, const std::string &bytes) override {
        if (role != "source" && role != "target") throw std::runtime_error("native_control_rejected");
        const auto target = directory / ("control-loaded-" + role + ".json");
        const auto temporary = directory / ("control-loaded-" + role + ".json.tmp");
        ::unlink(temporary.c_str());
        const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) throw std::runtime_error("native_control_rejected");
        std::size_t written = 0;
        bool ok = true;
        while (written < bytes.size()) {
            const auto count = ::write(fd, bytes.data() + written, bytes.size() - written);
            if (count <= 0) {
                ok = false;
                break;
            }
            written += static_cast<std::size_t>(count);
        }
        if (ok) ok = ::fsync(fd) == 0;
        if (::close(fd) != 0) ok = false;
        if (!ok || ::rename(temporary.c_str(), target.c_str()) != 0) {
            ::unlink(temporary.c_str());
            throw std::runtime_error("native_control_rejected");
        }
    }
};

class PosixAttestOps final : public AttestOps {
public:
    std::string processStart() override {
        const int fd = ::open("/proc/1/stat", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) throw std::runtime_error("native_control_rejected");
        std::string raw;
        std::array<char, 4096> buffer{};
        ssize_t count = 0;
        do {
            count = ::read(fd, buffer.data(), buffer.size());
        } while (count < 0 && errno == EINTR);
        ::close(fd);
        if (count <= 0) throw std::runtime_error("native_control_rejected");
        raw.assign(buffer.data(), static_cast<std::size_t>(count));
        std::size_t field = 0, position = 0;
        std::string value;
        while (position < raw.size()) {
            while (position < raw.size() && (raw[position] == ' ' || raw[position] == '\n')) ++position;
            const auto begin = position;
            while (position < raw.size() && raw[position] != ' ' && raw[position] != '\n') ++position;
            if (begin == position) break;
            if (field == 21) {
                value = raw.substr(begin, position - begin);
                break;
            }
            ++field;
        }
        if (value.empty() || value.size() > 20 || value.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("native_control_rejected");
        return value;
    }
    FdAttestation attest(int fd) override {
        // Receipt descriptors belong to PID1, not this docker-exec verifier.
        // Follow only this fixed procfs alias after the receipt's integer bound
        // and process-start checks; never interpret the number as a local fd.
        struct HeldFd {
            int value;
            ~HeldFd() { if (value >= 0) ::close(value); }
        } held{::open(("/proc/1/fd/" + std::to_string(fd)).c_str(),
                      O_RDONLY | O_CLOEXEC | O_NONBLOCK)};
        if (held.value < 0) throw std::runtime_error("native_control_rejected");
        struct stat info {};
        if (::fstat(held.value, &info) != 0) throw std::runtime_error("native_control_rejected");
        FdAttestation attested;
        attested.regular = S_ISREG(info.st_mode);
        attested.size = static_cast<std::uint64_t>(info.st_size);
        const int seals = ::fcntl(held.value, F_GET_SEALS);
        if (seals < 0) throw std::runtime_error("native_control_rejected");
        attested.seals = static_cast<std::uint32_t>(seals);
        if (!attested.regular || attested.size > 32ull * 1024 * 1024) throw std::runtime_error("native_control_rejected");
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("native_control_rejected");
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> guard(ctx, EVP_MD_CTX_free);
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned length = 0;
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) throw std::runtime_error("native_control_rejected");
        std::vector<char> buffer(128 * 1024);
        std::uint64_t offset = 0;
        while (offset < attested.size) {
            const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(attested.size - offset, buffer.size()));
            const auto count = ::pread(held.value, buffer.data(), want, static_cast<off_t>(offset));
            if (count <= 0) throw std::runtime_error("native_control_rejected");
            if (EVP_DigestUpdate(ctx, buffer.data(), static_cast<std::size_t>(count)) != 1)
                throw std::runtime_error("native_control_rejected");
            offset += static_cast<std::uint64_t>(count);
        }
        if (EVP_DigestFinal_ex(ctx, digest.data(), &length) != 1 || length != 32)
            throw std::runtime_error("native_control_rejected");
        static const char *digits = "0123456789abcdef";
        attested.sha256.reserve(64);
        for (unsigned index = 0; index < length; ++index) {
            attested.sha256.push_back(digits[digest[index] >> 4]);
            attested.sha256.push_back(digits[digest[index] & 0x0f]);
        }
        return attested;
    }
};

class PosixHttpTransport final : public ControlTransport {
public:
    explicit PosixHttpTransport(std::uint16_t port) : port_(port) {}
    ~PosixHttpTransport() override {
        if (listener_ >= 0) ::close(listener_);
    }
    bool next(ControlHttpRequest &request, std::string &framingError) override {
        if (listener_ < 0) {
            listener_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (listener_ < 0) throw std::runtime_error("native_control_rejected");
            int reuse = 1;
            ::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
            sockaddr_in endpoint{};
            endpoint.sin_family = AF_INET;
            endpoint.sin_port = htons(port_);
            endpoint.sin_addr.s_addr = htonl(INADDR_ANY);
            if (::bind(listener_, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) != 0
                || ::listen(listener_, 16) != 0) throw std::runtime_error("native_control_rejected");
        }
        sockaddr_in peer{};
        socklen_t peerSize = sizeof(peer);
        const int connection = ::accept4(listener_, reinterpret_cast<sockaddr *>(&peer), &peerSize, SOCK_CLOEXEC);
        if (connection < 0) {
            if (errno == EINTR) return true;
            throw std::runtime_error("native_control_rejected");
        }
        std::array<char, 64> address{};
        if (!::inet_ntop(AF_INET, &peer.sin_addr, address.data(), address.size())) {
            ::close(connection);
            throw std::runtime_error("native_control_rejected");
        }
        framingError.clear();
        std::string raw;
        std::array<char, 8192> buffer{};
        for (;;) {
            const auto split = raw.find("\r\n\r\n");
            std::size_t declared = 0;
            bool complete = false;
            if (split != std::string::npos) {
                const std::string head = raw.substr(0, split);
                const auto position = head.find("\r\nContent-Length: ");
                if (position != std::string::npos) {
                    const auto begin = position + 18;
                    const auto end = head.find("\r\n", begin);
                    const std::string value = head.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
                    if (!value.empty() && value.size() <= 6 && value.find_first_not_of("0123456789") == std::string::npos) {
                        declared = static_cast<std::size_t>(std::stoul(value));
                        complete = raw.size() >= split + 4 + declared;
                    }
                } else {
                    complete = true; // let the strict parser reject the missing length
                }
            }
            if (complete) break;
            pollfd descriptor{connection, POLLIN, 0};
            const int ready = ::poll(&descriptor, 1, 10000);
            if (ready <= 0) {
                framingError = "timeout";
                break;
            }
            const auto count = ::read(connection, buffer.data(), buffer.size());
            if (count <= 0) {
                framingError = "closed";
                break;
            }
            raw.append(buffer.data(), static_cast<std::size_t>(count));
            if (raw.size() > 256 * 1024) {
                framingError = "oversize";
                break;
            }
        }
        try {
            if (framingError.empty()) request = parseHttpRequest(raw, address.data());
        } catch (...) {
            framingError = "malformed";
        }
        client_ = connection;
        return true;
    }
    void respond(const ControlHttpResponse &response) override {
        if (client_ < 0) return;
        const std::string bytes = serializeResponse(response);
        std::size_t written = 0;
        while (written < bytes.size()) {
            const auto count = ::send(client_, bytes.data() + written, bytes.size() - written, MSG_NOSIGNAL);
            if (count <= 0) break;
            written += static_cast<std::size_t>(count);
        }
        ::shutdown(client_, SHUT_RDWR);
        ::close(client_);
        client_ = -1;
    }

private:
    std::uint16_t port_;
    int listener_ = -1;
    int client_ = -1;
};

// ---- Production-only assembly. Everything below compiles in the proposal but
// is never invoked by the inert test binary: no socket, proc, memfd or file
// access happens unless controlPid1Main/verifyLoadedControlMain actually run in
// the PID1 container.
std::string readBoundedFile(const std::filesystem::path &path, std::size_t limit) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("native_control_rejected");
    std::string raw((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    if (raw.empty() || raw.size() > limit) throw std::runtime_error("native_control_rejected");
    return raw;
}

using JsonPtr = std::unique_ptr<json_object, decltype(&json_object_put)>;
JsonPtr ownJson(json_object *value) {
    if (!value) throw std::runtime_error("native_control_rejected");
    return JsonPtr(value, json_object_put);
}
std::string jsonText(json_object *root, const char *key) {
    json_object *value = nullptr;
    if (!json_object_object_get_ex(root, key, &value) || !value
        || !json_object_is_type(value, json_type_string)) throw std::runtime_error("native_control_rejected");
    return std::string(json_object_get_string(value), static_cast<std::size_t>(json_object_get_string_len(value)));
}

// target.py Server.verify_request: exactly the mapped VPN peer IP for this role.
std::set<std::string> readyPeers(const std::string &role) {
    const std::string raw = readBoundedFile("/migration/ready.json", 8 * 1024 * 1024);
    std::unique_ptr<json_tokener, decltype(&json_tokener_free)> tokener(json_tokener_new(), json_tokener_free);
    if (!tokener) throw std::runtime_error("native_control_rejected");
    json_tokener_set_flags(tokener.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    auto root = ownJson(json_tokener_parse_ex(tokener.get(), raw.data(), static_cast<int>(raw.size())));
    if (json_tokener_get_error(tokener.get()) != json_tokener_success
        || !json_object_is_type(root.get(), json_type_object)) throw std::runtime_error("native_control_rejected");
    json_object *peers = nullptr;
    if (!json_object_object_get_ex(root.get(), "peers", &peers) || !peers
        || !json_object_is_type(peers, json_type_object)) throw std::runtime_error("native_control_rejected");
    std::set<std::string> addresses;
    json_object_object_foreach(peers, key, value) {
        (void)key;
        if (!json_object_is_type(value, json_type_object)) throw std::runtime_error("native_control_rejected");
        addresses.insert(jsonText(value, role == "source" ? "sourceIp" : "targetIp"));
    }
    return addresses;
}

// target.py Handler.authenticate: exact client id plus constant-time token match.
bool authenticateToken(const std::string &client, const std::string &token, std::string &out) {
    if (client.size() != 64 || token.empty() || token.size() > 512) return false;
    for (const unsigned char character : token) if (character > 127) return false;
    const std::string raw = readBoundedFile("/logs/tokens.tsv", 4 * 1024 * 1024);
    std::istringstream lines(raw);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto first = line.find('\t');
        if (first == std::string::npos || line.substr(0, first) != client) continue;
        const auto second = line.find('\t', first + 1);
        const std::string value = line.substr(first + 1, second == std::string::npos ? std::string::npos : second - first - 1);
        if (value.size() == token.size() && CRYPTO_memcmp(value.data(), token.data(), token.size()) == 0) {
            out = client;
            return true;
        }
    }
    return false;
}

ControlHooks productionHooks(const std::string &role) {
    ControlHooks hooks;
    hooks.allowPeer = [role](const std::string &peer) {
        try {
            return readyPeers(role).count(peer) != 0;
        } catch (...) {
            return false;
        }
    };
    hooks.authenticate = [](const std::string &client, const std::string &token, std::string &out) {
        try {
            return authenticateToken(client, token, out);
        } catch (...) {
            return false;
        }
    };
    // hooks.dispatch intentionally left empty: serveControl falls back to the
    // actual controlRuntimeRequest/control_service dispatcher.
    return hooks;
}

// Python-equivalent admission: one accept loop plus exactly controlSlotLimit
// worker threads. A worker owns an admitted connection from framing through
// dispatch and response, so sixteen handlers execute concurrently like Python's
// ThreadingHTTPServer. The seventeenth concurrent connection is closed with no
// bytes, exactly like target.py process_request()/shutdown_request().
class PosixPoolTransport final : public ControlTransport {
public:
    explicit PosixPoolTransport(std::uint16_t port) : port_(port) {}
    void setPeerAdmission(const std::function<bool(const std::string &)> &allow) override {
        peerAdmission_ = allow;
    }
    ~PosixPoolTransport() override {
        requestStop();
        joinWorkers();
        closeQueued();
        if (listener_ >= 0) ::close(listener_);
        listener_ = -1;
    }

    // The pool serves only through serveConcurrently(): next()/respond() cannot
    // express per-connection ownership and would serialize handlers again.
    bool next(ControlHttpRequest &, std::string &) override {
        throw std::runtime_error("native_control_pool_requires_concurrent_serve");
    }
    void respond(const ControlHttpResponse &) override {
        throw std::runtime_error("native_control_pool_requires_concurrent_serve");
    }

    std::optional<int> serveConcurrently(const ControlRequestHandler &handler) override {
        start(handler);
        try {
            acceptUntilStopped();
        } catch (...) {
            requestStop();
            drainAndJoin();
            throw;
        }
        drainAndJoin();
        return 0;
    }

    void requestStop() override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        changed_.notify_all();
    }

private:
    struct Connection {
        int fd = -1;
        std::string peer;
    };

    void start(const ControlRequestHandler &handler) {
        std::lock_guard<std::mutex> guard(startMutex_);
        if (started_) return;
        listener_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (listener_ < 0) throw std::runtime_error("native_control_rejected");
        int reuse = 1;
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(port_);
        endpoint.sin_addr.s_addr = htonl(INADDR_ANY);
        if (::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0
            || ::bind(listener_, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) != 0
            || ::listen(listener_, static_cast<int>(controlSlotLimit)) != 0) {
            ::close(listener_);
            listener_ = -1;
            throw std::runtime_error("native_control_rejected");
        }
        for (std::size_t index = 0; index < controlSlotLimit; ++index)
            workers_.emplace_back([this, &handler] { workerLoop(handler); });
        started_ = true;
    }

    void acceptUntilStopped() {
        for (;;) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stopping_) return;
            }
            pollfd descriptor{listener_, POLLIN, 0};
            const int ready = ::poll(&descriptor, 1, 100);
            if (ready < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("native_control_rejected");
            }
            if (ready == 0) continue;
            if (!(descriptor.revents & POLLIN)) throw std::runtime_error("native_control_rejected");
            acceptSome();
        }
    }

    void acceptSome() {
        for (;;) {
            sockaddr_in peer{};
            socklen_t size = sizeof(peer);
            const int fd = ::accept4(listener_, reinterpret_cast<sockaddr *>(&peer), &size, SOCK_CLOEXEC);
            if (fd < 0) {
                if (errno == EINTR) continue;
                return;
            }
            std::array<char, 64> address{};
            if (!::inet_ntop(AF_INET, &peer.sin_addr, address.data(), address.size())) {
                ::close(fd);
                continue;
            }
            bool admitted = false;
            try { admitted = peerAdmission_ && peerAdmission_(address.data()); }
            catch (...) { admitted = false; }
            if (!admitted) {
                // Match TCPServer.verify_request: no read, response or slot.
                ::close(fd);
                continue;
            }
            if (!slots_.tryAcquire()) {
                // BoundedSemaphore exhausted: close without a response.
                ::close(fd);
                continue;
            }
            Connection connection{fd, address.data()};
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stopping_) {
                    slots_.release();
                    ::close(fd);
                    return;
                }
                connections_.push_back(std::move(connection));
            }
            changed_.notify_one();
        }
    }

    void workerLoop(const ControlRequestHandler &handler) {
        for (;;) {
            Connection connection;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                changed_.wait(lock, [this] { return stopping_ || !connections_.empty(); });
                if (stopping_ || connections_.empty()) return;
                connection = std::move(connections_.front());
                connections_.pop_front();
            }
            finish(connection.fd, handle(connection, handler));
        }
    }

    ControlHttpResponse handle(const Connection &connection, const ControlRequestHandler &handler) {
        try {
            const ControlHttpRequest request = frameRequest(connection);
            try {
                return handler(request);
            } catch (...) {
                return {403, ""};
            }
        } catch (...) {
            return {403, ""};
        }
    }

    void finish(int fd, const ControlHttpResponse &response) {
        try {
            sendAll(fd, serializeResponse(response));
        } catch (...) {
        }
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
        slots_.release();
    }

    void drainAndJoin() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        changed_.notify_all();
        closeQueued();
        joinWorkers();
    }

    void closeQueued() {
        std::deque<Connection> queued;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queued.swap(connections_);
        }
        for (const auto &connection : queued) {
            ::close(connection.fd);
            slots_.release();
        }
    }

    void joinWorkers() {
        std::vector<std::thread> workers;
        {
            std::lock_guard<std::mutex> guard(startMutex_);
            workers.swap(workers_);
        }
        for (auto &worker : workers) if (worker.joinable()) worker.join();
    }

    ControlHttpRequest frameRequest(const Connection &connection) {
        std::string raw;
        std::array<char, 8192> buffer{};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        for (;;) {
            const auto split = raw.find(std::string{13, 10, 13, 10});
            if (split != std::string::npos) {
                const auto lineEnd = raw.find(static_cast<char>(13));
                if (raw.substr(0, lineEnd).rfind("POST /migration/v1/", 0) != 0) break;
                std::size_t declared = 0;
                bool lengthSeen = false, complete = false;
                const std::string head = raw.substr(0, split);
                std::size_t position = head.find("\r\n");
                position = position == std::string::npos ? head.size() : position + 2;
                while (position < head.size()) {
                    const auto end = head.find("\r\n", position);
                    const std::string line = head.substr(position, end == std::string::npos ? std::string::npos : end - position);
                    position = end == std::string::npos ? head.size() : end + 2;
                    const auto colon = line.find(':');
                    if (colon == std::string::npos) continue;
                    std::string name = line.substr(0, colon), value = line.substr(colon + 1);
                    for (char &character : name) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
                    const auto begin = value.find_first_not_of(" \t");
                    value = begin == std::string::npos ? "" : value.substr(begin, value.find_last_not_of(" \t") - begin + 1);
                    if (name != "content-length") continue;
                    if (lengthSeen || value.empty() || value.size() > 6
                        || value.find_first_not_of("0123456789") != std::string::npos) throw std::runtime_error("native_control_rejected");
                    declared = static_cast<std::size_t>(std::stoul(value));
                    lengthSeen = true;
                    complete = raw.size() >= split + 4 + declared;
                }
                if (!lengthSeen || complete) break;
            }
            pollfd descriptor{connection.fd, POLLIN, 0};
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0 || ::poll(&descriptor, 1, static_cast<int>(left)) <= 0)
                throw std::runtime_error("native_control_rejected");
            const auto count = ::read(connection.fd, buffer.data(), buffer.size());
            if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (count <= 0) throw std::runtime_error("native_control_rejected");
            raw.append(buffer.data(), static_cast<std::size_t>(count));
            if (raw.size() > 256 * 1024) throw std::runtime_error("native_control_rejected");
        }
        return parseHttpRequest(raw, connection.peer);
    }

    static void sendAll(int fd, const std::string &bytes) {
        std::size_t sent = 0;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (sent < bytes.size()) {
            pollfd descriptor{fd, POLLOUT, 0};
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0 || ::poll(&descriptor, 1, static_cast<int>(left)) <= 0) return;
            const auto count = ::send(fd, bytes.data() + sent, bytes.size() - sent, MSG_NOSIGNAL);
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            if (count <= 0) return;
            sent += static_cast<std::size_t>(count);
        }
    }

    std::uint16_t port_;
    int listener_ = -1;
    bool started_ = false;
    bool stopping_ = false;
    std::mutex startMutex_;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<Connection> connections_;
    std::vector<std::thread> workers_;
    ControlSlots slots_{controlSlotLimit};
    std::function<bool(const std::string &)> peerAdmission_;
};
} // namespace

int controlPid1Main() {
    try {
        const char *shaValue = std::getenv("AMNEZIA_CONTROL_NATIVE_SHA256");
        const char *roleValue = std::getenv("AMNEZIA_MIGRATION_ROLE");
        const char *scopeValue = std::getenv("AMNEZIA_MIGRATION_SCOPE");
        const std::string expected = shaValue ? shaValue : "";
        const std::string role = roleValue ? roleValue : "target";
        const std::string scope = scopeValue ? scopeValue : "";
        if (expected.size() != 64 || expected.find_first_not_of("0123456789abcdef") != std::string::npos
            || (role != "source" && role != "target")
            || (scope != "amnezia-awg" && scope != "amnezia-awg2")) return 2;
        ControlPid1Config config;
        config.executable = "/app/awg-feed";
        config.directory = "/migration";
        config.expectedSha256 = expected;
        config.role = role;
        config.scope = scope;
        PosixCaptureOps capture;
        PosixReceiptSink sink;
        PosixPoolTransport transport(18082);
        ControlPid1Deps deps{capture, sink, transport,
                             [] { PosixAttestOps attest; return attest.processStart(); },
                             productionHooks(role)};
        return controlPid1Run(config, deps);
    } catch (...) {
        return 2;
    }
}

int verifyLoadedControlMain(const std::string &role, const std::string &expectedSha256,
                            const std::string &receiptPath) {
    if ((role != "source" && role != "target") || expectedSha256.size() != 64
        || expectedSha256.find_first_not_of("0123456789abcdef") != std::string::npos
        || receiptPath.empty()) return 2;
    try {
        const int fd = ::open(receiptPath.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return 3;
        struct stat info {};
        if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != ::geteuid()
            || info.st_nlink != 1 || info.st_size < 2 || info.st_size > 65536
            || (info.st_mode & 0777) != 0600) {
            ::close(fd);
            return 3;
        }
        std::string raw;
        std::array<char, 4096> buffer{};
        for (;;) {
            const auto count = ::read(fd, buffer.data(), buffer.size());
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) {
                ::close(fd);
                return 3;
            }
            if (count == 0) break;
            raw.append(buffer.data(), static_cast<std::size_t>(count));
            if (raw.size() > 65536) {
                ::close(fd);
                return 3;
            }
        }
        ::close(fd);
        PosixAttestOps attest;
        verifyLoadedControl(raw, role, expectedSha256, attest);
        return 0;
    } catch (...) {
        return 3;
    }
}

// Narrow seam for the inert boundary runner: construct the actual production
// pooled transport without starting any OS work. Serving begins only when
// controlPid1Run/serveControl hands it a request handler.
std::unique_ptr<ControlTransport> makePosixPoolTransport(std::uint16_t port) {
    return std::make_unique<PosixPoolTransport>(port);
}
} // namespace amnezia::awgMigration::controlPid1
