#pragma once
#include <atomic>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace amnezia::awgMigration::controlPid1 {
// Python target.py: ThreadingHTTPServer.request_queue_size == 16 and
// BoundedSemaphore(16); a request beyond the sixteenth is closed without any
// HTTP response instead of being queued.
inline constexpr std::size_t controlSlotLimit = 16;

struct ControlHttpRequest {
    std::string method;
    std::string target;       // request path, decoded only as far as framing requires
    std::string peerAddress;  // kernel-supplied address, never a request header
    std::string clientId;     // X-Amnezia-Client-Id, transport-only
    std::string logToken;     // X-Amnezia-Log-Token, transport-only
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};
struct ControlHttpResponse {
    int status = 403;
    std::string body;
};
// One fully framed request handed back to a transport that owns the connection.
using ControlRequestHandler = std::function<ControlHttpResponse(const ControlHttpRequest &)>;

// Framing boundary. The sequential interface (next/respond) remains valid for
// scripted transports; the production POSIX pool additionally accepts complete
// per-connection request handling through serveConcurrently().
class ControlTransport {
public:
    virtual ~ControlTransport() = default;
    // Returns false when the listener should stop. `framingError` non-empty means a
    // client was received but its bytes were invalid; the listener answers 403.
    virtual bool next(ControlHttpRequest &request, std::string &framingError) = 0;
    virtual void respond(const ControlHttpResponse &response) = 0;
    // TCPServer.verify_request runs before HTTP reads and worker-slot admission.
    // Scripted transports retain their existing next/respond behavior.
    virtual void setPeerAdmission(const std::function<bool(const std::string &)> &allow) {
        (void)allow;
    }
    // Pooled transports take ownership of framing, dispatch and response for one
    // connection per worker thread, so up to controlSlotLimit handlers execute
    // concurrently like Python's ThreadingHTTPServer. Returns the serve exit code
    // when the transport handled serving; nullopt keeps the sequential loop.
    virtual std::optional<int> serveConcurrently(const ControlRequestHandler &handler) {
        (void)handler;
        return std::nullopt;
    }
    // Requests a graceful stop of a pooled listener. Inert for sequential
    // transports, which stop when next() returns false.
    virtual void requestStop() {}
};

struct ControlHooks {
    // ready.json allowlist: sourceIp for role=source, targetIp for role=target.
    std::function<bool(const std::string &)> allowPeer;
    // tokens.tsv lookup; returns false on any mismatch. Called only after the
    // dispatcher defers authentication, preserving auth precedence.
    std::function<bool(const std::string &, const std::string &, std::string &)> authenticate;
    // Actual dispatcher. Production wiring MUST leave this as the default (the real
    // controlRuntimeRequest); tests replace it only to exercise auth orchestration.
    std::function<std::string(const std::string &, const std::filesystem::path &)> dispatch;
};

struct ControlConfig {
    std::filesystem::path directory;
    std::string role, scope;
};

// Bounded admission accounting for the production listener. Mirrors Python's
// BoundedSemaphore(16) exactly: sixteen holders, the seventeenth claim fails and
// the caller closes the connection without a response.
class ControlSlots {
public:
    explicit ControlSlots(std::size_t capacity = controlSlotLimit) : capacity_(capacity) {}
    bool tryAcquire();
    void release();
    std::size_t inUse() const { return inUse_.load(); }
    std::size_t capacity() const { return capacity_; }
private:
    std::size_t capacity_;
    std::atomic<std::size_t> inUse_{0};
};

//Answers every framed request until the transport closes. Returns 0; request-level
//failures are answered 403/404/501 and never kill the listener.
int serveControl(const ControlConfig &config, const ControlHooks &hooks, ControlTransport &transport);
// Full request policy for an already-admitted HTTP/1.x byte stream. Production
// TCP peer admission precedes slots and framing; POST rechecks its allowlist.
// Then method (non-POST 501), path 404, body/header bounds, deferred auth/dispatch.
ControlHttpResponse handleControlRequest(const ControlConfig &config, const ControlHooks &hooks,
                                         const std::string &raw, const std::string &peerAddress);
// Parses exactly one CRLF HTTP/1.x request with a bounded body. Throws on invalid framing.
ControlHttpRequest parseHttpRequest(const std::string &raw, const std::string &peerAddress);
std::string serializeResponse(const ControlHttpResponse &response);
} // namespace amnezia::awgMigration::controlPid1
