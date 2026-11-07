#include "control_http.h"
#include "control_loaded.h"
#include "control_pid1.h"

#include <json-c/json.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace amnezia::awgMigration::controlPid1;

namespace {
int checks = 0;
void check(bool condition) {
    ++checks;
    if (!condition) {
        std::cerr << "check failed at " << checks << std::endl;
        throw std::runtime_error("check failed");
    }
}
void rejects(const std::function<void()> &action) {
    ++checks;
    try {
        action();
    } catch (const std::exception &) {
        return;
    }
    std::cerr << "expected rejection at check " << checks << std::endl;
    throw std::runtime_error("expected rejection");
}
std::string sha(const std::string &bytes) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> guard(ctx, EVP_MD_CTX_free);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1
        || EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) != 1
        || EVP_DigestFinal_ex(ctx, digest.data(), &length) != 1) throw std::runtime_error("sha");
    static const char *digits = "0123456789abcdef";
    std::string result;
    for (unsigned i = 0; i < length; ++i) {
        result.push_back(digits[digest[i] >> 4]);
        result.push_back(digits[digest[i] & 0x0f]);
    }
    return result;
}
void put16(std::string &raw, std::size_t at, unsigned value) {
    raw[at] = static_cast<char>(value & 0xff);
    raw[at + 1] = static_cast<char>((value >> 8) & 0xff);
}
void put32(std::string &raw, std::size_t at, unsigned value) {
    for (int i = 0; i < 4; ++i) raw[at + static_cast<std::size_t>(i)] = static_cast<char>((value >> (8 * i)) & 0xff);
}
void put64(std::string &raw, std::size_t at, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) raw[at + static_cast<std::size_t>(i)] = static_cast<char>((value >> (8 * i)) & 0xff);
}
// Minimal non-loadable ET_EXEC with one executable PT_LOAD covering the entry.
std::string elfFixture(unsigned machine = 62, unsigned type = 2, bool executable = true, unsigned kind = 1) {
    std::string raw(512, '\0');
    raw[0] = '\x7f'; raw[1] = 'E'; raw[2] = 'L'; raw[3] = 'F';
    raw[4] = 2; raw[5] = 1; raw[6] = 1; raw[7] = 0; raw[8] = 0;
    put16(raw, 16, type);
    put16(raw, 18, machine);
    put32(raw, 20, 1);
    put64(raw, 24, 0x1000);
    put64(raw, 32, 64);
    put16(raw, 52, 64);
    put16(raw, 54, 56);
    put16(raw, 56, 1);
    put32(raw, 64, kind);
    put32(raw, 68, executable ? 5u : 4u);
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
    bool extra = false;
    bool useAfter = false;
    FileIdentity after;
};
class FakeCapture : public CaptureOps {
public:
    std::map<int, FakeFile> files;
    int nextFd = 10, memfd = 100, nextMemfd = 100;
    bool failWrite = false, failSeal = false, failMode = false;
    std::vector<int> closed;
    int identifies = 0;
    std::string machineName = "x86_64";
    std::uint32_t uid = 1000;
    FileIdentity defaults(const std::string &bytes) {
        FileIdentity identity;
        identity.regular = true;
        identity.mode = 0100755;
        identity.uid = uid;
        identity.nlink = 1;
        identity.device = 7;
        identity.inode = 11;
        identity.size = bytes.size();
        identity.mtimeNs = 1000;
        identity.ctimeNs = 2000;
        return identity;
    }
    void add(int fd, const std::string &bytes) {
        FakeFile file;
        file.bytes = bytes;
        file.identity = defaults(bytes);
        files[fd] = file;
    }
    int openNoFollow(const std::filesystem::path &) override { return files.empty() ? -1 : nextFd; }
    FileIdentity identify(int fd) override {
        auto &file = files.at(fd);
        ++identifies;
        return file.useAfter && identifies > 1 ? file.after : file.identity;
    }
    std::string readChunk(int fd, std::size_t limit) override {
        auto &file = files.at(fd);
        const auto count = std::min(limit, file.bytes.size() - file.offset);
        std::string chunk = file.bytes.substr(file.offset, count);
        file.offset += count;
        return chunk;
    }
    bool hasExtraByte(int fd) override { return files.at(fd).extra; }
    int createSealedMemfd() override { return failSeal ? -1 : nextMemfd++; }
    bool writeAll(int fd, const std::string &bytes) override {
        (void)fd;
        (void)bytes;
        return !failWrite;
    }
    bool setMode0500(int fd) override {
        (void)fd;
        return !failMode;
    }
    bool sealAndVerify(int fd) override {
        (void)fd;
        return !failSeal;
    }
    std::uint32_t currentUid() override { return uid; }
    std::string machine() override { return machineName; }
    void close(int fd) override { closed.push_back(fd); }
};
class FakeSink : public ReceiptSink {
public:
    bool fail = false;
    int commits = 0;
    std::string role, bytes;
    void commit(const std::filesystem::path &, const std::string &value, const std::string &content) override {
        if (fail) throw std::runtime_error("native_control_rejected");
        ++commits;
        role = value;
        bytes = content;
    }
};
class FakeAttest : public AttestOps {
public:
    std::string start = "12345";
    FdAttestation value;
    std::string processStart() override { return start; }
    FdAttestation attest(int) override { return value; }
};
class FakeTransport : public ControlTransport {
public:
    struct Item {
        std::string raw;
        std::string framingError;
    };
    std::vector<Item> items;
    std::vector<ControlHttpResponse> responses;
    std::size_t index = 0;
    int used = 0;
    bool next(ControlHttpRequest &request, std::string &framingError) override {
        if (index >= items.size()) return false;
        ++used;
        const auto &item = items[index++];
        if (!item.framingError.empty()) {
            framingError = item.framingError;
            return true;
        }
        try {
            request = parseHttpRequest(item.raw, "10.0.0.9");
        } catch (...) {
            framingError = "malformed";
        }
        return true;
    }
    void respond(const ControlHttpResponse &response) override { responses.push_back(response); }
};

std::string request(const std::string &path, const std::string &body = "{}",
                    const std::string &extra = "", const std::string &peer = "10.0.0.9") {
    (void)peer;
    return "POST " + path + " HTTP/1.1\r\nHost: control\r\nContent-Length: " + std::to_string(body.size())
        + "\r\n" + extra + "\r\n" + body;
}
ControlHooks allowAll() {
    ControlHooks hooks;
    hooks.allowPeer = [](const std::string &) { return true; };
    hooks.authenticate = [](const std::string &, const std::string &, std::string &) { return false; };
    return hooks;
}
ControlConfig config() { return {"/migration", "target", "amnezia-awg"}; }

ExecutableImage captureFixture(FakeCapture &capture, std::string &elf) {
    elf = elfFixture();
    capture.add(capture.nextFd, elf);
    return captureExecutable("/app/awg-feed", sha(elf), capture);
}

void captureTests() {
    {
        FakeCapture capture;
        std::string elf;
        auto image = captureFixture(capture, elf);
        check(image.fd == 100);
        check(image.sha256 == sha(elf));
        check(image.elf.machine == 62 && image.elf.executableEntry);
        check(capture.closed.size() == 1 && capture.closed[0] == capture.nextFd);
    }
    const auto rejected = [](const std::string &bytes, const std::string &expected, auto mutate) {
        FakeCapture capture;
        capture.add(capture.nextFd, bytes);
        mutate(capture, capture.files[capture.nextFd]);
        rejects([&] { captureExecutable("/app/awg-feed", expected, capture); });
        check(capture.closed.size() == 1);
    };
    const auto good = elfFixture();
    const auto digest = sha(good);
    rejected(good, digest, [](FakeCapture &, FakeFile &f) { f.identity.mode = 0100700; });
    rejected(good, digest, [](FakeCapture &, FakeFile &f) { f.identity.nlink = 2; });
    rejected(good, digest, [](FakeCapture &, FakeFile &f) { f.identity.uid = 2000; });
    rejected(good, digest, [](FakeCapture &, FakeFile &f) { f.identity.regular = false; });
    rejected(good, digest, [](FakeCapture &, FakeFile &f) { f.identity.size = 63; });
    rejected(good, digest, [](FakeCapture &, FakeFile &f) { f.extra = true; });
    {
        FakeCapture capture;
        capture.add(capture.nextFd, good);
        capture.files[capture.nextFd].useAfter = true;
        capture.files[capture.nextFd].after = capture.files[capture.nextFd].identity;
        capture.files[capture.nextFd].after.ctimeNs = 9999;
        rejects([&] { captureExecutable("/app/awg-feed", digest, capture); });
        check(capture.closed.size() == 1);
    }
    rejected(good, sha("other"), [](FakeCapture &, FakeFile &) {});
    rejected("short", sha("short"), [](FakeCapture &, FakeFile &) {});
    rejected(elfFixture(183), sha(elfFixture(183)), [](FakeCapture &, FakeFile &) {});
    rejected(elfFixture(62, 3), sha(elfFixture(62, 3)), [](FakeCapture &, FakeFile &) {});
    rejected(elfFixture(62, 2, false), sha(elfFixture(62, 2, false)), [](FakeCapture &, FakeFile &) {});
    rejected(elfFixture(62, 2, true, 3), sha(elfFixture(62, 2, true, 3)), [](FakeCapture &, FakeFile &) {});
    {
        FakeCapture capture;
        capture.add(capture.nextFd, good);
        capture.failSeal = true;
        rejects([&] { captureExecutable("/app/awg-feed", digest, capture); });
    }
    {
        FakeCapture capture;
        capture.add(capture.nextFd, good);
        rejects([&] { captureExecutable("/app/awg-feed", std::string(64, 'A'), capture); });
    }
}

void receiptTests() {
    FakeAttest attest;
    attest.value = {true, 512, requiredSeals, std::string(64, 'a')};
    const std::string valid = receiptJson({"target", "12345", std::string(64, 'a'), 77});
    check(valid.find("\"kind\":\"native-control-http-v1\"") != std::string::npos);
    check(valid.find("\"protocol\":\"control-http-v1\"") != std::string::npos);
    verifyLoadedControl(valid, "target", std::string(64, 'a'), attest);
    rejects([&] { verifyLoadedControl(valid, "source", std::string(64, 'a'), attest); });
    rejects([&] { verifyLoadedControl(valid, "target", std::string(64, 'b'), attest); });
    {
        FakeAttest wrongStart = attest;
        wrongStart.start = "99999";
        rejects([&] { verifyLoadedControl(valid, "target", std::string(64, 'a'), wrongStart); });
        FakeAttest wrongSeal = attest;
        wrongSeal.value.seals = 0;
        rejects([&] { verifyLoadedControl(valid, "target", std::string(64, 'a'), wrongSeal); });
        FakeAttest notRegular = attest;
        notRegular.value.regular = false;
        rejects([&] { verifyLoadedControl(valid, "target", std::string(64, 'a'), notRegular); });
        FakeAttest badDigest = attest;
        badDigest.value.sha256 = std::string(64, 'c');
        rejects([&] { verifyLoadedControl(valid, "target", std::string(64, 'a'), badDigest); });
    }
    const std::string legacy = "{\"hashes\":{\"service.py\":\"" + std::string(64, 'a')
        + "\"},\"nativeControl\":{\"fd\":77,\"protocol\":\"control-json-v1\",\"sha256\":\""
        + std::string(64, 'a') + "\"},\"processStart\":\"12345\",\"role\":\"target\"}";
    bool unsupported = false;
    try {
        verifyLoadedControl(legacy, "target", std::string(64, 'a'), attest);
    } catch (const std::exception &error) {
        unsupported = std::string(error.what()) == "native_control_receipt_variant_unsupported";
    }
    check(unsupported);
    rejects([&] { verifyLoadedControl(valid + "x", "target", std::string(64, 'a'), attest); });
    rejects([&] { verifyLoadedControl(valid.substr(0, valid.size() - 1) + ",\"role\":\"target\"}", "target", std::string(64, 'a'), attest); });
    rejects([&] { receiptJson({"root", "12345", std::string(64, 'a'), 77}); });
    rejects([&] { receiptJson({"target", "", std::string(64, 'a'), 77}); });
    rejects([&] { receiptJson({"target", "12345", std::string(64, 'a'), 2}); });
}

void listenerTests() {
    {
        FakeTransport transport;
        transport.items.push_back({request("/migration/v1/native-control-capability"), ""});
        transport.items.push_back({request("/migration/v1/native-control-capability", "{}", "X-Amnezia-Migration-Grant: a\r\nX-Amnezia-Migration-Grant: b\r\n"), ""});
        transport.items.push_back({"", "malformed"});
        transport.items.push_back({request("/other"), ""});
        transport.items.push_back({request("/migration/v1/native-control-capability", "{}", "Transfer-Encoding: chunked\r\n"), ""});
        auto hooks = allowAll();
        int authCalls = 0;
        hooks.authenticate = [&](const std::string &, const std::string &, std::string &) {
            ++authCalls;
            return true;
        };
        check(serveControl(config(), hooks, transport) == 0);
        check(transport.responses.size() == 5);
        check(transport.responses[0].status == 403); // real dispatcher: unhandled
        check(transport.responses[1].status == 403);
        check(transport.responses[2].status == 403);
        check(transport.responses[3].status == 404);
        check(transport.responses[4].status == 403);
        check(authCalls == 0);
    }
    {
        FakeTransport transport;
        transport.items.push_back({request("/migration/v1/bootstrap", "{}",
            "X-Amnezia-Client-Id: " + std::string(64, 'a') + char(13) + char(10)
            + "X-Amnezia-Log-Token: secret" + char(13) + char(10)), ""});
        auto hooks = allowAll();
        int calls = 0;
        hooks.authenticate = [&](const std::string &client, const std::string &token, std::string &out) {
            ++calls;
            if (client == std::string(64, 'a') && token == "secret") {
                out = client;
                return true;
            }
            return false;
        };
        hooks.dispatch = [&](const std::string &frame, const std::filesystem::path &) {
            ++calls;
            const bool authenticated = frame.find("\"authenticatedClient\":\"") != std::string::npos;
            if (!authenticated) return std::string("{\"result\":{\"handled\":true,\"status\":403,\"body\":\"\",\"authenticate\":true}}");
            return std::string("{\"result\":{\"handled\":true,\"status\":200,\"body\":\"{}\",\"authenticate\":false}}");
        };
        check(serveControl(config(), hooks, transport) == 0);
        check(transport.responses.size() == 1);
        check(transport.responses[0].status == 200);
        check(calls == 3);
    }
    {
        FakeTransport transport;
        transport.items.push_back({request("/migration/v1/bootstrap", "{}", "X-Amnezia-Client-Id: " + std::string(64, 'a') + "\r\nX-Amnezia-Log-Token: secret\r\n"), ""});
        auto hooks = allowAll();
        hooks.allowPeer = [](const std::string &) { return false; };
        hooks.authenticate = [](const std::string &, const std::string &, std::string &out) {
            out = std::string(64, 'a');
            return true;
        };
        check(serveControl(config(), hooks, transport) == 0);
        check(transport.responses.size() == 1 && transport.responses[0].status == 403);
    }
    {
        FakeTransport transport;
        transport.items.push_back({request("/migration/v1/bootstrap", "{}", "X-Amnezia-Client-Id: " + std::string(64, 'a') + "\r\nX-Amnezia-Log-Token: secret\r\n"), ""});
        auto hooks = allowAll();
        hooks.authenticate = [](const std::string &, const std::string &, std::string &out) {
            out = std::string(64, 'a');
            return true;
        };
        hooks.dispatch = [](const std::string &frame, const std::filesystem::path &) {
            if (frame.find("\"authenticatedClient\":\"") == std::string::npos)
                return std::string("{\"result\":{\"handled\":true,\"status\":403,\"body\":\"\",\"authenticate\":true}}");
            return std::string("{\"result\":{\"handled\":true,\"status\":403,\"body\":\"\",\"authenticate\":true}}");
        };
        check(serveControl(config(), hooks, transport) == 0);
        check(transport.responses.size() == 1 && transport.responses[0].status == 403);
    }
    {
        // Python BaseHTTPRequestHandler has no do_GET/do_HEAD/do_PUT: every
        // non-POST method is answered 501 before path or peer/auth processing.
        FakeTransport transport;
        transport.items.push_back({"GET /migration/v1/bootstrap HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", ""});
        transport.items.push_back({"HEAD /migration/v2/nope HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", ""});
        transport.items.push_back({"PUT /migration/v1/bootstrap HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", ""});
        auto hooks = allowAll();
        int authCalls = 0, dispatched = 0;
        hooks.authenticate = [&](const std::string &, const std::string &, std::string &) {
            ++authCalls;
            return true;
        };
        hooks.dispatch = [&](const std::string &, const std::filesystem::path &) {
            ++dispatched;
            return std::string();
        };
        check(serveControl(config(), hooks, transport) == 0);
        check(transport.responses.size() == 3);
        check(transport.responses[0].status == 501);
        check(transport.responses[1].status == 501);
        check(transport.responses[2].status == 501);
        check(authCalls == 0 && dispatched == 0);
    }
    rejects([] { parseHttpRequest("POST /migration/v1/x HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "10.0.0.9"); });
    rejects([] { parseHttpRequest("POST /migration/v1/x HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}x", "10.0.0.9"); });
    rejects([] { parseHttpRequest("POST /migration/v1/x HTTP/1.1\r\nContent-Length: 16385\r\n\r\n", "10.0.0.9"); });
    check(parseHttpRequest(request("/migration/v1/x", "{}"), "10.0.0.9").body == "{}");
}

void entrypointTests() {
    {
        FakeCapture capture;
        std::string elf;
        elf = elfFixture();
        capture.add(capture.nextFd, elf);
        FakeSink sink;
        FakeTransport transport;
        transport.items.push_back({request("/migration/v1/native-control-capability"), ""});
        ControlPid1Deps deps{capture, sink, transport, [] { return std::string("12345"); }, allowAll()};
        ControlPid1Config value{"/app/awg-feed", "/migration", sha(elf), "target", "amnezia-awg"};
        check(controlPid1Run(value, deps) == 0);
        check(sink.commits == 1 && sink.role == "target");
        check(transport.responses.size() == 1 && transport.responses[0].status == 403);
        FakeAttest attest;
        attest.value = {true, 512, requiredSeals, sha(elf)};
        verifyLoadedControl(sink.bytes, "target", sha(elf), attest);
    }
    {
        FakeCapture capture;
        FakeSink sink;
        FakeTransport transport;
        ControlPid1Deps deps{capture, sink, transport, [] { return std::string("12345"); }, allowAll()};
        ControlPid1Config value{"/app/awg-feed", "/migration", std::string(64, 'a'), "target", "amnezia-awg"};
        check(controlPid1Run(value, deps) == 2);
        check(sink.commits == 0 && transport.used == 0 && capture.closed.empty());
    }
    {
        FakeCapture capture;
        std::string elf;
        capture.add(capture.nextFd, elfFixture());
        FakeSink sink;
        sink.fail = true;
        FakeTransport transport;
        ControlPid1Deps deps{capture, sink, transport, [] { return std::string("12345"); }, allowAll()};
        ControlPid1Config value{"/app/awg-feed", "/migration", sha(elfFixture()), "target", "amnezia-awg"};
        check(controlPid1Run(value, deps) == 2);
        check(capture.closed.size() == 2 && capture.closed[1] == 100);
        check(transport.used == 0);
    }
    {
        FakeCapture capture;
        FakeSink sink;
        FakeTransport transport;
        ControlPid1Deps deps{capture, sink, transport, [] { return std::string("12345"); }, allowAll()};
        ControlPid1Config value{"/app/awg-feed", "/migration", std::string(64, 'a'), "root", "amnezia-awg"};
        check(controlPid1Run(value, deps) == 2);
        check(sink.commits == 0);
    }
}
void boundaryTests() {
    // Python BoundedSemaphore(16): exactly sixteen concurrent admissions.
    ControlSlots slots;
    check(slots.capacity() == controlSlotLimit && slots.capacity() == 16);
    check(slots.inUse() == 0);
    for (std::size_t index = 0; index < controlSlotLimit; ++index) check(slots.tryAcquire());
    check(slots.inUse() == 16);
    check(!slots.tryAcquire());
    check(slots.inUse() == 16);
    slots.release();
    check(slots.inUse() == 15 && slots.tryAcquire() && slots.inUse() == 16);
    for (std::size_t index = 0; index < controlSlotLimit; ++index) slots.release();
    check(slots.inUse() == 0);
    rejects([] { ControlSlots none(0); none.release(); });
    // Non-POST policy is reachable through both the raw framer and the runner.
    check(handleControlRequest(config(), allowAll(),
        "DELETE /migration/v1/x HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", "10.0.0.9").status == 501);
    check(handleControlRequest(config(), allowAll(),
        "POST /migration/v2/nope HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", "10.0.0.9").status == 404);
    check(serializeResponse({501, ""}).find("HTTP/1.1 501 Not Implemented\r\n") == 0);
}

void argvTests() {
    const auto arg = [](const std::string &value) {
        std::vector<char> bytes(value.begin(), value.end());
        bytes.push_back('\0');
        return bytes;
    };
    auto program = arg("awg-feed"), control = arg("--control-pid1"), verify = arg("--verify-control-loaded");
    auto roleArg = arg("target"), digestArg = arg(std::string(64, 'a')), pathArg = arg("/migration/control-loaded-target.json");
    std::string role, digest, path;
    {
        char *args[] = {program.data(), control.data()};
        check(parseNativeControlArgv(2, args, role, digest, path) == NativeArgv::ControlPid1);
    }
    {
        char *args[] = {program.data(), control.data(), control.data()};
        check(parseNativeControlArgv(3, args, role, digest, path) == NativeArgv::Invalid);
    }
    {
        char *args[] = {program.data(), verify.data(), roleArg.data(), digestArg.data(), pathArg.data()};
        check(parseNativeControlArgv(5, args, role, digest, path) == NativeArgv::VerifyLoaded);
        check(role == "target" && digest == std::string(64, 'a') && path == "/migration/control-loaded-target.json");
    }
    {
        char *args[] = {program.data(), verify.data(), roleArg.data(), digestArg.data()};
        check(parseNativeControlArgv(4, args, role, digest, path) == NativeArgv::Invalid);
    }
    {
        auto badRole = arg("root");
        char *args[] = {program.data(), verify.data(), badRole.data(), digestArg.data(), pathArg.data()};
        check(parseNativeControlArgv(5, args, role, digest, path) == NativeArgv::Invalid);
    }
    {
        char *onlyProgram[] = {program.data()};
        check(parseNativeControlArgv(1, onlyProgram, role, digest, path) == NativeArgv::NotNative);
        auto serveArg = arg("--serve");
        char *serve[] = {program.data(), serveArg.data()};
        check(parseNativeControlArgv(2, serve, role, digest, path) == NativeArgv::NotNative);
    }
    // Usage failures are decided before any filesystem/proc access.
    check(verifyLoadedControlMain("root", std::string(64, 'a'), "/migration/x") == 2);
    check(verifyLoadedControlMain("target", std::string(63, 'a'), "/migration/x") == 2);
    check(verifyLoadedControlMain("target", std::string(64, 'A'), "/migration/x") == 2);
    check(verifyLoadedControlMain("target", std::string(64, 'a'), "") == 2);
}
} // namespace

int main() {
    try {
        captureTests();
        receiptTests();
        listenerTests();
        entrypointTests();
        boundaryTests();
        argvTests();
        std::cout << "control pid1 inert checks: " << checks << '\n';
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "control pid1 inert failure: " << error.what() << '\n';
        return 1;
    }
}
