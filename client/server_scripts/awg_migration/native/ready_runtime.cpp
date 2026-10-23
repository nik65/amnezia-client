#include "ready_runtime.h"
#include "bounded_docker.h"
#include "ready_attestation.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <poll.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <set>
#include <unistd.h>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t frameLimit = 16 * 1024 * 1024;
constexpr std::size_t configLimit = 1024 * 1024;
[[noreturn]] void reject() { throw ReadyRuntimeError("native_ready_rejected"); }
[[noreturn]] void identityDrift() { throw ReadyRuntimeError("native_ready_identity_drift"); }
[[noreturn]] void notObserved() { throw ReadyRuntimeError("native_ready_not_observed"); }

struct UniqueKeys : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, UniqueKeys> {
    struct Frame { bool object; std::set<std::string> keys; };
    std::vector<Frame> stack;
    bool StartObject() { if (stack.size() >= 32) return false; stack.push_back({true, {}}); return true; }
    bool StartArray() { if (stack.size() >= 32) return false; stack.push_back({false, {}}); return true; }
    bool EndObject(rapidjson::SizeType) { if (stack.empty() || !stack.back().object) return false; stack.pop_back(); return true; }
    bool EndArray(rapidjson::SizeType) { if (stack.empty() || stack.back().object) return false; stack.pop_back(); return true; }
    bool Key(const char *s, rapidjson::SizeType size, bool) {
        if (stack.empty() || !stack.back().object) return false;
        std::string key(s, size);
        return key.find('\0') == std::string::npos && stack.back().keys.insert(std::move(key)).second;
    }
};
PlannerJson parse(const std::string &raw, std::size_t limit) {
    if (raw.size() > limit || raw.find('\0') != std::string::npos) reject();
    rapidjson::MemoryStream stream(raw.data(), raw.size());
    rapidjson::Reader reader;
    UniqueKeys keys;
    if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, keys) || !keys.stack.empty()
        || stream.Tell() != raw.size()) reject();
    auto tok = std::unique_ptr<json_tokener, decltype(&json_tokener_free)>(json_tokener_new(), json_tokener_free);
    if (!tok) reject();
    json_tokener_set_flags(tok.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    PlannerJson root(json_tokener_parse_ex(tok.get(), raw.data(), static_cast<int>(raw.size())));
    if (json_tokener_get_error(tok.get()) != json_tokener_success || !root
        || !json_object_is_type(root.get(), json_type_object)) reject();
    return root;
}
json_object *member(json_object *root, const char *key, json_type type) {
    json_object *out = nullptr;
    if (!root || !json_object_is_type(root, json_type_object)
        || !json_object_object_get_ex(root, key, &out) || !out || !json_object_is_type(out, type)) reject();
    return out;
}
void exact(json_object *root, std::set<std::string> keys) {
    if (!root || !json_object_is_type(root, json_type_object)) reject();
    json_object_object_foreach(root, key, value) { (void)value; if (!keys.erase(key)) reject(); }
    if (!keys.empty()) reject();
}
std::string text(json_object *root, const char *key, bool opaque = false) {
    auto *value = member(root, key, json_type_string);
    std::string out(json_object_get_string(value), static_cast<std::size_t>(json_object_get_string_len(value)));
    if (!opaque && out.find('\0') != std::string::npos) reject();
    return out;
}
bool hex(const std::string &s, std::size_t count) {
    return s.size() == count && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
bool name(const std::string &s) {
    const std::string prefix = "/amnezia-awg";
    if (s.compare(0, prefix.size(), prefix)) return false;
    std::size_t at = prefix.size();
    if (at < s.size() && s[at] == '2') ++at;
    const std::string middle = "-migration-";
    if (s.compare(at, middle.size(), middle)) return false;
    at += middle.size();
    if (at == s.size() || s[at] == '0' || s.size() - at > 16) return false;
    std::uint64_t generation = 0;
    for (; at < s.size(); ++at) {
        const unsigned char c = s[at];
        if (c < '0' || c > '9') return false;
        generation = generation * 10 + (c - '0');
    }
    return generation <= 9007199254740991ULL;
}
struct Expected { std::string id, name, image, owner, startedAt; };
Expected expected(json_object *v) {
    exact(v, {"id", "name", "image", "owner", "startedAt"});
    Expected e{text(v, "id"), text(v, "name"), text(v, "image"), text(v, "owner"), text(v, "startedAt")};
    if (!hex(e.id, 64) || !name(e.name) || e.image.compare(0, 7, "sha256:") || !hex(e.image.substr(7), 64)
        || !hex(e.owner, 32) || e.startedAt.empty() || e.startedAt.size() > 128
        || std::any_of(e.startedAt.begin(), e.startedAt.end(), [](unsigned char c) { return c < 32 || c >= 127; })) reject();
    return e;
}
std::size_t commandLimit(const ProcessArgs &args, const std::string &id) {
    if (!hex(id, 64)) reject();
    if (args == ProcessArgs{"docker", "inspect", "--format", ReadyInspectFormat, id}) return configLimit;
    if (args == ProcessArgs{"docker", "exec", id, "awg", "show", "awg0", "dump"}
        || args == ProcessArgs{"docker", "exec", id, "awg", "showconf", "awg0"}) return frameLimit;
    if (args == ProcessArgs{"docker", "exec", id, "sh", "-c", ReadyEngineProbe}) return 4096;
    reject();
}
class CheckedRunner final : public ProcessRunner {
    ProcessRunner &underlying;
    std::string id;
public:
    CheckedRunner(ProcessRunner &r, std::string pinned) : underlying(r), id(std::move(pinned)) {}
    std::string run(const ProcessArgs &args) override {
        const auto limit = commandLimit(args, id);
        try {
            auto output = underlying.run(args);
            if (output.size() > limit) notObserved();
            return output;
        } catch (const ReadyRuntimeError &) { throw; }
        catch (...) { notObserved(); }
    }
};
class DockerRunner final : public ProcessRunner {
public:
    std::string run(const ProcessArgs &args) override {
        std::string id;
        if (args.size() == 5 && args[1] == "inspect") id = args[4];
        else if (args.size() >= 3 && args[1] == "exec") id = args[2];
        const auto limit = commandLimit(args, id);
        try { return runBoundedDocker(args, limit); }
        catch (const BoundedDockerError &) { notObserved(); }
    }
};
void observe(CheckedRunner &run, const Expected &e) {
    const auto output = run.run({"docker", "inspect", "--format", ReadyInspectFormat, e.id});
    PlannerJson observed;
    try {
        observed = parse(output, configLimit);
        exact(observed.get(), {"id", "name", "image", "owner", "running", "startedAt"});
        if (text(observed.get(), "id") != e.id || text(observed.get(), "name") != e.name
            || text(observed.get(), "image") != e.image || text(observed.get(), "owner") != e.owner
            || text(observed.get(), "startedAt") != e.startedAt
            || !json_object_get_boolean(member(observed.get(), "running", json_type_boolean))) identityDrift();
    } catch (const ReadyRuntimeError &) { identityDrift(); }
}
std::string readInput() {
    std::string input;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (true) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) reject();
        pollfd fd {STDIN_FILENO, POLLIN, 0};
        const int ready = ::poll(&fd, 1, static_cast<int>(left));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || fd.revents & (POLLNVAL | POLLERR)) reject();
        std::array<char, 8192> data{};
        const auto count = ::read(STDIN_FILENO, data.data(), data.size());
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) reject();
        if (!count) return input;
        input.append(data.data(), static_cast<std::size_t>(count));
        if (input.size() > frameLimit) reject();
    }
}
}
std::string readyRuntimeRequest(const std::string &raw, ProcessRunner &runner) {
    auto root = parse(raw, frameLimit);
    exact(root.get(), {"source", "target", "ready", "expected", "automatic"});
    const auto sourceRaw = text(root.get(), "source", true), targetRaw = text(root.get(), "target", true);
    if (sourceRaw.size() > configLimit || targetRaw.size() > configLimit) reject();
    ReadyConfig source, target;
    try { source = parseConfig(sourceRaw); target = parseConfig(targetRaw); }
    catch (const ConfigError &) { reject(); }
    const auto e = expected(member(root.get(), "expected", json_type_object));
    auto *state = member(root.get(), "ready", json_type_object);
    exact(state, {"targetContainer", "serverPublicKey", "parameters"});
    if (text(state, "targetContainer") != e.id) reject();
    const auto key = text(state, "serverPublicKey");
    if (key.size() != 44 || key.back() != '=' || key.substr(0, 43).find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") != std::string::npos) reject();
    auto *params = member(state, "parameters", json_type_object);
    // This runtime command attests a newly prepared generation, not arbitrary
    // legacy parameter subsets. Every declared capability must be observed.
    exact(params, {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
        "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
        "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"});
    json_object_object_foreach(params, k, value) {
        (void)k;
        if (!value || !json_object_is_type(value, json_type_string)) reject();
        const std::string v(json_object_get_string(value), static_cast<std::size_t>(json_object_get_string_len(value)));
        if (v.find('\0') != std::string::npos) reject();
    }
    const bool automatic = json_object_get_boolean(member(root.get(), "automatic", json_type_boolean));
    CheckedRunner checked(runner, e.id);
    observe(checked, e);
    try { validateReadyTarget(checked, state, source, target, automatic); }
    catch (const ConfigError &) { throw ReadyRuntimeError("migration_ready_drift"); }
    observe(checked, e);
    return "{\"result\":true}";
}
int readyJsonMain() {
    try {
        DockerRunner runner;
        std::cout << readyRuntimeRequest(readInput(), runner) << '\n';
        return 0;
    } catch (const ReadyRuntimeError &error) {
        const std::set<std::string> allowed = {"migration_ready_drift", "native_ready_not_observed", "native_ready_identity_drift", "native_ready_rejected"};
        const std::string code = allowed.count(error.what()) ? error.what() : "native_ready_rejected";
        std::cout << "{\"error\":\"" << code << "\"}\n";
        return 2;
    } catch (...) {
        std::cout << "{\"error\":\"native_ready_rejected\"}\n";
        return 2;
    }
}
}
