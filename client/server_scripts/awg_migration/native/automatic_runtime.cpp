#include "automatic_runtime.h"
#include "bounded_docker.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <set>
#include <sys/socket.h>
#include <unistd.h>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t frameLimit = 8 * 1024 * 1024;
constexpr std::size_t processLimit = 1024 * 1024;
[[noreturn]] void reject() { throw AutomaticRuntimeError("native_automatic_rejected"); }
struct UniqueKeys : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, UniqueKeys> {
    struct Frame { bool object; std::set<std::string> keys; };
    std::vector<Frame> stack;
    bool StartObject() { if (stack.size() >= 32) return false; stack.push_back({true, {}}); return true; }
    bool StartArray() { if (stack.size() >= 32) return false; stack.push_back({false, {}}); return true; }
    bool EndObject(rapidjson::SizeType) { if (stack.empty() || !stack.back().object) return false; stack.pop_back(); return true; }
    bool EndArray(rapidjson::SizeType) { if (stack.empty() || stack.back().object) return false; stack.pop_back(); return true; }
    bool Key(const char *s, rapidjson::SizeType length, bool) {
        if (stack.empty() || !stack.back().object) return false;
        std::string key(s, length);
        return key.find('\0') == std::string::npos && stack.back().keys.insert(std::move(key)).second;
    }
};
PlannerJson parse(const std::string &raw) {
    if (raw.empty() || raw.size() > frameLimit || raw.find('\0') != std::string::npos) reject();
    rapidjson::MemoryStream stream(raw.data(), raw.size());
    rapidjson::Reader reader;
    UniqueKeys keys;
    if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, keys)
        || !keys.stack.empty() || stream.Tell() != raw.size()) reject();
    auto tok = std::unique_ptr<json_tokener, decltype(&json_tokener_free)>(json_tokener_new_ex(32), json_tokener_free);
    if (!tok) reject();
    json_tokener_set_flags(tok.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    PlannerJson result(json_tokener_parse_ex(tok.get(), raw.data(), static_cast<int>(raw.size())));
    if (!result || json_tokener_get_error(tok.get()) != json_tokener_success
        || !json_object_is_type(result.get(), json_type_object)) reject();
    return result;
}
json_object *member(json_object *root, const char *key, json_type type) {
    json_object *value = nullptr;
    if (!root || !json_object_is_type(root, json_type_object)
        || !json_object_object_get_ex(root, key, &value) || !value || !json_object_is_type(value, type)) reject();
    return value;
}
void exact(json_object *root, std::set<std::string> keys) {
    json_object_object_foreach(root, key, value) { (void)value; if (!keys.erase(key)) reject(); }
    if (!keys.empty()) reject();
}
std::string text(json_object *root, const char *key, std::size_t limit, bool opaque = false) {
    auto *value = member(root, key, json_type_string);
    std::string out(json_object_get_string(value), static_cast<std::size_t>(json_object_get_string_len(value)));
    if (out.size() > limit || (!opaque && out.find('\0') != std::string::npos)) reject();
    return out;
}
unsigned portValue(json_object *value, unsigned minimum) {
    if (!value || !json_object_is_type(value, json_type_int)) reject();
    auto n = json_object_get_int64(value);
    if (n < minimum || n > 65535) reject();
    return static_cast<unsigned>(n);
}
bool hexId(const std::string &value) {
    return value.size() >= 12 && value.size() <= 64
        && std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9');
        });
}
void checkInventoryArgs(const ProcessArgs &args) {
    if (args == ProcessArgs{"ss", "-H", "-uan"} || args == ProcessArgs{"docker", "ps", "-q"}) return;
    if (args.size() < 3 || args.size() > 4098 || args[0] != "docker" || args[1] != "inspect") reject();
    for (std::size_t i = 2; i < args.size(); ++i) if (!hexId(args[i])) reject();
}
class CheckedRunner final : public ProcessRunner {
    ProcessRunner &source;
public:
    explicit CheckedRunner(ProcessRunner &r) : source(r) {}
    std::string run(const ProcessArgs &args) override {
        checkInventoryArgs(args);
        auto value = source.run(args);
        if (value.size() > processLimit) throw PlannerError("udp_inventory_unavailable");
        return value;
    }
};
class InventoryRunner final : public ProcessRunner {
public:
    std::string run(const ProcessArgs &args) override {
        checkInventoryArgs(args);
        if (args == ProcessArgs{"ss", "-H", "-uan"}) return runBoundedSs(processLimit);
        return runBoundedDocker(args, processLimit);
    }
};
class SystemLease final : public PortLease {
    int descriptor;
public:
    explicit SystemLease(UdpFamily family) : descriptor(::socket(family == UdpFamily::V4 ? AF_INET : AF_INET6,
                                                               SOCK_DGRAM | SOCK_CLOEXEC, 0)) {
        if (descriptor < 0) throw PlannerError("migration_udp_port_unavailable");
    }
    ~SystemLease() override { ::close(descriptor); }
    void ipv6Only() override {
        const int yes = 1;
        if (::setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof yes))
            throw PlannerError("migration_udp_port_unavailable");
    }
    void bind(const std::string &address, unsigned port) override {
        if (address == "0.0.0.0") {
            sockaddr_in v4{}; v4.sin_family = AF_INET; v4.sin_port = htons(static_cast<std::uint16_t>(port));
            if (::bind(descriptor, reinterpret_cast<const sockaddr *>(&v4), sizeof v4))
                throw PlannerError("migration_udp_port_unavailable");
        } else if (address == "::") {
            sockaddr_in6 v6{}; v6.sin6_family = AF_INET6; v6.sin6_port = htons(static_cast<std::uint16_t>(port));
            if (::bind(descriptor, reinterpret_cast<const sockaddr *>(&v6), sizeof v6))
                throw PlannerError("migration_udp_port_unavailable");
        } else reject();
    }
};
class SystemProbe final : public PortProbe {
public:
    std::unique_ptr<PortLease> open(UdpFamily family) override { return std::make_unique<SystemLease>(family); }
};
std::string readInput() {
    std::string input;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) reject();
        pollfd fd{STDIN_FILENO, POLLIN, 0};
        auto status = ::poll(&fd, 1, static_cast<int>(left));
        if (status < 0 && errno == EINTR) continue;
        if (status <= 0 || (fd.revents & (POLLNVAL | POLLERR))) reject();
        std::array<char, 8192> buffer{};
        auto count = ::read(STDIN_FILENO, buffer.data(), buffer.size());
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) reject();
        if (!count) return input;
        input.append(buffer.data(), static_cast<std::size_t>(count));
        if (input.size() > frameLimit) reject();
    }
}
}
std::string automaticRuntimeRequest(const std::string &raw, ProcessRunner &runner, PortProbe &probe) {
    auto request = parse(raw);
    const auto op = text(request.get(), "op", 32);
    PlannerJson value;
    if (op == "inventory") {
        exact(request.get(), {"op"});
        CheckedRunner checked(runner);
        value.reset(json_object_new_array());
        for (auto port : occupiedUdpPorts(checked)) json_object_array_add(value.get(), json_object_new_int64(port));
    } else if (op == "verify-port") {
        exact(request.get(), {"op", "port"});
        verifyAutomaticPort(portValue(member(request.get(), "port", json_type_int), 1024), probe);
        value.reset(json_object_new_boolean(true));
    } else if (op == "plan") {
        exact(request.get(), {"op", "root", "source", "host", "image", "raw", "sourcePort", "occupied"});
        const auto root = text(request.get(), "root", 4096), source = text(request.get(), "source", 32),
                   host = text(request.get(), "host", 253), image = text(request.get(), "image", 1024),
                   sourceRaw = text(request.get(), "raw", processLimit, true);
        const std::filesystem::path path(root);
        if (root.empty() || !path.is_absolute() || path.lexically_normal() != path
            || std::any_of(root.begin(), root.end(), [](unsigned char c) { return c < 32; })) reject();
        if (source != "amnezia-awg" && source != "amnezia-awg2") reject();
        const auto marker = image.find("@sha256:");
        if (marker == std::string::npos || marker == 0 || image.size() - marker != 72
            || !std::all_of(image.begin(), image.begin() + static_cast<std::ptrdiff_t>(marker), [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '/' || c == ':' || c == '_' || c == '-';
            }) || !hexId(image.substr(marker + 8)) || image.substr(marker + 8).size() != 64) reject();
        auto *ports = member(request.get(), "occupied", json_type_array);
        if (json_object_array_length(ports) > 65536) reject();
        UdpPorts occupied;
        for (std::size_t i = 0; i < json_object_array_length(ports); ++i)
            occupied.insert(portValue(json_object_array_get_idx(ports, i), 0));
        const auto result = automaticPlan(path, source, host, image, sourceRaw,
            portValue(member(request.get(), "sourcePort", json_type_int), 1), occupied);
        value = plannerJson(automaticRequestJson(result));
    } else reject();
    PlannerJson result(json_object_new_object());
    json_object_object_add(result.get(), "result", value.release());
    return json_object_to_json_string_ext(result.get(), JSON_C_TO_STRING_PLAIN);
}
int automaticJsonMain() {
    try {
        InventoryRunner runner;
        SystemProbe probe;
        std::cout << automaticRuntimeRequest(readInput(), runner, probe) << '\n';
        return 0;
    } catch (const PlannerError &error) {
        const std::set<std::string> codes = {"udp_inventory_unavailable", "migration_udp_port_unavailable",
            "migration_endpoint_unsupported", "migration_journal_conflict", "migration_ready_drift"};
        const std::string code = codes.count(error.code()) ? error.code() : "native_automatic_rejected";
        std::cout << "{\"error\":\"" << code << "\"}\n";
        return 2;
    } catch (...) {
        std::cout << "{\"error\":\"native_automatic_rejected\"}\n";
        return 2;
    }
}
}
