#include "control_runtime.h"
#include "control_service.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <iostream>
#include <json-c/json.h>
#include <memory>
#include <poll.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <set>
#include <stdexcept>
#include <unistd.h>
#include <vector>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t frameLimit = 256 * 1024;
constexpr std::size_t bodyLimit = 16384;
constexpr std::size_t outputLimit = 16 * 1024 * 1024;
[[noreturn]] void reject() { throw std::runtime_error("native_control_rejected"); }
using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;
Json own(json_object *value) {
    if (!value) reject();
    return Json(value, json_object_put);
}
struct UniqueKeys : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, UniqueKeys> {
    struct Frame { bool object; std::set<std::string> keys; };
    std::vector<Frame> stack;
    bool StartObject() { if (stack.size() >= 8) return false; stack.push_back({true, {}}); return true; }
    bool StartArray() { if (stack.size() >= 8) return false; stack.push_back({false, {}}); return true; }
    bool EndObject(rapidjson::SizeType) { if (stack.empty() || !stack.back().object) return false; stack.pop_back(); return true; }
    bool EndArray(rapidjson::SizeType) { if (stack.empty() || stack.back().object) return false; stack.pop_back(); return true; }
    bool Key(const char *value, rapidjson::SizeType length, bool) {
        if (stack.empty() || !stack.back().object) return false;
        std::string key(value, length);
        return key.find('\0') == std::string::npos && stack.back().keys.insert(std::move(key)).second;
    }
};
Json parse(const std::string &raw) {
    if (raw.size() > frameLimit || raw.find('\0') != std::string::npos) reject();
    rapidjson::MemoryStream stream(raw.data(), raw.size());
    rapidjson::Reader reader;
    UniqueKeys unique;
    if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, unique)
        || !unique.stack.empty() || stream.Tell() != raw.size()) reject();
    auto tok = std::unique_ptr<json_tokener, decltype(&json_tokener_free)>(json_tokener_new(), json_tokener_free);
    if (!tok) reject();
    json_tokener_set_flags(tok.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    auto root = own(json_tokener_parse_ex(tok.get(), raw.data(), static_cast<int>(raw.size())));
    if (json_tokener_get_error(tok.get()) != json_tokener_success
        || !json_object_is_type(root.get(), json_type_object)
        || json_object_object_length(root.get()) != 7) reject();
    const std::set<std::string> expected = {"role", "scope", "path", "peerAddress", "body", "headers", "authenticatedClient"};
    json_object_object_foreach(root.get(), key, value) {
        (void)value;
        if (!expected.count(key)) reject();
    }
    return root;
}
json_object *member(json_object *root, const char *key, json_type type) {
    json_object *value = nullptr;
    if (!json_object_object_get_ex(root, key, &value) || !value || !json_object_is_type(value, type)) reject();
    return value;
}
std::string text(json_object *root, const char *key, std::size_t limit, bool metadata = true) {
    auto *value = member(root, key, json_type_string);
    const std::string result(json_object_get_string(value), static_cast<std::size_t>(json_object_get_string_len(value)));
    if (result.size() > limit || (metadata && result.find('\0') != std::string::npos)) reject();
    return result;
}
void put(json_object *root, const char *key, Json value) {
    if (json_object_object_add(root, key, value.get()) != 0) reject();
    value.release();
}
Json string(const std::string &value) {
    return own(json_object_new_string_len(value.data(), static_cast<int>(value.size())));
}
std::string readInput() {
    std::string input;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) reject();
        pollfd descriptor{STDIN_FILENO, POLLIN, 0};
        const int ready = ::poll(&descriptor, 1, static_cast<int>(left));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || (descriptor.revents & (POLLNVAL | POLLERR))) reject();
        std::array<char, 8192> data{};
        const auto count = ::read(STDIN_FILENO, data.data(), data.size());
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) reject();
        if (!count) return input;
        input.append(data.data(), static_cast<std::size_t>(count));
        if (input.size() > frameLimit) reject();
    }
}
struct DeferredAuthentication final : std::runtime_error {
    DeferredAuthentication() : std::runtime_error("private callback deferred") {}
};
}

std::string controlRuntimeRequest(const std::string &raw, const std::filesystem::path &directory) {
    auto request = parse(raw);
    ControlOptions options;
    options.directory = directory;
    options.role = text(request.get(), "role", 6);
    options.scope = text(request.get(), "scope", 12);
    if ((options.role != "source" && options.role != "target")
        || (options.scope != "amnezia-awg" && options.scope != "amnezia-awg2")) reject();
    ControlRequest input;
    input.path = text(request.get(), "path", 65536);
    input.peerAddress = text(request.get(), "peerAddress", 64);
    input.body = text(request.get(), "body", bodyLimit, false);
    auto *headers = member(request.get(), "headers", json_type_object);
    json_object_object_foreach(headers, key, value) {
        (void)value;
        const std::string name(key);
        if (name != "content-length" && name != "transfer-encoding" && name != "x-amnezia-migration-grant") reject();
        input.headers.emplace(name, text(headers, key, 65536));
    }
    json_object *clientValue = nullptr;
    if (!json_object_object_get_ex(request.get(), "authenticatedClient", &clientValue)) reject();
    const bool deferred = clientValue == nullptr;
    std::string client;
    if (!deferred) {
        client = text(request.get(), "authenticatedClient", 64);
        if (client.size() != 64 || client.find_first_not_of("0123456789abcdef") != std::string::npos) reject();
    }
    bool authenticationRequired = false;
    const auto result = ControlService(std::move(options)).dispatch(input, [&]() -> std::string {
        if (deferred) {
            authenticationRequired = true;
            // Throw at the callback boundary; returning empty could compare equal
            // to malformed empty clientId state in renewal and permit a commit.
            throw DeferredAuthentication();
        }
        return client;
    });
    if ((result.status != 200 && result.status != 403)
        || (authenticationRequired && (!deferred || !result.handled || result.status != 403 || !result.body.empty()))) reject();
    auto output = own(json_object_new_object());
    put(output.get(), "handled", own(json_object_new_boolean(result.handled)));
    put(output.get(), "status", own(json_object_new_int(result.status)));
    put(output.get(), "body", string(result.body));
    put(output.get(), "authenticate", own(json_object_new_boolean(authenticationRequired)));
    auto response = own(json_object_new_object());
    put(response.get(), "result", std::move(output));
    const char *serialized = json_object_to_json_string_ext(response.get(), JSON_C_TO_STRING_PLAIN);
    if (!serialized) reject();
    std::string encoded(serialized);
    if (encoded.size() > outputLimit) reject();
    return encoded;
}

int controlJsonMain(const std::filesystem::path &directory) {
    try {
        std::cout << controlRuntimeRequest(readInput(), directory) << '\n';
        return 0;
    } catch (...) {
        std::cout << "{\"error\":\"native_control_rejected\"}\n";
        return 2;
    }
}
}
