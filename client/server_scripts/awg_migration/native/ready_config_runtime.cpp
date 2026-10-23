#include "ready_config_runtime.h"
#include "ready_config.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <iostream>
#include <json-c/json.h>
#include <memory>
#include <poll.h>
#include <set>
#include <unistd.h>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t inputLimit = 1024 * 1024;
constexpr std::size_t outputLimit = 8 * 1024 * 1024;
using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;

[[noreturn]] void reject() { throw ConfigError("native_config_rejected"); }
Json own(json_object *value) {
    if (!value) reject();
    return Json(value, json_object_put);
}
void put(json_object *object, const char *key, Json value) {
    if (json_object_object_add(object, key, value.get()) != 0) reject();
    value.release();
}
Json fields(const ConfigFields &values) {
    auto object = own(json_object_new_object());
    for (const auto &entry : values)
        put(object.get(), entry.first.c_str(), own(json_object_new_string_len(
            entry.second.data(), static_cast<int>(entry.second.size()))));
    return object;
}
std::string serialize(json_object *value) {
    const char *text = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
    if (!text) reject();
    std::string result(text);
    if (result.size() > outputLimit) reject();
    return result;
}
std::string errorResponse(const std::string &code) {
    const std::set<std::string> allowed = {
        "invalid UTF-8", "missing field", "configuration address", "duplicate interface",
        "configuration syntax", "duplicate configuration key", "missing identity",
        "unknown interface key", "only IPv4 isolation supported", "unsupported peer field",
        "peer identity", "PSK", "ambiguous peer route", "duplicate peer address"
    };
    auto output = own(json_object_new_object());
    const std::string selected = allowed.count(code) ? code : "native_config_rejected";
    put(output.get(), "error", own(json_object_new_string(selected.c_str())));
    return serialize(output.get());
}
std::string readInput() {
    std::string input;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (true) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) reject();
        pollfd descriptor { STDIN_FILENO, POLLIN, 0 };
        const int result = ::poll(&descriptor, 1, static_cast<int>(remaining));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || descriptor.revents & (POLLNVAL | POLLERR)) reject();
        std::array<char, 8192> buffer {};
        const auto size = ::read(STDIN_FILENO, buffer.data(), buffer.size());
        if (size < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (size < 0) reject();
        if (size == 0) return input;
        input.append(buffer.data(), static_cast<std::size_t>(size));
        if (input.size() > inputLimit) reject();
    }
}
}

std::string configRuntimeRequest(const std::string &raw) {
    if (raw.size() > inputLimit) reject();
    const auto config = parseConfig(raw);
    auto result = own(json_object_new_object());
    put(result.get(), "interface", fields(config.Interface));
    auto peers = own(json_object_new_array());
    for (const auto &entry : config.Peers) {
        auto peer = fields(entry);
        if (json_object_array_add(peers.get(), peer.get()) != 0) reject();
        peer.release();
    }
    put(result.get(), "peers", std::move(peers));
    auto response = own(json_object_new_object());
    put(response.get(), "result", std::move(result));
    return serialize(response.get());
}

int configJsonMain() {
    try {
        std::cout << configRuntimeRequest(readInput()) << '\n';
        return 0;
    } catch (const ConfigError &error) {
        try { std::cout << errorResponse(error.code()) << '\n'; }
        catch (...) { std::cout << "{\"error\":\"native_config_rejected\"}\n"; }
        return 2;
    } catch (...) {
        std::cout << "{\"error\":\"native_config_rejected\"}\n";
        return 2;
    }
}
}
