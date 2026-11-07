#include "control_http.h"

#include "control_runtime.h"

#include <json-c/json.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <memory>
#include <set>
#include <stdexcept>

namespace amnezia::awgMigration::controlPid1 {
namespace {
constexpr std::size_t headerLimit = 16 * 1024;
constexpr std::size_t bodyLimit = 16384;
constexpr std::size_t outputLimit = 8 * 1024 * 1024;
constexpr std::size_t headerCountLimit = 100;
const std::set<std::string> framedHeaders = {"content-length", "transfer-encoding", "x-amnezia-migration-grant"};

[[noreturn]] void reject() { throw std::runtime_error("native_control_rejected"); }
using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;
Json own(json_object *value) {
    if (!value) reject();
    return Json(value, json_object_put);
}
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return value;
}
bool validName(const std::string &name) {
    if (name.empty() || name.size() > 64) return false;
    for (const unsigned char character : name) {
        if (!std::isalnum(character) && character != '-' && character != '_') return false;
    }
    return true;
}
std::string trim(const std::string &value) {
    std::size_t begin = 0, end = value.size();
    while (begin < end && (value[begin] == ' ' || value[begin] == '\t')) ++begin;
    while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t')) --end;
    return value.substr(begin, end - begin);
}
bool decimal(const std::string &value, std::size_t &result) {
    if (value.empty() || value.size() > 6 || value.find_first_not_of("0123456789") != std::string::npos) return false;
    result = 0;
    for (const char digit : value) result = result * 10 + static_cast<std::size_t>(digit - '0');
    return true;
}

struct ParsedResult {
    bool handled = false;
    int status = 403;
    std::string body;
    bool authenticate = false;
};
ParsedResult parseResult(const std::string &raw) {
    if (raw.empty() || raw.size() > outputLimit + 4096) reject();
    auto tok = std::unique_ptr<json_tokener, decltype(&json_tokener_free)>(json_tokener_new(), json_tokener_free);
    if (!tok) reject();
    json_tokener_set_flags(tok.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    auto root = own(json_tokener_parse_ex(tok.get(), raw.data(), static_cast<int>(raw.size())));
    if (json_tokener_get_error(tok.get()) != json_tokener_success || raw.find('\0') != std::string::npos
        || !json_object_is_type(root.get(), json_type_object) || json_object_object_length(root.get()) != 1) reject();
    json_object *value = nullptr;
    if (!json_object_object_get_ex(root.get(), "result", &value) || !value
        || !json_object_is_type(value, json_type_object) || json_object_object_length(value) != 4) reject();
    const std::set<std::string> keys = {"handled", "status", "body", "authenticate"};
    {
        json_object_object_foreach(value, key, unused) {
            (void)unused;
            if (!keys.count(key)) reject();
        }
    }
    json_object *handled = nullptr, *status = nullptr, *body = nullptr, *authenticate = nullptr;
    if (!json_object_object_get_ex(value, "handled", &handled) || !handled || !json_object_is_type(handled, json_type_boolean)
        || !json_object_object_get_ex(value, "authenticate", &authenticate) || !authenticate
        || !json_object_is_type(authenticate, json_type_boolean)
        || !json_object_object_get_ex(value, "status", &status) || !status || !json_object_is_type(status, json_type_int)
        || !json_object_object_get_ex(value, "body", &body) || !body || !json_object_is_type(body, json_type_string)) reject();
    ParsedResult result;
    result.handled = json_object_get_boolean(handled) != 0;
    result.authenticate = json_object_get_boolean(authenticate) != 0;
    result.status = json_object_get_int(status);
    result.body.assign(json_object_get_string(body), static_cast<std::size_t>(json_object_get_string_len(body)));
    if ((result.status != 200 && result.status != 403) || result.body.size() > outputLimit) reject();
    if (result.authenticate && (!result.handled || result.status != 403 || !result.body.empty())) reject();
    if (result.status == 403 && !result.body.empty()) reject();
    if (!result.handled && (!result.body.empty() || result.authenticate || result.status != 403)) reject();
    return result;
}

std::string frame(const ControlConfig &config, const ControlHttpRequest &request,
                  const std::map<std::string, std::string> &headers, const std::string *client) {
    auto root = own(json_object_new_object());
    if (json_object_object_add(root.get(), "role", json_object_new_string(config.role.c_str())) != 0
        || json_object_object_add(root.get(), "scope", json_object_new_string(config.scope.c_str())) != 0
        || json_object_object_add(root.get(), "path", json_object_new_string_len(request.target.data(), static_cast<int>(request.target.size()))) != 0
        || json_object_object_add(root.get(), "peerAddress", json_object_new_string(request.peerAddress.c_str())) != 0) reject();
    auto values = own(json_object_new_object());
    for (const auto &entry : headers) {
        if (json_object_object_add(values.get(), entry.first.c_str(),
                                   json_object_new_string_len(entry.second.data(), static_cast<int>(entry.second.size()))) != 0) reject();
    }
    if (json_object_object_add(root.get(), "headers", values.get()) != 0) reject();
    values.release();
    if (json_object_object_add(root.get(), "body", json_object_new_string_len(request.body.data(), static_cast<int>(request.body.size()))) != 0) reject();
    if (client) {
        if (json_object_object_add(root.get(), "authenticatedClient", json_object_new_string(client->c_str())) != 0) reject();
    } else if (json_object_object_add(root.get(), "authenticatedClient", nullptr) != 0) reject();
    const char *serialized = json_object_to_json_string_ext(root.get(), JSON_C_TO_STRING_PLAIN);
    if (!serialized) reject();
    std::string encoded(serialized);
    if (encoded.size() > 256 * 1024) reject();
    return encoded;
}
} // namespace

ControlHttpRequest parseHttpRequest(const std::string &raw, const std::string &peerAddress) {
    const auto split = raw.find("\r\n\r\n");
    if (split == std::string::npos || split > headerLimit) reject();
    const std::string head = raw.substr(0, split);
    const std::string body = raw.substr(split + 4);
    const auto lineEnd = head.find("\r\n");
    const std::string requestLine = head.substr(0, lineEnd == std::string::npos ? head.size() : lineEnd);
    const auto first = requestLine.find(' ');
    const auto second = first == std::string::npos ? std::string::npos : requestLine.find(' ', first + 1);
    if (first == std::string::npos || second == std::string::npos || requestLine.find(' ', second + 1) != std::string::npos) reject();
    ControlHttpRequest request;
    request.method = requestLine.substr(0, first);
    request.target = requestLine.substr(first + 1, second - first - 1);
    const std::string version = requestLine.substr(second + 1);
    if (request.method.empty() || request.method.size() > 16 || request.target.empty()
        || request.target[0] != '/' || request.target.find_first_of(" \t") != std::string::npos
        || (version != "HTTP/1.1" && version != "HTTP/1.0")) reject();
    request.peerAddress = peerAddress;
    std::size_t position = lineEnd == std::string::npos ? head.size() : lineEnd + 2;
    std::size_t count = 0;
    std::map<std::string, std::string> auth;
    while (position < head.size()) {
        const auto end = head.find("\r\n", position);
        const std::string line = head.substr(position, end == std::string::npos ? std::string::npos : end - position);
        position = end == std::string::npos ? head.size() : end + 2;
        if (line.empty() || line[0] == ' ' || line[0] == '\t') reject();
        const auto colon = line.find(':');
        if (colon == std::string::npos) reject();
        const std::string name = lower(line.substr(0, colon));
        if (!validName(name)) reject();
        const std::string value = trim(line.substr(colon + 1));
        if (value.find('\0') != std::string::npos) reject();
        if (++count > headerCountLimit) reject();
        if (name == "x-amnezia-client-id" || name == "x-amnezia-log-token") {
            if (auth.count(name)) reject();
            auth.emplace(name, value);
            continue;
        }
        request.headers.emplace_back(name, value);
    }
    request.clientId = auth.count("x-amnezia-client-id") ? auth["x-amnezia-client-id"] : "";
    request.logToken = auth.count("x-amnezia-log-token") ? auth["x-amnezia-log-token"] : "";
    // BaseHTTPRequestHandler does not read a body for unsupported methods, and
    // MigrationService.dispatch returns outside-prefix 404 before body framing.
    if (request.method != "POST" || request.target.rfind("/migration/v1/", 0) != 0)
        return request;
    if (body.size() > bodyLimit) reject();
    std::map<std::string, std::string> framed;
    for (const auto &header : request.headers) {
        if (!framedHeaders.count(header.first)) continue;
        if (framed.count(header.first)) reject();
        framed.emplace(header.first, header.second);
    }
    if (framed.count("transfer-encoding")) reject();
    if (!framed.count("content-length")) reject();
    std::size_t declared = 0;
    if (!decimal(framed["content-length"], declared) || declared == 0 || declared > bodyLimit
        || declared != body.size()) reject();
    request.body = body;
    return request;
}

namespace {
// Policy for one strictly framed request. Kept separate from byte framing so the
// transport runner and the pooled POSIX listener share the exact same order.
ControlHttpResponse dispatchFramed(const ControlConfig &config, const ControlHooks &hooks,
                                   const ControlHttpRequest &request) {
    // Python http.server answers unsupported methods 501 before path, peer and
    // authentication processing. Only POST has a handler in target.py.
    if (request.method != "POST") return {501, ""};
    if (request.target.rfind("/migration/v1/", 0) != 0) return {404, ""};
    if (!hooks.allowPeer || !hooks.allowPeer(request.peerAddress)) return {403, ""};
    const auto dispatcher = hooks.dispatch ? hooks.dispatch : [](const std::string &raw, const std::filesystem::path &directory) {
        return controlRuntimeRequest(raw, directory);
    };
    try {
        std::map<std::string, std::string> headers;
        for (const auto &header : request.headers) {
            if (!framedHeaders.count(header.first)) continue;
            if (headers.count(header.first)) reject();
            headers.emplace(header.first, header.second);
        }
        if (headers.count("transfer-encoding") || !headers.count("content-length")) reject();
        std::size_t declared = 0;
        if (!decimal(headers["content-length"], declared) || declared == 0 || declared > bodyLimit
            || declared != request.body.size()) reject();
        auto result = parseResult(dispatcher(frame(config, request, headers, nullptr), config.directory));
        if (result.authenticate) {
            std::string client;
            if (!hooks.authenticate || !hooks.authenticate(request.clientId, request.logToken, client)
                || client.size() != 64 || client.find_first_not_of("0123456789abcdef") != std::string::npos) {
                return {403, ""};
            }
            result = parseResult(dispatcher(frame(config, request, headers, &client), config.directory));
            if (result.authenticate) return {403, ""};
        }
        if (result.handled && result.status == 200) return {200, result.body};
        return {403, ""};
    } catch (...) {
        return {403, ""};
    }
}
} // namespace

ControlHttpResponse handleControlRequest(const ControlConfig &config, const ControlHooks &hooks,
                                         const std::string &raw, const std::string &peerAddress) {
    try {
        return dispatchFramed(config, hooks, parseHttpRequest(raw, peerAddress));
    } catch (...) {
        return {403, ""};
    }
}

int serveControl(const ControlConfig &config, const ControlHooks &hooks, ControlTransport &transport) {
    transport.setPeerAdmission(hooks.allowPeer);
    const ControlRequestHandler handler = [&](const ControlHttpRequest &request) {
        return dispatchFramed(config, hooks, request);
    };
    // The production pool resolves this and runs framing, dispatch and response
    // on controlSlotLimit worker threads; scripted transports keep the loop below.
    if (const auto pooled = transport.serveConcurrently(handler)) return *pooled;
    for (;;) {
        ControlHttpRequest request;
        std::string framingError;
        if (!transport.next(request, framingError)) return 0;
        if (!framingError.empty()) {
            transport.respond({403, ""});
            continue;
        }
        transport.respond(dispatchFramed(config, hooks, request));
    }
}

bool ControlSlots::tryAcquire() {
    std::size_t current = inUse_.load();
    while (current < capacity_) {
        if (inUse_.compare_exchange_weak(current, current + 1)) return true;
    }
    return false;
}

void ControlSlots::release() {
    if (inUse_.load() == 0) throw std::logic_error("native_control_slot_underflow");
    inUse_.fetch_sub(1);
}

std::string serializeResponse(const ControlHttpResponse &response) {
    if (response.status != 200 && response.status != 403 && response.status != 404
        && response.status != 501) reject();
    std::string output = "HTTP/1.1 " + std::to_string(response.status)
        + (response.status == 200 ? " OK" : response.status == 404 ? " Not Found"
           : response.status == 501 ? " Not Implemented" : " Forbidden") + "\r\n";
    if (response.status == 200) {
        output += "Content-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: "
            + std::to_string(response.body.size()) + "\r\n";
    } else {
        output += "Content-Length: 0\r\nConnection: close\r\n";
    }
    return output + "\r\n" + (response.status == 200 ? response.body : std::string());
}
} // namespace amnezia::awgMigration::controlPid1
