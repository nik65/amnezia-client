#include "config_generation_runtime.h"
#include "config_generation.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <iostream>
#include <json-c/json.h>
#include <memory>
#include <openssl/evp.h>
#include <poll.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <set>
#include <unistd.h>
#include <vector>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t frameLimit = 8 * 1024 * 1024;
constexpr std::size_t configLimit = 1024 * 1024;
constexpr std::size_t outputLimit = 16 * 1024 * 1024;
[[noreturn]] void reject() { throw GenerationError(); }
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
    UniqueKeys keys;
    if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, keys) || !keys.stack.empty()
        || stream.Tell() != raw.size()) reject();
    auto tok = std::unique_ptr<json_tokener, decltype(&json_tokener_free)>(json_tokener_new(), json_tokener_free);
    if (!tok) reject();
    json_tokener_set_flags(tok.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    auto root = own(json_tokener_parse_ex(tok.get(), raw.data(), static_cast<int>(raw.size())));
    if (json_tokener_get_error(tok.get()) != json_tokener_success
        || !json_object_is_type(root.get(), json_type_object)
        ) reject();
    return root;
}
json_object *member(json_object *root, const char *key, json_type type) {
    json_object *value = nullptr;
    if (!json_object_object_get_ex(root, key, &value) || !value || !json_object_is_type(value, type)) reject();
    return value;
}
void put(json_object *root, const char *key, Json value) {
    if (json_object_object_add(root, key, value.get()) != 0) reject();
    value.release();
}
Json string(const std::string &value) {
    return own(json_object_new_string_len(value.data(), static_cast<int>(value.size())));
}
Json fields(const ConfigFields &source) {
    auto root = own(json_object_new_object());
    for (const auto &entry : source) put(root.get(), entry.first.c_str(), string(entry.second));
    return root;
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
}
std::string generationRuntimeRequest(const std::string &raw) {
    auto request = parse(raw);
    json_object *operation = nullptr;
    if (json_object_object_get_ex(request.get(), "op", &operation)) {
        if (!operation || !json_object_is_type(operation,json_type_string)) reject();
        const std::string op(json_object_get_string(operation),static_cast<std::size_t>(json_object_get_string_len(operation)));
        if (op == "capability") {
            if (json_object_object_length(request.get()) != 1) reject();
            return "{\"result\":{\"peerMappingVersion\":1}}";
        }
        if (op == "server-key-capability") {
            if (json_object_object_length(request.get()) != 1) reject();
            return "{\"result\":{\"serverKeyVersion\":1}}";
        }
        if (op == "server-key") {
            if (json_object_object_length(request.get()) != 2) reject();
            auto *value = member(request.get(),"source",json_type_string);
            const std::string source(json_object_get_string(value),static_cast<std::size_t>(json_object_get_string_len(value)));
            if (source.size() > configLimit) reject();
            ReadyConfig config; try { config=parseConfig(source); } catch (...) { reject(); }
            const auto &encoded=config.Interface.at("PrivateKey");
            std::array<unsigned char,33> secret{};
            struct CleanSecret { std::array<unsigned char,33> &value; ~CleanSecret() { OPENSSL_cleanse(value.data(),value.size()); } } clean{secret};
            if (EVP_DecodeBlock(secret.data(),reinterpret_cast<const unsigned char*>(encoded.data()),static_cast<int>(encoded.size())) != 33) reject();
            std::array<unsigned char,45> canonical{};
            if (EVP_EncodeBlock(canonical.data(),secret.data(),32) != 44 || encoded != reinterpret_cast<const char*>(canonical.data())) reject();
            auto key=std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)>(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,nullptr,secret.data(),32),EVP_PKEY_free);
            OPENSSL_cleanse(secret.data(),secret.size());
            if (!key) reject();
            std::array<unsigned char,32> publicKey{}; std::size_t length=publicKey.size();
            if (EVP_PKEY_get_raw_public_key(key.get(),publicKey.data(),&length) != 1 || length != 32) reject();
            std::array<unsigned char,45> output{};
            if (EVP_EncodeBlock(output.data(),publicKey.data(),32) != 44) reject();
            return "{\"result\":\""+std::string(reinterpret_cast<const char*>(output.data()),44)+"\"}";
        }
        if (op != "peer-mapping" || json_object_object_length(request.get()) != 3) reject();
        auto *scopeValue = member(request.get(),"scope",json_type_string);
        const std::string scope(json_object_get_string(scopeValue),static_cast<std::size_t>(json_object_get_string_len(scopeValue)));
        if (scope != "amnezia-awg" && scope != "amnezia-awg2") reject();
        auto *sourceValue = member(request.get(),"source",json_type_string);
        const std::string source(json_object_get_string(sourceValue),static_cast<std::size_t>(json_object_get_string_len(sourceValue)));
        if (source.size() > configLimit) reject();
        ReadyConfig config;
        try { config = parseConfig(source); } catch (...) { reject(); }
        auto mapping = own(json_object_new_object());
        for (const auto &peer : config.Peers) {
            const auto &key = peer.at("PublicKey"), &address = peer.at("AllowedIPs");
            const auto ip = address.substr(0,address.find('/'));
            const auto identity = scope + "\t" + key;
            std::array<unsigned char,EVP_MAX_MD_SIZE> digest{}; unsigned length = 0;
            if (EVP_Digest(identity.data(),identity.size(),digest.data(),&length,EVP_sha256(),nullptr) != 1 || length != 32) reject();
            std::string client; const char *hex = "0123456789abcdef";
            for (unsigned i=0;i<length;++i) { client += hex[digest[i]>>4]; client += hex[digest[i]&15]; }
            auto item = own(json_object_new_object());
            put(item.get(),"sourceIp",string(ip)); put(item.get(),"targetIp",string(ip));
            put(item.get(),"clientAddress",string(address)); put(item.get(),"clientId",string(client));
            put(mapping.get(),key.c_str(),std::move(item));
        }
        auto response = own(json_object_new_object()); put(response.get(),"result",std::move(mapping));
        const char *serialized = json_object_to_json_string_ext(response.get(),JSON_C_TO_STRING_PLAIN);
        if (!serialized || std::char_traits<char>::length(serialized) > outputLimit) reject();
        return serialized;
    }
    if (json_object_object_length(request.get()) != 3) reject();
    auto *sourceValue = member(request.get(), "source", json_type_string);
    const std::string source(json_object_get_string(sourceValue),
        static_cast<std::size_t>(json_object_get_string_len(sourceValue)));
    if (source.size() > configLimit) reject();
    const auto port = json_object_get_int64(member(request.get(), "port", json_type_int));
    const auto mtu = json_object_get_int64(member(request.get(), "mtu", json_type_int));
    if (port < 1024 || port > 65535 || mtu < 576 || mtu > 9000) reject();
    const auto generated = generateConfig(source, static_cast<unsigned>(port), static_cast<unsigned>(mtu));
    auto result = own(json_object_new_object());
    put(result.get(), "parameters", fields(generated.parameters));
    put(result.get(), "interface", fields(generated.interface));
    put(result.get(), "config", string(generated.config));
    put(result.get(), "nativeConfig", string(generated.nativeConfig));
    auto response = own(json_object_new_object());
    put(response.get(), "result", std::move(result));
    const char *text = json_object_to_json_string_ext(response.get(), JSON_C_TO_STRING_PLAIN);
    if (!text) reject();
    std::string output(text);
    if (output.size() > outputLimit) reject();
    return output;
}
int generationJsonMain() {
    try {
        std::cout << generationRuntimeRequest(readInput()) << '\n';
        return 0;
    } catch (...) {
        std::cout << "{\"error\":\"native_generation_rejected\"}\n";
        return 2;
    }
}
}
