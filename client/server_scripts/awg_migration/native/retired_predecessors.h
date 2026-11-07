#pragma once
#include "client_operation.h"
#include <json-c/json.h>
#include <openssl/evp.h>
#include <cstdint>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace amnezia::awgMigration {
struct RetiredPredecessor {
    std::uint64_t generation = 0;
    std::string sha256, operationId, journalSha256;
};
inline bool retiredDigest(const std::string& value)
{
    if (value.size() != 64) return false;
    for (const auto ch : value) if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    return true;
}
inline void validateRetiredPredecessors(const std::vector<RetiredPredecessor>& proofs)
{
    if (proofs.size() > 32) throw std::runtime_error("retired predecessor limit");
    std::uint64_t previous = 0;
    std::set<std::string> operations;
    for (const auto& proof : proofs) {
        if (proof.generation <= previous || proof.generation > 9007199254740991ULL
            || !retiredDigest(proof.sha256) || !retiredDigest(proof.journalSha256)
            || !validClientOperationId(proof.operationId) || !operations.insert(proof.operationId).second)
            throw std::runtime_error("retired predecessor binding");
        previous = proof.generation;
    }
}
inline std::string retiredPredecessorsJson(const std::vector<RetiredPredecessor>& proofs)
{
    validateRetiredPredecessors(proofs);
    std::unique_ptr<json_object, decltype(&json_object_put)> result(json_object_new_array(), json_object_put);
    if (!result) throw std::runtime_error("retired predecessor JSON");
    for (const auto& proof : proofs) {
        auto* item = json_object_new_object();
        if (!item) throw std::runtime_error("retired predecessor JSON");
        // QJsonDocument's lexical key order, exact integer representation.
        json_object_object_add(item, "generation", json_object_new_int64(static_cast<std::int64_t>(proof.generation)));
        json_object_object_add(item, "journalSha256", json_object_new_string(proof.journalSha256.c_str()));
        json_object_object_add(item, "operationId", json_object_new_string(proof.operationId.c_str()));
        json_object_object_add(item, "sha256", json_object_new_string(proof.sha256.c_str()));
        json_object_array_add(result.get(), item);
    }
    return json_object_to_json_string_ext(result.get(), JSON_C_TO_STRING_PLAIN);
}
inline std::vector<RetiredPredecessor> retiredPredecessorsFromJson(json_object* value)
{
    if (!value || !json_object_is_type(value, json_type_array) || json_object_array_length(value) > 32)
        throw std::runtime_error("retired predecessor JSON");
    auto field = [](json_object* item, const char* key, json_type type) {
        json_object* result = nullptr;
        if (!json_object_object_get_ex(item, key, &result) || !json_object_is_type(result, type))
            throw std::runtime_error("retired predecessor JSON");
        return result;
    };
    std::vector<RetiredPredecessor> result;
    for (std::size_t i = 0; i < json_object_array_length(value); ++i) {
        auto* item = json_object_array_get_idx(value, i);
        if (!json_object_is_type(item, json_type_object) || json_object_object_length(item) != 4)
            throw std::runtime_error("retired predecessor JSON");
        const auto number = json_object_get_int64(field(item, "generation", json_type_int));
        if (number < 1 || number > 9007199254740991LL) throw std::runtime_error("retired predecessor generation");
        auto text = [&](const char* key) {
            auto* data = field(item, key, json_type_string);
            return std::string(json_object_get_string(data), json_object_get_string_len(data));
        };
        result.push_back({static_cast<std::uint64_t>(number), text("sha256"), text("operationId"), text("journalSha256")});
    }
    validateRetiredPredecessors(result);
    return result;
}
inline void validateBoundRetiredRequest(json_object* request, const std::string& owner, bool native)
{
    if (!request || !json_object_is_type(request, json_type_object)) throw std::runtime_error("retired request shape");
    for (const auto* name : {"generation", "port", "host", "image"}) {
        json_object* required = nullptr;
        const auto type = (std::string(name) == "generation" || std::string(name) == "port") ? json_type_int : json_type_string;
        if (!json_object_object_get_ex(request, name, &required) || !json_object_is_type(required, type))
            throw std::runtime_error("retired request shape");
    }
    json_object *operation = nullptr, *history = nullptr;
    const bool hasOperation = json_object_object_get_ex(request, "clientOperationId", &operation);
    const bool hasHistory = json_object_object_get_ex(request, "retiredPredecessors", &history);
    if (json_object_object_length(request) != 4 + (hasOperation ? 1 : 0) + (hasHistory ? 1 : 0))
        throw std::runtime_error("retired request shape");
    std::string nonce;
    if (hasOperation) {
        if (!native || !json_object_is_type(operation, json_type_string)) throw std::runtime_error("retired request binding");
        nonce.assign(json_object_get_string(operation), json_object_get_string_len(operation));
        if (!validClientOperationId(nonce) || owner != clientOperationOwner(nonce)) throw std::runtime_error("retired request binding");
    }
    if (hasHistory) {
        if (!hasOperation) throw std::runtime_error("retired request binding");
        auto proofs = retiredPredecessorsFromJson(history);
        json_object* generation = nullptr;
        if (proofs.empty() || !json_object_object_get_ex(request, "generation", &generation)
            || !json_object_is_type(generation, json_type_int)
            || json_object_get_int64(generation) < 1
            || proofs.back().generation >= static_cast<std::uint64_t>(json_object_get_int64(generation)))
            throw std::runtime_error("retired request generation");
        for (const auto& proof : proofs) if (proof.operationId == nonce) throw std::runtime_error("retired request operation reused");
    }
}
inline std::string retiredBase64(const std::string& raw)
{
    std::string result(4 * ((raw.size() + 2) / 3) + 1, '\0');
    const int size = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()),
        reinterpret_cast<const unsigned char*>(raw.data()), static_cast<int>(raw.size()));
    if (size < 0) throw std::runtime_error("retired predecessor encoding");
    result.resize(static_cast<std::size_t>(size));
    return result;
}
inline std::string encodeRetiredPredecessors(const std::vector<RetiredPredecessor>& proofs)
{
    return retiredBase64(retiredPredecessorsJson(proofs));
}
inline std::vector<RetiredPredecessor> parseRetiredPredecessors(const std::string& encoded)
{
    if (encoded.empty() || encoded.size() > 32768 || encoded.size() % 4)
        throw std::runtime_error("retired predecessor encoding");
    std::string raw(encoded.size() / 4 * 3, '\0');
    int count = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(raw.data()),
        reinterpret_cast<const unsigned char*>(encoded.data()), static_cast<int>(encoded.size()));
    if (count < 0) throw std::runtime_error("retired predecessor encoding");
    if (encoded.back() == '=') --count;
    if (encoded.size() > 1 && encoded[encoded.size() - 2] == '=') --count;
    if (count < 0) throw std::runtime_error("retired predecessor encoding");
    raw.resize(static_cast<std::size_t>(count));
    if (retiredBase64(raw) != encoded) throw std::runtime_error("retired predecessor encoding");
    auto* tok = json_tokener_new();
    if (!tok) throw std::runtime_error("retired predecessor JSON");
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    std::unique_ptr<json_object, decltype(&json_object_put)> value(
        json_tokener_parse_ex(tok, raw.data(), static_cast<int>(raw.size())), json_object_put);
    const bool valid = value && json_tokener_get_error(tok) == json_tokener_success
        && json_tokener_get_parse_end(tok) == raw.size();
    json_tokener_free(tok);
    if (!valid) throw std::runtime_error("retired predecessor JSON");
    auto result = retiredPredecessorsFromJson(value.get());
    if (result.empty() || retiredPredecessorsJson(result) != raw)
        throw std::runtime_error("retired predecessor canonical JSON");
    return result;
}
} // namespace amnezia::awgMigration
