#include "control_runtime.h"
#include "control_service.h"
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <json-c/json.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using namespace amnezia::awgMigration;
namespace {
unsigned checks = 0;
void check(bool value) { ++checks; assert(value); }
using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;
Json own(json_object *value) { assert(value); return Json(value, json_object_put); }
std::string encode(json_object *value) { return json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN); }
void string(json_object *value, const char *name, const std::string &text) {
    assert(json_object_object_add(value, name, json_object_new_string_len(text.data(), static_cast<int>(text.size()))) == 0);
}
json_object *get(json_object *value, const char *name) {
    json_object *result = nullptr;
    assert(json_object_object_get_ex(value, name, &result));
    return result;
}
std::string text(json_object *value, const char *name) { return json_object_get_string(get(value, name)); }
std::string responseBody(const std::string &response) {
    auto root = own(json_tokener_parse(response.c_str()));
    return text(get(root.get(), "result"), "body");
}
std::string request(const std::string &body, const std::string &path, const char *client = nullptr,
                    const std::string &role = "source") {
    auto root = own(json_object_new_object());
    string(root.get(), "role", role);
    string(root.get(), "scope", "amnezia-awg2");
    string(root.get(), "path", "/migration/v1/" + path);
    string(root.get(), "peerAddress", "10.8.1.2");
    string(root.get(), "body", body);
    auto headers = own(json_object_new_object());
    string(headers.get(), "content-length", std::to_string(body.size()));
    assert(json_object_object_add(root.get(), "headers", headers.release()) == 0);
    assert(json_object_object_add(root.get(), "authenticatedClient", client ? json_object_new_string(client) : nullptr) == 0);
    return encode(root.get());
}
void result(const std::string &raw, int status, bool authenticate, bool handled = true) {
    auto root = own(json_tokener_parse(raw.c_str()));
    auto *value = get(root.get(), "result");
    check(json_object_get_int(get(value, "status")) == status);
    check(static_cast<bool>(json_object_get_boolean(get(value, "authenticate"))) == authenticate);
    check(static_cast<bool>(json_object_get_boolean(get(value, "handled"))) == handled);
    if (status == 403) check(text(value, "body").empty());
}
struct Directory {
    std::filesystem::path path;
    Directory() {
        char name[] = "/tmp/amnezia-owned-control-runtime-XXXXXX";
        auto *created = ::mkdtemp(name);
        assert(created);
        path = created;
    }
    ~Directory() { std::filesystem::remove_all(path); }
};
void write(const std::filesystem::path &path, const std::string &content) {
    std::ofstream stream(path, std::ios::binary);
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    stream.close();
    assert(::chmod(path.c_str(), 0600) == 0);
}
std::string signer(const std::filesystem::path &path) {
    auto context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    assert(context && EVP_PKEY_keygen_init(context.get()) == 1);
    EVP_PKEY *raw = nullptr;
    assert(EVP_PKEY_keygen(context.get(), &raw) == 1);
    auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(raw, EVP_PKEY_free);
    auto *file = std::fopen(path.c_str(), "wb");
    assert(file && ::fchmod(::fileno(file), 0600) == 0);
    assert(PEM_write_PrivateKey(file, key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);
    assert(std::fclose(file) == 0);
    unsigned char bytes[32], encoded[45];
    std::size_t size = sizeof bytes;
    assert(EVP_PKEY_get_raw_public_key(key.get(), bytes, &size) == 1 && size == 32);
    assert(EVP_EncodeBlock(encoded, bytes, sizeof bytes) == 44);
    return std::string(reinterpret_cast<char *>(encoded), 44);
}
int count(const std::filesystem::path &path, const char *sql) {
    sqlite3 *raw = nullptr;
    assert(sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    auto db = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>(raw, sqlite3_close);
    sqlite3_stmt *statement = nullptr;
    assert(sqlite3_prepare_v2(db.get(), sql, -1, &statement, nullptr) == SQLITE_OK);
    auto query = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>(statement, sqlite3_finalize);
    assert(sqlite3_step(query.get()) == SQLITE_ROW);
    return sqlite3_column_int(query.get(), 0);
}
template<class Function> void rejects(Function function) {
    ++checks;
    try { function(); assert(false); }
    catch (const std::runtime_error &error) { assert(std::string(error.what()) == "native_control_rejected"); }
}
}
int main() {
    Directory directory;
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const auto peer = std::string(43, 'A') + '=';
    const auto client = std::string(64, 'c');
    const auto publicKey = signer(directory.path / "signing.pem");
    auto state = own(json_object_new_object());
    string(state.get(), "serverPublicKey", peer);
    string(state.get(), "containerId", "amnezia-awg2");
    string(state.get(), "signingPublicKey", publicKey);
    string(state.get(), "endpoint", "owned.test:51821");
    assert(json_object_object_add(state.get(), "parameters", json_object_new_object()) == 0);
    assert(json_object_object_add(state.get(), "generation", json_object_new_int(1)) == 0);
    assert(json_object_object_add(state.get(), "expiresAt", json_object_new_int64(now + 3600)) == 0);
    auto peers = own(json_object_new_object()), mapping = own(json_object_new_object());
    string(mapping.get(), "sourceIp", "10.8.1.2");
    string(mapping.get(), "targetIp", "10.8.1.2");
    string(mapping.get(), "clientAddress", "10.8.1.2/32");
    string(mapping.get(), "clientId", client);
    auto *mappingPointer = mapping.get();
    assert(json_object_object_add(peers.get(), peer.c_str(), mapping.release()) == 0);
    assert(json_object_object_add(state.get(), "peers", peers.release()) == 0);
    write(directory.path / "ready.json", encode(state.get()));
    write(directory.path / "handshakes.tsv", peer + '\t' + std::to_string(now) + '\n');
    const auto bootstrap = "{\"schema\":1,\"peerPublicKey\":\"" + peer + "\",\"sourceFingerprint\":\"" + std::string(64, 'a')
        + "\",\"nonce\":\"" + std::string(43, 'n') + "\"}";
    const auto initial = request(bootstrap, "bootstrap");
    result(controlRuntimeRequest(initial, directory.path), 403, true);
    check(count(directory.path / "grants.sqlite3", "SELECT count(*) FROM sqlite_master WHERE type='table'") == 0);
    const auto enrolled = controlRuntimeRequest(request(bootstrap, "bootstrap", client.c_str()), directory.path);
    result(enrolled, 200, false);
    auto envelope = own(json_tokener_parse(responseBody(enrolled).c_str()));
    const auto grant = text(envelope.get(), "grant");
    check(count(directory.path / "grants.sqlite3", "SELECT count(*) FROM grants") == 1);
    result(controlRuntimeRequest(request(bootstrap, "bootstrap", client.c_str()), directory.path), 200, false);
    check(count(directory.path / "grants.sqlite3", "SELECT count(*) FROM grants") == 1);
    // A valid target challenge creates the real signed receipt. Subsequent renew
    // reaches the callback with proof/grant/handshake already validated.
    sqlite3 *db = nullptr;
    assert(sqlite3_open((directory.path / "grants.sqlite3").c_str(), &db) == SQLITE_OK);
    sqlite3_stmt *query = nullptr;
    assert(sqlite3_prepare_v2(db, "SELECT challenge FROM grants", -1, &query, nullptr) == SQLITE_OK);
    assert(sqlite3_step(query) == SQLITE_ROW);
    const std::string challenge(reinterpret_cast<const char *>(sqlite3_column_text(query, 0)));
    sqlite3_finalize(query);
    sqlite3_close(db);
    const auto challengeBody = "{\"schema\":1,\"peerPublicKey\":\"" + peer + "\",\"generation\":1,\"grant\":\"" + grant
        + "\",\"nonce\":\"" + challenge + "\"}";
    const auto challenged = controlRuntimeRequest(request(challengeBody, "challenge", nullptr, "target"), directory.path);
    result(challenged, 200, false);
    const auto receipt = responseBody(challenged);
    const auto renewBody = "{\"schema\":1,\"peerPublicKey\":\"" + peer + "\",\"generation\":1,\"grant\":\"" + grant
        + "\",\"nonce\":\"" + std::string(43, 'r') + "\",\"challengeReceipt\":" + receipt + "}";
    // Regression: an empty malformed mapping must not turn deferred auth's empty
    // value into a successful equality check and mutate SQLite.
    string(mappingPointer, "clientId", "");
    write(directory.path / "ready.json", encode(state.get()));
    result(controlRuntimeRequest(request(renewBody, "renew", nullptr, "target"), directory.path), 403, true);
    check(count(directory.path / "grants.sqlite3", "SELECT count(*) FROM renewalNonces") == 0);
    check(count(directory.path / "grants.sqlite3", "SELECT count(*) FROM grants") == 1);
    result(controlRuntimeRequest(request(renewBody, "renew", client.c_str(), "target"), directory.path), 403, false);
    string(mappingPointer, "clientId", client);
    write(directory.path / "ready.json", encode(state.get()));
    result(controlRuntimeRequest(request(renewBody, "renew", nullptr, "target"), directory.path), 403, true);
    check(count(directory.path / "grants.sqlite3", "SELECT count(*) FROM renewalNonces") == 0);
    result(controlRuntimeRequest(request(renewBody, "renew", client.c_str(), "target"), directory.path), 200, false);
    check(count(directory.path / "grants.sqlite3", "SELECT count(*) FROM renewalNonces") == 1);
    check(count(directory.path / "grants.sqlite3", "SELECT count(*) FROM grants") == 2);
    result(controlRuntimeRequest(request(renewBody, "renew", client.c_str(), "target"), directory.path), 403, false);
    // No auth is requested for failures before the callback boundary.
    result(controlRuntimeRequest(request("{}", "bootstrap"), directory.path), 403, false);
    for (const auto &bad : {std::string("{}"), std::string("[]"), initial + "trailing", std::string(256 * 1024 + 1, ' '),
                           initial.substr(0, initial.size() - 1) + ",\"role\":\"source\"}",
                           initial.substr(0, initial.size() - 1) + ",\"r\\u006fle\":\"source\"}"})
        rejects([&] { controlRuntimeRequest(bad, directory.path); });
    for (const auto *badClient : {"", "wrong", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"})
        rejects([&] { controlRuntimeRequest(request(bootstrap, "bootstrap", badClient), directory.path); });
    std::cout << "control runtime checks: " << checks << '\n';
}
