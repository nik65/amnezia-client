#pragma once
#include "ready_runtime.h"
#include <utility>

namespace readyTest {
inline std::string id(char c = 'a') { return std::string(64, c); }
inline std::string key(char c) { return std::string(43, c) + '='; }
inline const std::string epoch = "2026-10-21T00:00:00.000000000Z";
inline const std::string header = "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=";
inline std::vector<std::pair<std::string, std::string>> parameters() {
    return {{"Jc", "4"}, {"Jmin", "10"}, {"Jmax", "50"},
        {"S1", "16"}, {"S2", "16"}, {"S3", "16"}, {"S4", "16"},
        {"H1", "1"}, {"H2", "2"}, {"H3", "3"}, {"H4", "4"},
        {"HeaderProtectionKey", header}, {"ContentPaddingAddition", "0"},
        {"RekeyAfterTime", "120"}, {"RekeyTimeout", "5"}, {"RejectAfterTime", "180"},
        {"KeepaliveTimeout", "10"}, {"MaxHandshakeAttempts", "20"},
        {"RandomTrailers", "0"}, {"DisableCookies", "0"}};
}
inline std::string peers() {
    return "[Peer]\nPublicKey=" + key('B') + "\nPresharedKey=" + key('C') + "\nAllowedIPs=10.0.0.2/32\n";
}
inline std::string source() {
    return "[Interface]\nPrivateKey=" + key('A') + "\nAddress=10.0.0.1/24\nListenPort=51820\n" + peers();
}
inline std::string target() {
    std::string raw = "[Interface]\nPrivateKey=" + key('A') + "\nAddress=10.0.0.1/24\nListenPort=51821\n";
    for (const auto &kv : parameters()) raw += kv.first + '=' + kv.second + '\n';
    return raw + peers();
}
inline std::string metadata(const std::string &identity = id(), const std::string &started = epoch, bool running = true) {
    return "{\"id\":\"" + identity + "\",\"name\":\"/amnezia-awg-migration-1\",\"image\":\"sha256:"
        + std::string(64, 'd') + "\",\"owner\":\"" + std::string(32, 'c') + "\",\"running\":"
        + (running ? "true" : "false") + ",\"startedAt\":\"" + started + "\"}";
}
inline std::string dump(bool wrongPort = false) {
    return "private\t" + key('A') + (wrongPort ? "\t51822\t0\n" : "\t51821\t0\n")
        + key('B') + '\t' + key('C') + "\t(none)\t10.0.0.2/32\t0\t0\t0\t0\n";
}
inline std::string showconf(bool wrongJc = false) {
    std::string output;
    for (const auto &kv : parameters()) {
        if (kv.first == "ContentPaddingAddition") continue;
        output += kv.first + " = " + (wrongJc && kv.first == "Jc" ? "5" : kv.second) + '\n';
    }
    return output;
}
inline amnezia::awgMigration::PlannerJson request(const std::string &identity = id(), bool automatic = true) {
    using namespace amnezia::awgMigration;
    PlannerJson result(json_object_new_object());
    json_object_object_add(result.get(), "source", json_object_new_string(source().c_str()));
    json_object_object_add(result.get(), "target", json_object_new_string(target().c_str()));
    auto *ready = json_object_new_object();
    json_object_object_add(ready, "targetContainer", json_object_new_string(identity.c_str()));
    json_object_object_add(ready, "serverPublicKey", json_object_new_string(key('A').c_str()));
    auto *params = json_object_new_object();
    for (const auto &kv : parameters()) json_object_object_add(params, kv.first.c_str(), json_object_new_string(kv.second.c_str()));
    json_object_object_add(ready, "parameters", params);
    json_object_object_add(result.get(), "ready", ready);
    PlannerJson expected(json_tokener_parse(metadata(identity).c_str()));
    json_object_object_del(expected.get(), "running");
    json_object_object_add(result.get(), "expected", expected.release());
    json_object_object_add(result.get(), "automatic", json_object_new_boolean(automatic));
    return result;
}
inline std::string serialize(json_object *value) { return json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN); }
}
