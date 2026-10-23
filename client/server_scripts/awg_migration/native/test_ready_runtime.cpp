#include "test_ready_runtime_data.h"
#include <cassert>
#include <iostream>
using namespace amnezia::awgMigration;
struct FakeRunner final : ProcessRunner {
    int calls = 0, inspections = 0;
    std::string mode;
    explicit FakeRunner(std::string value = "valid") : mode(std::move(value)) {}
    std::string run(const ProcessArgs &args) override {
        ++calls;
        const auto id = readyTest::id();
        if (mode == "backend-failed") throw std::runtime_error("private fixture details");
        if (args == ProcessArgs{"docker", "inspect", "--format", ReadyInspectFormat, id}) {
            ++inspections;
            if (mode == "malformed-inspect") return "{private-fixture";
            return readyTest::metadata(id, mode == "changed-epoch" && inspections > 1 ? "changed" : readyTest::epoch,
                                       mode != "not-running");
        }
        if (args == ProcessArgs{"docker", "exec", id, "awg", "show", "awg0", "dump"}) {
            if (mode == "short-dump") return "header\npeer\n";
            if (mode == "large-output") return std::string(16 * 1024 * 1024 + 1, 'x');
            auto value = readyTest::dump(mode == "wrong-port");
            if (mode == "invalid-utf8") value[0] = static_cast<char>(0xff);
            return value;
        }
        if (args == ProcessArgs{"docker", "exec", id, "awg", "showconf", "awg0"}) return readyTest::showconf(mode == "wrong-param");
        if (args == ProcessArgs{"docker", "exec", id, "sh", "-c", ReadyEngineProbe})
            return std::string(mode == "wrong-engine" ? std::string(64, '0') : TrustedBinarySha256) + "  /proc/100/exe\n";
        throw std::runtime_error("unexpected fixture command");
    }
};
static void failed(const std::string &request, const std::string &mode, const std::string &code, bool noCalls = false) {
    FakeRunner runner(mode);
    bool rejected = false;
    try { (void)readyRuntimeRequest(request, runner); }
    catch (const ReadyRuntimeError &error) { rejected = error.what() == code; }
    assert(rejected);
    if (noCalls) assert(runner.calls == 0);
}
int main() {
    auto request = readyTest::request();
    const auto raw = readyTest::serialize(request.get());
    FakeRunner valid;
    assert(readyRuntimeRequest(raw, valid) == "{\"result\":true}");
    assert(valid.calls == 5 && valid.inspections == 2);
    FakeRunner manual;
    auto manualRequest = readyTest::request(readyTest::id(), false);
    assert(readyRuntimeRequest(readyTest::serialize(manualRequest.get()), manual) == "{\"result\":true}");
    assert(manual.calls == 4);
    for (const auto &mode : {"wrong-port", "wrong-param", "short-dump", "invalid-utf8", "wrong-engine"})
        failed(raw, mode, "migration_ready_drift");
    for (const auto &mode : {"changed-epoch", "not-running", "malformed-inspect"})
        failed(raw, mode, "native_ready_identity_drift");
    for (const auto &mode : {"backend-failed", "large-output"}) failed(raw, mode, "native_ready_not_observed");
    failed("{}", "valid", "native_ready_rejected", true);
    failed(raw + "extra", "valid", "native_ready_rejected", true);
    failed(std::string(16 * 1024 * 1024 + 1, ' '), "valid", "native_ready_rejected", true);
    failed("{\"source\":\"x\",\"source\":\"y\"}", "valid", "native_ready_rejected", true);
    for (const auto &invalid : {std::string("target"), std::string(63, 'a'), "--" + std::string(62, 'a')}) {
        auto f = readyTest::request(invalid);
        failed(readyTest::serialize(f.get()), "valid", "native_ready_rejected", true);
    }
    auto f = readyTest::request();
    auto *expected = json_object_object_get(f.get(), "expected");
    json_object_object_add(expected, "name", json_object_new_string("/amnezia-awg-migration-01"));
    failed(readyTest::serialize(f.get()), "valid", "native_ready_rejected", true);
    f = readyTest::request();
    json_object_object_add(f.get(), "automatic", json_object_new_int(1));
    failed(readyTest::serialize(f.get()), "valid", "native_ready_rejected", true);
    f = readyTest::request();
    json_object_object_add(f.get(), "responses", json_object_new_object());
    failed(readyTest::serialize(f.get()), "valid", "native_ready_rejected", true);
    for (const auto &kind : {"empty", "missing", "extra", "wrong-type"}) {
        f = readyTest::request();
        auto *ready = json_object_object_get(f.get(), "ready");
        auto *params = json_object_object_get(ready, "parameters");
        if (std::string(kind) == "empty") json_object_object_add(ready, "parameters", json_object_new_object());
        else if (std::string(kind) == "missing") json_object_object_del(params, "Jc");
        else if (std::string(kind) == "extra") json_object_object_add(params, "unexpected", json_object_new_string("x"));
        else json_object_object_add(params, "Jc", json_object_new_int(4));
        failed(readyTest::serialize(f.get()), "valid", "native_ready_rejected", true);
    }
    f = readyTest::request();
    auto malformedKey = readyTest::key('A'); malformedKey[0] = '=';
    json_object_object_add(json_object_object_get(f.get(), "ready"), "serverPublicKey", json_object_new_string(malformedKey.c_str()));
    failed(readyTest::serialize(f.get()), "valid", "native_ready_rejected", true);
    f = readyTest::request();
    const auto opaque = readyTest::source().insert(readyTest::source().find("[Peer]"), std::string("PostUp=left\0right\n", 18));
    json_object_object_add(f.get(), "source", json_object_new_string_len(opaque.data(), static_cast<int>(opaque.size())));
    FakeRunner nul;
    assert(readyRuntimeRequest(readyTest::serialize(f.get()), nul) == "{\"result\":true}");
    std::cout << "ready runtime owned FakeRunner checks passed; actual Docker calls=0\n";
}
