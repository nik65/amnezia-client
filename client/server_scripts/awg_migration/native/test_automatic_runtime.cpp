#include "automatic_runtime.h"
#include <filesystem>
#include <functional>
#include <iostream>
#include <unistd.h>
using namespace amnezia::awgMigration;
namespace {
void check(bool condition) { if (!condition) throw std::runtime_error("automatic runtime assertion"); }
struct Runner : ProcessRunner {
    unsigned calls = 0;
    std::string ss = "UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n", ids = "aaaaaaaaaaaa\n",
                inspect = "[{\"NetworkSettings\":{\"Ports\":{\"5454/udp\":[{\"HostPort\":\"5454\"}]}}}]";
    std::string run(const ProcessArgs &args) override {
        ++calls;
        if (args == ProcessArgs{"ss", "-H", "-uan"}) return ss;
        if (args == ProcessArgs{"docker", "ps", "-q"}) return ids;
        if (args == ProcessArgs{"docker", "inspect", "aaaaaaaaaaaa"}) return inspect;
        throw std::runtime_error("unexpected fake process call");
    }
};
struct Probe : PortProbe {
    unsigned opened = 0, closed = 0, bound = 0, ipv6 = 0;
    unsigned failAt = 0;
    struct Lease : PortLease {
        Probe &owner;
        explicit Lease(Probe &p) : owner(p) {}
        ~Lease() override { ++owner.closed; }
        void ipv6Only() override { ++owner.ipv6; }
        void bind(const std::string &address, unsigned port) override {
            check(port == 51821);
            check(address == (owner.bound == 0 ? "0.0.0.0" : "::"));
            ++owner.bound;
            check(owner.opened - owner.closed == owner.bound);
            if (owner.bound == owner.failAt) throw std::runtime_error("owned private bind failure");
        }
    };
    std::unique_ptr<PortLease> open(UdpFamily family) override {
        check(family == (opened == 0 ? UdpFamily::V4 : UdpFamily::V6));
        ++opened; return std::make_unique<Lease>(*this);
    }
};
struct Temp {
    std::filesystem::path path;
    Temp() { char pattern[] = "/tmp/awg-automatic-runtime-XXXXXX"; const auto *v = mkdtemp(pattern); check(v); path = v; }
    ~Temp() { std::filesystem::remove_all(path); }
};
void rejects(const std::string &raw) {
    Runner runner; Probe probe;
    try { static_cast<void>(automaticRuntimeRequest(raw, runner, probe)); }
    catch (const AutomaticRuntimeError &e) {
        check(std::string(e.what()) == "native_automatic_rejected");
        check(runner.calls == 0 && probe.opened == 0); return;
    }
    throw std::runtime_error("expected input rejection");
}
}
int main() {
    unsigned count = 0;
    for (const auto &raw : {"", "{}", "[]", "null", "{\"op\":\"unknown\"}",
        "{\"op\":\"inventory\",\"extra\":0}", "{\"op\":\"inventory\",\"op\":\"inventory\"}",
        "{\"op\":\"inventory\"}x", "{\"op\":\"inventory\",\"x\":NaN}",
        "{\"op\":\"verify-port\",\"port\":true}", "{\"op\":\"verify-port\",\"port\":1.0}",
        "{\"op\":\"verify-port\",\"port\":1023}", "{\"op\":\"verify-port\",\"port\":65536}"}) {
        rejects(raw); ++count;
    }
    rejects(std::string("{\"op\":\"invent") + static_cast<char>(0xff) + "ory\"}"); ++count;
    rejects(std::string(8 * 1024 * 1024 + 1, ' ')); ++count;
    {
        Runner runner; Probe probe;
        check(automaticRuntimeRequest("{\"op\":\"inventory\"}", runner, probe) == "{\"result\":[53,5454]}");
        check(runner.calls == 3 && probe.opened == 0); ++count;
    }
    for (const auto &invalid : {"short", "UNCONN 0 0 0.0.0.0:65536 0.0.0.0:*\n"}) {
        Runner runner; Probe probe; runner.ss = invalid;
        try { static_cast<void>(automaticRuntimeRequest("{\"op\":\"inventory\"}", runner, probe)); check(false); }
        catch (const PlannerError &e) { check(std::string(e.code()) == "udp_inventory_unavailable"); }
        ++count;
    }
    {
        Runner runner; Probe probe; runner.ss.assign(1024 * 1024 + 1, ' ');
        try { static_cast<void>(automaticRuntimeRequest("{\"op\":\"inventory\"}", runner, probe)); check(false); }
        catch (const PlannerError &e) { check(std::string(e.code()) == "udp_inventory_unavailable"); }
        ++count;
    }
    for (unsigned failure : {0u, 1u, 2u}) {
        Runner runner; Probe probe; probe.failAt = failure;
        try {
            check(automaticRuntimeRequest("{\"op\":\"verify-port\",\"port\":51821}", runner, probe) == "{\"result\":true}");
            check(failure == 0);
        } catch (const PlannerError &e) { check(failure && std::string(e.code()) == "migration_udp_port_unavailable"); }
        check(probe.opened == probe.closed && runner.calls == 0); ++count;
    }
    {
        Temp root; Runner runner; Probe probe;
        PlannerJson request(json_object_new_object());
        for (const auto &item : std::vector<std::pair<std::string,std::string>>{
            {"op", "plan"}, {"root", root.path.string()}, {"source", "amnezia-awg"},
            {"host", "fixture.test"}, {"image", "repo@sha256:" + std::string(64,'a')}, {"raw", "owned source"}})
            json_object_object_add(request.get(), item.first.c_str(), json_object_new_string(item.second.c_str()));
        json_object_object_add(request.get(), "sourcePort", json_object_new_int64(443));
        auto *occupied = json_object_new_array(); json_object_array_add(occupied, json_object_new_int64(51821));
        json_object_object_add(request.get(), "occupied", occupied);
        const auto invoke = [&] { return automaticRuntimeRequest(json_object_to_json_string_ext(request.get(), JSON_C_TO_STRING_PLAIN), runner, probe); };
        check(invoke().find("\"port\":51822") != std::string::npos); check(runner.calls == 0 && probe.opened == 0); ++count;
        for (const auto &badRoot : {"relative", "/tmp/../tmp/owned"}) {
            json_object_object_add(request.get(), "root", json_object_new_string(badRoot));
            rejects(json_object_to_json_string_ext(request.get(), JSON_C_TO_STRING_PLAIN)); ++count;
        }
        json_object_object_add(request.get(), "root", json_object_new_string(root.path.c_str()));
        json_object_array_add(occupied, json_object_new_boolean(true));
        rejects(json_object_to_json_string_ext(request.get(), JSON_C_TO_STRING_PLAIN)); ++count;
    }
    std::cout << count << " automatic runtime cases PASS; fake processes/probes and owned temp only\n";
}
