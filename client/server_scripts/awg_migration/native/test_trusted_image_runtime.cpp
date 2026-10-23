#include "trusted_image_runtime.h"
#include "bounded_docker.h"
#include <functional>
#include <iostream>
#include <optional>
using namespace amnezia::awgMigration;
namespace {
void checkAt(bool value, int line) {
    if (!value) throw std::runtime_error("trusted image runtime assertion at line " + std::to_string(line));
}
#define check(condition) checkAt((condition), __LINE__)
ProcessArgs sandbox(ProcessArgs tail) {
    auto command = trustedSandboxArgs(); command.insert(command.end(), tail.begin(), tail.end()); return command;
}
struct Runner : ProcessRunner {
    std::vector<ProcessArgs> calls;
    bool missingCache = false, badIdentity = false, badHash = false, badVersion = false, badTools = false;
    unsigned inspections = 0;
    std::string architecture = "amd64";
    std::string failureStage;
    std::optional<ProcessFailureKind> failure;
    std::string run(const ProcessArgs &args) override {
        calls.push_back(args);
        const std::string stage = args[1] == "run" ? "probe" : args[1];
        if (failure && stage == failureStage) throw ProcessFailure(*failure);
        if (args == ProcessArgs{"docker", "info", "--format", "{{json .}}"})
            return "{\"OSType\":\"linux\",\"Architecture\":\"" + architecture + "\"}";
        if (args == ProcessArgs{"docker", "image", "inspect", TrustedImage}) {
            ++inspections;
            if (missingCache && inspections == 1) throw ProcessFailure(ProcessFailureKind::Exit);
            if (badIdentity) return "[]";
            return "[{\"Id\":\"" + std::string(TrustedImageId) + "\",\"RepoDigests\":[\"" + TrustedImage
                + "\"],\"Os\":\"linux\",\"Architecture\":\"amd64\"}]";
        }
        if (args == ProcessArgs{"docker", "pull", "--platform", "linux/amd64", TrustedImage}) return {};
        if (args == sandbox({"--entrypoint", "sha256sum", TrustedImage, "/usr/bin/amneziawg-go"}))
            return badHash ? "owned wrong hash" : std::string(TrustedBinarySha256) + "  /usr/bin/amneziawg-go\n";
        if (args == sandbox({"--entrypoint", "/usr/bin/amneziawg-go", TrustedImage, "--version"}))
            return badVersion ? "owned wrong version" : TrustedReportedVersion;
        if (args == sandbox({"--entrypoint", "sh", TrustedImage, "-c",
            "set -eu; for tool in awg awg-quick amneziawg-go iptables ip sleep mv cat cut sha256sum; do "
            "command -v \"$tool\" >/dev/null; done; printf ready"})) return badTools ? "owned wrong tools" : "ready";
        throw std::runtime_error("unexpected fake command");
    }
};
void plannerError(Runner &runner, const std::string &code) {
    try { static_cast<void>(trustedImageRuntimeRequest("{\"op\":\"resolve\"}", runner)); }
    catch (const PlannerError &error) { check(error.code() == code); return; }
    throw std::runtime_error("expected planner error");
}
}
int main() {
    unsigned count = 0;
    for (const auto &raw : {"", "{}", "[]", "null", "{\"op\":\"wrong\"}",
        "{\"op\":\"resolve\",\"image\":\"operator-image\"}",
        "{\"op\":\"resolve\",\"op\":\"resolve\"}", "{\"op\":1}",
        "{\"op\":\"resolve\"}x", "{\"op\":\"resolve\",\"x\":NaN}",
        "{\"op\":\"resolve\\u0000\"}"}) {
        Runner runner;
        try { static_cast<void>(trustedImageRuntimeRequest(raw, runner)); check(false); }
        catch (const TrustedImageRuntimeError &error) { check(std::string(error.what()) == "native_trusted_image_rejected"); }
        check(runner.calls.empty()); ++count;
    }
    for (const auto &raw : {std::string(4097, ' '), std::string("{\"op\":\"resol") + char(0xff) + "ve\"}"}) {
        Runner runner;
        try { static_cast<void>(trustedImageRuntimeRequest(raw, runner)); check(false); }
        catch (const TrustedImageRuntimeError &) { check(runner.calls.empty()); }
        ++count;
    }
    for (bool missing : {false, true}) {
        Runner runner; runner.missingCache = missing;
        auto result = plannerJson(trustedImageRuntimeRequest("{\"op\":\"resolve\"}", runner));
        json_object *image = nullptr;
        check(json_object_object_length(result.get()) == 1
            && json_object_object_get_ex(result.get(), "result", &image)
            && json_object_is_type(image, json_type_string)
            && std::string_view(json_object_get_string(image), json_object_get_string_len(image)) == TrustedImage);
        check(runner.calls.size() == (missing ? 7 : 6));
        for (const auto &args : runner.calls) {
            const auto limits = trustedImageCommandLimits(args);
            check(limits.outputLimit == 1024 * 1024);
            check(limits.timeoutSeconds == (args[1] == "run" ? 30 : args[1] == "pull" ? 180 : 10));
        }
        ++count;
    }
    for (const auto &args : {ProcessArgs{"sh", "-c", "owned"}, ProcessArgs{"docker", "pull", "unreviewed"},
        ProcessArgs{"docker", "image", "inspect", "unreviewed"}, ProcessArgs{"docker", "info"},
        sandbox({"--entrypoint", "sh", TrustedImage, "-c", "owned arbitrary command"})}) {
        try { static_cast<void>(trustedImageCommandLimits(args)); check(false); }
        catch (const TrustedImageRuntimeError &) { }
        ++count;
    }
    for (auto kind : {ProcessFailureKind::Exit, ProcessFailureKind::Timeout, ProcessFailureKind::Os, ProcessFailureKind::Other}) {
        Runner fetch; fetch.missingCache = true; fetch.failure = kind; fetch.failureStage = "pull";
        plannerError(fetch, kind == ProcessFailureKind::Other ? "trusted_image_unavailable" : "image_fetch_unavailable");
        Runner probe; probe.failure = kind; probe.failureStage = "probe";
        plannerError(probe, "trusted_image_unavailable");
        count += 2;
    }
    {
        Runner runner; runner.architecture = "arm64";
        plannerError(runner, "unsupported_server_architecture"); check(runner.calls.size() == 1); ++count;
    }
    for (auto flag : {&Runner::badIdentity, &Runner::badHash, &Runner::badVersion, &Runner::badTools}) {
        Runner runner; runner.*flag = true; plannerError(runner, "trusted_image_unavailable"); ++count;
    }
    for (const unsigned invalid : {0u, 3u, 11u, 330u}) {
        try { static_cast<void>(runBoundedDockerWithBudget({"docker", "owned-test"}, 16, invalid)); check(false); }
        catch (const BoundedDockerError &error) { check(error.kind == BoundedDockerFailureKind::Other); }
        ++count;
    }
    std::cout << count << " trusted image runtime cases PASS; fake runner only, no Docker/pull/run\n";
}
