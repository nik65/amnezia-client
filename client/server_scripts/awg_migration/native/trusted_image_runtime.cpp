#include "trusted_image_runtime.h"
#include "bounded_docker.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <iostream>
#include <poll.h>
#include <set>
#include <unistd.h>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t inputLimit = 4096;
constexpr std::size_t outputLimit = 1024 * 1024;
[[noreturn]] void reject() { throw TrustedImageRuntimeError("native_trusted_image_rejected"); }
ProcessArgs sandboxCommand(const ProcessArgs &tail) {
    auto command = trustedSandboxArgs();
    command.insert(command.end(), tail.begin(), tail.end());
    return command;
}
class CheckedRunner final : public ProcessRunner {
    ProcessRunner &runner;
public:
    explicit CheckedRunner(ProcessRunner &source) : runner(source) {}
    std::string run(const ProcessArgs &args) override {
        const auto limits = trustedImageCommandLimits(args);
        auto value = runner.run(args);
        if (value.size() > limits.outputLimit) throw ProcessFailure(ProcessFailureKind::Other);
        return value;
    }
};
class DockerRunner final : public ProcessRunner {
public:
    std::string run(const ProcessArgs &args) override {
        const auto limits = trustedImageCommandLimits(args);
        try { return runBoundedDockerWithBudget(args, limits.outputLimit, limits.timeoutSeconds); }
        catch (const BoundedDockerError &error) {
            switch (error.kind) {
            case BoundedDockerFailureKind::Exit: throw ProcessFailure(ProcessFailureKind::Exit);
            case BoundedDockerFailureKind::Timeout: throw ProcessFailure(ProcessFailureKind::Timeout);
            case BoundedDockerFailureKind::Os: throw ProcessFailure(ProcessFailureKind::Os);
            case BoundedDockerFailureKind::Other: throw ProcessFailure(ProcessFailureKind::Other);
            }
            throw ProcessFailure(ProcessFailureKind::Other);
        }
    }
};
std::string readInput() {
    std::string input;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) reject();
        pollfd fd{STDIN_FILENO, POLLIN, 0};
        const int ready = ::poll(&fd, 1, static_cast<int>(left));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || (fd.revents & (POLLNVAL | POLLERR))) reject();
        std::array<char, 1024> buffer{};
        const auto count = ::read(STDIN_FILENO, buffer.data(), buffer.size());
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) reject();
        if (!count) return input;
        input.append(buffer.data(), static_cast<std::size_t>(count));
        if (input.size() > inputLimit) reject();
    }
}
}
TrustedImageCommandLimits trustedImageCommandLimits(const ProcessArgs &args) {
    if (args == ProcessArgs{"docker", "info", "--format", "{{json .}}"}
        || args == ProcessArgs{"docker", "image", "inspect", TrustedImage}) return {outputLimit, 10};
    if (args == ProcessArgs{"docker", "pull", "--platform", "linux/amd64", TrustedImage}) return {outputLimit, 180};
    if (args == sandboxCommand({"--entrypoint", "sha256sum", TrustedImage, "/usr/bin/amneziawg-go"})
        || args == sandboxCommand({"--entrypoint", "/usr/bin/amneziawg-go", TrustedImage, "--version"})
        || args == sandboxCommand({"--entrypoint", "sh", TrustedImage, "-c",
            "set -eu; for tool in awg awg-quick amneziawg-go iptables ip sleep mv cat cut sha256sum; do "
            "command -v \"$tool\" >/dev/null; done; printf ready"})) return {outputLimit, 30};
    reject();
}
std::string trustedImageRuntimeRequest(const std::string &raw, ProcessRunner &runner) {
    PlannerJson request;
    try { request = plannerJson(raw, inputLimit); }
    catch (...) { reject(); }
    json_object *op = nullptr;
    if (!json_object_is_type(request.get(), json_type_object)
        || json_object_object_length(request.get()) != 1
        || !json_object_object_get_ex(request.get(), "op", &op)
        || !op || !json_object_is_type(op, json_type_string)
        || std::string_view(json_object_get_string(op), json_object_get_string_len(op)) != "resolve") reject();
    CheckedRunner checked(runner);
    const auto image = resolveTrustedImage(checked);
    if (image != TrustedImage) reject();
    PlannerJson result(json_object_new_object());
    json_object_object_add(result.get(), "result", json_object_new_string(TrustedImage));
    return json_object_to_json_string_ext(result.get(), JSON_C_TO_STRING_PLAIN);
}
int trustedImageJsonMain() {
    try {
        DockerRunner runner;
        std::cout << trustedImageRuntimeRequest(readInput(), runner) << '\n';
        return 0;
    } catch (const PlannerError &error) {
        const std::set<std::string> allowed = {"unsupported_server_architecture", "image_fetch_unavailable", "trusted_image_unavailable"};
        const std::string code = allowed.count(error.code()) ? error.code() : "native_trusted_image_rejected";
        std::cout << "{\"error\":\"" << code << "\"}\n";
        return 2;
    } catch (...) {
        std::cout << "{\"error\":\"native_trusted_image_rejected\"}\n";
        return 2;
    }
}
}
