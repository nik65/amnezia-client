// Test-only executable. Every execve is replaced; real Docker is never invoked.
#include "test_ready_runtime_data.h"
#include "ready_config_runtime.h"
#include "control_runtime.h"
#include "network_topology_runtime.h"
#include "automatic_runtime.h"
#include "trusted_image_runtime.h"
#include "config_generation_runtime.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
using namespace amnezia::awgMigration;
namespace {
std::map<int, int> sockets;
unsigned socketOpened = 0, socketClosed = 0;
bool socketFailure = false, optionFailure = false, invalidSocketCall = false;
std::string imageMode = "success";
bool generationRandomFailure = false;
}
// Test-only RNG interposer; runtime targets link the real OpenSSL implementation.
extern "C" int RAND_priv_bytes(unsigned char *buffer, int count) {
    if (generationRandomFailure || count != 32) return 0;
    std::memset(buffer, 'c', static_cast<std::size_t>(count));
    return 1;
}
// Test-only syscall replacements: no network socket or actual bind is created.
extern "C" int socket(int family, int type, int protocol) noexcept {
    if (socketFailure) { errno = EMFILE; return -1; }
    if ((family != AF_INET && family != AF_INET6) || type != (SOCK_DGRAM | SOCK_CLOEXEC) || protocol) {
        invalidSocketCall = true; errno = EINVAL; return -1;
    }
    const int fd = static_cast<int>(::syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY | O_CLOEXEC, 0));
    if (fd >= 0) { sockets.emplace(fd, family); ++socketOpened; }
    return fd;
}
extern "C" int setsockopt(int fd, int level, int option, const void *value, socklen_t size) noexcept {
    if (!sockets.count(fd) || sockets.at(fd) != AF_INET6 || level != IPPROTO_IPV6
        || option != IPV6_V6ONLY || size != sizeof(int) || *static_cast<const int *>(value) != 1) {
        invalidSocketCall = true; errno = EINVAL; return -1;
    }
    if (optionFailure) { errno = EINVAL; return -1; }
    return 0;
}
extern "C" int bind(int fd, const sockaddr *address, socklen_t size) noexcept {
    if (!sockets.count(fd)) { invalidSocketCall = true; errno = EBADF; return -1; }
    unsigned port = 0;
    if (sockets.at(fd) == AF_INET && address->sa_family == AF_INET && size == sizeof(sockaddr_in)) {
        const auto *v4 = reinterpret_cast<const sockaddr_in *>(address);
        if (v4->sin_addr.s_addr != INADDR_ANY || sockets.size() != 1) invalidSocketCall = true;
        port = ntohs(v4->sin_port);
    } else if (sockets.at(fd) == AF_INET6 && address->sa_family == AF_INET6 && size == sizeof(sockaddr_in6)) {
        const auto *v6 = reinterpret_cast<const sockaddr_in6 *>(address);
        const in6_addr any{};
        if (std::memcmp(&v6->sin6_addr, &any, sizeof any) || sockets.size() != 2) invalidSocketCall = true;
        port = ntohs(v6->sin6_port);
    } else invalidSocketCall = true;
    if (invalidSocketCall || (port == 60001 && sockets.at(fd) == AF_INET)
        || (port == 60002 && sockets.at(fd) == AF_INET6)) { errno = EADDRINUSE; return -1; }
    return 0;
}
extern "C" int close(int fd) {
    if (sockets.erase(fd)) ++socketClosed;
    return static_cast<int>(::syscall(SYS_close, fd));
}
[[noreturn]] static void output(const std::string &text, int status = 0) {
    std::size_t done = 0;
    while (done < text.size()) {
        const auto size = ::write(STDOUT_FILENO, text.data() + done, text.size() - done);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) _exit(112);
        done += static_cast<std::size_t>(size);
    }
    _exit(status);
}
extern "C" int execve(const char *path, char *const argv[], char *const[]) noexcept {
    try {
        if (std::strcmp(path, "/usr/bin/ss") == 0) {
            if (std::string(argv[0]) != "/usr/bin/ss" || !argv[1] || !argv[2] || argv[3]
                || std::string(argv[1]) != "-H" || std::string(argv[2]) != "-uan") _exit(110);
            output("UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n");
        }
        if (std::strcmp(path, "/usr/bin/docker")) _exit(110);
        ProcessArgs args;
        for (std::size_t n = 0; argv[n]; ++n) {
            if (n > 32) _exit(110);
            args.emplace_back(argv[n]);
        }
        if (args.empty() || args[0] != "/usr/bin/docker") _exit(110);
        auto catalog = args;
        catalog[0] = "docker";
        if (catalog == ProcessArgs{"docker", "info", "--format", "{{json .}}"}) {
            if (imageMode == "architecture-failure") output("{\"OSType\":\"linux\",\"Architecture\":\"arm64\"}");
            output("{\"OSType\":\"linux\",\"Architecture\":\"amd64\"}");
        }
        if (catalog == ProcessArgs{"docker", "image", "inspect", TrustedImage}) {
            if (imageMode == "fetch-failure" || imageMode == "identity-failure") output("[]");
            output("[{\"Id\":\"" + std::string(TrustedImageId) + "\",\"RepoDigests\":[\"" + TrustedImage
                + "\"],\"Os\":\"linux\",\"Architecture\":\"amd64\"}]");
        }
        if (catalog == ProcessArgs{"docker", "pull", "--platform", "linux/amd64", TrustedImage})
            output("", imageMode == "fetch-failure" ? 1 : 0);
        auto sandbox = trustedSandboxArgs();
        if (catalog.size() > sandbox.size() && std::equal(sandbox.begin(), sandbox.end(), catalog.begin())) {
            // The runtime's same exact allowlist checks every fixed sandbox tail.
            static_cast<void>(trustedImageCommandLimits(catalog));
            if (catalog[sandbox.size() + 1] == "sha256sum")
                output(imageMode == "hash-failure" ? "owned-wrong-hash" : std::string(TrustedBinarySha256) + "  /usr/bin/amneziawg-go\n");
            if (catalog[sandbox.size() + 1] == "/usr/bin/amneziawg-go")
                output(imageMode == "version-failure" ? "owned-wrong-version" : TrustedReportedVersion);
            output(imageMode == "tools-failure" ? "owned-not-ready" : "ready");
        }
        if (args == ProcessArgs{"/usr/bin/docker", "ps", "-q"}) output("aaaaaaaaaaaa\n");
        if (args == ProcessArgs{"/usr/bin/docker", "inspect", "aaaaaaaaaaaa"})
            // Legitimate opaque text must survive JSON decoding as literal text,
            // while an actual decoded NUL remains rejected by plannerJson.
            output(R"([{"Config":{"Env":["OWNED=literal\\u0000"]},"NetworkSettings":{"Ports":{"5454/udp":[{"HostPort":"5454"}]}}}])" "\n");
        std::string id;
        if (args.size() == 5 && args[1] == "inspect" && args[2] == "--format" && args[3] == ReadyInspectFormat) id = args[4];
        else if (args.size() >= 3 && args[1] == "exec") id = args[2];
        if (id.size() != 64 || id != std::string(64, id.front()) || id.front() < 'a' || id.front() > 'f') _exit(110);
        const char mode = id.front();
        if (mode == 'f') _exit(1);
        if (args.size() == 5 && args[1] == "inspect")
            output(readyTest::metadata(id, mode == 'e' ? "2026-10-21T00:00:01.000000000Z" : readyTest::epoch) + '\n');
        if (args == ProcessArgs{"/usr/bin/docker", "exec", id, "awg", "show", "awg0", "dump"}) {
            auto text = readyTest::dump(mode == 'b');
            if (mode == 'd') text[0] = static_cast<char>(0xff);
            output(text);
        }
        if (args == ProcessArgs{"/usr/bin/docker", "exec", id, "awg", "showconf", "awg0"}) output(readyTest::showconf(mode == 'c'));
        if (args == ProcessArgs{"/usr/bin/docker", "exec", id, "sh", "-c", ReadyEngineProbe})
            output(std::string(TrustedBinarySha256) + "  /proc/100/exe\n");
        _exit(110);
    } catch (...) { _exit(111); }
}
int main(int argc, char **argv) {
    if (argc == 2 && std::string(argv[1]) == "--network-json") return networkTopologyJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--control-json") return controlJsonMain();
    if (argc == 2 && (std::string(argv[1]) == "--automatic-json"
        || std::string(argv[1]) == "--automatic-socket-failure-json"
        || std::string(argv[1]) == "--automatic-option-failure-json")) {
        socketFailure = std::string(argv[1]) == "--automatic-socket-failure-json";
        optionFailure = std::string(argv[1]) == "--automatic-option-failure-json";
        const int result = automaticJsonMain();
        return sockets.empty() && socketOpened == socketClosed && !invalidSocketCall ? result : 113;
    }
    if (argc == 2) {
        const std::string option = argv[1];
        if (option == "--trusted-image-json") return trustedImageJsonMain();
        for (const auto *mode : {"architecture-failure", "fetch-failure", "identity-failure", "hash-failure", "version-failure", "tools-failure"}) {
            if (option == "--trusted-image-" + std::string(mode) + "-json") {
                imageMode = mode;
                return trustedImageJsonMain();
            }
        }
    }
    if (argc == 2 && (std::string(argv[1]) == "--generate-config-json"
        || std::string(argv[1]) == "--generate-config-rng-failure-json")) {
        generationRandomFailure = std::string(argv[1]) == "--generate-config-rng-failure-json";
        return generationJsonMain();
    }
    if (argc == 2 && std::string(argv[1]) == "--config-json") return configJsonMain();
    if (argc == 2 && std::string(argv[1]) == "--ready-json") return readyJsonMain();
    return 2;
}
