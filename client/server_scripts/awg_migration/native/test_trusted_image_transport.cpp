#include "bounded_docker.h"
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
using namespace amnezia::awgMigration;
namespace { const char *mode = "success"; pid_t owner = -1; unsigned polls = 0; }
extern "C" int poll(pollfd *fds, nfds_t count, int timeout) {
    if (getpid() == owner) ++polls;
    return static_cast<int>(::syscall(SYS_poll, fds, count, timeout));
}
// Test-only failure injection: no real Docker executable is reached.
extern "C" int pipe2(int fds[2], int flags) noexcept {
    if (std::strcmp(mode, "os") == 0) { errno = EMFILE; return -1; }
    return static_cast<int>(::syscall(SYS_pipe2, fds, flags));
}
extern "C" int execve(const char *path, char *const argv[], char *const[]) noexcept {
    if (std::strcmp(path, "/usr/bin/docker") || !argv[1] || std::strcmp(argv[1], "owned-test-only")) _exit(111);
    if (std::strcmp(mode, "timeout") == 0) for (;;) pause();
    if (std::strcmp(mode, "eof") == 0) { close(STDOUT_FILENO); usleep(300000); _exit(0); }
    if (std::strcmp(mode, "exit") == 0) _exit(17);
    const char *text = std::strcmp(mode, "cap") == 0 ? "owned text beyond cap" : "owned";
    if (write(STDOUT_FILENO, text, std::strlen(text)) != static_cast<ssize_t>(std::strlen(text))) _exit(112);
    _exit(0);
}
int main(int argc, char **argv) {
    alarm(8);
    if (argc != 2) return 2;
    mode = argv[1];
    owner = getpid();
    const auto started = std::chrono::steady_clock::now();
    try {
        const auto value = std::strcmp(mode, "timeout") == 0
            ? runBoundedDocker({"docker", "owned-test-only"}, 16)
            : runBoundedDockerWithBudget({"docker", "owned-test-only"}, 16, 10);
        if (std::strcmp(mode, "eof") == 0) {
            if (!value.empty() || polls >= 100
                || std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count() < .28) return 5;
        } else if (std::strcmp(mode, "success") || value != "owned") return 3;
    } catch (const BoundedDockerError &error) {
        const auto expected = std::strcmp(mode, "exit") == 0 ? BoundedDockerFailureKind::Exit
            : std::strcmp(mode, "timeout") == 0 ? BoundedDockerFailureKind::Timeout
            : std::strcmp(mode, "os") == 0 ? BoundedDockerFailureKind::Os : BoundedDockerFailureKind::Other;
        const bool expectedFailure = std::strcmp(mode, "exit") == 0 || std::strcmp(mode, "timeout") == 0
            || std::strcmp(mode, "os") == 0 || std::strcmp(mode, "cap") == 0;
        if (!expectedFailure || error.kind != expected) return 4;
    }
    std::cout << "owned transport case=" << mode << " PASS realDockerExec=0\n";
}
