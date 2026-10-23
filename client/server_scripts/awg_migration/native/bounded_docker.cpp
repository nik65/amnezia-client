#include "bounded_docker.h"
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace amnezia::awgMigration {
namespace {
std::string runBoundedCommand(const std::vector<std::string> &a, const char *executable, std::size_t outputLimit, unsigned timeoutSeconds = 3) {
    if (a.empty() || !outputLimit || outputLimit > 16 * 1024 * 1024)
        throw BoundedDockerError();
    for (const auto &value : a)
        if (value.find('\0') != std::string::npos) throw BoundedDockerError();
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC | O_NONBLOCK))
        throw BoundedDockerError(BoundedDockerFailureKind::Os);
    const pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) {
        close(pipes[0]);
        close(pipes[1]);
        throw BoundedDockerError(BoundedDockerFailureKind::Os);
    }
    if (!pid) {
        // Stay in the helper session group: wrapper cancellation reaches every child.
        // PDEATHSIG also covers helper-only death. The identity recheck closes the
        // fork/prctl race where the parent dies before the kernel installs the signal.
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent)
            _exit(127);
        int flags = fcntl(pipes[1], F_GETFL);
        // Setup failure must never reach exec with inherited private descriptors.
        if (flags < 0 || fcntl(pipes[1], F_SETFL, flags & ~O_NONBLOCK) != 0
            || dup2(pipes[1], 1) < 0)
            _exit(127);
        int null = open("/dev/null", O_RDWR);
        if (null < 0 || dup2(null, 0) < 0 || dup2(null, 2) < 0)
            _exit(127);
        close(pipes[0]);
        close(pipes[1]);
        if (null > 2)
            close(null);
        auto command = a;
        command[0] = executable;
        std::vector<char *> args;
        for (auto &s : command)
            args.push_back(s.data());
        args.push_back(nullptr);
        char envPath[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
        char envLang[] = "LC_ALL=C";
        char *env[] = { envPath, envLang, nullptr };
        execve(args[0], args.data(), env);
        _exit(127);
    }
    close(pipes[1]);
    std::string result;
    bool ok = false;
    bool reaped = false;
    int status = 0;
    auto failure = BoundedDockerFailureKind::Timeout;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        char b[8192];
        ssize_t n = read(pipes[0], b, sizeof b);
        if (n > 0) {
            result.append(b, n);
            if (result.size() > outputLimit) {
                failure = BoundedDockerFailureKind::Other;
                break;
            }
            continue;
        }
        if (n == 0) {
            if (waitpid(pid, &status, WNOHANG) == pid) {
                reaped = true;
                ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
                failure = BoundedDockerFailureKind::Exit;
                break;
            }
        } else if (errno != EAGAIN && errno != EINTR) {
            failure = BoundedDockerFailureKind::Os;
            break;
        }
        pollfd f { pipes[0], POLLIN, 0 };
        // EOF is permanently readable as POLLHUP while the child may still run.
        // Sleep without that descriptor so a closed stdout cannot busy-spin.
        poll(n == 0 ? nullptr : &f, n == 0 ? 0 : 1, 20);
    }
    close(pipes[0]);
    if (!ok) {
        if (!reaped) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
            }
        }
        throw BoundedDockerError(failure);
    }
    return result;
}
}
std::string runBoundedDocker(const std::vector<std::string> &a, std::size_t outputLimit) {
    if (a.empty() || a.front() != "docker") throw BoundedDockerError();
    return runBoundedCommand(a, "/usr/bin/docker", outputLimit);
}
std::string runBoundedDockerWithBudget(const std::vector<std::string> &a, std::size_t outputLimit, unsigned timeoutSeconds) {
    if (a.empty() || a.front() != "docker" || outputLimit > 1024 * 1024
        || (timeoutSeconds != 10 && timeoutSeconds != 30 && timeoutSeconds != 180)) throw BoundedDockerError();
    return runBoundedCommand(a, "/usr/bin/docker", outputLimit, timeoutSeconds);
}
std::string runBoundedSs(std::size_t outputLimit) {
    if (outputLimit > 1024 * 1024) throw BoundedDockerError();
    return runBoundedCommand({"ss", "-H", "-uan"}, "/usr/bin/ss", outputLimit);
}
}
