#include "bounded_docker.h"
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
pid_t owner = -1;
const char *fault = "none";
int marker = -1;
struct stat parentStdout {}, ownedStdin {}, ownedStderr {};
struct Event {
    int expectedExecutable = 0;
    int stdinInherited = 0;
    int stderrInherited = 0;
    int stdoutInherited = 0;
    int stdoutNonblocking = 0;
    int stdinBytes = 0;
};
bool childFault(const char *name) { return getpid() != owner && std::strcmp(fault, name) == 0; }
bool same(int fd, const struct stat &expected) {
    struct stat actual {};
    return fstat(fd, &actual) == 0 && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino;
}
}
extern "C" int __real_open(const char *, int, ...);
extern "C" int __real_dup2(int, int);
extern "C" int __real_fcntl(int, int, ...);
extern "C" int __wrap_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); mode = static_cast<mode_t>(va_arg(args, int)); va_end(args);
    }
    if (childFault("open-null") && std::strcmp(path, "/dev/null") == 0) { errno = EMFILE; return -1; }
    return __real_open(path, flags, mode);
}
extern "C" int __wrap_dup2(int oldfd, int newfd) {
    if ((childFault("dup2-stdin") && newfd == STDIN_FILENO)
        || (childFault("dup2-stdout") && newfd == STDOUT_FILENO)
        || (childFault("dup2-stderr") && newfd == STDERR_FILENO)) { errno = EBADF; return -1; }
    return __real_dup2(oldfd, newfd);
}
extern "C" int __wrap_fcntl(int fd, int operation, ...) {
    if (operation == F_GETFL) {
        if (childFault("fcntl-getfl")) { errno = EBADF; return -1; }
        return __real_fcntl(fd, operation);
    }
    va_list args; va_start(args, operation); const int value = va_arg(args, int); va_end(args);
    if (childFault("fcntl-setfl") && operation == F_SETFL) { errno = EBADF; return -1; }
    return __real_fcntl(fd, operation, value);
}
// Link-time-only interposer: no actual executable can be launched by this probe.
extern "C" int __wrap_execve(const char *path, char *const[], char *const[]) noexcept {
    Event event;
    event.expectedExecutable = std::strcmp(path, "/usr/bin/docker") == 0;
    event.stdinInherited = same(STDIN_FILENO, ownedStdin);
    event.stderrInherited = same(STDERR_FILENO, ownedStderr);
    event.stdoutInherited = same(STDOUT_FILENO, parentStdout);
    const int flags = __real_fcntl(STDOUT_FILENO, F_GETFL);
    event.stdoutNonblocking = flags >= 0 && (flags & O_NONBLOCK) != 0;
    char buffer[64];
    event.stdinBytes = static_cast<int>(read(STDIN_FILENO, buffer, sizeof buffer));
    constexpr char stderrText[] = "owned-stderr-marker";
    const auto stderrWritten = write(STDERR_FILENO, stderrText, sizeof stderrText - 1);
    if (stderrWritten != sizeof stderrText - 1) _exit(10);
    if (write(marker, &event, sizeof event) != sizeof event) _exit(9);
    _exit(0);
}
// Belt-and-braces test guard: accidental loss of --wrap=execve still cannot
// execute Docker. This symbol exists only in the standalone test executable.
extern "C" int execve(const char *path, char *const argv[], char *const env[]) noexcept {
    return __wrap_execve(path, argv, env);
}
int main(int argc, char **argv) {
    alarm(10);
    owner = getpid();
    if (argc != 2) return 2;
    fault = argv[1];
    int input[2], error[2], events[2];
    if (pipe(input) || pipe(error) || pipe(events)) return 3;
    const int savedInput = dup(STDIN_FILENO), savedError = dup(STDERR_FILENO);
    if (savedInput < 0 || savedError < 0 || fstat(STDOUT_FILENO, &parentStdout)) return 4;
    constexpr char inputText[] = "owned-stdin-sentinel";
    if (write(input[1], inputText, sizeof inputText - 1) != sizeof inputText - 1) return 5;
    close(input[1]);
    if (__real_dup2(input[0], STDIN_FILENO) < 0 || __real_dup2(error[1], STDERR_FILENO) < 0) return 6;
    close(input[0]); close(error[1]);
    if (fstat(STDIN_FILENO, &ownedStdin) || fstat(STDERR_FILENO, &ownedStderr)) return 7;
    marker = events[1];
    bool returned = false, rejected = false;
    try {
        // This argv is inert and no real exec occurs: every execve is intercepted.
        static_cast<void>(amnezia::awgMigration::runBoundedDocker({"docker", "owned-test-only"}, 1024));
        returned = true;
    } catch (const amnezia::awgMigration::BoundedDockerError &) { rejected = true; }
    if (__real_dup2(savedInput, STDIN_FILENO) < 0 || __real_dup2(savedError, STDERR_FILENO) < 0) return 8;
    close(savedInput); close(savedError); close(events[1]);
    Event event;
    const auto eventSize = read(events[0], &event, sizeof event);
    close(events[0]);
    char stderrBytes[128]; const auto stderrSize = read(error[0], stderrBytes, sizeof stderrBytes); close(error[0]);
    if (eventSize != 0 && eventSize != sizeof event) return 9;
    std::cout << "{\"mode\":\"" << fault << "\",\"transportReturned\":" << returned
              << ",\"transportRejected\":" << rejected << ",\"fakeExecReached\":" << (eventSize == sizeof event)
              << ",\"expectedExecutable\":" << event.expectedExecutable
              << ",\"stdinInherited\":" << event.stdinInherited << ",\"stdinReadBytes\":" << event.stdinBytes
              << ",\"stderrInherited\":" << event.stderrInherited << ",\"stderrCapturedBytes\":" << stderrSize
              << ",\"stdoutInherited\":" << event.stdoutInherited << ",\"stdoutNonblocking\":" << event.stdoutNonblocking
              << ",\"actualExecCalls\":0}\n";
    const bool control = std::strcmp(fault, "none") == 0;
    const bool reached = eventSize == sizeof event;
    if (control)
        return returned && !rejected && reached && event.expectedExecutable
            && !event.stdinInherited && !event.stderrInherited && !event.stdoutInherited
            && !event.stdoutNonblocking && event.stdinBytes == 0 && stderrSize == 0 ? 0 : 11;
    return !returned && rejected && !reached && stderrSize == 0 ? 0 : 12;
}
