#include "policy_runtime.h"
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
static int marker = -1;
// Test-only link interposer. No actual executable, Docker or server is invoked.
extern "C" int execve(const char *, char *const[], char *const[]) noexcept
{
    const pid_t own = getpid();
    if (write(marker, &own, sizeof own) != sizeof own)
        _exit(9);
    for (;;)
        pause();
}
int main(int argc, char **)
{
    alarm(10);
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0)
        return 2;
    int fds[2];
    if (pipe(fds))
        return 3;
    marker = fds[1];
    const pid_t helper = fork();
    if (helper < 0) {
        close(fds[0]);
        close(fds[1]);
        return 7;
    }
    if (!helper) {
        if (setsid() != getpid())
            _exit(8);
        amnezia::awgMigration::policy::runReadOnlyDocker({ "docker", "exec", "amnezia-awg", "ip", "rule", "show" });
        _exit(4);
    }
    close(fds[1]);
    pollfd p { fds[0], POLLIN, 0 };
    if (poll(&p, 1, 2000) <= 0) {
        kill(helper, SIGKILL);
        waitpid(helper, nullptr, 0);
        return 5;
    }
    pid_t simulatedDocker = -1;
    const auto markerSize = read(fds[0], &simulatedDocker, sizeof simulatedDocker);
    close(fds[0]);
    // Only the forked helper's verified session group may be signalled.
    if (markerSize != sizeof simulatedDocker || simulatedDocker <= 0 || simulatedDocker == helper
        || getpgid(helper) != helper || getsid(helper) != helper || getpgid(simulatedDocker) != helper) {
        if (getpgid(helper) == helper && getsid(helper) == helper)
            kill(-helper, SIGKILL);
        else
            kill(helper, SIGKILL);
        waitpid(helper, nullptr, 0);
        return 6;
    }
    kill(argc > 1 ? helper : -helper, SIGKILL);
    waitpid(helper, nullptr, 0);
    bool escaped = true;
    for (int n = 0; n < 100; ++n) {
        if (waitpid(simulatedDocker, nullptr, WNOHANG) == simulatedDocker) {
            escaped = false;
            break;
        }
        usleep(1000);
    }
    if (escaped) {
        kill(simulatedDocker, SIGKILL);
        waitpid(simulatedDocker, nullptr, 0);
    }
    std::cout << "readOnlyChildSurvivedWrapperGroupKill=" << escaped
              << " actualExecCalls=0 allOwnedChildrenReaped=true\n";
    return escaped ? 1 : 0;
}
