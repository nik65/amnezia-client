// Actual production entry, automatic request, first external IO regression.
// Every OS/process/socket boundary is fenced at link time before entry. The
// transport answers the read-only observation and then stops at the first
// planner IO, so a GREEN run proves the production planner is dispatched while
// still performing no Docker/process/socket operation.
#include "prepare_entry.h"
#include "test_default_transport.h"
#include <cerrno>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/socket.h>

namespace amnezia::awgMigration::prepareEntry {
int productionMain(int argc, char **argv);
}

extern "C" {
uid_t geteuid() noexcept { return 0; }  // inert UID0 model, not root FS acceptance
int socket(int, int, int) noexcept { errno = EPERM; return -1; }
int connect(int, const sockaddr *, socklen_t) noexcept { errno = EPERM; return -1; }
int bind(int, const sockaddr *, socklen_t) noexcept { errno = EPERM; return -1; }
int listen(int, int) noexcept { errno = EPERM; return -1; }
int setsockopt(int, int, int, const void *, socklen_t) noexcept { errno = EPERM; return -1; }
pid_t fork() noexcept { errno = EPERM; return -1; }
int execve(const char *, char *const[], char *const[]) noexcept { errno = EPERM; return -1; }
int unshare(int) noexcept { errno = EPERM; return -1; }
int setns(int, int) noexcept { errno = EPERM; return -1; }
}

int main(int argc, char **argv) {
    if (argc != 2) { std::cerr << "fixture base required\n"; return 2; }
    (void)argv;
    defaultFixture::State &state = defaultFixture::state();
    state.mode = "first-io";
    std::vector<std::string> values = {"awg-native-prepare", "--source", "amnezia-awg",
        "--host", "example.invalid", "--automatic"};
    std::vector<char *> args;
    for (auto &value : values) args.push_back(const_cast<char *>(value.c_str()));

    std::ostringstream captured;
    std::streambuf *previous = std::cout.rdbuf(captured.rdbuf());
    const int status = amnezia::awgMigration::prepareEntry::productionMain(static_cast<int>(args.size()), args.data());
    std::cout.rdbuf(previous);
    const std::string output = captured.str();

    int failures = 0;
    auto check = [&](bool value, const char *name) {
        if (!value) { std::cerr << "FAIL " << name << "\n"; ++failures; }
    };
#ifdef FIRST_IO_FIXED
    // GREEN: the automatic request passes validation, performs the real
    // read-only observation and dispatches planAutomatic. Its first planner IO
    // (Docker host info) is the single simulated external boundary.
    check(status == 23, "green exit 23");
    check(state.sentinel, "green planner first IO reached");
    check(state.plannerInfoCalls == 1, "green exactly one planner IO");
    check(state.calls.size() > 10, "green real observation ran");
    check(output.find("trusted_image_unavailable") != std::string::npos,
          "green planner failure code");
    std::cout << "FIRST_IO_GREEN status=" << status << " calls=" << state.calls.size()
              << " plannerIo=" << state.plannerInfoCalls << " sentinel=" << state.sentinel
              << " failure=trusted_image_unavailable\n";
#else
    // RED: the unchanged production entry passes no planner, so the sequencer
    // rejects the automatic request before observe/plan: zero external IO.
    check(status == 23, "red exit 23");
    check(!state.sentinel, "red never reached planner IO");
    check(state.plannerInfoCalls == 0, "red no planner IO");
    check(state.calls.empty(), "red zero external IO");
    check(output.find("native_automatic_rejected") != std::string::npos,
          "red dispatch rejection code");
    std::cout << "FIRST_IO_RED status=" << status << " calls=" << state.calls.size()
              << " plannerIo=" << state.plannerInfoCalls
              << " failure=native_automatic_rejected\n";
#endif
    if (state.fatal) std::cerr << "FATAL " << state.fatalDetail << "\n";
    return failures ? 1 : 0;
}
