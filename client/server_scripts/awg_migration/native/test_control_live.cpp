// Actual production verifyLiveControlMain with inert syscall boundaries.
// Every OS/proc/directory/link/socket/process boundary is a link-time fake
// installed before the real entry runs. No proc, network, socket, namespace,
// service or product code is executed.
#include "control_live.h"
#include "control_loaded.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace amnezia::awgMigration::controlPid1;
namespace {
const std::string executableSha = "64531077024b8fe57566a3d556ef54fd598bab2e0ca49b43185f765a6a86cb5d";
const char *validTcp =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 00000000:46A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0\n";
std::string receipt, receiptSha, tcpTable = validTcp, statValue = "12345";
std::vector<std::pair<std::string, std::string>> fdLinks;
bool drift = false, driftDuringListener = false;
int statOpenCount = 0, unexpected = 0, procFdOpens = 0, fdDirectoryOpens = 0;
std::map<int, std::size_t> offsets;

std::string statLine(const std::string &start) {
    std::string raw = "1 (awg-feed) S";
    for (int field = 3; field < 22; ++field) raw += field == 21 ? " " + start : " 0";
    return raw;
}
std::string bytes(int fd) {
    if (fd == 100) return receipt;
    if (fd == 101) return statLine(statValue);
    if (fd == 102) return std::string(128, 'X');
    if (fd == 103) return tcpTable;
    return {};
}
int denied() { ++unexpected; errno = EPERM; return -1; }

struct FakeDir { int index; };
FakeDir fakeDir;
} // namespace

extern "C" {
int __wrap_open(const char *path, int, ...) {
    const std::string name(path ? path : "");
    int fd = -1;
    if (name == "fixture-receipt") fd = 100;
    else if (name == "/proc/1/stat") {
        fd = 101;
        ++statOpenCount;
        statValue = (drift && statOpenCount >= 3) ? "99999" : "12345";
    } else if (name == "/proc/1/fd/12") {
        ++procFdOpens;
        fd = 102;
    } else if (name == "/proc/net/tcp") {
        fd = 103;
        if (driftDuringListener) drift = true;
    }
    else return denied();
    offsets[fd] = 0;
    return fd;
}
int __wrap_fstat(int fd, struct stat *out) {
    const std::string data = bytes(fd);
    if (data.empty() || !out) { errno = EBADF; return -1; }
    std::memset(out, 0, sizeof(*out));
    out->st_mode = S_IFREG | (fd == 100 ? 0600 : 0500);
    out->st_uid = 1000;
    out->st_gid = 1000;
    out->st_nlink = 1;
    out->st_dev = 17;
    out->st_ino = static_cast<ino_t>(fd);
    out->st_size = static_cast<off_t>(data.size());
    return 0;
}
ssize_t __wrap_read(int fd, void *buffer, size_t size) {
    const std::string data = bytes(fd);
    auto &offset = offsets[fd];
    if (data.empty()) { errno = EBADF; return -1; }
    const auto begin = std::min(offset, data.size());
    const auto count = std::min(size, data.size() - begin);
    std::memcpy(buffer, data.data() + begin, count);
    offset += count;
    return static_cast<ssize_t>(count);
}
ssize_t __wrap_pread(int fd, void *buffer, size_t size, off_t offset) {
    const std::string data = bytes(fd);
    if (data.empty() || offset < 0) { errno = EBADF; return -1; }
    const auto begin = std::min(static_cast<size_t>(offset), data.size());
    const auto count = std::min(size, data.size() - begin);
    std::memcpy(buffer, data.data() + begin, count);
    return static_cast<ssize_t>(count);
}
int __wrap_close(int) { return 0; }
uid_t __wrap_geteuid() { return 1000; }
int __wrap_fcntl(int fd, int command, ...) {
    if (fd == 102 && command == F_GET_SEALS) return requiredSeals;
    return denied();
}
DIR *__wrap_opendir(const char *path) {
    if (path && std::string(path) == "/proc/1/fd") {
        ++fdDirectoryOpens;
        fakeDir.index = 0;
        return reinterpret_cast<DIR *>(&fakeDir);
    }
    ++unexpected;
    errno = EPERM;
    return nullptr;
}
struct dirent *__wrap_readdir(DIR *directory) {
    if (directory != reinterpret_cast<DIR *>(&fakeDir)) { errno = EBADF; return nullptr; }
    if (fakeDir.index >= static_cast<int>(fdLinks.size())) return nullptr;
    static struct dirent entry;
    std::memset(&entry, 0, sizeof(entry));
    const auto &link = fdLinks[static_cast<std::size_t>(fakeDir.index++)];
    entry.d_type = DT_LNK;
    entry.d_ino = static_cast<ino_t>(fakeDir.index);
    std::strncpy(entry.d_name, link.first.c_str(), sizeof(entry.d_name) - 1);
    return &entry;
}
int __wrap_closedir(DIR *directory) {
    return directory == reinterpret_cast<DIR *>(&fakeDir) ? 0 : denied();
}
ssize_t __wrap_readlink(const char *path, char *buffer, size_t size) {
    const std::string name(path ? path : "");
    const std::string prefix = "/proc/1/fd/";
    if (name.compare(0, prefix.size(), prefix) != 0 || !buffer) return denied();
    const std::string entry = name.substr(prefix.size());
    for (const auto &link : fdLinks) {
        if (link.first != entry) continue;
        const auto count = std::min(size, link.second.size());
        std::memcpy(buffer, link.second.data(), count);
        return static_cast<ssize_t>(count);
    }
    errno = ENOENT;
    return -1;
}
// No socket/process/namespace/control operation may be attempted.
int __wrap_socket(int, int, int) { return denied(); }
int __wrap_bind(int, const void *, unsigned) { return denied(); }
int __wrap_listen(int, int) { return denied(); }
int __wrap_accept4(int, void *, void *, int) { return denied(); }
int __wrap_connect(int, const void *, unsigned) { return denied(); }
int __wrap_poll(void *, unsigned long, int) { return denied(); }
ssize_t __wrap_send(int, const void *, size_t, int) { return denied(); }
int __wrap_shutdown(int, int) { return denied(); }
int __wrap_uname(void *) { return denied(); }
int __wrap_memfd_create(const char *, unsigned) { return denied(); }
int __wrap_fsync(int) { return denied(); }
int __wrap_fchmod(int, unsigned) { return denied(); }
int __wrap_unlink(const char *) { return denied(); }
int __wrap_rename(const char *, const char *) { return denied(); }
ssize_t __wrap_write(int, const void *, size_t) { return denied(); }
int __wrap_dup(int) { return denied(); }
int __wrap_execve(const char *, char *const[], char *const[]) { return denied(); }
int __wrap_fork() { return denied(); }
int __wrap_clone(int (*)(void *), void *, int, void *, int *) { return denied(); }
int __wrap_unshare(int) { return denied(); }
int __wrap_setns(int, int) { return denied(); }
} // extern "C"

namespace {
void reset() {
    statOpenCount = 0;
    procFdOpens = 0;
    fdDirectoryOpens = 0;
    drift = false;
    driftDuringListener = false;
    statValue = "12345";
    receiptSha = executableSha;
    receipt = receiptJson(LoadedControl{"target", "12345", receiptSha, 12});
    tcpTable = validTcp;
    fdLinks = {{"0", "/dev/null"},
               {"1", "/dev/null"},
               {"12", "/memfd:awg-control (deleted)"},
               {"777", "socket:[777]"}};
    offsets.clear();
}
int failures = 0;
void expect(const char *name, int expected) {
    const int actual = verifyLiveControlMain("target", executableSha, "fixture-receipt");
    const bool okay = actual == expected && (expected != 0 || (procFdOpens > 0 && fdDirectoryOpens > 0));
    std::cout << name << " actual=" << actual << " expected=" << expected
              << " held_proc_fd_opens=" << procFdOpens << " fd_dir_scans=" << fdDirectoryOpens << "\n";
    if (!okay) ++failures;
}
} // namespace

int main(int argc, char **argv) {
    reset();
    expect("valid-pid1-owned-listener", 0);

    reset(); tcpTable =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    expect("absent-listener", 4);

    reset(); tcpTable =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:46A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0\n";
    expect("wrong-address-loopback", 4);

    reset(); tcpTable =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:46A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0\n"
        "   1: 0100007F:46A2 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 888 1 0000000000000000 100 0 0 10 0\n";
    fdLinks.push_back({"888", "socket:[888]"});
    expect("concurrent-established-connection", 0);

    reset(); tcpTable =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:46A3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0\n";
    expect("wrong-port", 4);

    reset(); tcpTable =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:46A2 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0\n";
    expect("wrong-state-established", 4);

    reset(); tcpTable =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:46A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 999 1 0000000000000000 100 0 0 10 0\n";
    expect("foreign-socket-inode", 4);

    reset(); tcpTable =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:46A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 nope 1 0000000000000000 100 0 0 10 0\n";
    expect("malformed-proc-tcp", 4);

    reset(); fdLinks[3].second = "socket:[not-a-number]";
    expect("malformed-fd-link", 4);

    reset(); drift = true;
    expect("pid1-incarnation-drift", 4);

    reset(); driftDuringListener = true;
    expect("pid1-incarnation-drift-during-listener", 4);

    reset(); receiptSha = std::string(64, 'a');
    receipt = receiptJson(LoadedControl{"target", "12345", receiptSha, 12});
    expect("loaded-receipt-digest-mismatch", 3);

    reset();
    const int invalid = verifyLiveControlMain("helper", executableSha, "fixture-receipt");
    std::cout << "invalid-role actual=" << invalid << " expected=2\n";
    if (invalid != 2 || statOpenCount != 0) ++failures;

    if (unexpected) {
        std::cerr << "unexpected OS boundary calls=" << unexpected << "\n";
        ++failures;
    }
    if (argc >= 2 && std::string(argv[1]) == "--fail-work") return 23;
    return failures ? 1 : 0;
}
