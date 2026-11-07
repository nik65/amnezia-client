#include "control_live.h"

#include "control_pid1.h"

#include <algorithm>
#include <cerrno>

#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace amnezia::awgMigration::controlPid1 {
namespace {
// Fixed procfs paths only. No caller-supplied path, symlink target, process
// handle, namespace, socket or control operation is ever used here.
constexpr const char *statPath = "/proc/1/stat";
constexpr const char *tcpPath = "/proc/net/tcp";
constexpr const char *fdDirectoryPath = "/proc/1/fd";
constexpr std::size_t maxStatBytes = 4096;
constexpr std::size_t maxTcpBytes = 256 * 1024;
constexpr std::size_t maxFdEntries = 8192;
constexpr std::size_t maxLinkBytes = 4096;
constexpr std::size_t maxFields = 32;
constexpr std::size_t maxRows = 65536;
constexpr const char *listenAddress = "00000000";
constexpr const char *listenPort = "46A2";
constexpr const char *listenState = "0A";

[[noreturn]] void reject() { throw std::runtime_error("native_control_live_rejected"); }

std::string readFixed(const char *path, std::size_t limit) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) reject();
    std::string raw;
    char buffer[4096];
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            ::close(fd);
            reject();
        }
        if (count == 0) break;
        raw.append(buffer, static_cast<std::size_t>(count));
        if (raw.size() > limit) {
            ::close(fd);
            reject();
        }
    }
    if (::close(fd) != 0) reject();
    return raw;
}

// Same field-21 (kernel starttime) extraction as the existing PosixAttestOps.
std::string observeProcessStart() {
    const std::string raw = readFixed(statPath, maxStatBytes);
    std::size_t field = 0, position = 0;
    std::string value;
    while (position < raw.size()) {
        while (position < raw.size() && (raw[position] == ' ' || raw[position] == '\n')) ++position;
        const auto begin = position;
        while (position < raw.size() && raw[position] != ' ' && raw[position] != '\n') ++position;
        if (begin == position) break;
        if (field == 21) {
            value = raw.substr(begin, position - begin);
            break;
        }
        ++field;
    }
    if (value.empty() || value.size() > 20 || value.find_first_not_of("0123456789") != std::string::npos)
        reject();
    return value;
}

bool hex(const std::string &value, std::size_t length) {
    return value.size() == length && value.find_first_not_of("0123456789ABCDEF") == std::string::npos;
}
bool decimal(const std::string &value) {
    return !value.empty() && value.find_first_not_of("0123456789") == std::string::npos;
}

std::vector<std::string> fields(const std::string &line) {
    std::vector<std::string> result;
    std::size_t position = 0;
    while (position < line.size()) {
        while (position < line.size() && (line[position] == ' ' || line[position] == '\t')) ++position;
        if (position >= line.size()) break;
        const auto begin = position;
        while (position < line.size() && line[position] != ' ' && line[position] != '\t') ++position;
        result.push_back(line.substr(begin, position - begin));
        if (result.size() > maxFields) reject();
    }
    return result;
}

// Exact set of socket inodes referenced by PID1's own open descriptors.
std::set<std::string> pid1SocketInodes() {
    DIR *directory = ::opendir(fdDirectoryPath);
    if (!directory) reject();
    std::set<std::string> owned;
    std::size_t entries = 0;
    for (;;) {
        errno = 0;
        const struct dirent *entry = ::readdir(directory);
        if (!entry) {
            if (errno != 0) {
                ::closedir(directory);
                reject();
            }
            break;
        }
        if (++entries > maxFdEntries) {
            ::closedir(directory);
            reject();
        }
        const std::string name(entry->d_name);
        if (name.empty()) {
            ::closedir(directory);
            reject();
        }
        if (name == "." || name == "..") continue;
        if (!decimal(name)) {
            ::closedir(directory);
            reject();
        }
        const std::string linkPath = std::string(fdDirectoryPath) + "/" + name;
        char target[maxLinkBytes + 1] = {};
        const ssize_t length = ::readlink(linkPath.c_str(), target, maxLinkBytes);
        if (length <= 0 || static_cast<std::size_t>(length) >= maxLinkBytes) {
            ::closedir(directory);
            reject();
        }
        const std::string link(target, static_cast<std::size_t>(length));
        if (link.size() > 9 && link.compare(0, 8, "socket:[") == 0 && link.back() == ']') {
            const std::string inode = link.substr(8, link.size() - 9);
            if (!decimal(inode)) {
                ::closedir(directory);
                reject();
            }
            owned.insert(inode);
        }
    }
    if (::closedir(directory) != 0) reject();
    return owned;
}

// Existing Python predicate, made strict: every row for port 46A2 must be the
// wildcard IPv4 LISTEN address in PID1's descriptor set, and one must exist.
void requireOwnedListener(const std::set<std::string> &owned) {
    const std::string raw = readFixed(tcpPath, maxTcpBytes);
    bool header = false;
    std::size_t rows = 0, matched = 0;
    std::size_t begin = 0;
    while (begin <= raw.size()) {
        auto end = raw.find('\n', begin);
        if (end == std::string::npos) end = raw.size();
        const std::string line = raw.substr(begin, end - begin);
        begin = end + 1;
        if (line.empty()) {
            if (end == raw.size()) break;
            continue;
        }
        if (!header) {
            if (line.find("local_address") == std::string::npos
                || line.find("inode") == std::string::npos
                || line.find("st") == std::string::npos) reject();
            header = true;
            continue;
        }
        if (++rows > maxRows) reject();
        const auto columns = fields(line);
        if (columns.size() < 10) reject();
        const std::string &address = columns[1];
        const std::string &state = columns[3];
        const std::string &inode = columns[9];
        if (address.size() != 13 || address[8] != ':' || !hex(address.substr(0, 8), 8)
            || !hex(address.substr(9), 4) || !hex(state, 2) || !decimal(inode)) reject();
        if (address.substr(9) != listenPort) continue;
        // Accepted connections also carry the service port with a concrete
        // local address; only the wildcard binding is the listener identity.
        if (address.substr(0, 8) != listenAddress) continue;
        if (state != listenState) reject();
        if (!owned.count(inode)) reject();
        if (++matched > 64) reject();
    }
    if (!header || matched == 0) reject();
}
} // namespace

int verifyLiveControlMain(const std::string &role, const std::string &expectedSha256,
                          const std::string &receiptPath) {
    if ((role != "source" && role != "target") || expectedSha256.size() != 64
        || expectedSha256.find_first_not_of("0123456789abcdef") != std::string::npos
        || receiptPath.empty()) return 2;
    try {
        // Existing loaded-control gate, unchanged and still the first decision.
        const std::string before = observeProcessStart();
        const int loaded = verifyLoadedControlMain(role, expectedSha256, receiptPath);
        if (loaded != 0) return loaded;
        // The receipt's captured starttime was just checked against PID1; the
        // same incarnation must survive the whole verification.
        const std::string after = observeProcessStart();

        if (before.empty() || after.empty() || before != after) return 4;
        requireOwnedListener(pid1SocketInodes());
        if (observeProcessStart() != before) return 4;
        return 0;
    } catch (...) {
        return 4;
    }
}

LiveArgv parseVerifyControlLiveArgv(int argc, char **argv, std::string &role,
                                    std::string &sha256, std::string &receiptPath) {
    if (argc < 2 || !argv || !argv[1]) return LiveArgv::NotLive;
    if (std::string(argv[1]) != "--verify-control-live") return LiveArgv::NotLive;
    if (argc != 5 || !argv[2] || !argv[3] || !argv[4]) return LiveArgv::Invalid;
    // Same role/digest bounds as the loaded gate; verified again by the entry.
    const std::string candidate(argv[2]), digest(argv[3]), path(argv[4]);
    if ((candidate != "source" && candidate != "target") || digest.size() != 64
        || digest.find_first_not_of("0123456789abcdef") != std::string::npos || path.empty())
        return LiveArgv::Invalid;
    role = candidate;
    sha256 = digest;
    receiptPath = path;
    return LiveArgv::VerifyLive;
}

bool runVerifyControlLiveArgv(int argc, char **argv, int &status) {
    std::string role, sha256, receiptPath;
    const LiveArgv mode = parseVerifyControlLiveArgv(argc, argv, role, sha256, receiptPath);
    if (mode == LiveArgv::NotLive) return false;
    status = mode == LiveArgv::Invalid ? 2 : verifyLiveControlMain(role, sha256, receiptPath);
    return true;
}
} // namespace amnezia::awgMigration::controlPid1
