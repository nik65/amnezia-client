#include "anchor_storage.hpp"

#include <QCryptographicHash>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <set>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace headless_anchor {
namespace {
constexpr std::size_t maximumWorkerBytes = 8u * 1024u * 1024u;
constexpr const char* protocol = "headless-journal-v1\n";
void check(bool ok, const char* message) { if (!ok) throw Error(message); }
void point(const Fault& fault, const char* name) { if (fault) fault(name); }
struct Fd {
    int value = -1;
    explicit Fd(int fd) : value(fd) { check(fd >= 0, "anchor open failed"); }
    ~Fd() { if (value >= 0) ::close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value(std::exchange(other.value, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            if (value >= 0) ::close(value);
            value = std::exchange(other.value, -1);
        }
        return *this;
    }
};
struct stat metadata(int fd) {
    struct stat result {};
    check(::fstat(fd, &result) == 0, "anchor fstat failed");
    return result;
}
bool canonicalSha(const std::string& sha) {
    if (sha.size() != 64) return false;
    for (const char c : sha) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
std::vector<std::string> components(const std::string& path) {
    check(path.size() > 1 && path.front() == '/' && path.back() != '/'
          && path.find('\0') == std::string::npos, "anchor path must be absolute/canonical");
    std::vector<std::string> result;
    std::size_t start = 1;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto part = path.substr(start, end == std::string::npos ? end : end - start);
        check(!part.empty() && part != "." && part != "..", "anchor path has unsafe components");
        result.push_back(part);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}
void directoryMetadata(int fd, uid_t uid, bool exactPrivate) {
    const auto st = metadata(fd);
    check(S_ISDIR(st.st_mode), "anchor path is not a directory");
    if (exactPrivate) {
        check(st.st_uid == uid && (st.st_mode & 07777) == 0700,
              "anchor directory is not owner-private mode 0700");
    } else {
        // A root-owned sticky shared ancestor (normally /tmp) may contain a
        // private source snapshot. The final source/anchor directory is stricter.
        const bool stickyShared = st.st_uid == 0 && (st.st_mode & S_ISVTX)
                && (st.st_mode & S_IWOTH) && !(st.st_mode & (S_ISUID | S_ISGID));
        check((st.st_uid == 0 || st.st_uid == uid)
              && (!(st.st_mode & 0022) || stickyShared)
              && !(st.st_mode & (S_ISUID | S_ISGID)), "unsafe anchor/source ancestor");
    }
}
// createTail is used only for the fixed anchor namespace's last two directories.
// Missing source/transaction directories are never created by this traversal.
Fd openDirectory(const std::string& path, uid_t uid, std::size_t createTail) {
    const auto parts = components(path);
    Fd current(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    directoryMetadata(current.value, uid, false);
    for (std::size_t index = 0; index < parts.size(); ++index) {
        int next = ::openat(current.value, parts[index].c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 && errno == ENOENT && createTail != 0 && parts.size() - index <= createTail) {
            check(::mkdirat(current.value, parts[index].c_str(), 0700) == 0, "anchor mkdir failed");
            check(::fsync(current.value) == 0, "anchor parent directory fsync failed");
            next = ::openat(current.value, parts[index].c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        Fd opened(next);
        directoryMetadata(opened.value, uid, createTail != 0 && parts.size() - index <= createTail);
        current = std::move(opened);
    }
    return current;
}
bool existsAt(int parent, const std::string& name) {
    struct stat st {};
    if (::fstatat(parent, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) return true;
    check(errno == ENOENT, "anchor entry stat failed");
    return false;
}
void requireNoTransaction(const Policy& policy) {
    Fd current(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    directoryMetadata(current.value, policy.expectedUid, false);
    for (const auto& part : components(policy.transactionRoot)) {
        const int next = ::openat(current.value, part.c_str(),
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 && errno == ENOENT) return;
        Fd opened(next);
        directoryMetadata(opened.value, policy.expectedUid, false);
        current = std::move(opened);
    }
    check(!existsAt(current.value, ".headless-provisioning-journal.json")
          && !existsAt(current.value, ".headless-provisioning-recovery-required"),
          "anchor installation refuses active provisioning journal/recovery marker");
}
void regularMetadata(const struct stat& st, uid_t uid, mode_t mode) {
    check(S_ISREG(st.st_mode) && st.st_uid == uid && (st.st_mode & 07777) == mode
          && st.st_nlink == 1, "anchor file is not an isolated owner-private regular file");
}
void requireProvisioningLock(const Policy& policy) {
    // Borrow the inherited descriptor. Never wrap it in an owning RAII handle,
    // close it or unlock it: the installer retains this same OFD through exit.
    const auto inherited = metadata(policy.lockFd);
    regularMetadata(inherited, policy.expectedUid, 0600);
    const auto parts = components(policy.lockPath);
    const auto separator = policy.lockPath.rfind('/');
    check(separator != 0, "anchor provisioning lock path is unsafe");
    Fd parent = openDirectory(policy.lockPath.substr(0, separator), policy.expectedUid, 0);
    const auto parentInfo = metadata(parent.value);
    check(parentInfo.st_uid == policy.expectedUid && !(parentInfo.st_mode & 0022)
          && !(parentInfo.st_mode & (S_ISUID | S_ISGID | S_ISVTX)), "anchor provisioning lock parent is unsafe");
    Fd named(::openat(parent.value, parts.back().c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    const auto namedInfo = metadata(named.value);
    regularMetadata(namedInfo, policy.expectedUid, 0600);
    check(inherited.st_dev == namedInfo.st_dev && inherited.st_ino == namedInfo.st_ino,
          "anchor inherited provisioning lock does not match the fixed lock inode");
    check(::flock(policy.lockFd, LOCK_EX | LOCK_NB) == 0,
          "anchor inherited provisioning lock is not exclusively held");
}
void writeAll(int fd, const char* bytes, std::size_t length) {
    while (length != 0) {
        const ssize_t written = ::write(fd, bytes, length);
        if (written < 0 && errno == EINTR) continue;
        check(written > 0, "anchor write failed");
        bytes += written;
        length -= static_cast<std::size_t>(written);
    }
}
bool stable(const struct stat& before, const struct stat& after) {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino
            && before.st_size == after.st_size && before.st_uid == after.st_uid
            && before.st_mode == after.st_mode
            && before.st_mtim.tv_sec == after.st_mtim.tv_sec
            && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec
            && before.st_ctim.tv_sec == after.st_ctim.tv_sec
            && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}
std::string copyOrHash(int source, int destination) {
    QCryptographicHash hash(QCryptographicHash::Sha256);
    std::array<char, 65536> buffer {};
    std::size_t size = 0;
    while (true) {
        const ssize_t count = ::read(source, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        check(count >= 0, "anchor read failed");
        if (count == 0) break;
        size += static_cast<std::size_t>(count);
        check(size <= maximumWorkerBytes, "anchor worker exceeds 8 MiB");
        hash.addData(QByteArrayView(buffer.data(), count));
        if (destination >= 0) writeAll(destination, buffer.data(), static_cast<std::size_t>(count));
    }
    check(size != 0, "anchor worker is empty");
    return hash.result().toHex().toStdString();
}
std::string readSmall(int parent, const char* name, uid_t uid, std::size_t maximum) {
    Fd fd(::openat(parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    const auto before = metadata(fd.value);
    regularMetadata(before, uid, 0600);
    check(before.st_size >= 0 && static_cast<uint64_t>(before.st_size) <= maximum, "anchor record exceeds bound");
    std::string bytes;
    std::array<char, 128> buffer {};
    while (true) {
        const ssize_t count = ::read(fd.value, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        check(count >= 0, "anchor record read failed");
        if (count == 0) break;
        bytes.append(buffer.data(), static_cast<std::size_t>(count));
        check(bytes.size() <= maximum, "anchor record changed beyond bound");
    }
    check(stable(before, metadata(fd.value)), "anchor record changed while reading");
    return bytes;
}
void requireExactGeneration(int root, const std::string& sha, uid_t uid) {
    Fd generation(::openat(root, ("payload-" + sha).c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    directoryMetadata(generation.value, uid, true);
    DIR* entries = ::fdopendir(::dup(generation.value));
    check(entries != nullptr, "anchor generation enumeration failed");
    std::set<std::string> names;
    bool unexpectedEntry = false;
    errno = 0;
    while (auto* entry = ::readdir(entries)) {
        const std::string name(entry->d_name);
        if (name != "." && name != "..") {
            if (name != "worker" && name != "PIN") {
                unexpectedEntry = true;
                break;
            }
            names.insert(name); // At most the two fixed names, never an unbounded scan.
        }
        errno = 0;
    }
    const int directoryError = errno;
    ::closedir(entries);
    check(!unexpectedEntry && directoryError == 0 && names == std::set<std::string>{"worker", "PIN"},
          "anchor generation contains unexpected entries");
    check(readSmall(generation.value, "PIN", uid, 65) == sha + "\n", "anchor independent pin is invalid");
    Fd worker(::openat(generation.value, "worker", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    const auto before = metadata(worker.value);
    regularMetadata(before, uid, 0700);
    check(before.st_size > 0 && static_cast<uint64_t>(before.st_size) <= maximumWorkerBytes,
          "anchor worker has invalid size");
    check(copyOrHash(worker.value, -1) == sha && stable(before, metadata(worker.value)),
          "anchor worker does not match its independent pin");
}
void requireCurrentValid(int root, uid_t uid) {
    if (!existsAt(root, "CURRENT")) return;
    const auto current = readSmall(root, "CURRENT", uid, 128);
    const std::string header(protocol);
    check(current.size() == header.size() + 65 && current.compare(0, header.size(), header) == 0
          && current.back() == '\n', "anchor CURRENT is not canonical");
    const auto sha = current.substr(header.size(), 64);
    check(canonicalSha(sha), "anchor CURRENT has invalid digest");
    requireExactGeneration(root, sha, uid);
}
std::string temporaryName(const char* prefix) {
    static std::atomic<unsigned long> sequence {0};
    return std::string(prefix) + std::to_string(::getpid()) + "-" + std::to_string(++sequence);
}
struct Pending {
    int parent;
    std::string name;
    bool directory;
    bool active = true;
    ~Pending() {
        if (!active) return;
        if (directory) {
            const int fd = ::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (fd >= 0) {
                ::unlinkat(fd, "worker", 0);
                ::unlinkat(fd, "PIN", 0);
                ::close(fd);
            }
            ::unlinkat(parent, name.c_str(), AT_REMOVEDIR);
        } else {
            ::unlinkat(parent, name.c_str(), 0);
        }
        // The operation is already failing. Failure to retire an unexpected
        // pending entry does not turn that failure into a success/clean receipt.
        ::fsync(parent);
    }
};
bool durableFile(int parent, const char* name, const std::string& bytes, bool allowCollision = false) {
    const int opened = ::openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (opened < 0 && errno == EEXIST && allowCollision) return false;
    Fd fd(opened);
    Pending pending {parent, name, false};
    check(::fchmod(fd.value, 0600) == 0, "anchor pin chmod failed");
    writeAll(fd.value, bytes.data(), bytes.size());
    check(::fsync(fd.value) == 0, "anchor pin fsync failed");
    pending.active = false;
    return true;
}
}

void install(const Policy& policy, const std::string& source,
             const std::string& expectedSha256, Fault fault) {
    check(::geteuid() == policy.expectedUid, "anchor installation requires its fixed owner");
    check(canonicalSha(expectedSha256), "anchor expected digest must be 64 lowercase hexadecimal characters");
    requireProvisioningLock(policy);
    requireNoTransaction(policy);
    auto path = components(source);
    const auto leaf = path.back();
    const auto separator = source.rfind('/');
    check(separator != 0, "anchor source requires a private parent directory");
    Fd sourceParent = openDirectory(source.substr(0, separator), policy.expectedUid, 0);
    const auto parentMetadata = metadata(sourceParent.value);
    check(parentMetadata.st_uid == policy.expectedUid && !(parentMetadata.st_mode & 0022)
          && !(parentMetadata.st_mode & (S_ISUID | S_ISGID | S_ISVTX)), "anchor source parent is not private");
    Fd input(::openat(sourceParent.value, leaf.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    const auto before = metadata(input.value);
    check(S_ISREG(before.st_mode) && before.st_uid == policy.expectedUid
          && ((before.st_mode & 07777) == 0755 || (before.st_mode & 07777) == 0700)
          && before.st_size > 0 && static_cast<uint64_t>(before.st_size) <= maximumWorkerBytes,
          "anchor source is not a bounded owner-private executable");
    Fd root = openDirectory(policy.root, policy.expectedUid, 2);
    Fd lock(::openat(root.value, ".install.lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600));
    regularMetadata(metadata(lock.value), policy.expectedUid, 0600);
    check(::flock(lock.value, LOCK_EX | LOCK_NB) == 0, "anchor installation is already running");
    requireCurrentValid(root.value, policy.expectedUid);
    const auto generationName = "payload-" + expectedSha256;
    if (existsAt(root.value, generationName)) {
        requireExactGeneration(root.value, expectedSha256, policy.expectedUid);
        check(copyOrHash(input.value, -1) == expectedSha256 && stable(before, metadata(input.value)),
              "anchor source does not match the independently supplied digest");
    } else {
        std::string pendingName;
        bool created = false;
        for (unsigned attempt = 0; attempt < 64; ++attempt) {
            pendingName = temporaryName(".pending-");
            if (::mkdirat(root.value, pendingName.c_str(), 0700) == 0) {
                created = true;
                break;
            }
            check(errno == EEXIST, "anchor staging directory create failed");
        }
        check(created, "anchor staging name collision limit exceeded");
        Pending pending {root.value, pendingName, true};
        Fd stage(::openat(root.value, pendingName.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        check(::fchmod(stage.value, 0700) == 0, "anchor staging mode failed");
        directoryMetadata(stage.value, policy.expectedUid, true);
        Fd output(::openat(stage.value, "worker", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0700));
        point(fault, "worker-copy");
        check(copyOrHash(input.value, output.value) == expectedSha256
              && stable(before, metadata(input.value)), "anchor source does not match the independently supplied digest");
        check(::fchmod(output.value, 0700) == 0, "anchor worker chmod failed");
        point(fault, "worker-fsync");
        check(::fsync(output.value) == 0, "anchor worker fsync failed");
        durableFile(stage.value, "PIN", expectedSha256 + "\n");
        point(fault, "generation-fsync");
        check(::fsync(stage.value) == 0, "anchor generation fsync failed");
        point(fault, "generation-rename");
        check(::syscall(SYS_renameat2, root.value, pendingName.c_str(), root.value,
                        generationName.c_str(), RENAME_NOREPLACE) == 0, "anchor generation publication failed");
        pending.active = false;
        check(::fsync(root.value) == 0, "anchor root fsync after generation publication failed");
    }
    point(fault, "generation-published");
    requireExactGeneration(root.value, expectedSha256, policy.expectedUid);
    std::string currentName;
    bool created = false;
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        currentName = temporaryName(".CURRENT-");
        if (durableFile(root.value, currentName.c_str(), std::string(protocol) + expectedSha256 + "\n", true)) {
            created = true;
            break;
        }
    }
    check(created, "anchor CURRENT name collision limit exceeded");
    Pending pendingCurrent {root.value, currentName, false};
    point(fault, "current-rename");
    requireProvisioningLock(policy);
    requireNoTransaction(policy);
    requireCurrentValid(root.value, policy.expectedUid);
    check(::renameat(root.value, currentName.c_str(), root.value, "CURRENT") == 0, "anchor CURRENT selection failed");
    pendingCurrent.active = false;
    point(fault, "current-directory-fsync");
    check(::fsync(root.value) == 0, "anchor CURRENT directory fsync failed");
}
}
