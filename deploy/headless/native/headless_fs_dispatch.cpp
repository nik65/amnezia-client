// Linux-only, deliberately no installer, shell, network or service operations.
#include <array>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include "journal/journal.hpp"
#include "headless_fs_dispatch.h"

namespace {
struct Fd {
    int value;
    explicit Fd(int v) : value(v) { if (v < 0) throw std::runtime_error("open failed"); }
    ~Fd() { ::close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct stat metadata(int fd) {
    struct stat st {};
    require(::fstat(fd, &st) == 0, "fstat failed");
    return st;
}
void syncPath(const char* path, bool directory) {
    Fd fd(::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
                       | (directory ? O_DIRECTORY : 0)));
    const auto st = metadata(fd.value);
    require(directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode), "unexpected fsync path type");
    require(::fsync(fd.value) == 0, "fsync failed");
}
void elf(const char* path) {
    Fd fd(::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    require(S_ISREG(metadata(fd.value).st_mode), "ELF input is not regular");
    std::array<unsigned char, 20> bytes {};
    std::size_t used = 0;
    while (used < bytes.size()) {
        const auto n = ::read(fd.value, bytes.data() + used, bytes.size() - used);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "truncated ELF header");
        used += static_cast<std::size_t>(n);
    }
    require(bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F'
            && bytes[4] == 2 && (bytes[5] == 1 || bytes[5] == 2), "not ELF64");
    const unsigned machine = bytes[5] == 1 ? bytes[18] + 256u * bytes[19]
                                          : 256u * bytes[18] + bytes[19];
    require(machine == 62, "not x86_64");
}
gid_t runtimeGroup() {
    const group* entry = ::getgrnam("amnezia");
    require(entry != nullptr, "amnezia group missing");
    return entry->gr_gid;
}
void validate(const struct stat& st, const std::string& name, bool root) {
    const auto mode = st.st_mode & 07777;
    if (!root && name == "amneziad.sock" && S_ISSOCK(st.st_mode)) {
        require(st.st_uid == 0 && st.st_gid == runtimeGroup() && mode == 0660, "unsafe runtime socket");
    } else if (!root && name == "amneziad.sock.lock" && S_ISREG(st.st_mode)) {
        require(st.st_uid == 0 && st.st_gid == runtimeGroup()
                && (mode == 0600 || mode == 0640 || mode == 0660), "unsafe runtime lock");
    } else {
        require(S_ISREG(st.st_mode) || S_ISDIR(st.st_mode), "unsupported tree entry");
        require(st.st_uid == 0 && !(st.st_mode & 0022), "tree entry not root-owned/private");
    }
}
void tree(int parent, const char* name, bool root, unsigned depth) {
    require(depth < 256, "tree nesting limit exceeded");
    Fd fd(::openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    validate(metadata(fd.value), "", root);
    DIR* entries = ::fdopendir(::dup(fd.value));
    require(entries != nullptr, "directory enumeration failed");
    try {
        errno = 0;
        while (auto* item = ::readdir(entries)) {
            const std::string child(item->d_name);
            if (child == "." || child == "..") continue;
            struct stat st {};
            require(::fstatat(fd.value, child.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0, "tree stat failed");
            // Socket/lock exceptions belong only to the root's immediate children.
            validate(st, root ? child : "", false);
            if (S_ISDIR(st.st_mode)) tree(fd.value, child.c_str(), false, depth + 1);
            errno = 0;
        }
        require(errno == 0, "directory read failed");
    } catch (...) { ::closedir(entries); throw; }
    ::closedir(entries);
}
}
int headless_fs::dispatch(int argc, char** argv) {
    try {
        if (argc >= 2 && std::string(argv[1]).rfind("journal-",0) == 0) {
            QStringList args;
            for (int i=1;i<argc;++i) args.append(QString::fromLocal8Bit(argv[i]));
            return headless_journal::dispatch(args);
        }
        require(argc == 3, "usage: amnezia-headless-fs COMMAND PATH");
        const std::string command(argv[1]);
        if (command == "fsync-directory") syncPath(argv[2], true);
        else if (command == "fsync-file") syncPath(argv[2], false);
        else if (command == "verify-elf64-x86-64") elf(argv[2]);
        else if (command == "verify-root-private-tree") {
            tree(AT_FDCWD, argv[2], true, 0);
        } else throw std::runtime_error("unknown command");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "headless native check: " << error.what() << '\n';
        return 1;
    }
}
