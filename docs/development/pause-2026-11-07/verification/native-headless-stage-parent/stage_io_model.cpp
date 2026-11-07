// Test-only lstat boundary. No UID, namespace, ownership or host state is changed.
// Only an exact parent-pinned owned directory is reported with MODEL uid0.
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" int __real_lstat(const char *, struct stat *);
namespace {
unsigned role_stats = 0;
bool number(const char *text, unsigned long long &value) {
    if (!text || !*text) return false;
    value = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        const auto old = value; value = value * 10 + unsigned(*p - '0');
        if (value < old) return false;
    }
    return true;
}
}
extern "C" int __wrap_lstat(const char *path, struct stat *metadata) {
    const char *swap = std::getenv("W_ROLE_SWAP_PATH");
    if (swap && path && std::strcmp(path, swap) == 0 && ++role_stats == 3) {
        // This is the actual source-copy lstat, after the role digest check.
        // Mutate one byte in an owned extracted DATA copy, never the archive.
        const int fd = ::open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        unsigned char byte = 0;
        if (fd < 0 || ::pread(fd, &byte, 1, 0) != 1) _exit(97);
        byte ^= 1;
        if (::pwrite(fd, &byte, 1, 0) != 1 || ::fsync(fd) != 0) _exit(98);
        ::close(fd);
        std::fprintf(stderr, "MODEL_ROLE_SWAP_BEFORE_COPY\n");
    }
    const int status = __real_lstat(path, metadata);
    const char *root = std::getenv("W_PRIVATE_MODEL_ROOT");
    if (status == 0 && root && path && std::strcmp(path, root) == 0) {
        unsigned long long dev = 0, ino = 0;
        if (!number(std::getenv("W_PRIVATE_MODEL_DEV"), dev)
            || !number(std::getenv("W_PRIVATE_MODEL_INO"), ino)
            || !S_ISDIR(metadata->st_mode) || metadata->st_uid != ::getuid()
            || static_cast<unsigned long long>(metadata->st_dev) != dev
            || static_cast<unsigned long long>(metadata->st_ino) != ino) {
            errno = ESTALE; return -1;
        }
        metadata->st_uid = 0; // Explicit MODEL ONLY; real metadata is unchanged.
    }
    return status;
}
