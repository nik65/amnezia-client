#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

// Test-only library. Refuses mutation outside its explicit private /tmp fixture.
extern "C" ssize_t read(int fd, void *buffer, size_t count) {
    using Read = ssize_t (*)(int, void *, size_t);
    static auto real = reinterpret_cast<Read>(dlsym(RTLD_NEXT, "read"));
    if (!real) { errno = EIO; return -1; }
    const auto n = real(fd, buffer, count);
    static bool swapped = false;
    const char *target = std::getenv("AWG_OWNED_JOURNAL"), *replacement = std::getenv("AWG_OWNED_REPLACEMENT");
    if (n != 0 || swapped || !target || !replacement) return n;
    const std::string file(target), other(replacement), prefix("/tmp/awg-planner-read-audit-");
    if (file.compare(0, prefix.size(), prefix) || other != file + ".replacement") return n;
    char descriptor[64], path[4096];
    std::snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd);
    const auto length = readlink(descriptor, path, sizeof path);
    if (length < 0 || std::string(path, static_cast<std::size_t>(length)) != file) return n;
    struct stat source {}, next {};
    if (lstat(file.c_str(), &source) || lstat(other.c_str(), &next)
        || !S_ISREG(source.st_mode) || !S_ISREG(next.st_mode)
        || source.st_uid != geteuid() || next.st_uid != geteuid()) return n;
    if (rename(other.c_str(), file.c_str())) _exit(72);
    swapped = true;
    return n;
}
