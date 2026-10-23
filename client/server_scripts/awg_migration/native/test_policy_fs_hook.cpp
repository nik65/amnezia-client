// Test-only LD_PRELOAD seam: deterministic mutation after the first pinned read.
// Requires an explicit owned fixture directory and action; never linked to policy.
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cstdlib>
#include <cstring>
#include <string>
extern "C" ssize_t read(int fd, void *buffer, size_t count) {
    using Read = ssize_t (*)(int, void *, size_t);
    static auto real = reinterpret_cast<Read>(dlsym(RTLD_NEXT, "read"));
    const auto result = real(fd, buffer, count);
    static bool changed = false;
    const char *root = std::getenv("POLICY_TEST_DIRECTORY");
    const char *action = std::getenv("POLICY_TEST_ACTION");
    if (!changed && result > 0 && root && action) {
        char path[4096];
        const auto size = ::readlink(("/proc/self/fd/" + std::to_string(fd)).c_str(), path, sizeof(path));
        const std::string expected = std::string(root) + "/rules.json";
        if (size > 0 && std::string(path, static_cast<std::size_t>(size)) == expected) {
            changed = true;
            if (!std::strcmp(action, "replace")) {
                ::rename((std::string(root) + "/replacement").c_str(), expected.c_str());
            } else if (!std::strcmp(action, "mutate")) {
                const int writer = ::open(expected.c_str(), O_WRONLY | O_CLOEXEC);
                if (writer < 0) std::_Exit(125);
                const char byte = ' ';
                const auto written = ::pwrite(writer, &byte, 1, 0);
                ::close(writer);
                if (written != 1) std::_Exit(125);
            } else if (!std::strcmp(action, "parent")) {
                ::rename(root, (std::string(root) + "-old").c_str());
                ::mkdir(root, 0700);
            }
        }
    }
    return result;
}
