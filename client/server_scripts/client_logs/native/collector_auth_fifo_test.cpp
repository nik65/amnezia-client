// Deterministically replace only this owned fixture between lstat and open.
#include "collector_store.h"
#include <cstdarg>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

static std::string replacePath;
static bool replaced = false;
extern "C" int __real_open(const char *, int, ...);
extern "C" int __wrap_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    if (!replacePath.empty() && replacePath == path && !(flags & O_CREAT)) {
        replacePath.clear();
        if (::unlink(path) || ::mkfifo(path, 0600))
            throw std::runtime_error("owned FIFO fixture replacement failed");
        replaced = true;
    }
    return __real_open(path, flags, mode);
}
int main()
{
    char name[] = "/tmp/amnezia-auth-fifo-test-XXXXXX";
    const char *made = ::mkdtemp(name);
    if (!made)
        return 1;
    const std::filesystem::path root(made);
    struct Cleanup {
        std::filesystem::path root;
        ~Cleanup() { std::filesystem::remove_all(root); }
    } cleanup { root };
    const auto path = root / "tokens.tsv";
    std::ofstream(path) << std::string(64, 'a') << "\ttest-token\n";
    amnezia::collector::CollectorOptions options;
    options.root = root;
    amnezia::collector::Collector collector(options);
    amnezia::collector::HttpRequest request;
    request.method = "POST";
    request.target = "/logs";
    request.peer = "127.0.0.1";
    request.headers = { { "x-amnezia-client-id", std::string(64, 'a') },
                        { "x-amnezia-log-token", "test-token" },
                        { "x-amnezia-batch-id", std::string(64, 'b') } };
    replacePath = path;
    const auto response = collector.preflight(request);
    return response.status == 503 && replaced && replacePath.empty() && std::filesystem::is_fifo(path) ? 0 : 1;
}
