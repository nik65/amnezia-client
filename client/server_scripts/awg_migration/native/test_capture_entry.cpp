// Actual productionMain with accepted feed+collector argv; stop at the real
// read-only planner boundary. UID0 is an explicit metadata MODEL only. No root
// filesystem, Docker, process, namespace or network acceptance is claimed.
#include "prepare_entry.h"
#include "test_default_transport.h"
#include <openssl/evp.h>
#include <cerrno>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <sys/socket.h>
extern "C" int __real_fstat(int, struct stat *);
extern "C" int __wrap_fstat(int fd, struct stat *st) {
    const int result = __real_fstat(fd, st);
    if (result == 0 && S_ISREG(st->st_mode)) st->st_uid = 0;
    return result;
}
extern "C" {
uid_t geteuid() noexcept { return 0; }
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
std::string digestFile(const char *path) {
    std::ifstream stream(path, std::ios::binary);
    std::string bytes{std::istreambuf_iterator<char>(stream), {}};
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
    if (!stream.eof() && stream.fail()) throw std::runtime_error("own test input read");
    EVP_Digest(bytes.data(), bytes.size(), digest, &length, EVP_sha256(), nullptr);
    std::ostringstream out;
    for (unsigned i = 0; i < length; ++i) out << std::hex << std::setfill('0') << std::setw(2) << unsigned(digest[i]);
    return out.str();
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    // Build outputs inherit the invoking umask; capture requires an explicit
    // deployment mode. Stage only test-owned copies rather than chmod shared
    // build artifacts or relaxing the production metadata checks.
    std::string temporary = (std::filesystem::temp_directory_path() / "awg-capture-entry-XXXXXX").string();
    if (!::mkdtemp(temporary.data())) return 2;
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code error; std::filesystem::remove_all(path, error); } } cleanup{temporary};
    const auto feed = (std::filesystem::path(temporary) / "awg-feed").string();
    const auto collector = (std::filesystem::path(temporary) / "collector").string();
    std::filesystem::copy_file(argv[1], feed);
    std::filesystem::copy_file(argv[2], collector);
    if (::chmod(feed.c_str(), 0755) != 0 || ::chmod(collector.c_str(), 0755) != 0) return 2;
    auto &state = defaultFixture::state();
    state.mode = "first-io";
    std::vector<std::string> values{"awg-native-prepare", "--source", "amnezia-awg", "--host", "example.invalid",
        "--automatic", "--native-control", "--native-feed", feed, "--native-feed-sha256", digestFile(feed.c_str()),
        "--native-collector", collector, "--native-collector-sha256", digestFile(collector.c_str())};
    std::vector<char *> args;
    for (auto &value : values) args.push_back(value.data());
    std::ostringstream captured;
    auto *previous = std::cout.rdbuf(captured.rdbuf());
    const int status = amnezia::awgMigration::prepareEntry::productionMain(static_cast<int>(args.size()), args.data());
    std::cout.rdbuf(previous);
    const bool passed = status == 23 && state.sentinel && state.plannerInfoCalls == 1
        && captured.str().find("trusted_image_unavailable") != std::string::npos && !state.fatal;
    std::cout << "actual_default_collector_capture status=" << status << " calls=" << state.calls.size()
        << " planner=" << state.plannerInfoCalls << " boundary=" << state.sentinel
        << " production_success=false\n" << captured.str();
    return passed ? 0 : 1;
}
