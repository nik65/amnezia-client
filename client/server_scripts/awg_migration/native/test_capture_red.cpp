// Strict RED probe for capture-before-mutation, compilable against the
// unchanged baseline API. A wrong feed digest must fail BEFORE signing,
// generation, journal or any docker/ss call: the known late-capture defect
// leaves signing.pem and a generation directory behind.
#include "prepare_entry.h"
#include "production_ports.h"
#include "test_default_transport.h"
#include <openssl/evp.h>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

extern "C" {
int socket(int, int, int) noexcept { return ::open("/dev/null", O_RDWR | O_CLOEXEC); }
int setsockopt(int, int, int, const void *, socklen_t) noexcept { return 0; }
int bind(int, const sockaddr *, socklen_t) noexcept { return 0; }
int connect(int, const sockaddr *, socklen_t) noexcept { errno = EPERM; return -1; }
int listen(int, int) noexcept { errno = EPERM; return -1; }
pid_t fork() noexcept { errno = EPERM; return -1; }
int execve(const char *, char *const[], char *const[]) noexcept { errno = EPERM; return -1; }
int unshare(int) noexcept { errno = EPERM; return -1; }
}

namespace fs = std::filesystem;
using namespace amnezia::awgMigration;
namespace {
int failures = 0;
#define CHECK(c) do { if (!(c)) { std::cerr << "FAIL line " << __LINE__ << ": " #c "\n"; ++failures; } } while (0)
std::string sha256Hex(const std::string &bytes) {
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
    EVP_Digest(bytes.data(), bytes.size(), digest, &length, EVP_sha256(), nullptr);
    std::ostringstream out;
    for (unsigned i = 0; i < length; ++i) out << std::hex << std::setfill('0') << std::setw(2) << unsigned(digest[i]);
    return out.str();
}
std::string readAll(const fs::path &path) {
    std::ifstream stream(path, std::ios::binary); std::ostringstream out; out << stream.rdbuf(); return out.str();
}
void writeFile(const fs::path &path, const std::string &bytes, unsigned mode) {
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size())); stream.close();
    fs::permissions(path, static_cast<fs::perms>(mode), fs::perm_options::replace);
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 3) { std::cerr << "base static-elf required\n"; return 2; }
    const fs::path base = fs::absolute(argv[1]);
    const std::string staticElf = readAll(argv[2]);
    fs::remove_all(base); fs::create_directories(base);
    writeFile(base / "policy" / "rules.json",
              "{\"policy\":{\"revision\":7,\"contentSha256\":\"sha256:" + std::string(64, 'c') + "\"}}", 0644);
    writeFile(base / "updates" / "manifest.json", "{\"updates\":[]}", 0644);
    defaultFixture::State fresh;
    fresh.mode = "full";
    fresh.policyRoot = (base / "policy").string();
    fresh.updatesRoot = (base / "updates").string();
    defaultFixture::state() = std::move(fresh);
    const fs::path root = base / "bad-feed";
    fs::create_directories(root / "amnezia-awg");
    fs::permissions(root, fs::perms::owner_all, fs::perm_options::replace);
    fs::permissions(root / "amnezia-awg", fs::perms::owner_all, fs::perm_options::replace);
    const fs::path feed = base / "awg-feed";
    writeFile(feed, staticElf, 0755);
    const std::string wrong = sha256Hex("wrong");
    prepareProduction::ProductionPorts::DataPaths paths;
    paths.policyRoot = base / "policy"; paths.updatesRoot = base / "updates"; paths.feedOwner = ::getuid();
    prepareProduction::ProductionPorts ports(root, feed, wrong, paths);
    std::vector<std::string> values = {"awg-native-prepare", "--source", "amnezia-awg",
        "--host", "example.invalid", "--automatic", "--native-feed", feed.string(),
        "--native-feed-sha256", wrong};
    std::vector<char *> args;
    for (auto &value : values) args.push_back(const_cast<char *>(value.c_str()));
    const auto parsed = prepareEntry::parseArgv(static_cast<int>(args.size()), args.data());
    std::ostringstream captured; std::streambuf *previous = std::cout.rdbuf(captured.rdbuf());
    const int status = prepareEntry::run(parsed, root, ports, ports, &ports);
    std::cout.rdbuf(previous);
    // Capture must run before preflight eligibility and before any signing.
    CHECK(status == 23);
    CHECK(!fs::exists(root / "amnezia-awg" / "signing.pem"));
    CHECK(!fs::exists(root / "amnezia-awg" / "1"));
    CHECK(defaultFixture::state().calls.empty());
    std::cout << "RED_PROBE status=" << status << " calls=" << defaultFixture::state().calls.size()
              << " signer=" << fs::exists(root / "amnezia-awg" / "signing.pem") << "\n";
    std::cout << "RED_PROBE_FAILURES=" << failures << "\n";
    return failures ? 1 : 0;
}
