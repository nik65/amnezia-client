// Private reachability probe: actual prepareEntry::run + real ProductionPorts,
// with ONE narrow EffectPort wrapper that injects a work failure at the first
// generation write. In "blocked" mode it also creates an owned 000 subdir inside
// the real generation directory so the real cleanup remove_all must fail EACCES.
// No product, CLI, installer, VPN, SSH, Docker, socket, service or process runs:
// the canonical Docker/ss boundary is the reviewed inert header fixture.
#include "prepare_entry.h"
#include "prepare_sequencer.h"
#include "production_ports.h"
#include "test_default_transport.h"
#include <openssl/evp.h>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
int setns(int, int) noexcept { errno = EPERM; return -1; }
}

namespace fs = std::filesystem;
using namespace amnezia::awgMigration;

namespace {
void writeFile(const fs::path &path, const std::string &bytes, unsigned mode) {
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    stream.close();
    fs::permissions(path, static_cast<fs::perms>(mode), fs::perm_options::replace);
}

// Owned 000 blocker: RAII restores permissions before the private FS is removed.
struct BlockerGuard {
    fs::path path;
    ~BlockerGuard() {
        std::error_code ec;
        if (!path.empty()) fs::permissions(path, fs::perms::owner_all,
                                           fs::perm_options::replace, ec);
    }
};

struct InjectingPort final : prepare::EffectPort {
    prepareProduction::ProductionPorts &real;
    std::string mode;
    bool fired = false;
    fs::path blocker;
    InjectingPort(prepareProduction::ProductionPorts &r, std::string m)
        : real(r), mode(std::move(m)) {}
    prepare::CommandResult command(const std::vector<std::string> &argv) override {
        return real.command(argv);
    }
    void write(const fs::path &path, const std::string &bytes, unsigned modeBits) override {
        if (!fired) {
            fired = true;
            if (mode == "blocked") {
                blocker = path.parent_path() / ".fixture-blocked";
                std::error_code ec;
                fs::create_directory(blocker, ec);
                { std::ofstream f(blocker / "residue.bin", std::ios::binary); f << "x"; }
                fs::permissions(blocker, fs::perms::none, fs::perm_options::replace, ec);
                std::cout << "INJECT target=" << path << " blocker=" << blocker
                          << " create_error=" << (ec ? ec.message() : "none") << "\n";
            } else {
                std::cout << "INJECT target=" << path << " blocker=none\n";
            }
            throw prepare::PrepareError("fixture_work_failure");
        }
        real.write(path, bytes, modeBits);
    }
    std::string signingPublicKey(const fs::path &directory) override {
        return real.signingPublicKey(directory);
    }
    prepare::Readiness ready(const prepare::SourceObservation &o,
                             const std::vector<std::string> &target,
                             const std::string &serverKey, bool automatic) override {
        return real.ready(o, target, serverKey, automatic);
    }
    void installNativeFeed(const fs::path &directory, const std::string &sha) override {
        real.installNativeFeed(directory, sha);
    }
    fs::path stageNativeControl(const fs::path &directory, const std::string &sha) override {
        return real.stageNativeControl(directory, sha);
    }
    void capturePayloads(const std::string &feed, const std::string &collector) override {
        real.capturePayloads(feed, collector);
    }
    fs::path stageNativeCollector(const fs::path &directory, const std::string &sha) override {
        return real.stageNativeCollector(directory, sha);
    }
    void pause(unsigned milliseconds) override { real.pause(milliseconds); }
    void verifyAutomaticPort(unsigned port) override { real.verifyAutomaticPort(port); }
};

prepareEntry::Parsed parse(const std::vector<std::string> &values) {
    std::vector<char *> args;
    for (auto &value : values) args.push_back(const_cast<char *>(value.c_str()));
    return prepareEntry::parseArgv(static_cast<int>(args.size()), args.data());
}
} // namespace

int main(int argc, char **argv) {
    if ((argc != 3 && argc != 4) || (argc == 4 && std::string(argv[3]) != "--fail-work")) return 2;
    if (::geteuid() == 0) { std::cerr << "nonroot fixture only\n"; return 2; }
    const fs::path base = fs::absolute(argv[1]).lexically_normal();
    const std::string mode = argv[2];
    if (mode != "clean" && mode != "blocked") return 2;
    const char *tmp = std::getenv("TMPDIR");
    if (!tmp || fs::canonical(base.parent_path()) != fs::canonical(tmp)
        || base.filename().string().rfind("cleanup-", 0) != 0
        || fs::exists(base) || fs::is_symlink(base)) return 2;
    // Exclusive attempt fixture only; never delete a prior run at startup.
    std::error_code cleanupEc;
    fs::create_directories(base);
    writeFile(base / "policy" / "rules.json",
              "{\"policy\":{\"revision\":7,\"contentSha256\":\"sha256:" + std::string(64, 'c') + "\"}}", 0644);
    writeFile(base / "updates" / "manifest.json", "{\"updates\":[]}", 0644);

    defaultFixture::State fresh;
    fresh.mode = "full";
    fresh.policyRoot = (base / "policy").string();
    fresh.updatesRoot = (base / "updates").string();
    defaultFixture::state() = std::move(fresh);

    const fs::path root = base / "run";
    fs::create_directories(root / "amnezia-awg");
    fs::permissions(root, fs::perms::owner_all, fs::perm_options::replace);
    fs::permissions(root / "amnezia-awg", fs::perms::owner_all, fs::perm_options::replace);
    prepareProduction::ProductionPorts::DataPaths paths;
    paths.policyRoot = base / "policy";
    paths.updatesRoot = base / "updates";
    paths.feedOwner = ::getuid();
    prepareProduction::ProductionPorts real(root, {}, {}, paths);
    InjectingPort effects(real, mode);
    BlockerGuard guard;

    const auto parsed = parse({"awg-native-prepare", "--source", "amnezia-awg",
        "--host", "example.invalid", "--image", "amnezia/awg@sha256:" + std::string(64, 'e'),
        "--port", "51821", "--generation", "1"});
    std::ostringstream captured;
    std::streambuf *previous = std::cout.rdbuf(captured.rdbuf());
    const int status = prepareEntry::run(parsed, root, real, effects, nullptr);
    std::cout.rdbuf(previous);
    guard.path = effects.blocker;
    const std::string output = captured.str();

    const fs::path generation = root / "amnezia-awg" / "1";
    const bool residue = fs::exists(generation);
    bool blockedExists = false;
    std::string blockedStat = "absent";
    if (!effects.blocker.empty() && fs::exists(effects.blocker)) {
        blockedExists = true;
        struct stat st{};
        if (::lstat(effects.blocker.c_str(), &st) == 0) {
            std::ostringstream s;
            s << "uid=" << st.st_uid << " mode=" << std::oct << (st.st_mode & 07777)
              << std::dec << " nlink=" << st.st_nlink;
            blockedStat = s.str();
        }
    }
    const bool cleaned = output.find("\"cleaned\":true") != std::string::npos;
    const bool workFailure = output.find("\"failure\":\"fixture_work_failure\"") != std::string::npos;
    const bool attempted = output.find("\"prepared\":false") != std::string::npos;
    std::cout << "PROBE mode=" << mode << " status=" << status
              << " prepared=false:" << attempted
              << " work_failure:" << workFailure
              << " cleaned:" << cleaned
              << " residue:" << residue
              << " blocked_dir:" << blockedExists
              << " blocked_lstat:" << blockedStat
              << " output=" << output;
    const bool ok = status == 23 && attempted && workFailure &&
        (mode == "blocked" ? (!cleaned && residue && blockedExists)
                           : (cleaned && !residue));
    // Restore the owned 000 subdir, then remove only our private run tree.
    guard.path = effects.blocker;
    { BlockerGuard restore; restore.path = effects.blocker;
      if (!effects.blocker.empty() && fs::exists(effects.blocker))
          fs::permissions(effects.blocker, fs::perms::owner_all, fs::perm_options::replace, cleanupEc);
    }
    fs::remove_all(base, cleanupEc);
    std::cout << "PROBE_RESULT " << (ok ? "PASS" : "FAIL") << "\n";
    if (cleanupEc) { std::cerr << "private fixture cleanup failed\n"; return 1; }
    return !ok ? 1 : argc == 4 ? 23 : 0;
}
