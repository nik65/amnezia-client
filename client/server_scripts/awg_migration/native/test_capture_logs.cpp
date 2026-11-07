// S1 default production capture-before-mutation + native log collector cutover.
// Real production entry/sequencer/ports; only the bounded Docker/ss process
// boundary is simulated. No process, socket, namespace or Docker op is run.
#include "prepare_entry.h"
#include "prepare_sequencer.h"
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
#include <sys/stat.h>
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
int setns(int, int) noexcept { errno = EPERM; return -1; }
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
std::string fixturePolicy() {
    return "{\"policy\":{\"revision\":7,\"contentSha256\":\"sha256:" + std::string(64, 'c') + "\"}}";
}
std::string fixtureUpdates() { return "{\"updates\":[]}"; }
void resetTransport(const fs::path &base) {
    defaultFixture::State fresh;
    fresh.mode = "full";
    fresh.policyRoot = (base / "policy").string();
    fresh.updatesRoot = (base / "updates").string();
    defaultFixture::state() = std::move(fresh);
}
prepareEntry::Parsed parse(const std::vector<std::string> &values) {
    std::vector<char *> args;
    for (auto &value : values) args.push_back(const_cast<char *>(value.c_str()));
    return prepareEntry::parseArgv(static_cast<int>(args.size()), args.data());
}
std::vector<std::string> automaticArgs(const fs::path &feed, const std::string &feedSha,
                                       const fs::path &collector, const std::string &collectorSha,
                                       bool preflight, bool nativeControl) {
    std::vector<std::string> values = {"awg-native-prepare", "--source", "amnezia-awg",
        "--host", "example.invalid", "--automatic", "--native-feed", feed.string(),
        "--native-feed-sha256", feedSha};
    if (!collector.empty()) {
        values.push_back("--native-collector"); values.push_back(collector.string());
        values.push_back("--native-collector-sha256"); values.push_back(collectorSha);
    }
    if (nativeControl) values.push_back("--native-control");
    if (preflight) values.push_back("--preflight");
    return values;
}
int invoke(const prepareEntry::Parsed &parsed, const fs::path &root,
           prepareProduction::ProductionPorts &ports, std::string &output) {
    std::ostringstream captured;
    std::streambuf *previous = std::cout.rdbuf(captured.rdbuf());
    const int status = prepareEntry::run(parsed, root, ports, ports, &ports);
    std::cout.rdbuf(previous);
    output = captured.str();
    return status;
}
fs::path makeFile(const fs::path &directory, const std::string &name, const std::string &bytes, unsigned mode) {
    const fs::path path = directory / name;
    writeFile(path, bytes, mode);
    return path;
}
bool anyCall(const defaultFixture::State &state, const std::string &needle) {
    for (auto &call : state.calls) if (call.find(needle) != std::string::npos) return true;
    return false;
}
const std::string* findCall(const defaultFixture::State &state, const std::string &needle) {
    for (auto &call : state.calls) if (call.find(needle) != std::string::npos) return &call;
    return nullptr;
}
void prepareRoot(const fs::path &root) {
    fs::remove_all(root);
    fs::create_directories(root / "amnezia-awg");
    fs::permissions(root, fs::perms::owner_all, fs::perm_options::replace);
    fs::permissions(root / "amnezia-awg", fs::perms::owner_all, fs::perm_options::replace);
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 5) { std::cerr << "base static-elf dynamic-elf static-collector required\n"; return 2; }
    const fs::path base = fs::absolute(argv[1]);
    const std::string staticElf = readAll(argv[2]);
    const std::string dynamicElf = readAll(argv[3]);
    const std::string collectorElf = readAll(argv[4]);
    fs::remove_all(base);
    fs::create_directories(base);
    writeFile(base / "policy" / "rules.json", fixturePolicy(), 0644);
    writeFile(base / "updates" / "manifest.json", fixtureUpdates(), 0644);
    const std::string staticSha = sha256Hex(staticElf);
    const std::string collectorSha = sha256Hex(collectorElf);
    const uid_t self = ::getuid();

    // A. Actual default automatic producer with authenticated native collector.
    {
        resetTransport(base);
        const fs::path root = base / "producer";
        prepareRoot(root);
        const fs::path feed = makeFile(base / "feeds-producer", "awg-feed", staticElf, 0755);
        const fs::path collector = makeFile(base / "collector-producer", "amnezia-client-logs-collector", collectorElf, 0755);
        prepareProduction::ProductionPorts::DataPaths paths;
        paths.policyRoot = base / "policy";
        paths.updatesRoot = base / "updates";
        paths.feedOwner = self;
        prepareProduction::ProductionPorts ports(root, feed, staticSha, paths, collector, collectorSha);
        defaultFixture::state().configPath = (root / "amnezia-awg" / "1" / "awg0.conf").string();
        const auto parsed = parse(automaticArgs(feed, staticSha, collector, collectorSha, false, true));
        std::string output;
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 0);
        CHECK(output.find("\"prepared\":true") != std::string::npos);
        CHECK(!defaultFixture::state().fatal);
        const fs::path generation = root / "amnezia-awg" / "1";
        CHECK(fs::exists(generation / "transaction.json"));
        const std::string *logs = findCall(defaultFixture::state(), "--name amnezia-awg-migration-1-logs ");
        CHECK(logs != nullptr);
        if (logs) {
            CHECK(logs->find("--entrypoint /app/amnezia-client-logs-collector") != std::string::npos);
            CHECK(logs->find("--root /data --bind 0.0.0.0 --port 17866 --upload-path /logs --bootstrap-path /bootstrap") != std::string::npos);
            CHECK(logs->find("AMNEZIA_CLIENT_LOGS_BOOTSTRAP=1") != std::string::npos);
            CHECK(logs->find("AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg") != std::string::npos);
            CHECK(logs->find("--network container:amnezia-awg-migration-1 ") != std::string::npos);
            CHECK(logs->find("amnezia.migration.owner=") != std::string::npos);
            CHECK(logs->find("logs-image:/app:ro") != std::string::npos);
            CHECK(logs->find("/opt/amnezia/client-logs:/data:rw") != std::string::npos);
            CHECK(logs->find("python") == std::string::npos);
            CHECK(logs->find("/data/collector.py") == std::string::npos);
        }
        CHECK(fs::exists(generation / "logs-image" / "amnezia-client-logs-collector"));
        CHECK(readAll(generation / "logs-image" / "amnezia-client-logs-collector") == collectorElf);
        CHECK(fs::exists(generation / "control-image" / "awg-feed"));
        CHECK(readAll(generation / "control-image" / "awg-feed") == staticElf);
        CHECK(anyCall(defaultFixture::state(), "docker image inspect --format {{.Id}} amnezia-awg-migration-1-logs-image"));
        CHECK(anyCall(defaultFixture::state(), "docker exec amnezia-awg-migration-1-control /app/awg-feed --check-policy-epoch 7 sha256:" + std::string(64, 'c')));
        std::cout << "PRODUCER_NATIVE_COLLECTOR status=" << status << " calls="
                  << defaultFixture::state().calls.size() << "\n";
    }

    // B. --native-control without collector material is a usage refusal.
    {
        resetTransport(base);
        const fs::path root = base / "usage";
        prepareRoot(root);
        const fs::path feed = makeFile(base / "feeds-usage", "awg-feed", staticElf, 0755);
        const auto parsed = parse(automaticArgs(feed, staticSha, {}, {}, false, true));
        CHECK(!parsed.valid);
        std::string output;
        prepareProduction::ProductionPorts ports(root, feed, staticSha);
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 2);
        CHECK(!fs::exists(root / "amnezia-awg" / "1"));
        std::cout << "USAGE_COLLECTOR status=" << status << "\n";
    }

    // C. Wrong collector digest: capture fails before any mutation.
    {
        resetTransport(base);
        const fs::path root = base / "bad-collector";
        prepareRoot(root);
        const fs::path feed = makeFile(base / "feeds-bad-collector", "awg-feed", staticElf, 0755);
        const fs::path collector = makeFile(base / "collector-bad", "amnezia-client-logs-collector", collectorElf, 0755);
        prepareProduction::ProductionPorts::DataPaths paths;
        paths.policyRoot = base / "policy"; paths.updatesRoot = base / "updates"; paths.feedOwner = self;
        const std::string wrong = sha256Hex("other-collector");
        prepareProduction::ProductionPorts ports(root, feed, staticSha, paths, collector, wrong);
        const auto parsed = parse(automaticArgs(feed, staticSha, collector, wrong, false, true));
        std::string output;
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 23);
        CHECK(output.find("native_collector_invalid") != std::string::npos);
        CHECK(!fs::exists(root / "amnezia-awg" / "1"));
        CHECK(!fs::exists(root / "amnezia-awg" / "signing.pem"));
        CHECK(!fs::exists(root / "amnezia-awg" / "1" / "transaction.json"));
        CHECK(defaultFixture::state().calls.empty());
        std::cout << "BAD_COLLECTOR status=" << status << " calls=" << defaultFixture::state().calls.size() << "\n";
    }

    // D. Wrong feed digest: same zero-mutation guarantee (regression of the
    // proven late-capture violation that left signing.pem + journal behind).
    {
        resetTransport(base);
        const fs::path root = base / "bad-feed";
        prepareRoot(root);
        const fs::path feed = makeFile(base / "feeds-bad-feed", "awg-feed", staticElf, 0755);
        const fs::path collector = makeFile(base / "collector-bad-feed", "amnezia-client-logs-collector", collectorElf, 0755);
        prepareProduction::ProductionPorts::DataPaths paths;
        paths.policyRoot = base / "policy"; paths.updatesRoot = base / "updates"; paths.feedOwner = self;
        const std::string wrong = sha256Hex("other-feed");
        prepareProduction::ProductionPorts ports(root, feed, wrong, paths, collector, collectorSha);
        const auto parsed = parse(automaticArgs(feed, wrong, collector, collectorSha, false, true));
        std::string output;
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 23);
        CHECK(output.find("native_feed_invalid") != std::string::npos);
        CHECK(!fs::exists(root / "amnezia-awg" / "1"));
        CHECK(!fs::exists(root / "amnezia-awg" / "signing.pem"));
        CHECK(defaultFixture::state().calls.empty());
        std::cout << "BAD_FEED status=" << status << " calls=" << defaultFixture::state().calls.size() << "\n";
    }

    // E. Unsafe collector bytes: wrong mode / dynamic ELF fail closed.
    {
        struct Bad { const char *name; std::string bytes; unsigned mode; } cases[] = {
            {"mode", collectorElf, 0644}, {"dynamic", dynamicElf, 0755}, {"non-elf", std::string(256, 'x'), 0755}};
        for (auto &item : cases) {
            resetTransport(base);
            const fs::path root = base / ("bad-" + std::string(item.name));
            prepareRoot(root);
            const fs::path feed = makeFile(base / ("feeds-" + std::string(item.name)), "awg-feed", staticElf, 0755);
            const fs::path collector = makeFile(base / ("collector-" + std::string(item.name)),
                                                "amnezia-client-logs-collector", item.bytes, item.mode);
            prepareProduction::ProductionPorts::DataPaths paths;
            paths.policyRoot = base / "policy"; paths.updatesRoot = base / "updates"; paths.feedOwner = self;
            const std::string digest = sha256Hex(item.bytes);
            prepareProduction::ProductionPorts ports(root, feed, staticSha, paths, collector, digest);
            const auto parsed = parse(automaticArgs(feed, staticSha, collector, digest, false, true));
            std::string output;
            const int status = invoke(parsed, root, ports, output);
            CHECK(status == 23);
            CHECK(output.find("native_collector_invalid") != std::string::npos);
            CHECK(!fs::exists(root / "amnezia-awg" / "signing.pem"));
            CHECK(defaultFixture::state().calls.empty());
            std::cout << "UNSAFE_COLLECTOR " << item.name << " status=" << status << "\n";
        }
    }

    // F. Capture-once: overwrite both source paths at the first external call;
    // the producer must consume only the early captured bytes.
    {
        resetTransport(base);
        const fs::path root = base / "cached";
        prepareRoot(root);
        const fs::path feed = makeFile(base / "feeds-cached", "awg-feed", staticElf, 0755);
        const fs::path collector = makeFile(base / "collector-cached", "amnezia-client-logs-collector", collectorElf, 0755);
        prepareProduction::ProductionPorts::DataPaths paths;
        paths.policyRoot = base / "policy"; paths.updatesRoot = base / "updates"; paths.feedOwner = self;
        prepareProduction::ProductionPorts ports(root, feed, staticSha, paths, collector, collectorSha);
        defaultFixture::state().configPath = (root / "amnezia-awg" / "1" / "awg0.conf").string();
        defaultFixture::state().onFirstCommand = [feed, collector] {
            writeFile(feed, std::string(256, 'Z'), 0755);
            writeFile(collector, std::string(256, 'Y'), 0755);
        };
        const auto parsed = parse(automaticArgs(feed, staticSha, collector, collectorSha, false, true));
        std::string output;
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 0);
        CHECK(output.find("\"prepared\":true") != std::string::npos);
        CHECK(readAll(root / "amnezia-awg" / "1" / "control-image" / "awg-feed") == staticElf);
        CHECK(readAll(root / "amnezia-awg" / "1" / "logs-image" / "amnezia-client-logs-collector") == collectorElf);
        std::cout << "CAPTURE_CACHED status=" << status << "\n";
    }

    // G. Legacy mode is preserved: no collector flags, read-only preflight.
    {
        resetTransport(base);
        const fs::path root = base / "legacy";
        const fs::path feed = makeFile(base / "feeds-legacy", "awg-feed", staticElf, 0755);
        prepareProduction::ProductionPorts::DataPaths paths;
        paths.policyRoot = base / "policy"; paths.updatesRoot = base / "updates"; paths.feedOwner = self;
        prepareProduction::ProductionPorts ports(root, feed, staticSha, paths);
        const auto parsed = parse(automaticArgs(feed, staticSha, {}, {}, true, false));
        std::string output;
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 0);
        CHECK(output.find("\"preflight\":true") != std::string::npos);
        CHECK(output.find("\"eligible\":true") != std::string::npos);
        CHECK(!fs::exists(root));
        std::cout << "LEGACY_PREFLIGHT status=" << status << "\n";
    }

    std::cout << "CAPTURE_LOGS_FAILURES=" << failures << "\n";
    return failures ? 1 : 0;
}
