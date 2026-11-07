// Actual default production adapter acceptance: prepareEntry::run with the real
// ProductionPorts and real source/policy/automatic/trusted-image/ready
// primitives. Only the bounded Docker/ss process boundary is simulated, and no
// process, socket, namespace or Docker operation is performed.
#include "prepare_entry.h"
#include "prepare_sequencer.h"
#include "production_ports.h"
#include "transaction_journal.h"
#include "test_default_transport.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
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
// Socket/process fences only. The full producer runs with the unprivileged
// fixture owner (no inert root identity), so journal ownership remains real.
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
    std::ifstream stream(path, std::ios::binary);
    std::ostringstream out; out << stream.rdbuf(); return out.str();
}
void writeFile(const fs::path &path, const std::string &bytes, unsigned mode) {
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    stream.close();
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
std::vector<std::string> automaticArgs(const fs::path &feed, const std::string &digest,
                                       bool preflight, bool nativeControl,
                                       const fs::path &collector = {}, const std::string &collectorSha = {}) {
    std::vector<std::string> values = {"awg-native-prepare", "--source", "amnezia-awg",
        "--host", "example.invalid", "--automatic", "--native-feed", feed.string(),
        "--native-feed-sha256", digest};
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
fs::path makeFeed(const fs::path &directory, const std::string &bytes, unsigned mode) {
    const fs::path path = directory / "awg-feed";
    writeFile(path, bytes, mode);
    return path;
}
bool anyCall(const defaultFixture::State &state, const std::string &needle) {
    for (auto &call : state.calls) if (call.find(needle) != std::string::npos) return true;
    return false;
}
std::string retiredInitial(const std::string& pin) {
    return "{\"owner\":\"00112233445546778899aabbccddeeff\",\"phase\":\"aborted\",\"source\":\"amnezia-awg\","
        "\"sourceId\":\"" + defaultFixture::kSourceId + "\",\"sourceIface\":\"wg0\",\"sourceRules\":false,"
        "\"sourceDigest\":\"" + sha256Hex(defaultFixture::rawConfig()) + "\",\"sourceEpoch\":\"" + defaultFixture::kStartedAt
        + "\",\"targetEpoch\":\"" + defaultFixture::kStartedAt + "\",\"target\":\"amnezia-awg-migration-1\",\"containers\":{},"
        "\"nativeFeedSha256\":\"" + pin + "\",\"request\":{\"generation\":1,\"port\":51821,\"host\":\"example.invalid\","
        "\"image\":\"" + TrustedImage + "\",\"clientOperationId\":\"00112233-4455-4677-8899-aabbccddeeff\"}}";
}
} // namespace

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) { std::cerr << "base static-elf dynamic-elf static-collector required\n"; return 2; }
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

    // A. Inert UID0/owner metadata model is explicit, production defaults are
    // still root and the canonical /opt trust paths.
    {
        prepareProduction::ProductionPorts::DataPaths defaults{};
        CHECK(defaults.feedOwner == 0);
        CHECK(defaults.feedMode == 0755);
        CHECK(defaults.policyRoot == "/opt/amnezia/server-routing-rules");
        CHECK(defaults.updatesRoot == "/opt/amnezia/client-updates");
    }

    // B. Actual default read-only preflight: canonical /opt policy data is not
    // present on this host, so the real adapter refuses eligibility without any
    // mutation. This is the unmodified production default.
    {
        const fs::path root = base / "preflight-default";
        const fs::path feed = makeFeed(base / "feeds-default", staticElf, 0755);
        (void)feed;
        prepareProduction::ProductionPorts ports(root, {}, {});
        const auto parsed = parse(automaticArgs({}, {}, true, false));
        std::string output;
        if (!fs::exists("/opt/amnezia/server-routing-rules/rules.json")) {
            const int status = invoke(parsed, root, ports, output);
            CHECK(status == 23);
            CHECK(output.find("managed_client_policy_not_ready") != std::string::npos);
            CHECK(!fs::exists(root));
            std::cout << "PREFLIGHT_DEFAULT_NEG status=" << status << " failure=managed_client_policy_not_ready\n";
        } else {
            std::cout << "PREFLIGHT_DEFAULT_NEG skipped=/opt present\n";
        }
    }

    // C. Positive read-only preflight through the real adapter with fixture
    // policy/feed data. No directory, generation, receipt or command mutates.
    {
        resetTransport(base);
        const fs::path root = base / "preflight-green";
        const fs::path feed = makeFeed(base / "feeds-green", staticElf, 0755);
        prepareProduction::ProductionPorts::DataPaths paths;
        paths.policyRoot = base / "policy";
        paths.updatesRoot = base / "updates";
        paths.feedOwner = self;
        prepareProduction::ProductionPorts ports(root, feed, staticSha, paths);
        const auto parsed = parse(automaticArgs(feed, staticSha, true, false));
        std::string output;
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 0);
        CHECK(output.find("\"prepared\":false") != std::string::npos);
        CHECK(output.find("\"preflight\":true") != std::string::npos);
        CHECK(output.find("\"eligible\":true") != std::string::npos);
        CHECK(!fs::exists(root));
        CHECK(!defaultFixture::state().fatal);
        std::cout << "PREFLIGHT_GREEN status=" << status << " calls="
                  << defaultFixture::state().calls.size() << " output=" << output;
    }

    // D. Real preflight refuses an existing native-feed generation read-only.
    {
        resetTransport(base);
        const fs::path root = base / "preflight-existing";
        fs::create_directories(root / "amnezia-awg" / "1");
        writeFile(root / "amnezia-awg" / "1" / "transaction.json",
                  "{\"owner\":\"" + std::string(32, '0') + "\",\"phase\":\"ready\",\"containers\":{},"
                  "\"source\":\"amnezia-awg\",\"sourceId\":\"" + std::string(64, 'a') + "\","
                  "\"sourceIface\":\"wg0\",\"sourceRules\":true,\"sourceDigest\":\"" + std::string(64, 'f')
                  + "\",\"target\":\"amnezia-awg-migration-1\",\"sourceEpoch\":\"2026-11-07T00:00:00Z\","
                  "\"request\":{\"image\":\"x\",\"host\":\"h\",\"port\":51821,\"generation\":1}}", 0600);
        const fs::path feed = makeFeed(base / "feeds-existing", staticElf, 0755);
        prepareProduction::ProductionPorts::DataPaths paths;
        paths.policyRoot = base / "policy";
        paths.updatesRoot = base / "updates";
        paths.feedOwner = self;
        prepareProduction::ProductionPorts ports(root, feed, staticSha, paths);
        const auto parsed = parse(automaticArgs(feed, staticSha, true, false));
        std::string output;
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 23);
        CHECK(output.find("native_feed_existing_generation_requires_maintenance") != std::string::npos);
        CHECK(fs::exists(root / "amnezia-awg" / "1" / "transaction.json"));
        std::cout << "PREFLIGHT_EXISTING_NEG status=" << status << " output=" << output;
    }

    // E. Full actual default automatic producer: real planning, selected
    // request state, journal, generation, target, real ready-attestation,
    // feed binding, logs and native control. Only the Docker/ss boundary is
    // simulated; no synthetic ready collaborator exists.
    {
        resetTransport(base);
        defaultFixture::state().twoFeeds = true;
        const fs::path root = base / "producer";
        fs::create_directories(root / "amnezia-awg");
        fs::permissions(root, fs::perms::owner_all, fs::perm_options::replace);
        fs::permissions(root / "amnezia-awg", fs::perms::owner_all, fs::perm_options::replace);
        const fs::path feed = makeFeed(base / "feeds-producer", staticElf, 0755);
        const fs::path collector = makeFeed(base / "collector-producer", collectorElf, 0755);
        prepareProduction::ProductionPorts::DataPaths paths;
        paths.policyRoot = base / "policy";
        paths.updatesRoot = base / "updates";
        paths.feedOwner = self;
        prepareProduction::ProductionPorts ports(root, feed, staticSha, paths, collector, collectorSha);
        defaultFixture::state().configPath = (root / "amnezia-awg" / "1" / "awg0.conf").string();
        const std::string clientOperationId = "00112233-4455-4677-8899-aabbccddeeff";
        auto values = automaticArgs(feed, staticSha, false, true, collector, collectorSha);
        values.insert(values.end(), {"--client-operation-id", clientOperationId});
        const auto parsed = parse(values);
        CHECK(parsed.valid && parsed.request.clientOperationId == clientOperationId);
        auto invalidOperation = values; invalidOperation.back() = clientOperationId + "\n";
        CHECK(!parse(invalidOperation).valid);
        invalidOperation.back().clear();
        CHECK(!parse(invalidOperation).valid);
        std::string output;
        const int status = invoke(parsed, root, ports, output);
        CHECK(status == 0);
        CHECK(output.find("\"prepared\":true") != std::string::npos);
        CHECK(output.find("\"eligible\":true") != std::string::npos);
        CHECK(output.find("\"generation\":1") != std::string::npos);
        CHECK(output.find("\"port\":51821") != std::string::npos);
        CHECK(!defaultFixture::state().fatal);
        const fs::path generation = root / "amnezia-awg" / "1";
        CHECK(fs::exists(generation / "transaction.json"));
        CHECK(!fs::exists(root / "amnezia-awg" / "0"));
        const std::string journal = readAll(generation / "transaction.json");
        CHECK(journal.find("\"phase\":\"ready\"") != std::string::npos);
        CHECK(journal.find("\"owner\":\"00112233445546778899aabbccddeeff\"") != std::string::npos);
        CHECK(journal.find("\"clientOperationId\":\"" + clientOperationId + "\"") != std::string::npos);
        CHECK(output.find(clientOperationId) != std::string::npos);
        CHECK(anyCall(defaultFixture::state(), "amnezia.migration.owner=00112233445546778899aabbccddeeff"));
        CHECK(journal.find("\"generation\":1") != std::string::npos);
        CHECK(journal.find("\"port\":51821") != std::string::npos);
        CHECK(journal.find("\"variant\":\"native-control-http-v1\"") != std::string::npos);
        CHECK(journal.find("\"authority\":\"authenticated-operator-sha256\"") != std::string::npos);
        CHECK(journal.find("\"controlLoadedReceipt\":true") != std::string::npos);
        CHECK(fs::exists(generation / "ready.json"));
        CHECK(fs::exists(generation / "control-image" / "awg-feed"));
        CHECK(readAll(generation / "control-image" / "awg-feed") == staticElf);
        CHECK(anyCall(defaultFixture::state(), "awg show awg0 dump"));
        CHECK(anyCall(defaultFixture::state(), "awg showconf awg0"));
        CHECK(anyCall(defaultFixture::state(), "--verify-control-live target"));
        CHECK(anyCall(defaultFixture::state(), "--verify-control-live source"));
        CHECK(anyCall(defaultFixture::state(), "--check-feed routing 17864 " + sha256Hex(fixturePolicy())));
        CHECK(anyCall(defaultFixture::state(), "--check-feed updates 17865 " + sha256Hex(fixtureUpdates())));
        CHECK(anyCall(defaultFixture::state(), "AMNEZIA_FEED_PORTS=17864,17865"));
        unsigned feedStarts = 0;
        for (const auto &call : defaultFixture::state().calls)
            if (call.find("docker run ") == 0 && call.find("--name amnezia-awg-migration-1-feeds ") != std::string::npos)
                ++feedStarts;
        CHECK(feedStarts == 1);
        std::cout << "PRODUCER status=" << status << " calls=" << defaultFixture::state().calls.size()
                  << " output=" << output;
    }

    // F. Retry requires an independently saved retirement proof. The actual
    // producer retains the old evidence and uses a higher generation/new ID.
    // Faults stay at inert Docker/ss boundaries, never a live container.
    for (const std::string fault : {"none", "hash", "pin", "nonce", "running", "foreign", "rules", "unknown", "changed-after-plan"}) {
        resetTransport(base);
        defaultFixture::state().twoFeeds = true;
        const auto root = base / ("retired-" + fault), oldDir = root / "amnezia-awg" / "1";
        fs::create_directories(oldDir);
        for (auto path : {root, oldDir.parent_path(), oldDir}) fs::permissions(path, fs::perms::owner_all, fs::perm_options::replace);
        const auto feed = makeFeed(base / ("retired-feed-" + fault), staticElf, 0755);
        const auto collector = makeFeed(base / ("retired-collector-" + fault), collectorElf, 0755);
        {
            TransactionJournal old(oldDir, [](const auto&) { return CommandResult{1,"","Error: No such object"}; }, retiredInitial(staticSha));
            old.plan("amnezia-awg-migration-1", TrustedImageId);old.save("aborted");
            if (fault == "rules") {
                auto raw = old.snapshot();const auto at = raw.find("\"sourceRules\":false");raw.replace(at,19,"\"sourceRules\":true");old.replaceValue(raw);
            }
        }
        const auto oldRaw = readAll(oldDir / "transaction.json");
        RetiredPredecessor proof{1,staticSha,"00112233-4455-4677-8899-aabbccddeeff",sha256Hex(oldRaw)};
        if (fault == "hash") proof.journalSha256 = std::string(64,'d');
        if (fault == "pin") proof.sha256 = std::string(64,'d');
        if (fault == "nonce") proof.operationId = "11223344-5566-4788-99aa-bbccddeeff00";
        if (fault == "running" || fault == "foreign") {
            defaultFixture::Container live;live.name="amnezia-awg-migration-1";live.id=std::string(64,'7');live.image=TrustedImageId;
            live.owner=fault=="running"?"00112233445546778899aabbccddeeff":std::string(32,'f');live.running=true;live.startedAt=defaultFixture::kStartedAt;
            defaultFixture::state().containers[live.name]=live;
        }
        if (fault == "unknown") fs::create_directory(oldDir.parent_path()/"7");
        if (fault == "changed-after-plan") defaultFixture::state().onFirstCommand = [oldDir] {
            std::ofstream stream(oldDir/"transaction.json",std::ios::app);stream << '\n';
        };
        prepareProduction::ProductionPorts::DataPaths paths;paths.policyRoot=base/"policy";paths.updatesRoot=base/"updates";paths.feedOwner=self;
        const auto wire=encodeRetiredPredecessors({proof});
        if (fault == "none") {
            auto values=automaticArgs(feed,staticSha,true,true,collector,collectorSha);
            values.insert(values.end(),{"--retired-predecessors",wire});
            const auto parsed=parse(values);CHECK(parsed.valid && parsed.request.clientOperationId.empty());
            prepareProduction::ProductionPorts preflight(root,feed,staticSha,paths,collector,collectorSha);
            std::string output;CHECK(invoke(parsed,root,preflight,output)==0);
            CHECK(output.find("\"eligible\":true")!=std::string::npos && !fs::exists(oldDir.parent_path()/"2"));
            CHECK(readAll(oldDir/"transaction.json")==oldRaw);
        }
        auto values=automaticArgs(feed,staticSha,false,true,collector,collectorSha);
        values.insert(values.end(),{"--client-operation-id","11223344-5566-4788-99aa-bbccddeeff00","--retired-predecessors",wire});
        // The nonce fault also checks that a new attempt cannot reuse the ID
        // in the retirement history, independently of the server journal.
        const auto parsed=parse(values);
        if (fault == "nonce") {CHECK(!parsed.valid);continue;}
        CHECK(parsed.valid && parsed.request.retiredPredecessors.size()==1);
        defaultFixture::state().configPath=(oldDir.parent_path()/"2"/"awg0.conf").string();
        prepareProduction::ProductionPorts ports(root,feed,staticSha,paths,collector,collectorSha);
        std::string output;const auto status=invoke(parsed,root,ports,output);
        if (fault == "none") {
            CHECK(status==0 && output.find("\"prepared\":true")!=std::string::npos);
            const auto next=readAll(oldDir.parent_path()/"2"/"transaction.json");
            CHECK(next.find("\"generation\":2")!=std::string::npos && next.find("\"phase\":\"ready\"")!=std::string::npos);
            CHECK(next.find("\"retiredPredecessors\":[")!=std::string::npos);
            CHECK(next.find("112233445566478899aabbccddeeff00")!=std::string::npos);
            CHECK(readAll(oldDir/"transaction.json")==oldRaw);
        } else {
            CHECK(status==23 && output.find("\"prepared\":true")==std::string::npos);
            CHECK(!fs::exists(oldDir.parent_path()/"2"/"awg0.conf"));
            CHECK(!anyCall(defaultFixture::state(),"--name amnezia-awg-migration-2 "));
            CHECK(!anyCall(defaultFixture::state(),"iptables -I"));
        }
        CHECK(!defaultFixture::state().fatal);
        std::cout << "RETIRED_RETRY fault=" << fault << " status=" << status << " output=" << output;
    }

    // G. Native payload validation on the actual write/stage path. Each case
    // must fail closed as native_feed_invalid and leave no generation behind.
    {
        struct Bad { const char *name; std::string bytes; unsigned mode; uid_t owner; std::string digest; };
        const std::string padded = std::string("not-an-elf") + std::string(128, '\0');
        std::vector<Bad> cases = {
            {"non-elf", padded, 0755, self, sha256Hex(padded)},
            {"dynamic-elf", dynamicElf, 0755, self, sha256Hex(dynamicElf)},
            {"wrong-owner", staticElf, 0755, static_cast<uid_t>(self + 1), staticSha},
            {"wrong-mode", staticElf, 0644, self, staticSha},
            {"wrong-digest", staticElf, 0755, self, sha256Hex("other-bytes")},
        };
        for (auto &item : cases) {
            resetTransport(base);
            const fs::path root = base / ("bad-" + std::string(item.name));
            fs::remove_all(root);
            fs::create_directories(root / "amnezia-awg");
            fs::permissions(root, fs::perms::owner_all, fs::perm_options::replace);
            fs::permissions(root / "amnezia-awg", fs::perms::owner_all, fs::perm_options::replace);
            const fs::path feed = makeFeed(base / ("bad-feed-" + std::string(item.name)), item.bytes, item.mode);
            prepareProduction::ProductionPorts::DataPaths paths;
            paths.policyRoot = base / "policy";
            paths.updatesRoot = base / "updates";
            paths.feedOwner = item.owner;
            prepareProduction::ProductionPorts ports(root, feed, item.digest, paths);
            const auto parsed = parse(automaticArgs(feed, item.digest, false, false));
            std::string output;
            const int status = invoke(parsed, root, ports, output);
            CHECK(status == 23);
            CHECK(output.find("native_feed_invalid") != std::string::npos);
            CHECK(output.find("\"prepared\":true") == std::string::npos);
            CHECK(!fs::exists(root / "amnezia-awg" / "1"));
            std::cout << "FEED_NEG " << item.name << " status=" << status
                      << " failure=native_feed_invalid\n";
        }
    }

    std::cout << "DEFAULT_PRODUCTION_FAILURES=" << failures << "\n";
    if (failures) return 1;
    if (argc == 6 && std::string(argv[5]) == "--fail-work") return 23;
    return 0;
}
