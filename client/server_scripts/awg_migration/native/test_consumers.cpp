// NEW S2 consumers: real runMaintenance through status/maintain/restart-controls/
// recover/cleanup against the explicit native-control-http-v1 journal and the
// unchanged legacy Python / legacy native-feed semantics. Docker/process/sleep are
// inert at the Ops boundary; the journal, filesystem and JSON are the real ones.
#include "maintenance_runtime.h"
#include <openssl/evp.h>
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

using namespace amnezia::awgMigration;
using namespace amnezia::awgMigration::maintenance;
namespace fs = std::filesystem;
static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::cerr << "FAIL line " << __LINE__ << ": " #cond "\n"; ++failures; } } while (0)
#define CHECK_THROW(expr, text) do { bool thrown=false; try { expr; } catch (const std::exception& e) { thrown=std::string(e.what()).find(text)!=std::string::npos; if(!thrown) std::cerr << "message: " << e.what() << "\n"; } if(!thrown){ std::cerr << "FAIL line " << __LINE__ << ": expected " text "\n"; ++failures; } } while (0)

static void expectThrows(const std::function<void()>& fn, const std::string& text, int line) {
    try { fn(); } catch (const std::exception& e) {
        if (std::string(e.what()).find(text) != std::string::npos) return;
        std::cerr << "message: " << e.what() << "\n";
    }
    std::cerr << "FAIL line " << line << ": expected " << text << "\n"; ++failures;
}
static std::string sha(const std::string& bytes) {
    unsigned char out[EVP_MAX_MD_SIZE]; unsigned n = 0;
    EVP_Digest(bytes.data(), bytes.size(), out, &n, EVP_sha256(), nullptr);
    std::string hex; char b[3];
    for (unsigned i = 0; i < n; ++i) { std::snprintf(b, sizeof b, "%02x", out[i]); hex += b; }
    return hex;
}
static void write(const fs::path& p, const std::string& bytes, mode_t mode = 0600) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc); out << bytes; out.close();
    chmod(p.c_str(), mode);
}
static std::string read(const fs::path& p) {
    std::ifstream in(p, std::ios::binary); return std::string(std::istreambuf_iterator<char>(in), {});
}
static void replaceOnce(std::string& text, const std::string& from, const std::string& to) {
    auto at = text.find(from);
    if (at == std::string::npos) throw std::runtime_error("fixture token absent: " + from);
    text.replace(at, from.size(), to);
}

struct Fixture {
    fs::path root, directory, recipe;
    const std::string owner = std::string(32, 'a');
    const std::string sourceId = std::string(64, 'b');
    const std::string targetId = std::string(64, 'c');
    const std::string controlId = std::string(64, 'e');
    const std::string sourceControlId = std::string(64, 'f');
    const std::string image = "sha256:" + std::string(64, 'd');
    std::string nativeSha;
    const std::string feedSha = std::string(64, '7');
    const std::string peerKey = std::string(43, 'Q') + "=";
    std::string config;
    bool native = false, legacyFeed = false;
    // Helper drift switches consumed by inspect().
    std::string entrypoint, command, envSha, envRoleSuffix, envScope, networkOverride;
    bool privileged = false;
    int mounts = 2;
    bool migrationRW = true;
    std::map<std::string, int> restarted;
    std::set<std::string> stopped;

    static void mkdir(const fs::path& p) { fs::create_directories(p); chmod(p.c_str(), 0700); }
    explicit Fixture(bool nativeMode, bool feedMode = false) : native(nativeMode), legacyFeed(feedMode) {
        nativeSha = sha("native-feed-bytes\n");
        root = fs::temp_directory_path() / ("awg-consumers-" + std::to_string(getpid()) + "-" + std::to_string(reinterpret_cast<std::uintptr_t>(this)));
        fs::remove_all(root); mkdir(root); directory = root / "amnezia-awg" / "1"; mkdir(root / "amnezia-awg"); mkdir(directory);
        write(root / ".prepare.lock", "lock\n");
        config = "[Interface]\nPrivateKey = " + std::string(43, 'A') + "=\nAddress = 10.8.0.1/24\nListenPort = 51820\nJc = 4\n\n[Peer]\nPublicKey = " + peerKey + "\nAllowedIPs = 10.8.0.2/32\n";
        for (const char* n : {"awg0.conf", "awg0.native.conf", "signing.pem", "start.sh", "grants.sqlite3"}) write(directory / n, std::string(n) + "-bytes\n");
        write(directory / "awg0.conf", config);
        if (!native) { write(directory / "service.py", "service-old\n"); write(directory / "target.py", "target-old\n"); }
        write(directory / "ready.json", "{\"containerId\":\"amnezia-awg\",\"targetContainer\":\"amnezia-awg-migration-1\",\"generation\":1,\"endpoint\":\"vpn.example:51820\",\"serverPublicKey\":\"" + peerKey + "\",\"parameters\":{\"Jc\":\"4\"},\"peers\":{\"" + peerKey + "\":{\"sourceIp\":\"10.8.0.2\",\"targetIp\":\"10.8.0.2\",\"clientAddress\":\"10.8.0.2/32\"}}}");
        recipe = root / "recipes"; mkdir(recipe);
        if (native) write(recipe / "awg-feed", "native-feed-bytes\n");
        else { write(recipe / "service.py", "service-old\n"); write(recipe / "target.py", "target-old\n"); }
        entrypoint = native ? "/app/awg-feed" : "python";
        command = native ? "--control-pid1" : "/migration/target.py";
        envSha = native ? nativeSha : std::string();
        envScope = "amnezia-awg";
        std::string containers = "{\"amnezia-awg-migration-1\":{\"image\":\"" + image + "\",\"id\":\"" + targetId + "\"},\"amnezia-awg-migration-1-control\":{\"image\":\"" + image + "\",\"id\":\"" + controlId + "\"},\"amnezia-awg-migration-1-source-control\":{\"image\":\"" + image + "\",\"id\":\"" + sourceControlId + "\"}}";
        std::string journal = "{\"owner\":\"" + owner + "\",\"phase\":\"ready\",\"source\":\"amnezia-awg\",\"sourceId\":\"" + sourceId + "\",\"target\":\"amnezia-awg-migration-1\",\"sourceIface\":\"wg0\",\"sourceRules\":false,\"sourceEpoch\":\"t-source\",\"targetEpoch\":\"t-target\",\"sourceDigest\":\"" + sha(config) + "\",\"controlLoadedReceipt\":true,\"request\":{\"generation\":1,\"port\":51820,\"host\":\"vpn.example\",\"image\":\"" + image + "\"},\"containers\":" + containers;
        if (native) {
            journal += ",\"nativeControl\":{\"variant\":\"native-control-http-v1\",\"protocol\":\"control-http-v1\",\"authority\":\"authenticated-operator-sha256\",\"sha256\":\"" + nativeSha + "\",\"image\":\"" + image + "\",\"verifier\":\"--verify-control-live\",\"roles\":[\"target\",\"source\"]}";
        } else {
            journal += ",\"controlRecipe\":{\"service.py\":\"" + sha("service-old\n") + "\",\"target.py\":\"" + sha("target-old\n") + "\"}";
            if (legacyFeed) journal += ",\"nativeFeedSha256\":\"" + feedSha + "\"";
        }
        journal += "}";
        write(directory / "transaction.json", journal);
        this->journal = journal;
    }
    std::string journal;
    ~Fixture() { fs::remove_all(root); }
    Request request(Mode mode) const {
        Request r; r.mode = mode; r.source = "amnezia-awg"; r.generation = 1;
        r.expectedJournalSha256 = sha(read(directory / "transaction.json"));
        r.nativeControlSha256 = native ? nativeSha : (legacyFeed ? std::string(64, '8') : std::string());
        r.root = root; r.recipeDirectory = recipe;
        return r;
    }
    void rewrite(const std::function<void(std::string&)>& change) {
        std::string text = read(directory / "transaction.json");
        change(text);
        write(directory / "transaction.json", text);
    }
    std::string envFor(const std::string& role) const {
        if (!native) return "\"AMNEZIA_MIGRATION_ROLE=" + role + "\",\"AMNEZIA_MIGRATION_SCOPE=" + (envScope.empty() ? "amnezia-awg" : envScope) + "\"";
        return "\"AMNEZIA_CONTROL_NATIVE_SHA256=" + envSha + "\",\"AMNEZIA_MIGRATION_ROLE=" + role + envRoleSuffix + "\",\"AMNEZIA_MIGRATION_SCOPE=" + (envScope.empty() ? "amnezia-awg" : envScope) + "\"";
    }
    std::string inspectFor(const std::string& id) const {
        std::string name, role, parent, epoch;
        if (id == sourceId) return "{\"Id\":\"" + sourceId + "\",\"Name\":\"/amnezia-awg\",\"State\":{\"Running\":true,\"StartedAt\":\"t-source\"}}";
        if (id == targetId) { name = "amnezia-awg-migration-1"; parent = sourceId; epoch = "t-target"; }
        else if (id == controlId) { name = "amnezia-awg-migration-1-control"; role = "target"; parent = targetId; epoch = "t-control"; }
        else if (id == sourceControlId) { name = "amnezia-awg-migration-1-source-control"; role = "source"; parent = sourceId; epoch = "t-source-control"; }
        else throw std::runtime_error("no such object");
        bool running = !stopped.count(id);
        auto restartCount = restarted.find(id);
        if (restartCount != restarted.end()) epoch += std::string(static_cast<std::size_t>(restartCount->second), '+');
        std::string ep = role.empty() ? "python" : entrypoint;
        std::string cmd = role.empty() ? "/migration/target.py" : command;
        std::string env = role.empty() ? "\"AMNEZIA_MIGRATION_ROLE=target\",\"AMNEZIA_MIGRATION_SCOPE=amnezia-awg\"" : envFor(role);
        std::string mountsJson;
        int count = role.empty() ? 2 : mounts;
        if (count >= 1) mountsJson += "{\"Type\":\"bind\",\"Source\":\"" + directory.generic_string() + "\",\"Destination\":\"/migration\",\"RW\":" + std::string(migrationRW ? "true" : "false") + "}";
        if (count >= 2) { if (!mountsJson.empty()) mountsJson += ","; mountsJson += "{\"Type\":\"bind\",\"Source\":\"/opt/amnezia/client-logs\",\"Destination\":\"/logs\",\"RW\":false}"; }
        if (count >= 3) { if (!mountsJson.empty()) mountsJson += ","; mountsJson += "{\"Type\":\"bind\",\"Source\":\"/tmp/extra\",\"Destination\":\"/extra\",\"RW\":false}"; }
        std::string network = networkOverride.empty() ? "container:" + parent : networkOverride;
        return "{\"Id\":\"" + id + "\",\"Name\":\"/" + name + "\",\"Image\":\"" + image + "\",\"State\":{\"Running\":" + std::string(running ? "true" : "false") + ",\"StartedAt\":\"" + epoch + "\"},"
            "\"Config\":{\"Labels\":{\"amnezia.migration.owner\":\"" + owner + "\"},\"Env\":[" + env + "],\"Entrypoint\":[\"" + ep + "\"],\"Cmd\":[\"" + cmd + "\"]},"
            "\"HostConfig\":{\"NetworkMode\":\"" + network + "\",\"Privileged\":" + std::string(privileged ? "true" : "false") + "},"
            "\"Mounts\":[" + mountsJson + "]}";
    }
};

struct FakeOps : Ops {
    Fixture& f;
    std::vector<std::vector<std::string>> calls;
    bool failNative = false, failRestart = false, failAllDocker = false, stopTarget = false;
    std::string rejectHash;
    explicit FakeOps(Fixture& fixture) : f(fixture) {}
    std::uint32_t euid() override { return 0; }
    void sleepSeconds(unsigned) override {}
    std::string run(const std::vector<std::string>& a) override {
        calls.push_back(a);
        if (failAllDocker) throw std::runtime_error("external boundary disabled");
        if (a.size() == 3 && a[0] == "docker" && a[1] == "inspect") {
            std::string raw = f.inspectFor(a[2]);
            if (stopTarget && a[2] == f.targetId) {
                auto p = raw.find("\"Running\":true"); if (p != std::string::npos) raw.replace(p, 14, "\"Running\":false");
            }
            return "[" + raw + "]";
        }
        if (a.size() >= 5 && a[0] == "docker" && a[1] == "exec") {
            const std::string& id = a[2]; const std::string& cmd = a[3];
            if (cmd == "cat") return f.config;
            if (cmd == "python") {
                if (f.native) throw std::runtime_error("python executed in native control path");
                if (!rejectHash.empty()) for (const auto& s : a) if (s.find(rejectHash) != std::string::npos) throw std::runtime_error("legacy probe rejected");
                return "";
            }
            if (cmd == "/app/awg-feed") { if (failNative) throw std::runtime_error("native control rejected"); return ""; }
            if (cmd == "awg" && a.size() >= 6 && a[4] == "show") {
                if (a.size() >= 7 && a[5] == "awg0" && a[6] == "dump")
                    return "priv\t" + f.peerKey + "\t51820\t0\n" + f.peerKey + "\t(none)\t0\t10.8.0.2/32\t0\n";
                return "Jc = 4\n";
            }
            if (cmd == "awg" && a.size() >= 6 && a[4] == "showconf") return "Jc = 4\n";
            if (cmd == "sh") return "6d96502ebd9ed6f9d17bdecd637cba7502c9960fed1b6922b3882784417a036d  /proc/123/exe\n";
            (void)id; return "";
        }
        if (a.size() >= 3 && a[0] == "docker" && a[1] == "restart") {
            if (failRestart) throw std::runtime_error("restart failed");
            ++f.restarted[a[2]]; return "";
        }
        if (a.size() == 3 && a[0] == "docker" && a[1] == "start") { f.stopped.erase(a[2]); return ""; }
        if (a.size() >= 4 && a[0] == "docker" && a[1] == "rm") return "";
        throw std::runtime_error("unexpected external command in inert consumer fixture");
    }
    bool saw(const std::string& sub) const {
        for (const auto& a : calls) for (const auto& s : a) if (s.find(sub) != std::string::npos) return true;
        return false;
    }
    std::size_t count(const std::string& pythonOrFeed, const std::string& flag = {}) const {
        std::size_t n = 0;
        for (const auto& a : calls) {
            if (a.size() > 4 && a[1] == "exec" && a[3] == pythonOrFeed && (flag.empty() || a[4] == flag)) ++n;
        }
        return n;
    }
    bool mutatingBoundary() const {
        for (const auto& a : calls)
            if (a.size() > 1 && (a[1] == "restart" || a[1] == "start" || a[1] == "rm" || a[1] == "run" || a[1] == "build")) return true;
        return false;
    }
};

static void expectFailure(Fixture& f, Mode mode, const char* text, const std::function<void()>& mutate) {
    if (mutate) mutate();
    FakeOps ops(f);
    expectThrows([&]{ runMaintenance(f.request(mode), ops); }, text, __LINE__);
    CHECK(ops.count("python") == 0 || std::string(text).find("legacy") != std::string::npos);
}

static void testNativePositives() {
    { Fixture f(true); FakeOps ops(f);
      auto s = runMaintenance(f.request(Mode::Status), ops);
      CHECK(s.ok && s.native && s.phase == "ready");
      CHECK(s.controlHashes.size() == 1 && s.controlHashes.at("awg-feed") == f.nativeSha);
      CHECK(ops.calls.empty()); }
    { Fixture f(true); FakeOps ops(f);
      auto r = runMaintenance(f.request(Mode::RestartControls), ops);
      CHECK(r.ok && r.native && r.controlHashes.at("awg-feed") == f.nativeSha);
      CHECK(ops.count("/app/awg-feed", "--verify-control-live") == 2);
      CHECK(ops.count("python") == 0);
      CHECK(ops.saw("--verify-control-loaded") == false);
      bool targetArgs = false, sourceArgs = false;
      for (const auto& a : ops.calls) if (a.size() == 8 && a[1] == "exec" && a[3] == "/app/awg-feed" && a[4] == "--verify-control-live") {
          if (a[5] == "target" && a[6] == f.nativeSha && a[7] == "/migration/control-loaded-target.json") targetArgs = true;
          if (a[5] == "source" && a[6] == f.nativeSha && a[7] == "/migration/control-loaded-source.json") sourceArgs = true;
      }
      CHECK(targetArgs && sourceArgs);
      CHECK(read(f.directory / "transaction.json") == f.journal); }
    { Fixture f(true); FakeOps ops(f); ops.stopTarget = true;
      auto r = runMaintenance(f.request(Mode::Recover), ops);
      CHECK(r.ok && r.phase == "ready" && r.controlHashes.at("awg-feed") == f.nativeSha);
      CHECK(ops.count("python") == 0);
      CHECK(ops.count("/app/awg-feed", "--verify-control-live") == 1);
      CHECK(ops.saw("start")); }
    { Fixture f(true); FakeOps ops(f);
      const auto before = read(f.directory / "transaction.json");
      auto m = runMaintenance(f.request(Mode::Maintain), ops);
      CHECK(m.ok && m.phase == "ready" && m.native && m.controlHashes.at("awg-feed") == f.nativeSha);
      CHECK(read(f.directory / "transaction.json") == before);
      CHECK(ops.count("python") == 0);
      CHECK(ops.count("/app/awg-feed", "--verify-control-live") >= 2);
      CHECK(ops.mutatingBoundary() == false); }
    { Fixture f(true); FakeOps ops(f);
      auto c = runMaintenance(f.request(Mode::Cleanup), ops);
      CHECK(c.ok && c.phase == "aborted" && c.controlHashes.at("awg-feed") == f.nativeSha);
      CHECK(std::count_if(ops.calls.begin(), ops.calls.end(), [](const auto& a){ return a.size() > 2 && a[1] == "rm"; }) == 3);
      CHECK(ops.count("python") == 0); }
}

static void testNativeChangedPayload() {
    Fixture f(true);
    write(f.recipe / "awg-feed", "different-native-feed-bytes\n");
    const auto before = read(f.directory / "transaction.json");
    FakeOps ops(f);
    CHECK_THROW(runMaintenance(f.request(Mode::Maintain), ops), "native_control_replacement_sha256_required");
    CHECK(read(f.directory / "transaction.json") == before);
    CHECK(ops.mutatingBoundary() == false);
    CHECK(ops.count("python") == 0);
    // Missing native payload is an honest blocker, never "unchanged".
    fs::remove(f.recipe / "awg-feed");
    FakeOps missing(f);
    CHECK_THROW(runMaintenance(f.request(Mode::Maintain), missing), "native control payload missing");
    CHECK(read(f.directory / "transaction.json") == before);
}

static void testVariantGuards() {
    { Fixture f(true); expectFailure(f, Mode::Status, "unsupported mixed control variant", [&]{
          f.rewrite([](std::string& j){ j.insert(j.size() - 1, ",\"nativeFeedSha256\":\"" + std::string(64, '7') + "\""); }); }); }
    { Fixture f(true); expectFailure(f, Mode::Status, "unsupported control variant", [&]{
          f.rewrite([](std::string& j){ replaceOnce(j, "native-control-http-v1", "native-control-json-v1"); }); }); }
    { Fixture f(true); expectFailure(f, Mode::Status, "unsupported control variant", [&]{
          f.rewrite([](std::string& j){ replaceOnce(j, "control-http-v1", "control-json-v1"); }); }); }
    { Fixture f(true); expectFailure(f, Mode::Status, "unsupported control variant", [&]{
          f.rewrite([](std::string& j){ replaceOnce(j, "authenticated-operator-sha256", "local"); }); }); }
    { Fixture f(true); expectFailure(f, Mode::Status, "unsupported control variant", [&]{
          f.rewrite([](std::string& j){ replaceOnce(j, "--verify-control-live", "--verify-control-loaded"); }); }); }
    { Fixture f(true); expectFailure(f, Mode::Status, "unsupported control variant", [&]{
          f.rewrite([](std::string& j){ replaceOnce(j, "[\"target\",\"source\"]", "[\"target\"]"); }); }); }
    { Fixture f(true); expectFailure(f, Mode::Status, "unsupported control variant", [&]{
          f.rewrite([](std::string& j){ replaceOnce(j, "\"image\":\"sha256:" + std::string(64, 'd') + "\",\"verifier\"", "\"image\":\"sha256:zz\",\"verifier\""); }); }); }
    { Fixture f(true); FakeOps ops(f); Request r = f.request(Mode::Status); r.nativeControlSha256.clear();
      CHECK_THROW(runMaintenance(r, ops), "native_control_sha256_required"); CHECK(ops.calls.empty()); }
    { Fixture f(true); FakeOps ops(f); Request r = f.request(Mode::Status); r.nativeControlSha256 = std::string(64, '8');
      CHECK_THROW(runMaintenance(r, ops), "native_control_sha256_mismatch"); CHECK(ops.calls.empty()); }
    { Fixture f(true); expectFailure(f, Mode::Status, "unsupported mixed control variant", [&]{
          f.rewrite([](std::string& j){ j.insert(j.size() - 1, ",\"controlRecipe\":{\"service.py\":\"" + std::string(64, 'a') + "\"}"); }); }); }
    { Fixture f(true); expectFailure(f, Mode::Status, "native_control_not_ready", [&]{
          f.rewrite([](std::string& j){ replaceOnce(j, "\"controlLoadedReceipt\":true", "\"controlLoadedReceipt\":false"); }); }); }
    { Fixture f(true); expectFailure(f, Mode::Maintain, "native_control_not_ready", [&]{
          f.rewrite([](std::string& j){ replaceOnce(j, "\"controlLoadedReceipt\":true", "\"controlLoadedReceipt\":false"); }); }); }
}

static void testNativeHelperGuards() {
    auto bindingFailure = [](Fixture& f, Mode mode, const std::function<void()>& mutate, const char* text = "control maintenance helper binding") {
        mutate(); FakeOps ops(f);
        expectThrows([&]{ runMaintenance(f.request(mode), ops); }, text, __LINE__);
        CHECK(ops.mutatingBoundary() == false);
        CHECK(ops.count("python") == 0);
    };
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.entrypoint = "python"; }); }
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.command = "/migration/target.py"; }); }
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.envSha = std::string(64, '1'); }, "control maintenance helper role/scope"); }
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.envRoleSuffix = "x"; }, "control maintenance helper role/scope"); }
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.envScope = "amnezia-awg2"; }, "control maintenance helper role/scope"); }
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.networkOverride = "container:" + std::string(64, 'b'); }); }
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.mounts = 3; }); }
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.migrationRW = false; }); }
    { Fixture f(true); bindingFailure(f, Mode::RestartControls, [&]{ f.privileged = true; }); }
    { Fixture f(true); bindingFailure(f, Mode::Maintain, [&]{ f.entrypoint = "python"; }); }
    { Fixture f(true); f.rewrite([&](std::string& j){
          replaceOnce(j, "\"image\":\"" + f.image + "\",\"verifier\"", "\"image\":\"sha256:" + std::string(64, '0') + "\",\"verifier\"");
      }); FakeOps ops(f);
      CHECK_THROW(runMaintenance(f.request(Mode::RestartControls), ops), "control maintenance helper image");
      CHECK(ops.count("/app/awg-feed") == 0); }
}

static void testLegacySeparation() {
    { Fixture f(false); FakeOps ops(f);
      auto s = runMaintenance(f.request(Mode::Status), ops);
      CHECK(s.ok && !s.native && s.controlHashes.size() == 2 && s.controlHashes.at("service.py") == sha("service-old\n"));
      CHECK(ops.calls.empty()); }
    { Fixture f(false); FakeOps ops(f);
      auto r = runMaintenance(f.request(Mode::RestartControls), ops);
      CHECK(r.ok && !r.native);
      CHECK(ops.count("python") >= 3);
      CHECK(ops.count("/app/awg-feed") == 0);
      CHECK(ops.saw("assert r[\"hashes\"]")); }
    { Fixture f(false, true); FakeOps ops(f);
      auto r = runMaintenance(f.request(Mode::RestartControls), ops);
      CHECK(r.ok && r.native);
      CHECK(ops.count("python") >= 2);
      CHECK(ops.count("/app/awg-feed", "--verify-control-loaded") == 2);
      CHECK(ops.count("/app/awg-feed", "--verify-control-live") == 0); }
    { Fixture f(false, true); FakeOps ops(f); Request r = f.request(Mode::RestartControls); r.nativeControlSha256.clear();
      CHECK_THROW(runMaintenance(r, ops), "native_control_sha256_required"); CHECK(ops.calls.empty()); }
    { Fixture f(false); FakeOps ops(f);
      auto r = runMaintenance(f.request(Mode::Maintain), ops);
      CHECK(r.ok && !r.native && r.controlHashes.at("service.py") == sha("service-old\n"));
      CHECK(read(f.directory / "transaction.json").find("\"controlLoadedReceipt\":true") != std::string::npos);
      CHECK(ops.count("/app/awg-feed") == 0); }
}

static void testRecoveryAndFaultOrdering() {
    // Native: malformed persisted rollback state still refuses before mutation;
    // valid replacement/recovery is covered by the full transaction consumer.
    { Fixture f(true);
      f.rewrite([](std::string& j){ j.insert(j.size() - 1, ",\"controlMaintenance\":{\"old\":{},\"new\":{},\"protected\":{}}"); });
      const auto before = read(f.directory / "transaction.json");
      FakeOps ops(f);
      CHECK_THROW(runMaintenance(f.request(Mode::Recover), ops), "control maintenance state");
      CHECK(read(f.directory / "transaction.json") == before);
      CHECK(ops.mutatingBoundary() == false && ops.count("python") == 0);
      FakeOps maintain(f);
      CHECK_THROW(runMaintenance(f.request(Mode::Maintain), maintain), "control maintenance recovery required");
      CHECK(maintain.calls.empty()); }
    // Native restart: a failed owned-listener verification propagates and never
    // writes a success journal.
    { Fixture f(true); FakeOps ops(f); ops.failNative = true;
      const auto before = read(f.directory / "transaction.json");
      CHECK_THROW(runMaintenance(f.request(Mode::RestartControls), ops), "native control rejected");
      CHECK(read(f.directory / "transaction.json") == before);
      CHECK(ops.count("python") == 0); }
    // Legacy rollback transaction is preserved unchanged.
    { Fixture f(false); write(f.recipe / "service.py", "service-new\n");
      FakeOps ops(f); ops.rejectHash = sha("service-new\n");
      TransactionJournal journal(f.directory, [&](const std::vector<std::string>& a){ CommandResult r; try { r.output = ops.run(a); } catch (const std::exception& e) { r.status = 1; r.error = e.what(); } return r; });
      bool threw = false;
      try { runControlMaintenance(journal, f.directory, f.recipe, false, "", ops, []{}); }
      catch (const std::exception& e) { threw = true; std::cerr << "legacy rollback primary: " << e.what() << "\n"; }
      CHECK(threw);
      CHECK(read(f.directory / "service.py") == "service-old\n");
      CHECK(journal.snapshot().find("\"controlMaintenance\"") == std::string::npos);
      CHECK(journal.snapshot().find("\"controlMaintenanceResult\":\"rolled_back\"") != std::string::npos); }
    // Legacy recover-ready keeps the Python listener attestation and never any
    // native verify flag.
    { Fixture f(false); FakeOps ops(f); ops.stopTarget = true;
      auto r = runMaintenance(f.request(Mode::Recover), ops);
      CHECK(r.ok && r.phase == "ready" && ops.count("python") > 0 && ops.count("/app/awg-feed") == 0); }
}

int main(int argc, char** argv) {
    try { testNativePositives(); } catch (const std::exception& e) { std::cerr << "EX native positives: " << e.what() << "\n"; ++failures; }
    try { testNativeChangedPayload(); } catch (const std::exception& e) { std::cerr << "EX native changed: " << e.what() << "\n"; ++failures; }
    try { testVariantGuards(); } catch (const std::exception& e) { std::cerr << "EX variant guards: " << e.what() << "\n"; ++failures; }
    try { testNativeHelperGuards(); } catch (const std::exception& e) { std::cerr << "EX helper guards: " << e.what() << "\n"; ++failures; }
    try { testLegacySeparation(); } catch (const std::exception& e) { std::cerr << "EX legacy: " << e.what() << "\n"; ++failures; }
    try { testRecoveryAndFaultOrdering(); } catch (const std::exception& e) { std::cerr << "EX recovery: " << e.what() << "\n"; ++failures; }
    if (failures) { std::cerr << failures << " failures\n"; return 1; }
    std::cout << "S2 consumer checks: ok\n";
    if (argc == 2 && std::string(argv[1]) == "--fail-work") return 23;
    return 0;
}
