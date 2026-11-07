// Inert, owned TEST fixture for the explicit native-control replacement lane.
// Docker/process/sleep are FAKE at the Ops boundary; the journal, JSON and
// filesystem checks in the subject are the real ones. No product execution, no
// guest, no network, no secret and no host control is reachable from here.
#pragma once
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

namespace awgfix {
using namespace amnezia::awgMigration;
using namespace amnezia::awgMigration::maintenance;
namespace fs = std::filesystem;

inline std::string sha(const std::string& bytes) {
    unsigned char out[EVP_MAX_MD_SIZE]; unsigned n = 0;
    EVP_Digest(bytes.data(), bytes.size(), out, &n, EVP_sha256(), nullptr);
    std::string hex; char b[3];
    for (unsigned i = 0; i < n; ++i) { std::snprintf(b, sizeof b, "%02x", out[i]); hex += b; }
    return hex;
}
inline void write(const fs::path& p, const std::string& bytes, mode_t mode = 0600) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc); out << bytes; out.close(); chmod(p.c_str(), mode);
}
inline std::string read(const fs::path& p) {
    std::ifstream in(p, std::ios::binary); return std::string(std::istreambuf_iterator<char>(in), {});
}
inline void replaceOnce(std::string& text, const std::string& from, const std::string& to) {
    auto at = text.find(from);
    if (at == std::string::npos) throw std::runtime_error("fixture token absent: " + from);
    text.replace(at, from.size(), to);
}
inline std::string hexId(unsigned long long n) {
    std::string s(64, '0'); char buf[32];
    std::snprintf(buf, sizeof buf, "%llx", n);
    std::string h(buf); s.replace(s.size() - h.size(), h.size(), h);
    return s;
}
// Minimal well-formed ELF64 program-header image (inert bytes; never executed).
inline std::string elfImage(const std::string& marker, unsigned programType = 1, unsigned machine = 62, unsigned type = 2) {
    std::string b(64 + 56, '\0');
    b[0] = '\x7f'; b[1] = 'E'; b[2] = 'L'; b[3] = 'F'; b[4] = 2; b[5] = 1; b[6] = 1;
    auto put = [&](std::size_t o, unsigned long long v, unsigned w) { for (unsigned i = 0; i < w; ++i) b[o + i] = char(v >> (8 * i)); };
    put(16, type, 2); put(18, machine, 2); put(20, 1, 4); put(24, 0x401000, 8);
    put(32, 64, 8); put(52, 64, 2); put(54, 56, 2); put(56, 1, 2);
    put(64, programType, 4);
    return b + marker;
}

struct Dyn {
    std::string id, name, image, role, payload, parent, started = "t0";
    bool running = false;
    unsigned starts = 0;
};

struct Fixture {
    fs::path root, directory, recipe, staging;
    const std::string owner = std::string(32, 'a');
    const std::string sourceId = std::string(64, 'b');
    const std::string targetId = std::string(64, 'c');
    const std::string controlId = std::string(64, 'e');
    const std::string sourceControlId = std::string(64, 'f');
    const std::string image = "sha256:" + std::string(64, 'd');
    std::string nativeSha, journal, config;
    const std::string feedSha = std::string(64, '7');
    const std::string peerKey = std::string(43, 'Q') + "=";
    bool native = false, legacyFeed = false;
    std::string entrypoint, command, envSha, envRoleSuffix, envScope, networkOverride;
    bool privileged = false;
    int mounts = 2;
    bool migrationRW = true;
    std::map<std::string, int> restarted;
    std::set<std::string> stopped, removed;
    std::map<std::string, Dyn> dyn;
    std::set<std::string> created;
    std::set<std::string> images;
    unsigned long long counter = 0x1000;

    static void mkdir(const fs::path& p) { fs::create_directories(p); chmod(p.c_str(), 0700); }
    explicit Fixture(bool nativeMode, bool feedMode = false) : native(nativeMode), legacyFeed(feedMode) {
        nativeSha = sha(elfImage("control-old\n"));
        root = fs::temp_directory_path() / ("awg-native-txn-" + std::to_string(getpid()) + "-" + std::to_string(reinterpret_cast<std::uintptr_t>(this)));
        fs::remove_all(root); mkdir(root); mkdir(root / "amnezia-awg"); directory = root / "amnezia-awg" / "1"; mkdir(directory);
        mkdir(root / "staging"); staging = root / "staging";
        write(root / ".prepare.lock", "lock\n");
        config = "[Interface]\nPrivateKey = " + std::string(43, 'A') + "=\nAddress = 10.8.0.1/24\nListenPort = 51820\nJc = 4\n\n[Peer]\nPublicKey = " + peerKey + "\nAllowedIPs = 10.8.0.2/32\n";
        for (const char* n : {"awg0.conf", "awg0.native.conf", "signing.pem", "start.sh", "grants.sqlite3"}) write(directory / n, std::string(n) + "-bytes\n");
        write(directory / "awg0.conf", config);
        if (!native) { write(directory / "service.py", "service-old\n"); write(directory / "target.py", "target-old\n"); }
        write(directory / "ready.json", "{\"containerId\":\"amnezia-awg\",\"targetContainer\":\"amnezia-awg-migration-1\",\"generation\":1,\"endpoint\":\"vpn.example:51820\",\"serverPublicKey\":\"" + peerKey + "\",\"parameters\":{\"Jc\":\"4\"},\"peers\":{\"" + peerKey + "\":{\"sourceIp\":\"10.8.0.2\",\"targetIp\":\"10.8.0.2\",\"clientAddress\":\"10.8.0.2/32\"}}}");
        recipe = root / "recipes"; mkdir(recipe);
        if (native) write(recipe / "awg-feed", elfImage("control-old\n"));
        else { write(recipe / "service.py", "service-old\n"); write(recipe / "target.py", "target-old\n"); }
        entrypoint = native ? "/app/awg-feed" : "python";
        command = native ? "--control-pid1" : "/migration/target.py";
        envSha = native ? nativeSha : std::string();
        envScope = "amnezia-awg";
        std::string containers = "{\"amnezia-awg-migration-1\":{\"image\":\"" + image + "\",\"id\":\"" + targetId + "\"},\"amnezia-awg-migration-1-control\":{\"image\":\"" + image + "\",\"id\":\"" + controlId + "\"},\"amnezia-awg-migration-1-source-control\":{\"image\":\"" + image + "\",\"id\":\"" + sourceControlId + "\"}}";
        std::string j = "{\"owner\":\"" + owner + "\",\"phase\":\"ready\",\"source\":\"amnezia-awg\",\"sourceId\":\"" + sourceId + "\",\"target\":\"amnezia-awg-migration-1\",\"sourceIface\":\"wg0\",\"sourceRules\":false,\"sourceEpoch\":\"t-source\",\"targetEpoch\":\"t-target\",\"sourceDigest\":\"" + sha(config) + "\",\"controlLoadedReceipt\":true,\"request\":{\"generation\":1,\"port\":51820,\"host\":\"vpn.example\",\"image\":\"" + image + "\"},\"containers\":" + containers;
        if (native) {
            j += ",\"nativeControl\":{\"variant\":\"native-control-http-v1\",\"protocol\":\"control-http-v1\",\"authority\":\"authenticated-operator-sha256\",\"sha256\":\"" + nativeSha + "\",\"image\":\"" + image + "\",\"verifier\":\"--verify-control-live\",\"roles\":[\"target\",\"source\"]}";
            // S1 binds the target feed to the same authenticated bytes at prepare
            // time; a control-only update is what makes them diverge afterwards.
            if (legacyFeed) j += ",\"nativeFeedSha256\":\"" + nativeSha + "\"";
        } else {
            j += ",\"controlRecipe\":{\"service.py\":\"" + sha("service-old\n") + "\",\"target.py\":\"" + sha("target-old\n") + "\"}";
            if (legacyFeed) j += ",\"nativeFeedSha256\":\"" + feedSha + "\"";
        }
        j += "}";
        write(directory / "transaction.json", j);
        journal = j;
    }
    ~Fixture() { fs::remove_all(root); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string protectedJson() const {
        std::string out = "{\"awg0.conf\":\"" + sha(read(directory / "awg0.conf")) + "\"";
        for (const char* n : {"ready.json", "signing.pem", "start.sh", "awg0.native.conf"})
            out += ",\"" + std::string(n) + "\":\"" + sha(read(directory / n)) + "\"";
        return out + "}";
    }
    Request request(Mode mode) const {
        Request r; r.mode = mode; r.source = "amnezia-awg"; r.generation = 1;
        r.expectedJournalSha256 = sha(read(directory / "transaction.json"));
        r.nativeControlSha256 = native ? nativeSha : (legacyFeed ? std::string(64, '8') : std::string());
        r.root = root; r.recipeDirectory = recipe; r.controlStagingDirectory = staging;
        return r;
    }
    // Operator-authenticated replacement request for the given candidate bytes.
    Request upgrade(const std::string& newBytes) const {
        Request r = request(Mode::Maintain);
        r.nativeControlReplacementSha256 = sha(newBytes);
        return r;
    }
    void rewrite(const std::function<void(std::string&)>& change) {
        std::string text = read(directory / "transaction.json");
        change(text);
        write(directory / "transaction.json", text);
    }
    // Plant the persisted-intent state a crash after the intent write leaves.
    void plantIntent(const std::string& newSha, const std::string& newImage) {
        std::string intent = ",\"controlMaintenance\":{\"old\":{\"payload\":\"" + nativeSha + "\",\"image\":\"" + image + "\"}"
            + ",\"new\":{\"payload\":\"" + newSha + "\",\"image\":\"" + newImage + "\",\"stage\":\"\",\"context\":\"\"}"
            + ",\"protected\":" + protectedJson() + ",\"oldLoadedReceipt\":true,\"feedSha256\":\"" + feedSha + "\"}";
        rewrite([&](std::string& text) { text.insert(text.size() - 1, intent); });
    }
    std::string addHelper(const std::string& name, const std::string& role, const std::string& img,
                          const std::string& payload, bool running, const std::string& ownerOverride = {}) {
        const auto id = hexId(counter++);
        created.insert(id);
        Dyn d; d.id = id; d.name = name; d.image = img; d.role = role; d.payload = payload;
        d.parent = role == "source" ? sourceId : targetId; d.running = running; d.starts = 1;
        d.started = "t-dyn-" + id.substr(0, 6);
        dyn[id] = d;
        if (!ownerOverride.empty()) owners[id] = ownerOverride;
        return id;
    }
    std::map<std::string, std::string> owners;
    std::string envFor(const std::string& role) const {
        if (!native) return "\"AMNEZIA_MIGRATION_ROLE=" + role + "\",\"AMNEZIA_MIGRATION_SCOPE=amnezia-awg\"";
        return "\"AMNEZIA_CONTROL_NATIVE_SHA256=" + envSha + "\",\"AMNEZIA_MIGRATION_ROLE=" + role + envRoleSuffix
            + "\",\"AMNEZIA_MIGRATION_SCOPE=" + (envScope.empty() ? "amnezia-awg" : envScope) + "\"";
    }
    std::string dynJson(const Dyn& d) const {
        const auto ownerValue = owners.count(d.id) ? owners.at(d.id) : owner;
        return "{\"Id\":\"" + d.id + "\",\"Name\":\"/" + d.name + "\",\"Image\":\"" + d.image + "\",\"State\":{\"Running\":"
            + std::string(d.running ? "true" : "false") + ",\"StartedAt\":\"" + d.started + "\"},"
            "\"Config\":{\"Labels\":{\"amnezia.migration.owner\":\"" + ownerValue + "\"},\"Env\":[\"AMNEZIA_CONTROL_NATIVE_SHA256="
            + d.payload + "\",\"AMNEZIA_MIGRATION_ROLE=" + d.role + "\",\"AMNEZIA_MIGRATION_SCOPE=amnezia-awg\"],"
            "\"Entrypoint\":[\"/app/awg-feed\"],\"Cmd\":[\"--control-pid1\"]},"
            "\"HostConfig\":{\"NetworkMode\":\"container:" + d.parent + "\",\"Privileged\":false},"
            "\"Mounts\":[{\"Type\":\"bind\",\"Source\":\"" + directory.generic_string() + "\",\"Destination\":\"/migration\",\"RW\":true}"
            ",{\"Type\":\"bind\",\"Source\":\"/opt/amnezia/client-logs\",\"Destination\":\"/logs\",\"RW\":false}]}";
    }
    std::string inspectFor(const std::string& reference) const {
        if (dyn.count(reference)) return dynJson(dyn.at(reference));
        for (const auto& item : dyn) if (item.second.name == reference && !removed.count(item.first)) return dynJson(item.second);
        if (reference == "amnezia-awg-migration-1-control") return inspectFor(controlId);
        if (reference == "amnezia-awg-migration-1-source-control") return inspectFor(sourceControlId);
        if (reference == "amnezia-awg-migration-1") return inspectFor(targetId);
        if (removed.count(reference)) throw std::runtime_error("no such object");
        std::string name, role, parent, epoch;
        if (reference == sourceId) return "{\"Id\":\"" + sourceId + "\",\"Name\":\"/amnezia-awg\",\"Image\":\"" + image + "\",\"State\":{\"Running\":true,\"StartedAt\":\"t-source\"},\"Config\":{\"Labels\":{}},\"HostConfig\":{},\"Mounts\":[]}";
        if (reference == targetId) { name = "amnezia-awg-migration-1"; parent = sourceId; epoch = "t-target"; }
        else if (reference == controlId) { name = "amnezia-awg-migration-1-control"; role = "target"; parent = targetId; epoch = "t-control"; }
        else if (reference == sourceControlId) { name = "amnezia-awg-migration-1-source-control"; role = "source"; parent = sourceId; epoch = "t-source-control"; }
        else throw std::runtime_error("no such object");
        bool running = !stopped.count(reference);
        auto restartCount = restarted.find(reference);
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
        return "{\"Id\":\"" + reference + "\",\"Name\":\"/" + name + "\",\"Image\":\"" + image + "\",\"State\":{\"Running\":" + std::string(running ? "true" : "false") + ",\"StartedAt\":\"" + epoch + "\"},"
            "\"Config\":{\"Labels\":{\"amnezia.migration.owner\":\"" + owner + "\"},\"Env\":[" + env + "],\"Entrypoint\":[\"" + ep + "\"],\"Cmd\":[\"" + cmd + "\"]},"
            "\"HostConfig\":{\"NetworkMode\":\"" + network + "\",\"Privileged\":" + std::string(privileged ? "true" : "false") + "},"
            "\"Mounts\":[" + mountsJson + "]}";
    }
};

struct FakeOps : Ops {
    Fixture& f;
    std::vector<std::vector<std::string>> calls;
    std::vector<std::pair<std::string,std::string>> builtContexts;
    bool failNative = false, failRestart = false, failAllDocker = false, stopTarget = false;
    bool failBuild = false, failImageInspect = false;
    std::string failCreateRole, failStartRole, failVerifyRole, rejectHash;
    explicit FakeOps(Fixture& fixture) : f(fixture) {}
    std::uint32_t euid() override { return 0; }
    void sleepSeconds(unsigned) override {}
    std::string run(const std::vector<std::string>& a) override {
        calls.push_back(a);
        if (failAllDocker) throw std::runtime_error("external boundary disabled");
        if (a.empty() || a[0] != "docker") throw std::runtime_error("unexpected external command in inert fixture");
        if (a.size() == 3 && a[1] == "inspect") return "[" + f.inspectFor(a[2]) + "]";
        if (a.size() >= 2 && a[1] == "build") {
            if (failBuild) throw std::runtime_error("image build failed");
            std::string iid;
            for (std::size_t i = 2; i + 1 < a.size(); ++i) if (a[i] == "--iidfile") iid = a[i + 1];
            const fs::path context(a.back());
            builtContexts.emplace_back(context.generic_string(), sha(read(context / "awg-feed")));
            const auto built = "sha256:" + hexId(f.counter++);
            f.images.insert(built);
            if (iid.empty()) throw std::runtime_error("build iid file missing");
            write(iid, built + "\n");
            return "";
        }
        if (a.size() == 6 && a[1] == "image" && a[2] == "inspect") {
            if (failImageInspect) throw std::runtime_error("image inspect failed");
            if (!f.images.count(a[5])) throw std::runtime_error("no such image");
            return a[5] + "\n";
        }
        if (a.size() >= 3 && a[1] == "create") {
            std::string name, image, payload, role, network, scope;
            for (std::size_t i = 2; i < a.size(); ++i) {
                if (a[i] == "--name") name = a[++i];
                else if (a[i] == "--env") { auto pair = a[++i]; auto eq = pair.find('='); auto key = pair.substr(0, eq); auto value = pair.substr(eq + 1);
                    if (key == "AMNEZIA_CONTROL_NATIVE_SHA256") payload = value;
                    else if (key == "AMNEZIA_MIGRATION_ROLE") role = value;
                    else if (key == "AMNEZIA_MIGRATION_SCOPE") scope = value; }
                else if (a[i] == "--network") network = a[++i];
                else if (a[i] == "--label" || a[i] == "--security-opt" || a[i] == "--mount") ++i;
                else image = a[i];
            }
            if (role.empty() || payload.empty() || name.empty()) throw std::runtime_error("create contract");
            if (failCreateRole == role) throw std::runtime_error("container create failed");
            if (network != "container:" + (role == "source" ? f.sourceId : f.targetId)) throw std::runtime_error("create network");
            const auto id = f.addHelper(name, role, image, payload, false);
            return id + "\n";
        }
        if (a.size() == 3 && a[1] == "start") {
            auto found = f.dyn.find(a[2]);
            if (found == f.dyn.end()) throw std::runtime_error("no such container");
            if (failStartRole == found->second.role) throw std::runtime_error("container start failed");
            found->second.running = true; ++found->second.starts;
            found->second.started += "+" + std::to_string(found->second.starts);
            return "";
        }
        if (a.size() >= 3 && a[1] == "restart") {
            if (failRestart) throw std::runtime_error("restart failed");
            if (f.dyn.count(a.back())) { f.dyn[a.back()].started += "+"; ++f.dyn[a.back()].starts; return ""; }
            ++f.restarted[a.back()]; return "";
        }
        if (a.size() >= 3 && a[1] == "rm") {
            if (f.dyn.erase(a.back())) return "";
            f.removed.insert(a.back()); return "";
        }
        if (a.size() >= 5 && a[1] == "exec") {
            const std::string id = a[2]; const std::string cmd = a[3];
            if (cmd == "cat") return f.config;
            if (cmd == "python") {
                if (f.native) throw std::runtime_error("python executed in native control path");
                if (!rejectHash.empty()) for (const auto& s : a) if (s.find(rejectHash) != std::string::npos) throw std::runtime_error("legacy probe rejected");
                return "";
            }
            if (cmd == "/app/awg-feed") {
                if (failNative) throw std::runtime_error("native control rejected");
                if (a.size() >= 8 && a[4] == "--verify-control-live") {
                    const auto role = a[5], payload = a[6];
                    auto found = f.dyn.find(id);
                    if (found != f.dyn.end()) {
                        if (!found->second.running || found->second.payload != payload || found->second.role != role)
                            throw std::runtime_error("native control rejected");
                    } else if (payload != f.nativeSha) throw std::runtime_error("native control rejected");
                    if (failVerifyRole == role) throw std::runtime_error("native control rejected");
                }
                return "";
            }
            if (cmd == "awg" && a.size() >= 6 && a[4] == "show") {
                if (a.size() >= 7 && a[5] == "awg0" && a[6] == "dump")
                    return "priv\t" + f.peerKey + "\t51820\t0\n" + f.peerKey + "\t(none)\t0\t10.8.0.2/32\t0\n";
                return "Jc = 4\n";
            }
            if (cmd == "awg" && a.size() >= 6 && a[4] == "showconf") return "Jc = 4\n";
            if (cmd == "sh") return "6d96502ebd9ed6f9d17bdecd637cba7502c9960fed1b6922b3882784417a036d  /proc/123/exe\n";
            return "";
        }
        throw std::runtime_error("unexpected external command in inert fixture");
    }
    bool saw(const std::string& sub) const {
        for (const auto& a : calls) for (const auto& s : a) if (s.find(sub) != std::string::npos) return true;
        return false;
    }
    std::size_t count(const std::string& command, const std::string& flag = {}) const {
        std::size_t n = 0;
        for (const auto& a : calls)
            if (a.size() > 3 && a[1] == "exec" && a[3] == command && (flag.empty() || (a.size() > 4 && a[4] == flag))) ++n;
        return n;
    }
    std::size_t verb(const std::string& name) const {
        std::size_t n = 0;
        for (const auto& a : calls) if (a.size() > 1 && a[1] == name) ++n;
        return n;
    }
    bool mutatingBoundary() const {
        for (const auto& a : calls)
            if (a.size() > 1 && (a[1] == "restart" || a[1] == "start" || a[1] == "rm" || a[1] == "run" || a[1] == "build" || a[1] == "create")) return true;
        return false;
    }
    std::size_t verifiedAs(const std::string& payload) const {
        std::size_t n = 0;
        for (const auto& a : calls)
            if (a.size() >= 8 && a[1] == "exec" && a[3] == "/app/awg-feed" && a[4] == "--verify-control-live" && a[6] == payload) ++n;
        return n;
    }
};
} // namespace awgfix
