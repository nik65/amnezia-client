#include "maintenance_runtime.h"
#include <json-c/json.h>
#include <openssl/evp.h>
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace amnezia::awgMigration::maintenance {
namespace {
namespace fs = std::filesystem;
using Json = std::shared_ptr<json_object>;
constexpr std::uint64_t kMaxGeneration = 9007199254740991ULL;
// Resolved once from the journal. Explicit native-control-http-v1 generations are
// never inferred from the legacy nativeFeedSha256 flag: that flag still denotes a
// Python PID1/control-json-v1 generation with an unchanged listener contract.
enum class ControlMode { LegacyPython, NativeHttp };
struct ControlBinding {
    ControlMode mode = ControlMode::LegacyPython;
    std::string payloadSha256;
    std::string image;
    bool nativeFeedFlag = false;
};
constexpr const char* kEngineSha256 = "6d96502ebd9ed6f9d17bdecd637cba7502c9960fed1b6922b3882784417a036d";
constexpr const char* kListenerProbe = "import os,pathlib; cmd=pathlib.Path(\"/proc/1/cmdline\").read_bytes().split(bytes([0])); assert b\"/migration/target.py\" in cmd; owned={os.readlink(p) for p in pathlib.Path(\"/proc/1/fd\").iterdir()}; rows=[line.split() for line in pathlib.Path(\"/proc/net/tcp\").read_text().splitlines()[1:]]; assert any(row[1]==\"00000000:46A2\" and row[3]==\"0A\" and \"socket:[\"+row[9]+\"]\" in owned for row in rows)";
const std::map<std::string,std::string> kBaselineA = {
    {"service.py","88254af95c85b49ee2bc0d1d6d981ee401e0be0c5bddce1d0c4462245419ae3e"},
    {"target.py","1ed03cc1fc41c6bbd87c58bcb207bcfa6d38d6501987d2a6a9d8faf469617d32"}};
const std::map<std::string,std::string> kBaselineB = {
    {"service.py","ed640e5fcbba634a6963d43e207ffaf672704d37044fdb186fd27d61351c6eb2"},
    {"target.py","1ed03cc1fc41c6bbd87c58bcb207bcfa6d38d6501987d2a6a9d8faf469617d32"}};

[[noreturn]] void fail(const std::string& text) { throw std::runtime_error(text); }
Json adopt(json_object* p) { if (!p) fail("invalid maintenance JSON"); return Json(p, json_object_put); }
Json parseJson(const std::string& raw) {
    json_tokener* tok = json_tokener_new();
    if (!tok) fail("invalid maintenance JSON");
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    json_object* value = json_tokener_parse_ex(tok, raw.data(), static_cast<int>(raw.size()));
    auto used = json_tokener_get_parse_end(tok);
    bool ok = value && json_tokener_get_error(tok) == json_tokener_success && used == raw.size();
    json_tokener_free(tok);
    if (!ok) { if (value) json_object_put(value); fail("invalid maintenance JSON"); }
    return adopt(value);
}
json_object* need(json_object* p, const char* key, json_type type) {
    json_object* value = nullptr;
    if (!p || !json_object_object_get_ex(p, key, &value) || !json_object_is_type(value, type))
        fail("control maintenance state");
    return value;
}
bool has(json_object* p, const char* key) { json_object* v = nullptr; return p && json_object_object_get_ex(p, key, &v); }
std::string text(json_object* p, const char* key) {
    json_object* v = need(p, key, json_type_string);
    return std::string(json_object_get_string(v), json_object_get_string_len(v));
}
std::string optionalText(json_object* p, const char* key) {
    json_object* v = nullptr;
    if (!p || !json_object_object_get_ex(p, key, &v) || json_object_is_type(v, json_type_null)) return {};
    if (!json_object_is_type(v, json_type_string)) fail("control maintenance state");
    return std::string(json_object_get_string(v), json_object_get_string_len(v));
}
bool booleanAt(json_object* p, const char* key) { return json_object_get_boolean(need(p, key, json_type_boolean)) != 0; }
std::int64_t integerAt(json_object* p, const char* key) { return json_object_get_int64(need(p, key, json_type_int)); }
std::string plain(json_object* p) { return json_object_to_json_string_ext(p, JSON_C_TO_STRING_PLAIN); }
std::string sha256(const std::string& bytes) {
    unsigned char out[EVP_MAX_MD_SIZE]; unsigned length = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), out, &length, EVP_sha256(), nullptr) != 1) fail("SHA256 unavailable");
    std::string value; char part[3];
    for (unsigned i = 0; i < length; ++i) { std::snprintf(part, sizeof part, "%02x", out[i]); value += part; }
    return value;
}
bool hex64(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c){ return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
std::string readBytes(const fs::path& path, const std::string& label, std::size_t limit = 4u * 1024u * 1024u) {
    std::error_code ec; auto status = fs::symlink_status(path, ec);
    if (ec || fs::is_symlink(status) || !fs::is_regular_file(status)) fail(label);
    std::ifstream in(path, std::ios::binary);
    if (!in) fail(label);
    std::string bytes((std::istreambuf_iterator<char>(in)), {});
    if (in.bad() || bytes.size() > limit) fail(label);
    return bytes;
}
std::map<std::string,std::string> textMap(json_object* object) {
    if (!json_object_is_type(object, json_type_object)) fail("control maintenance state");
    std::map<std::string,std::string> result;
    json_object_object_foreach(object, key, value) {
        if (!json_object_is_type(value, json_type_string)) fail("control maintenance state");
        result[key] = std::string(json_object_get_string(value), json_object_get_string_len(value));
    }
    return result;
}
Json mapJson(const std::map<std::string,std::string>& values) {
    Json result = adopt(json_object_new_object());
    for (const auto& item : values)
        json_object_object_add(result.get(), item.first.c_str(), json_object_new_string_len(item.second.data(), static_cast<int>(item.second.size())));
    return result;
}
bool sameMap(const std::map<std::string,std::string>& a, const std::map<std::string,std::string>& b) {
    if (a.size() != b.size()) return false;
    for (const auto& item : a) { auto found = b.find(item.first); if (found == b.end() || found->second != item.second) return false; }
    return true;
}
void durableWrite(const fs::path& path, const std::string& bytes) {
    if (bytes.size() > 4u * 1024u * 1024u) fail("control maintenance write budget");
    int fd = -1; std::string temporary;
    for (unsigned n = 0; n < 100; ++n) {
        temporary = "." + path.filename().string() + "-" + std::to_string(getpid()) + "-" + std::to_string(n);
        auto candidate = path.parent_path() / temporary;
        fd = open(candidate.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST) fail("control maintenance staging");
    }
    if (fd < 0) fail("control maintenance staging");
    auto temporaryPath = path.parent_path() / temporary;
    std::size_t position = 0;
    try {
        while (position < bytes.size()) {
            auto written = write(fd, bytes.data() + position, bytes.size() - position);
            if (written < 0) { if (errno == EINTR) continue; fail("control maintenance write"); }
            if (!written) fail("control maintenance short write");
            position += static_cast<std::size_t>(written);
        }
        if (fsync(fd) < 0) fail("control maintenance fsync");
        if (close(fd) < 0) { fd = -1; fail("control maintenance close"); }
        fd = -1;
        if (readBytes(temporaryPath, "control maintenance staged readback") != bytes) fail("control maintenance staged readback");
        if (rename(temporaryPath.c_str(), path.c_str()) < 0) fail("control maintenance replace");
        if (readBytes(path, "control maintenance readback") != bytes) fail("control maintenance readback");
        int dir = open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir < 0) fail("control maintenance directory");
        int synced = fsync(dir); close(dir);
        if (synced < 0) fail("control maintenance directory fsync");
    } catch (...) { if (fd >= 0) close(fd); unlink(temporaryPath.c_str()); throw; }
}

ControlBinding controlBinding(TransactionJournal& journal, const std::string& operatorSha) {
    Json value = parseJson(journal.snapshot());
    ControlBinding binding;
    json_object* feedRaw = nullptr;
    binding.nativeFeedFlag = json_object_object_get_ex(value.get(), "nativeFeedSha256", &feedRaw)
        && !json_object_is_type(feedRaw, json_type_null);
    json_object* raw = nullptr;
    if (!json_object_object_get_ex(value.get(), "nativeControl", &raw) || json_object_is_type(raw, json_type_null)) {
        binding.mode = ControlMode::LegacyPython;
        return binding;
    }
    if (!json_object_is_type(raw, json_type_object)) fail("unsupported control variant");
    Json control = adopt(json_object_get(raw));
    if (text(control.get(), "variant") != "native-control-http-v1"
        || text(control.get(), "protocol") != "control-http-v1"
        || text(control.get(), "authority") != "authenticated-operator-sha256"
        || text(control.get(), "verifier") != "--verify-control-live")
        fail("unsupported control variant");
    const auto payload = text(control.get(), "sha256");
    const auto image = text(control.get(), "image");
    if (!hex64(payload) || image.size() != 71 || image.rfind("sha256:", 0) != 0 || !hex64(image.substr(7)))
        fail("unsupported control variant");
    // S1 also binds the target feed to these same authenticated executable
    // bytes. That target-feed field does not select the control protocol.
    // Preserve legacy Python selection when nativeControl is absent, and
    // reject a conflicting or malformed target-feed binding when it is present.
    if (binding.nativeFeedFlag) {
        if (!json_object_is_type(feedRaw, json_type_string)) fail("unsupported mixed control variant");
        const std::string feed(std::string(json_object_get_string(feedRaw), json_object_get_string_len(feedRaw)));
        if (feed != payload) {
            // A control-only replacement leaves the independently bound target
            // feed bytes untouched. That divergence is legitimate only with the
            // exact committed replacement ledger recorded by the transaction.
            json_object* recorded = nullptr;
            if (!json_object_object_get_ex(value.get(), "controlReplacement", &recorded)
                || !json_object_is_type(recorded, json_type_object)
                || optionalText(recorded, "state") != "committed"
                || optionalText(recorded, "feedSha256") != feed
                || !hex64(optionalText(recorded, "priorControlSha256")))
                fail("unsupported mixed control variant");
        }
    }
    json_object* roles = need(control.get(), "roles", json_type_array);
    if (json_object_array_length(roles) != 2
        || !json_object_is_type(json_object_array_get_idx(roles, 0), json_type_string)
        || !json_object_is_type(json_object_array_get_idx(roles, 1), json_type_string)
        || std::string(json_object_get_string(json_object_array_get_idx(roles, 0))) != "target"
        || std::string(json_object_get_string(json_object_array_get_idx(roles, 1))) != "source")
        fail("unsupported control variant");
    json_object* recipeRaw = nullptr;
    if (json_object_object_get_ex(value.get(), "controlRecipe", &recipeRaw) && !json_object_is_type(recipeRaw, json_type_null))
        fail("unsupported mixed control variant");
    if (!booleanAt(value.get(), "controlLoadedReceipt"))
        fail("native_control_not_ready");
    if (operatorSha.empty() || !hex64(operatorSha)) fail("native_control_sha256_required");
    if (operatorSha != payload) fail("native_control_sha256_mismatch");
    binding.mode = ControlMode::NativeHttp;
    binding.payloadSha256 = payload;
    binding.image = image;
    return binding;
}

std::map<std::string,std::string> nativePayloadHashes(const ControlBinding& binding) {
    return {{"awg-feed", binding.payloadSha256}};
}

struct Helper { std::string name, id, role, started; };

Json owned(TransactionJournal& journal, const std::string& name) {
    auto raw = journal.ownedSnapshot(name);
    if (raw == "null") return {};
    return parseJson(raw);
}
Json inspected(TransactionJournal& journal, const std::string& id) {
    auto raw = journal.inspectSnapshot(id);
    if (raw == "null") return {};
    return parseJson(raw);
}

std::vector<Helper> controlHelpers(TransactionJournal& journal, const ControlBinding& binding,
                                   const std::string& expectedImage = {}, const std::string& expectedPayload = {}) {
    const std::string image = expectedImage.empty() ? binding.image : expectedImage;
    const std::string payload = expectedPayload.empty() ? binding.payloadSha256 : expectedPayload;
    Json value = parseJson(journal.snapshot());
    const auto owner = text(value.get(), "owner");
    const auto sourceId = text(value.get(), "sourceId");
    const auto sourceName = text(value.get(), "source");
    const auto targetName = text(value.get(), "target");
    const auto sourceEpoch = text(value.get(), "sourceEpoch");
    const auto targetEpoch = text(value.get(), "targetEpoch");
    auto source = inspected(journal, sourceId);
    auto target = owned(journal, targetName);
    auto state = [](Json& object){ return need(object.get(), "State", json_type_object); };
    if (!source || text(source.get(), "Id") != sourceId || text(source.get(), "Name") != "/" + sourceName
        || !booleanAt(state(source), "Running") || text(state(source), "StartedAt") != sourceEpoch)
        fail("control maintenance parent drift");
    if (!target || !booleanAt(state(target), "Running") || text(state(target), "StartedAt") != targetEpoch)
        fail("control maintenance parent drift");
    Json containers = adopt(json_object_get(need(value.get(), "containers", json_type_object)));
    std::vector<Helper> result;
    for (const auto& role : std::vector<std::pair<std::string,std::string>>{{"-control","target"},{"-source-control","source"}}) {
        const std::string name = targetName + role.first;
        auto helper = owned(journal, name);
        json_object* entry = nullptr;
        if (!json_object_object_get_ex(containers.get(), name.c_str(), &entry)) fail("control maintenance missing helper");
        auto expectedId = optionalText(entry, "id");
        if (!helper || expectedId.empty() || text(helper.get(), "Id") != expectedId) fail("control maintenance missing helper");
        json_object* mounts = nullptr;
        json_object* migration = nullptr; json_object* logMount = nullptr;
        std::size_t migrationCount = 0, logCount = 0, mountCount = 0;
        if (json_object_object_get_ex(helper.get(), "Mounts", &mounts) && json_object_is_type(mounts, json_type_array))
            for (std::size_t i = 0; i < json_object_array_length(mounts); ++i) {
                json_object* m = json_object_array_get_idx(mounts, i);
                if (!json_object_is_type(m, json_type_object)) fail("control maintenance helper binding");
                ++mountCount;
                auto destination = optionalText(m, "Destination");
                if (destination == "/migration") { ++migrationCount; migration = m; }
                if (destination == "/logs") { ++logCount; logMount = m; }
            }
        json_object* host = need(helper.get(), "HostConfig", json_type_object);
        json_object* config = need(helper.get(), "Config", json_type_object);
        json_object* environment = nullptr;
        std::map<std::string,std::string> values;
        if (json_object_object_get_ex(config, "Env", &environment) && json_object_is_type(environment, json_type_array)) {
            for (std::size_t i = 0; i < json_object_array_length(environment); ++i) {
                json_object* item = json_object_array_get_idx(environment, i);
                if (!json_object_is_type(item, json_type_string)) fail("control maintenance helper environment");
                std::string pair(json_object_get_string(item), json_object_get_string_len(item));
                auto equals = pair.find('=');
                if (equals == std::string::npos) fail("control maintenance helper environment");
                auto key = pair.substr(0, equals);
                if (key == "AMNEZIA_MIGRATION_ROLE" || key == "AMNEZIA_MIGRATION_SCOPE"
                    || key == "AMNEZIA_CONTROL_NATIVE_SHA256") {
                    if (values.count(key)) fail("control maintenance duplicate helper environment");
                    values[key] = pair.substr(equals + 1);
                }
            }
        } else if (environment && !json_object_is_type(environment, json_type_null)) fail("control maintenance helper environment");
        auto network = optionalText(host, "NetworkMode");
        json_object* privileged = nullptr;
        bool privilegedValue = true;
        if (json_object_object_get_ex(host, "Privileged", &privileged) && json_object_is_type(privileged, json_type_boolean)) privilegedValue = json_object_get_boolean(privileged);
        json_object* entrypoint = need(config, "Entrypoint", json_type_array);
        json_object* command = need(config, "Cmd", json_type_array);
        auto arrayOne = [](json_object* array, const char* expected) {
            return json_object_array_length(array) == 1 && json_object_is_type(json_object_array_get_idx(array, 0), json_type_string)
                && std::string(json_object_get_string(json_object_array_get_idx(array, 0))) == expected;
        };
        const auto parentId = text(role.second == "source" ? source.get() : target.get(), "Id");
        if (binding.mode == ControlMode::NativeHttp) {
            // Explicit native control: the helper PID1 is the captured /app/awg-feed
            // binary, bound to the authenticated payload, exact image, role and the
            // parent namespace. No Python listener is assumed or probed.
            if (optionalText(helper.get(), "Image") != image) fail("control maintenance helper image");
            json_object* labels = need(config, "Labels", json_type_object);
            if (optionalText(labels, "amnezia.migration.owner") != owner) fail("control maintenance helper identity");
            if (!values.count("AMNEZIA_CONTROL_NATIVE_SHA256") || !values.count("AMNEZIA_MIGRATION_ROLE")
                || !values.count("AMNEZIA_MIGRATION_SCOPE") || values.size() != 3)
                fail("control maintenance helper environment");
            if (values["AMNEZIA_CONTROL_NATIVE_SHA256"] != payload
                || values["AMNEZIA_MIGRATION_ROLE"] != role.second || values["AMNEZIA_MIGRATION_SCOPE"] != sourceName)
                fail("control maintenance helper role/scope");
            if (network != "container:" + parentId || privilegedValue
                || mountCount != 2 || migrationCount != 1 || logCount != 1 || !migration || !logMount
                || optionalText(migration, "Type") != "bind" || optionalText(migration, "Source") != journal.directory().generic_string()
                || !booleanAt(migration, "RW")
                || optionalText(logMount, "Type") != "bind" || optionalText(logMount, "Source") != "/opt/amnezia/client-logs" || booleanAt(logMount, "RW")
                || !arrayOne(entrypoint, "/app/awg-feed") || !arrayOne(command, "--control-pid1"))
                fail("control maintenance helper binding");
        } else {
            auto effectiveRole = values.count("AMNEZIA_MIGRATION_ROLE") ? values["AMNEZIA_MIGRATION_ROLE"] : "target";
            auto effectiveScope = values.count("AMNEZIA_MIGRATION_SCOPE") ? values["AMNEZIA_MIGRATION_SCOPE"] : sourceName;
            if (effectiveRole != role.second || effectiveScope != sourceName || (role.second == "source" && values["AMNEZIA_MIGRATION_SCOPE"] != sourceName))
                fail("control maintenance helper role/scope");
            if (network != "container:" + parentId || privilegedValue
                || migrationCount != 1 || logCount != 1 || !migration || !logMount
                || optionalText(migration, "Type") != "bind" || optionalText(migration, "Source") != journal.directory().generic_string()
                || !booleanAt(migration, "RW")
                || optionalText(logMount, "Type") != "bind" || optionalText(logMount, "Source") != "/opt/amnezia/client-logs" || booleanAt(logMount, "RW")
                || !arrayOne(entrypoint, "python") || !arrayOne(command, "/migration/target.py"))
                fail("control maintenance helper binding");
        }
        result.push_back({name, expectedId, role.second, text(state(helper), "StartedAt")});
    }
    return result;
}

std::map<std::string,std::string> controlHashes(const fs::path& directory) {
    return {{"service.py", sha256(readBytes(directory / "service.py", "control maintenance state"))},
            {"target.py", sha256(readBytes(directory / "target.py", "control maintenance state"))}};
}
std::map<std::string,std::string> protectedState(const fs::path& directory, bool requireNative) {
    std::vector<std::string> names{"awg0.conf","ready.json","signing.pem","start.sh"};
    auto native = directory / "awg0.native.conf";
    std::error_code ec; auto nativeStatus = fs::symlink_status(native, ec);
    if (requireNative || fs::exists(nativeStatus) || fs::is_symlink(nativeStatus)) names.push_back("awg0.native.conf");
    std::map<std::string,std::string> result;
    for (const auto& name : names) result[name] = sha256(readBytes(directory / name, "control maintenance protected state missing"));
    return result;
}
bool isBaseline(const std::map<std::string,std::string>& hashes) { return sameMap(hashes, kBaselineA) || sameMap(hashes, kBaselineB); }

void checkSourceConfiguration(TransactionJournal& journal, Ops& ops) {
    Json value = parseJson(journal.snapshot());
    auto source = text(value.get(), "source");
    auto path = "/opt/amnezia/awg/" + std::string(source == "amnezia-awg" ? "wg0.conf" : "awg0.conf");
    auto raw = ops.run({"docker","exec",text(value.get(), "sourceId"),"cat",path});
    if (sha256(raw) != text(value.get(), "sourceDigest")) fail("control maintenance source configuration drift");
}
void checkControlState(TransactionJournal& journal, const fs::path& directory, Ops& ops, const std::map<std::string,std::string>& protectedHashes) {
    if (!sameMap(protectedState(directory, true), protectedHashes)) fail("control maintenance protected state drift");
    checkSourceConfiguration(journal, ops);
}

std::string legacyProbe(const std::string& role, const std::map<std::string,std::string>& hashes) {
    std::string dict = "{'service.py': '" + hashes.at("service.py") + "', 'target.py': '" + hashes.at("target.py") + "'}";
    return "import json,pathlib; r=json.loads(pathlib.Path(\"/migration/control-loaded-" + role + ".json\").read_text()); assert r[\"role\"]=='"
        + role + "'; assert r[\"hashes\"]==" + dict + "; assert r[\"processStart\"]==pathlib.Path(\"/proc/1/stat\").read_text().split()[21]";
}
void verifyLoaded(const ControlBinding& binding, const Helper& helper, const std::map<std::string,std::string>& expected,
                  const std::string& operatorSha, Ops& ops) {
    if (binding.mode == ControlMode::NativeHttp) {
        // Sole native-control listener gate: the authenticated binary verifies its
        // own PID1/fd/socket ownership. No Python interpreter is executed here.
        ops.run({"docker","exec",helper.id,"/app/awg-feed","--verify-control-live",helper.role,binding.payloadSha256,
                 "/migration/control-loaded-" + helper.role + ".json"});
        return;
    }
    // Legacy generations (including the old nativeFeedSha256/control-json-v1 flag)
    // keep the Python PID1 listener probe and the loaded-receipt semantics exactly.
    ops.run({"docker","exec",helper.id,"python","-c",kListenerProbe});
    if (binding.nativeFeedFlag)
        ops.run({"docker","exec",helper.id,"/app/awg-feed","--verify-control-loaded",helper.role,operatorSha,
                 "/migration/control-loaded-" + helper.role + ".json"});
    else
        ops.run({"docker","exec",helper.id,"python","-c",legacyProbe(helper.role, expected)});
}
void checkLoadedControls(TransactionJournal& journal, const ControlBinding& binding,
                         const std::map<std::string,std::string>& expected, const std::string& operatorSha, Ops& ops) {
    for (const auto& helper : controlHelpers(journal, binding)) verifyLoaded(binding, helper, expected, operatorSha, ops);
}

void restartControls(TransactionJournal& journal, const ControlBinding& binding, const std::map<std::string,std::string>& expected,
                     bool loadedReceipt, const std::string& operatorSha, Ops& ops) {
    auto original = controlHelpers(journal, binding);
    for (const auto& entry : original) {
        auto currentSet = controlHelpers(journal, binding);
        auto current = std::find_if(currentSet.begin(), currentSet.end(), [&](const Helper& h){ return h.name == entry.name; });
        if (current == currentSet.end() || current->id != entry.id) fail("control maintenance helper replaced");
        ops.run({"docker","restart",entry.id});
        std::exception_ptr last;
        bool replaced = false;
        for (unsigned attempt = 0; attempt < 10; ++attempt) {
            try {
                auto fresh = owned(journal, entry.name);
                auto state = fresh ? need(fresh.get(), "State", json_type_object) : nullptr;
                if (!fresh || !booleanAt(state, "Running") || text(state, "StartedAt") == current->started)
                    fail("control maintenance process not replaced");
                Helper freshHelper{entry.name, text(fresh.get(), "Id"), entry.role, text(state, "StartedAt")};
                if (loadedReceipt) verifyLoaded(binding, freshHelper, expected, operatorSha, ops);
                else if (binding.mode == ControlMode::NativeHttp)
                    ops.run({"docker","exec",entry.id,"/app/awg-feed","--verify-control-live",entry.role,binding.payloadSha256,
                             "/migration/control-loaded-" + entry.role + ".json"});
                else
                    ops.run({"docker","exec",entry.id,"python","-c",kListenerProbe});
                replaced = true; break;
            } catch (...) {
                last = std::current_exception();
                if (attempt == 9) std::rethrow_exception(last);
                ops.sleepSeconds(1);
            }
        }
        if (!replaced) fail("control maintenance process not replaced");
    }
    controlHelpers(journal, binding);
}

void recoverControlMaintenance(TransactionJournal& journal, const fs::path& directory, const ControlBinding& binding,
                               const std::string& operatorSha, Ops& ops) {
    Json value = parseJson(journal.snapshot());
    json_object* pendingRaw = nullptr;
    if (!json_object_object_get_ex(value.get(), "controlMaintenance", &pendingRaw) || json_object_is_type(pendingRaw, json_type_null)) return;
    if (binding.mode == ControlMode::NativeHttp) fail("native control maintenance recovery unsupported");
    if (!json_object_is_type(pendingRaw, json_type_object)) fail("control maintenance recovery state");
    Json transaction = adopt(json_object_get(pendingRaw));
    controlHelpers(journal, binding);
    checkControlState(journal, directory, ops, textMap(need(transaction.get(), "protected", json_type_object)));
    auto oldHashes = textMap(need(transaction.get(), "old", json_type_object));
    auto newHashes = textMap(need(transaction.get(), "new", json_type_object));
    auto current = controlHashes(directory);
    for (const auto& name : std::vector<std::string>{"service.py","target.py"})
        if (current[name] != oldHashes.at(name) && current[name] != newHashes.at(name)) fail("control maintenance recovery file drift");
    auto backups = directory / ".control-maintenance";
    std::map<std::string,std::string> raw;
    for (const auto& name : std::vector<std::string>{"service.py","target.py"}) {
        raw[name] = readBytes(backups / name, "control maintenance backup drift");
        if (sha256(raw[name]) != oldHashes.at(name)) fail("control maintenance backup drift");
    }
    for (const auto& name : std::vector<std::string>{"service.py","target.py"}) durableWrite(directory / name, raw[name]);
    json_object* oldReceiptObject = nullptr;
    bool oldReceipt = json_object_object_get_ex(transaction.get(), "oldLoadedReceipt", &oldReceiptObject) && json_object_is_type(oldReceiptObject, json_type_boolean)
        ? json_object_get_boolean(oldReceiptObject) != 0 : false;
    restartControls(journal, binding, oldHashes, oldReceipt, operatorSha, ops);
    checkControlState(journal, directory, ops, textMap(need(transaction.get(), "protected", json_type_object)));
    Json updated = parseJson(journal.snapshot());
    json_object_object_add(updated.get(), "controlRecipe", json_object_get(mapJson(oldHashes).get()));
    json_object_object_add(updated.get(), "controlLoadedReceipt", json_object_new_boolean(oldReceipt));
    json_object_object_add(updated.get(), "controlMaintenanceResult", json_object_new_string("rolled_back"));
    json_object_object_del(updated.get(), "controlMaintenance");
    journal.replaceValue(plain(updated.get()));
}

// ---- explicit native-control payload replacement and its recovery ----------
// A native generation has no Python payload. Its control executable lives in an
// immutable image that the owned helpers run as PID1. A changed payload therefore
// needs an explicit, independently authenticated replacement: staged private
// bytes, an owned local image build, persisted intent before any mutation and an
// exact-owned recreation with a live listener proof. Nothing here infers native
// control from nativeFeedSha256, and no protected state is ever rewritten.
constexpr std::size_t kMaxControlPayload = 32u * 1024u * 1024u;

std::string trimText(const std::string& value) {
    const std::string whitespace = std::string(" \t\n") + static_cast<char>(0x0d);
    auto first = value.find_first_not_of(whitespace);
    if (first == std::string::npos) return {};
    auto last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1);
}
unsigned long long leValue(const std::string& bytes, std::size_t offset, unsigned width) {
    if (offset + width > bytes.size()) fail("native control payload truncated");
    unsigned long long result = 0;
    for (unsigned i = 0; i < width; ++i)
        result |= static_cast<unsigned long long>(static_cast<unsigned char>(bytes[offset + i])) << (8 * i);
    return result;
}
// Bounded, byte-bound static executable contract for the staged control payload.
void requireStaticExecutable(const std::string& bytes) {
    if (bytes.size() < 64 || bytes.compare(0, 4, std::string("\x7f" "ELF", 4)) != 0)
        fail("native control payload not an ELF image");
    if (static_cast<unsigned char>(bytes[4]) != 2 || static_cast<unsigned char>(bytes[5]) != 1
        || static_cast<unsigned char>(bytes[6]) != 1)
        fail("native control payload not a little-endian ELF64 image");
    const auto type = leValue(bytes, 16, 2), machine = leValue(bytes, 18, 2);
    if (type != 2 && type != 3) fail("native control payload not an executable image");
    if (machine != 62 && machine != 183) fail("native control payload unsupported machine");
    const auto headers = leValue(bytes, 32, 8), entrySize = leValue(bytes, 54, 2), count = leValue(bytes, 56, 2);
    if (count == 0 || count > 256 || entrySize < 56 || headers > bytes.size()
        || headers + entrySize * count > bytes.size())
        fail("native control payload program headers");
    for (unsigned long long i = 0; i < count; ++i)
        if (leValue(bytes, static_cast<std::size_t>(headers + i * entrySize), 4) == 3)
            fail("native control payload requires a dynamic loader");
}
void requirePrivateDirectory(const fs::path& path, const char* label) {
    if (path.empty() || !path.is_absolute()) fail(label);
    std::error_code ec; auto status = fs::symlink_status(path, ec);
    if (ec || fs::is_symlink(status) || !fs::is_directory(status)) fail(label);
    struct stat st{};
    if (lstat(path.c_str(), &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077)) fail(label);
}
// Bounded durable write for the staged executable and its build context.
void stageFile(const fs::path& path, const std::string& bytes) {
    if (bytes.size() > kMaxControlPayload) fail("control maintenance staging budget");
    int fd = -1; std::string temporary;
    for (unsigned n = 0; n < 100; ++n) {
        temporary = "." + path.filename().string() + "-" + std::to_string(getpid()) + "-" + std::to_string(n);
        fd = open((path.parent_path() / temporary).c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST) fail("control maintenance staging");
    }
    if (fd < 0) fail("control maintenance staging");
    const auto temporaryPath = path.parent_path() / temporary;
    std::size_t position = 0;
    try {
        while (position < bytes.size()) {
            auto written = write(fd, bytes.data() + position, bytes.size() - position);
            if (written < 0) { if (errno == EINTR) continue; fail("control maintenance write"); }
            if (!written) fail("control maintenance short write");
            position += static_cast<std::size_t>(written);
        }
        if (fsync(fd) < 0) fail("control maintenance fsync");
        if (close(fd) < 0) { fd = -1; fail("control maintenance close"); }
        fd = -1;
        if (readBytes(temporaryPath, "control maintenance staged readback", kMaxControlPayload) != bytes)
            fail("control maintenance staged readback");
        if (rename(temporaryPath.c_str(), path.c_str()) < 0) fail("control maintenance replace");
        if (readBytes(path, "control maintenance readback", kMaxControlPayload) != bytes) fail("control maintenance readback");
        int dir = open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir < 0) fail("control maintenance directory");
        int synced = fsync(dir); close(dir);
        if (synced < 0) fail("control maintenance directory fsync");
    } catch (...) { if (fd >= 0) close(fd); unlink(temporaryPath.c_str()); throw; }
}
struct ObservedControl {
    bool present = false, running = false;
    std::string id, name, image, owner, payload;
};
ObservedControl observeControl(TransactionJournal& journal, const std::string& reference) {
    ObservedControl result;
    auto raw = journal.inspectSnapshot(reference);
    if (raw == "null") return result;
    Json item = parseJson(raw);
    result.present = true;
    result.id = text(item.get(), "Id");
    result.name = text(item.get(), "Name");
    result.image = text(item.get(), "Image");
    json_object* config = need(item.get(), "Config", json_type_object);
    result.owner = optionalText(need(config, "Labels", json_type_object), "amnezia.migration.owner");
    json_object* environment = nullptr;
    if (json_object_object_get_ex(config, "Env", &environment) && json_object_is_type(environment, json_type_array))
        for (std::size_t i = 0; i < json_object_array_length(environment); ++i) {
            json_object* entry = json_object_array_get_idx(environment, i);
            if (!json_object_is_type(entry, json_type_string)) continue;
            std::string pair(json_object_get_string(entry), json_object_get_string_len(entry));
            static const std::string prefix = "AMNEZIA_CONTROL_NATIVE_SHA256=";
            if (pair.rfind(prefix, 0) == 0) result.payload = pair.substr(prefix.size());
        }
    result.running = booleanAt(need(item.get(), "State", json_type_object), "Running");
    return result;
}
void setOwnedContainer(TransactionJournal& journal, const std::string& name, const std::string& image, const std::string& id) {
    Json value = parseJson(journal.snapshot());
    json_object* containers = need(value.get(), "containers", json_type_object);
    Json entry = adopt(json_object_new_object());
    json_object_object_add(entry.get(), "image", json_object_new_string(image.c_str()));
    json_object_object_add(entry.get(), "id", json_object_new_string(id.c_str()));
    json_object_object_add(containers, name.c_str(), json_object_get(entry.get()));
    journal.replaceValue(plain(value.get()));
}
std::string createControlHelper(TransactionJournal& journal, const std::string& name, const std::string& role,
                                const std::string& image, const std::string& payload, Ops& ops) {
    Json value = parseJson(journal.snapshot());
    const auto owner = text(value.get(), "owner");
    const auto targetName = text(value.get(), "target");
    const auto sourceName = text(value.get(), "source");
    std::string parent;
    if (role == "source") parent = text(value.get(), "sourceId");
    else parent = optionalText(need(need(value.get(), "containers", json_type_object), targetName.c_str(), json_type_object), "id");
    if (!hex64(parent)) fail("control maintenance parent drift");
    const auto created = ops.run({"docker","create","--name",name,
        "--log-driver","none","--restart","unless-stopped",
        "--label","amnezia.migration.owner=" + owner,
        "--network","container:" + parent,
        "--cap-drop","ALL","--security-opt","no-new-privileges:true",
        "--env","AMNEZIA_CONTROL_NATIVE_SHA256=" + payload,
        "--env","AMNEZIA_MIGRATION_ROLE=" + role,
        "--env","AMNEZIA_MIGRATION_SCOPE=" + sourceName,
        "--mount","type=bind,source=" + journal.directory().generic_string() + ",target=/migration",
        "--mount","type=bind,source=/opt/amnezia/client-logs,target=/logs,readonly",
        "--entrypoint","/app/awg-feed",image,"--control-pid1"});
    const auto id = trimText(created);
    if (!hex64(id)) fail("control maintenance create");
    ops.run({"docker","start",id});
    ops.run({"docker","exec",id,"/app/awg-feed","--verify-control-live",role,payload,
             "/migration/control-loaded-" + role + ".json"});
    return id;
}
struct PendingNative {
    std::string oldPayload, oldImage, newPayload, newImage;
    std::string oldReplacementLedger;
    std::filesystem::path stage, context;
    std::map<std::string,std::string> protectedHashes;
    bool oldLoadedReceipt = false;
};
PendingNative readNativeTransaction(TransactionJournal& journal) {
    Json value = parseJson(journal.snapshot());
    json_object* raw = nullptr;
    if (!json_object_object_get_ex(value.get(), "controlMaintenance", &raw) || json_object_is_type(raw, json_type_null)
        || !json_object_is_type(raw, json_type_object))
        fail("control maintenance recovery state");
    Json transaction = adopt(json_object_get(raw));
    json_object* oldState = need(transaction.get(), "old", json_type_object);
    json_object* newState = need(transaction.get(), "new", json_type_object);
    PendingNative result;
    result.oldPayload = text(oldState, "payload");
    result.oldImage = text(oldState, "image");
    json_object* priorLedger = nullptr;
    if (json_object_object_get_ex(oldState, "controlReplacement", &priorLedger)) {
        if (!json_object_is_type(priorLedger, json_type_object)) fail("control maintenance recovery state");
        result.oldReplacementLedger = plain(priorLedger);
    }
    result.newPayload = text(newState, "payload");
    result.newImage = text(newState, "image");
    result.stage = optionalText(newState, "stage");
    result.context = optionalText(newState, "context");
    result.protectedHashes = textMap(need(transaction.get(), "protected", json_type_object));
    json_object* receipt = nullptr;
    if (json_object_object_get_ex(transaction.get(), "oldLoadedReceipt", &receipt) && json_object_is_type(receipt, json_type_boolean))
        result.oldLoadedReceipt = json_object_get_boolean(receipt) != 0;
    if (!hex64(result.oldPayload) || !hex64(result.newPayload)
        || result.oldImage.size() != 71 || result.newImage.size() != 71)
        fail("control maintenance recovery state");
    return result;
}
// Restores only transaction-owned helpers. A container whose owner label or image
// is outside the captured old/new pair is never destroyed: it is reported.
void restoreNativeControlState(TransactionJournal& journal, const fs::path& directory, const PendingNative& transaction, Ops& ops) {
    Json value = parseJson(journal.snapshot());
    const auto owner = text(value.get(), "owner");
    const auto targetName = text(value.get(), "target");
    if (!sameMap(protectedState(directory, true), transaction.protectedHashes))
        fail("control maintenance protected state drift");
    checkSourceConfiguration(journal, ops);
    // Preflight the complete owned set before any mutation: a foreign replacement
    // must fail without having touched the other helper.
    for (const auto& item : std::vector<std::pair<std::string,std::string>>{
             {targetName + "-source-control", "source"}, {targetName + "-control", "target"}}) {
        const auto observed = observeControl(journal, item.first);
        if (observed.present
            && (observed.owner != owner
                || (observed.image != transaction.oldImage && observed.image != transaction.newImage)))
            fail("control maintenance foreign replacement");
    }
    for (const auto& item : std::vector<std::pair<std::string,std::string>>{
             {targetName + "-source-control", "source"}, {targetName + "-control", "target"}}) {
        auto observed = observeControl(journal, item.first);
        if (observed.present) {
            if (observed.owner != owner
                || (observed.image != transaction.oldImage && observed.image != transaction.newImage))
                fail("control maintenance foreign replacement");
            if (observed.image == transaction.oldImage && observed.payload == transaction.oldPayload && observed.running) {
                setOwnedContainer(journal, item.first, transaction.oldImage, observed.id);
                ops.run({"docker","exec",observed.id,"/app/awg-feed","--verify-control-live",item.second,transaction.oldPayload,
                         "/migration/control-loaded-" + item.second + ".json"});
                continue;
            }
            ops.run({"docker","rm","-f",observed.id});
        }
        const auto id = createControlHelper(journal, item.first, item.second, transaction.oldImage, transaction.oldPayload, ops);
        setOwnedContainer(journal, item.first, transaction.oldImage, id);
    }
    Json restored = parseJson(journal.snapshot());
    json_object* control = need(restored.get(), "nativeControl", json_type_object);
    json_object_object_add(control, "sha256", json_object_new_string(transaction.oldPayload.c_str()));
    json_object_object_add(control, "image", json_object_new_string(transaction.oldImage.c_str()));
    json_object_object_add(restored.get(), "controlLoadedReceipt", json_object_new_boolean(transaction.oldLoadedReceipt));
    json_object_object_add(restored.get(), "controlMaintenanceResult", json_object_new_string("rolled_back"));
    json_object_object_del(restored.get(), "controlMaintenance");
    if (transaction.oldReplacementLedger.empty()) {
        json_object_object_del(restored.get(), "controlReplacement");
    } else {
        Json priorLedger = parseJson(transaction.oldReplacementLedger);
        json_object_object_add(restored.get(), "controlReplacement", json_object_get(priorLedger.get()));
    }
    journal.replaceValue(plain(restored.get()));
    checkControlState(journal, directory, ops, transaction.protectedHashes);
}
} // namespace

void runNativeControlMaintenance(TransactionJournal& journal, const fs::path& directory, const fs::path& recipeDirectory,
                                 const std::string& operatorSha, const std::string& replacementSha,
                                 const fs::path& stagingRoot, Ops& ops, const std::function<void()>& validate) {
    // 1. Operator authority: the existing field is the CURRENT payload; the new
    // field is the independently asserted replacement digest. Never interchangeable.
    if (!hex64(operatorSha)) fail("native_control_sha256_required");
    if (!hex64(replacementSha)) fail("native_control_replacement_sha256_required");
    if (replacementSha == operatorSha) fail("native_control_replacement_sha256_mismatch");
    Json value = parseJson(journal.snapshot());
    json_object* pendingRaw = nullptr;
    if (json_object_object_get_ex(value.get(), "controlMaintenance", &pendingRaw) && !json_object_is_type(pendingRaw, json_type_null))
        fail("control maintenance recovery required");
    const ControlBinding binding = controlBinding(journal, operatorSha);
    if (binding.mode != ControlMode::NativeHttp) fail("unsupported control variant");
    const auto owner = text(value.get(), "owner");
    const auto targetName = text(value.get(), "target");
    const auto oldImage = binding.image;
    std::string oldReplacementLedger;
    json_object* priorLedger = nullptr;
    if (json_object_object_get_ex(value.get(), "controlReplacement", &priorLedger)) {
        if (!json_object_is_type(priorLedger, json_type_object)) fail("control maintenance recovery state");
        oldReplacementLedger = plain(priorLedger);
    }
    // 2. Exact owned state and all protected/authoritative gates before mutation.
    controlHelpers(journal, binding);
    const auto protectedHashes = protectedState(directory, true);
    checkControlState(journal, directory, ops, protectedHashes);
    checkLoadedControls(journal, binding, nativePayloadHashes(binding), binding.payloadSha256, ops);
    // 3. Independently authenticated, byte-bound candidate payload.
    const auto bytes = readBytes(recipeDirectory / "awg-feed", "native control payload missing", kMaxControlPayload);
    const auto newPayload = sha256(bytes);
    if (newPayload == binding.payloadSha256) fail("native control payload unchanged");
    if (newPayload != replacementSha) fail("native_control_replacement_sha256_mismatch");
    requireStaticExecutable(bytes);
    requirePrivateDirectory(stagingRoot, "native control staging directory");
    const auto staged = stagingRoot / ("awg-feed-" + newPayload + ".bin");
    const auto context = stagingRoot / ("context-" + newPayload);
    stageFile(staged, bytes);
    if (chmod(staged.c_str(), 0500) != 0) fail("native control staging mode");
    if (sha256(readBytes(staged, "control maintenance staged readback", kMaxControlPayload)) != newPayload)
        fail("native control staged readback");
    fs::create_directory(context); chmod(context.c_str(), 0700);
    stageFile(context / "awg-feed", bytes);
    stageFile(context / "Dockerfile", "FROM scratch\nCOPY awg-feed /app/awg-feed\nENTRYPOINT [\"/app/awg-feed\"]\n");
    // 4. Owned local control image build. The image must be new and must exist.
    const auto iidFile = context / "image.iid";
    ops.run({"docker","build","--network=none","--label","amnezia.migration.owner=" + owner,
             "--iidfile", iidFile.string(), context.string()});
    const auto image = trimText(readBytes(iidFile, "native control image build"));
    if (image.size() != 71 || image.rfind("sha256:", 0) != 0 || !hex64(image.substr(7)))
        fail("native control image build");
    if (image == oldImage) fail("native control image not replaced");
    if (trimText(ops.run({"docker","image","inspect","--format","{{.Id}}",image})) != image)
        fail("native control image unavailable");
    // 5. Persisted intent BEFORE any mutation.
    PendingNative transaction;
    transaction.oldPayload = binding.payloadSha256; transaction.oldImage = oldImage;
    transaction.oldReplacementLedger = oldReplacementLedger;
    transaction.newPayload = newPayload; transaction.newImage = image;
    transaction.stage = staged; transaction.context = context;
    transaction.protectedHashes = protectedHashes; transaction.oldLoadedReceipt = true;
    json_object* feedRaw = nullptr;
    const bool feedBound = json_object_object_get_ex(value.get(), "nativeFeedSha256", &feedRaw)
        && json_object_is_type(feedRaw, json_type_string);
    Json intent = adopt(json_object_new_object());
    Json oldState = adopt(json_object_new_object());
    json_object_object_add(oldState.get(), "payload", json_object_new_string(transaction.oldPayload.c_str()));
    json_object_object_add(oldState.get(), "image", json_object_new_string(transaction.oldImage.c_str()));
    if (!transaction.oldReplacementLedger.empty()) {
        Json prior = parseJson(transaction.oldReplacementLedger);
        json_object_object_add(oldState.get(), "controlReplacement", json_object_get(prior.get()));
    }
    json_object_object_add(intent.get(), "old", json_object_get(oldState.get()));
    Json newState = adopt(json_object_new_object());
    json_object_object_add(newState.get(), "payload", json_object_new_string(transaction.newPayload.c_str()));
    json_object_object_add(newState.get(), "image", json_object_new_string(transaction.newImage.c_str()));
    json_object_object_add(newState.get(), "stage", json_object_new_string(staged.generic_string().c_str()));
    json_object_object_add(newState.get(), "context", json_object_new_string(context.generic_string().c_str()));
    json_object_object_add(intent.get(), "new", json_object_get(newState.get()));
    json_object_object_add(intent.get(), "protected", json_object_get(mapJson(protectedHashes).get()));
    json_object_object_add(intent.get(), "oldLoadedReceipt", json_object_new_boolean(true));
    if (feedBound) json_object_object_add(intent.get(), "feedSha256", json_object_get(feedRaw));
    Json prepared = parseJson(journal.snapshot());
    json_object_object_add(prepared.get(), "controlMaintenance", json_object_get(intent.get()));
    journal.replaceValue(plain(prepared.get()));
    try {
        // 6. Exact-owned recreation, target helper first, then the source helper.
        for (const auto& item : std::vector<std::pair<std::string,std::string>>{
                 {targetName + "-control", "target"}, {targetName + "-source-control", "source"}}) {
            const auto observed = observeControl(journal, item.first);
            if (!observed.present || observed.owner != owner || observed.image != oldImage
                || observed.payload != transaction.oldPayload)
                fail("control maintenance helper replaced");
            ops.run({"docker","rm","-f",observed.id});
            const auto id = createControlHelper(journal, item.first, item.second, image, newPayload, ops);
            setOwnedContainer(journal, item.first, image, id);
        }
        ControlBinding updated = binding;
        updated.payloadSha256 = newPayload; updated.image = image;
        for (const auto& helper : controlHelpers(journal, updated))
            verifyLoaded(updated, helper, nativePayloadHashes(updated), newPayload, ops);
        checkControlState(journal, directory, ops, protectedHashes);
        // 7. Final journal commit: new authority, prior binding kept as a ledger
        // entry only when the independently bound target feed bytes are unchanged.
        Json finish = parseJson(journal.snapshot());
        json_object* control = need(finish.get(), "nativeControl", json_type_object);
        json_object_object_add(control, "sha256", json_object_new_string(newPayload.c_str()));
        json_object_object_add(control, "image", json_object_new_string(image.c_str()));
        if (feedBound) {
            std::string feed(std::string(json_object_get_string(feedRaw), json_object_get_string_len(feedRaw)));
            if (feed != newPayload) {
                Json ledger = adopt(json_object_new_object());
                json_object_object_add(ledger.get(), "state", json_object_new_string("committed"));
                json_object_object_add(ledger.get(), "priorControlSha256", json_object_new_string(transaction.oldPayload.c_str()));
                json_object_object_add(ledger.get(), "priorImage", json_object_new_string(transaction.oldImage.c_str()));
                json_object_object_add(ledger.get(), "feedSha256", json_object_new_string(feed.c_str()));
                json_object_object_add(finish.get(), "controlReplacement", json_object_get(ledger.get()));
            } else {
                json_object_object_del(finish.get(), "controlReplacement");
            }
        }
        json_object_object_add(finish.get(), "controlLoadedReceipt", json_object_new_boolean(true));
        json_object_object_add(finish.get(), "controlMaintenanceResult", json_object_new_string("updated"));
        json_object_object_del(finish.get(), "controlMaintenance");
        journal.replaceValue(plain(finish.get()));
        ControlBinding committed = controlBinding(journal, newPayload);
        controlHelpers(journal, committed);
        const auto readback = parseJson(journal.snapshot());
        json_object* written = need(readback.get(), "nativeControl", json_type_object);
        if (text(written, "sha256") != newPayload || text(written, "image") != image)
            fail("native control final readback");
        // The real canonical validator now observes the committed authority.
        if (validate) validate();
    } catch (...) {
        auto primary = std::current_exception();
        std::string primaryText = "unknown";
        try { std::rethrow_exception(primary); } catch (const std::exception& error) { primaryText = error.what(); } catch (...) {}
        try {
            restoreNativeControlState(journal, directory, transaction, ops);
            if (validate) validate();
        } catch (const std::exception& rollback) {
            throw std::runtime_error("control maintenance failed: " + primaryText + "; rollback failed: " + rollback.what());
        }
        std::rethrow_exception(primary);
    }
}

void recoverNativeControlMaintenance(TransactionJournal& journal, const fs::path& directory,
                                     const std::string& operatorSha, Ops& ops, const std::function<void()>& validate) {
    if (!hex64(operatorSha)) fail("native_control_sha256_required");
    Json value = parseJson(journal.snapshot());
    json_object* raw = nullptr;
    if (!json_object_object_get_ex(value.get(), "controlMaintenance", &raw) || json_object_is_type(raw, json_type_null)) return;
    const PendingNative transaction = readNativeTransaction(journal);
    const ControlBinding binding = controlBinding(journal, operatorSha);
    if (binding.mode != ControlMode::NativeHttp
        || (binding.payloadSha256 != transaction.oldPayload && binding.payloadSha256 != transaction.newPayload))
        fail("native_control_sha256_mismatch");
    restoreNativeControlState(journal, directory, transaction, ops);
    if (validate) validate();
    ControlBinding restored = controlBinding(journal, transaction.oldPayload);
    controlHelpers(journal, restored);
}

void runControlMaintenance(TransactionJournal& journal, const fs::path& directory, const fs::path& recipeDirectory,
                           bool nativeFeed, const std::string& nativeSha, Ops& ops, const std::function<void()>& validate) {
    // This transaction is the unchanged legacy Python proxy recipe contract. The
    // legacy nativeFeedSha256 flag keeps Python PID1/control-json-v1 semantics.
    ControlBinding binding; binding.mode = ControlMode::LegacyPython; binding.nativeFeedFlag = nativeFeed;
    recoverControlMaintenance(journal, directory, binding, nativeSha, ops);
    controlHelpers(journal, binding);
    auto protectedHashes = protectedState(directory, true);
    checkControlState(journal, directory, ops, protectedHashes);
    auto oldHashes = controlHashes(directory);
    Json value = parseJson(journal.snapshot());
    json_object* pinnedRaw = nullptr;
    bool pinnedPresent = json_object_object_get_ex(value.get(), "controlRecipe", &pinnedRaw)
        && !json_object_is_type(pinnedRaw, json_type_null);
    if (pinnedPresent && !json_object_is_type(pinnedRaw, json_type_object)) fail("control maintenance unknown baseline");
    Json pinned = pinnedPresent ? adopt(json_object_get(pinnedRaw)) : adopt(json_object_new_object());
    if (!json_object_equal(pinned.get(), mapJson(oldHashes).get()) && (pinnedPresent || !isBaseline(oldHashes)))
        fail("control maintenance unknown baseline");
    std::map<std::string,std::string> raw, newHashes;
    for (const auto& name : std::vector<std::string>{"service.py","target.py"}) {
        raw[name] = readBytes(recipeDirectory / name, "control maintenance recipe");
        newHashes[name] = sha256(raw[name]);
    }
    if (sameMap(newHashes, oldHashes)) {
        checkLoadedControls(journal, binding, oldHashes, nativeSha, ops);
        checkControlState(journal, directory, ops, protectedHashes);
        if (validate) validate();
        value = parseJson(journal.snapshot());
        json_object_object_add(value.get(), "controlRecipe", json_object_get(mapJson(oldHashes).get()));
        json_object_object_add(value.get(), "controlLoadedReceipt", json_object_new_boolean(true));
        journal.replaceValue(plain(value.get()));
        return;
    }
    auto backup = directory / ".control-maintenance";
    std::error_code ec; auto backupStatus = fs::symlink_status(backup, ec);
    if (fs::is_symlink(backupStatus) || (fs::exists(backupStatus) && !fs::is_directory(backupStatus))) fail("control maintenance backup path");
    if (fs::exists(backupStatus)) {
        for (const auto& entry : fs::directory_iterator(backup)) {
            auto status = entry.symlink_status();
            if (fs::is_symlink(status) || !fs::is_regular_file(status)) fail("control maintenance backup state");
        }
    } else {
        fs::create_directory(backup); chmod(backup.c_str(), 0700);
    }
    for (const auto& name : std::vector<std::string>{"service.py","target.py"})
        durableWrite(backup / name, readBytes(directory / name, "control maintenance state"));
    Json transaction = parseJson("{}");
    json_object_object_add(transaction.get(), "old", json_object_get(mapJson(oldHashes).get()));
    json_object_object_add(transaction.get(), "new", json_object_get(mapJson(newHashes).get()));
    json_object_object_add(transaction.get(), "protected", json_object_get(mapJson(protectedHashes).get()));
    json_object_object_add(transaction.get(), "oldLoadedReceipt", json_object_new_boolean(false));
    value = parseJson(journal.snapshot());
    json_object_object_add(value.get(), "controlMaintenance", json_object_get(transaction.get()));
    journal.replaceValue(plain(value.get()));
    try {
        for (const auto& name : std::vector<std::string>{"service.py","target.py"}) durableWrite(directory / name, raw[name]);
        restartControls(journal, binding, newHashes, true, nativeSha, ops);
        checkControlState(journal, directory, ops, protectedHashes);
        if (validate) validate();
        if (!sameMap(controlHashes(directory), newHashes)) fail("control maintenance final readback");
        value = parseJson(journal.snapshot());
        json_object_object_add(value.get(), "controlRecipe", json_object_get(mapJson(newHashes).get()));
        json_object_object_add(value.get(), "controlLoadedReceipt", json_object_new_boolean(true));
        json_object_object_add(value.get(), "controlMaintenanceResult", json_object_new_string("updated"));
        json_object_object_del(value.get(), "controlMaintenance");
        journal.replaceValue(plain(value.get()));
    } catch (...) {
        auto primary = std::current_exception();
        value = parseJson(journal.snapshot());
        json_object_object_add(value.get(), "controlMaintenance", json_object_get(transaction.get()));
        try { journal.replaceValue(plain(value.get())); }
        catch (...) { std::rethrow_exception(primary); }
        try {
            recoverControlMaintenance(journal, directory, binding, nativeSha, ops);
        } catch (const std::exception& rollback) {
            std::string primaryText = "unknown";
            try { std::rethrow_exception(primary); } catch (const std::exception& e) { primaryText = e.what(); } catch (...) {}
            throw std::runtime_error("control maintenance failed: " + primaryText + "; rollback failed: " + rollback.what());
        }
        std::rethrow_exception(primary);
    }
}

Request parseRequest(const std::vector<std::string>& argv) {
    if (argv.empty()) fail("maintenance request");
    Request request;
    if (argv[0] == "--maintenance-status") request.mode = Mode::Status;
    else if (argv[0] == "--maintenance-cleanup") request.mode = Mode::Cleanup;
    else if (argv[0] == "--maintenance-recover") request.mode = Mode::Recover;
    else if (argv[0] == "--maintenance-restart-controls") request.mode = Mode::RestartControls;
    else if (argv[0] == "--maintenance") request.mode = Mode::Maintain;
    else fail("maintenance request");
    std::set<std::string> seen;
    for (std::size_t i = 1; i < argv.size(); i += 2) {
        if (i + 1 >= argv.size() || !seen.insert(argv[i]).second) fail("maintenance request");
        const auto& flag = argv[i]; const auto& value = argv[i+1];
        if (flag == "--source") request.source = value;
        else if (flag == "--generation") {
            if (value.empty() || value.size() > 16 || !std::all_of(value.begin(), value.end(), [](char c){ return c >= '0' && c <= '9'; })) fail("maintenance request");
            request.generation = std::stoll(value);
        }
        else if (flag == "--expected-journal-sha256") request.expectedJournalSha256 = value;
        else if (flag == "--native-control-sha256") request.nativeControlSha256 = value;
        else if (flag == "--native-control-replacement-sha256") request.nativeControlReplacementSha256 = value;
        else if (flag == "--control-staging-directory") request.controlStagingDirectory = value;
        else if (flag == "--recipe-directory") request.recipeDirectory = value;
        else fail("maintenance request");
    }
    if (request.source != "amnezia-awg" && request.source != "amnezia-awg2") fail("maintenance request");
    if (request.generation < 1 || static_cast<std::uint64_t>(request.generation) > kMaxGeneration) fail("maintenance request");
    if (!hex64(request.expectedJournalSha256)) fail("maintenance request");
    if (!request.nativeControlSha256.empty() && !hex64(request.nativeControlSha256)) fail("maintenance request");
    if (!request.nativeControlReplacementSha256.empty() && !hex64(request.nativeControlReplacementSha256)) fail("maintenance request");
    if (!request.controlStagingDirectory.empty() && !request.controlStagingDirectory.is_absolute()) fail("maintenance request");
    if (request.mode != Mode::Maintain
        && (!request.nativeControlReplacementSha256.empty() || !request.controlStagingDirectory.empty()))
        fail("maintenance request");
    return request;
}

std::string resultJson(const Result& result) {
    Json root = adopt(json_object_new_object());
    json_object_object_add(root.get(), "ok", json_object_new_boolean(result.ok));
    json_object_object_add(root.get(), "mode", json_object_new_string(result.mode.c_str()));
    json_object_object_add(root.get(), "source", json_object_new_string(result.source.c_str()));
    json_object_object_add(root.get(), "generation", json_object_new_int64(result.generation));
    json_object_object_add(root.get(), "journalSha256", json_object_new_string(result.journalSha256.c_str()));
    json_object_object_add(root.get(), "native", json_object_new_boolean(result.native));
    json_object_object_add(root.get(), "pendingRecovery", json_object_new_boolean(result.pendingRecovery));
    json_object_object_add(root.get(), "phase", json_object_new_string(result.phase.c_str()));
    Json hashes = adopt(json_object_new_object());
    for (const auto& item : result.controlHashes) json_object_object_add(hashes.get(), item.first.c_str(), json_object_new_string(item.second.c_str()));
    json_object_object_add(root.get(), "controlHashes", json_object_get(hashes.get()));
    return plain(root.get());
}

namespace {
JournalRunner runnerFor(Ops& ops) {
    return [&ops](const std::vector<std::string>& argv) {
        CommandResult result;
        try { result.output = ops.run(argv); }
        catch (const std::exception& error) { result.status = 1; result.error = error.what(); }
        return result;
    };
}
std::string modeName(Mode mode) {
    switch (mode) {
        case Mode::Status: return "status";
        case Mode::Cleanup: return "cleanup";
        case Mode::Recover: return "recover";
        case Mode::RestartControls: return "restart-controls";
        case Mode::Maintain: return "maintain";
    }
    return "unknown";
}
}

namespace {
struct V4 { std::uint32_t ip = 0; int prefix = 0; };
V4 ipv4(const std::string& value) {
    auto slash = value.find('/');
    if (slash == std::string::npos) fail("migration_ready_drift");
    V4 result;
    std::string address = value.substr(0, slash), prefix = value.substr(slash + 1);
    if (prefix.empty() || prefix.size() > 2 || !std::all_of(prefix.begin(), prefix.end(), [](char c){ return c >= '0' && c <= '9'; }))
        fail("migration_ready_drift");
    result.prefix = std::stoi(prefix);
    if (result.prefix < 0 || result.prefix > 32 || inet_pton(AF_INET, address.c_str(), &result.ip) != 1) fail("migration_ready_drift");
    return result;
}
bool v4contains(const V4& network, const V4& host) {
    if (host.prefix != 32) return false;
    std::uint32_t mask = network.prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - network.prefix));
    return (ntohl(network.ip) & mask) == (ntohl(host.ip) & mask);
}
bool awgKey(const std::string& value) {
    if (value.size() != 44 || value.back() != '=') return false;
    return std::all_of(value.begin(), value.end() - 1, [](char c){
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
    });
}
std::string trim(const std::string& value) {
    auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}
struct Config { std::map<std::string,std::string> interface; std::vector<std::map<std::string,std::string>> peers; };
Config parseConfig(const std::string& raw) {
    static const std::set<std::string> parameters{"Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4","HeaderProtectionKey",
        "ContentPaddingAddition","RekeyAfterTime","RekeyTimeout","RejectAfterTime","KeepaliveTimeout","MaxHandshakeAttempts",
        "RandomTrailers","DisableCookies"};
    static const std::set<std::string> interfaceKeys = [&]{
        std::set<std::string> keys = parameters;
        for (const char* key : {"PrivateKey","Address","ListenPort","MTU","PostUp","PostDown","SaveConfig","DNS","I1","I2","I3","I4","I5"}) keys.insert(key);
        return keys;
    }();
    Config config; bool inPeer = false; bool haveInterface = false;
    std::istringstream input(raw); std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line == "[Interface]") { if (haveInterface) fail("migration_ready_drift"); haveInterface = true; inPeer = false; continue; }
        if (line == "[Peer]") { if (!haveInterface) fail("migration_ready_drift"); inPeer = true; config.peers.emplace_back(); continue; }
        auto equals = line.find('=');
        if (equals == std::string::npos) fail("migration_ready_drift");
        std::string key = trim(line.substr(0, equals)), value = trim(line.substr(equals + 1));
        auto& current = inPeer ? config.peers.back() : config.interface;
        if (current.count(key)) fail("migration_ready_drift");
        current[key] = value;
    }
    if (!haveInterface || config.peers.empty() || !config.interface.count("PrivateKey") || !awgKey(config.interface["PrivateKey"])) fail("migration_ready_drift");
    for (const auto& item : config.interface) if (!interfaceKeys.count(item.first)) fail("migration_ready_drift");
    V4 network = ipv4(config.interface.at("Address"));
    std::set<std::string> seen; std::set<std::uint32_t> addresses;
    for (const auto& peer : config.peers) {
        for (const auto& item : peer)
            if (item.first != "PublicKey" && item.first != "PresharedKey" && item.first != "AllowedIPs" && item.first != "PersistentKeepalive")
                fail("migration_ready_drift");
        if (!peer.count("PublicKey") || !awgKey(peer.at("PublicKey")) || !seen.insert(peer.at("PublicKey")).second) fail("migration_ready_drift");
        if (peer.count("PresharedKey") && !awgKey(peer.at("PresharedKey"))) fail("migration_ready_drift");
        if (!peer.count("AllowedIPs")) fail("migration_ready_drift");
        V4 host = ipv4(peer.at("AllowedIPs"));
        if (host.ip == network.ip || !v4contains(network, host) || !addresses.insert(host.ip).second) fail("migration_ready_drift");
    }
    return config;
}
std::string peerAddress(const std::string& allowed) { auto v = ipv4(allowed); struct in_addr a{}; a.s_addr = v.ip; char b[INET_ADDRSTRLEN]{}; inet_ntop(AF_INET, &a, b, sizeof b); return b; }

void validateExistingTarget(TransactionJournal& journal, const std::string& source, json_object* value,
                            json_object* ready, Ops& ops) {
    auto target = text(value, "target"); auto sourceId = text(value, "sourceId");
    json_object* containers = need(value, "containers", json_type_object);
    json_object* targetEntry = need(containers, target.c_str(), json_type_object);
    auto targetId = optionalText(targetEntry, "id");
    json_object* request = need(value, "request", json_type_object);
    if (targetId.empty() || text(ready, "containerId") != source || text(ready, "targetContainer") != target
        || integerAt(ready, "generation") != integerAt(request, "generation")
        || text(ready, "endpoint") != text(request, "host") + ":" + std::to_string(integerAt(request, "port")))
        fail("migration_ready_drift");
    auto sourcePath = "/opt/amnezia/awg/" + std::string(source == "amnezia-awg" ? "wg0.conf" : "awg0.conf");
    auto sourceRaw = ops.run({"docker","exec",sourceId,"cat",sourcePath});
    if (sha256(sourceRaw) != text(value, "sourceDigest")) fail("migration_ready_drift");
    auto sourceConfig = parseConfig(sourceRaw);
    auto directory = journal.directory();
    auto targetRaw = readBytes(directory / "awg0.conf", "migration_ready_drift");
    if (ops.run({"docker","exec",targetId,"cat","/migration/awg0.conf"}) != targetRaw) fail("migration_ready_drift");
    auto targetConfig = parseConfig(targetRaw);
    auto port = std::to_string(integerAt(request, "port"));
    if (!targetConfig.interface.count("ListenPort") || targetConfig.interface.at("ListenPort") != port) fail("migration_ready_drift");
    json_object* mapping = need(ready, "peers", json_type_object);
    if (json_object_object_length(mapping) != static_cast<int>(sourceConfig.peers.size())) fail("migration_ready_drift");
    for (const auto& peer : sourceConfig.peers) {
        json_object* item = nullptr;
        if (!json_object_object_get_ex(mapping, peer.at("PublicKey").c_str(), &item) || !json_object_is_type(item, json_type_object)) fail("migration_ready_drift");
        if (optionalText(item, "sourceIp") != peerAddress(peer.at("AllowedIPs"))
            || optionalText(item, "targetIp") != peerAddress(peer.at("AllowedIPs"))
            || optionalText(item, "clientAddress") != peer.at("AllowedIPs")) fail("migration_ready_drift");
    }
    json_object* parameters = need(ready, "parameters", json_type_object);
    for (const auto& item : targetConfig.interface) {
        json_object* expected = nullptr;
        if (json_object_object_get_ex(parameters, item.first.c_str(), &expected)) {
            if (!json_object_is_type(expected, json_type_string) || item.second != json_object_get_string(expected)) fail("migration_ready_drift");
        }
    }
    // Live target endpoint/peer proof, exactly the commands maintenance.py uses.
    auto dump = ops.run({"docker","exec",targetId,"awg","show","awg0","dump"});
    std::vector<std::string> rows; std::istringstream dumpStream(dump); std::string rowLine;
    while (std::getline(dumpStream, rowLine)) if (!rowLine.empty()) rows.push_back(rowLine);
    auto split = [](const std::string& row){ std::vector<std::string> cells; std::size_t start = 0; while (true) { auto tab = row.find('\t', start); cells.push_back(row.substr(start, tab == std::string::npos ? std::string::npos : tab - start)); if (tab == std::string::npos) break; start = tab + 1; } return cells; };
    if (rows.size() != sourceConfig.peers.size() + 1) fail("migration_ready_drift");
    auto header = split(rows[0]);
    if (header.size() < 3 || header[1] != text(ready, "serverPublicKey") || header[2] != port) fail("migration_ready_drift");
    std::map<std::string,std::vector<std::string>> observed;
    for (std::size_t i = 1; i < rows.size(); ++i) { auto cells = split(rows[i]); observed[cells[0]] = cells; }
    if (observed.size() != sourceConfig.peers.size()) fail("migration_ready_drift");
    for (const auto& peer : sourceConfig.peers) {
        auto found = observed.find(peer.at("PublicKey"));
        if (found == observed.end() || found->second.size() < 4
            || found->second[1] != (peer.count("PresharedKey") ? peer.at("PresharedKey") : std::string("(none)"))
            || found->second[3] != peer.at("AllowedIPs")) fail("migration_ready_drift");
    }
    auto conf = ops.run({"docker","exec",targetId,"awg","showconf","awg0"});
    std::map<std::string,std::string> accepted; std::istringstream confStream(conf);
    while (std::getline(confStream, rowLine)) {
        auto equals = rowLine.find('=');
        if (equals == std::string::npos) continue;
        auto key = trim(rowLine.substr(0, equals)), value = trim(rowLine.substr(equals + 1));
        if (json_object_object_get_ex(parameters, key.c_str(), nullptr)) accepted[key] = value;
    }
    for (auto& item : accepted) {
        if (item.first == "RandomTrailers" || item.first == "DisableCookies") {
            if (item.second == "false" || item.second == "off") item.second = "0";
            if (item.second == "true" || item.second == "on") item.second = "1";
        }
    }
    json_object* padding = nullptr;
    if (json_object_object_get_ex(parameters, "ContentPaddingAddition", &padding) && json_object_is_type(padding, json_type_string)
        && std::string(json_object_get_string(padding)) == "0") accepted.emplace("ContentPaddingAddition", "0");
    json_object_object_foreach(parameters, key, parameter) {
        if (!json_object_is_type(parameter, json_type_string)) fail("migration_ready_drift");
        auto found = accepted.find(key);
        if (found == accepted.end() || found->second != json_object_get_string(parameter)) fail("migration_ready_drift");
    }
    auto live = ops.run({"docker","exec",targetId,"sh","-c","set -eu; engine=$(cat /migration/engine.pid); case \"$engine\" in \"\"|*[!0-9]*) exit 1;; esac; kill -0 \"$engine\"; sha256sum \"/proc/$engine/exe\""});
    std::istringstream liveStream(live); std::string digest, path;
    if (!(liveStream >> digest >> path) || digest != kEngineSha256) fail("migration_ready_drift");
}
void requireRegular(const fs::path& path, const std::string& label) {
    std::error_code ec; auto status = fs::symlink_status(path, ec);
    if (ec || fs::is_symlink(status) || !fs::is_regular_file(status)) fail(label);
}
void rejectSymlink(const fs::path& path, const std::string& label) {
    std::error_code ec; auto status = fs::symlink_status(path, ec);
    if (!ec && fs::is_symlink(status)) fail(label);
}
void checkBackupPath(const fs::path& backup) {
    std::error_code ec; auto status = fs::symlink_status(backup, ec);
    if (fs::is_symlink(status) || (fs::exists(status) && !fs::is_directory(status))) fail("maintenance backup path");
    if (fs::exists(status)) for (const auto& entry : fs::directory_iterator(backup)) {
        auto entryStatus = entry.symlink_status();
        if (fs::is_symlink(entryStatus) || !fs::is_regular_file(entryStatus)) fail("maintenance backup state");
    }
}
}

Result runMaintenance(const Request& request, Ops& ops) {
    if (request.source != "amnezia-awg" && request.source != "amnezia-awg2") fail("maintenance request");
    if (request.generation < 1 || static_cast<std::uint64_t>(request.generation) > kMaxGeneration || !hex64(request.expectedJournalSha256))
        fail("maintenance request");
    const auto directory = request.root / request.source / std::to_string(request.generation);
    rejectSymlink(request.root, "maintenance path");
    rejectSymlink(request.root / request.source, "maintenance path");
    rejectSymlink(directory, "maintenance path");
    rejectSymlink(request.root / ".prepare.lock", "maintenance lock");
    TransactionJournal journal(directory, runnerFor(ops));
    auto expectedBytes = readBytes(directory / "transaction.json", "maintenance state");
    if (sha256(expectedBytes) != request.expectedJournalSha256) fail("maintenance journal changed");
    Json value = parseJson(journal.snapshot());
    // The journal variant is authoritative. The explicit nativeControl object and
    // the legacy nativeFeedSha256 flag are never merged or inferred from each other.
    const ControlBinding binding = controlBinding(journal, request.nativeControlSha256);
    const bool native = binding.mode == ControlMode::NativeHttp;
    if (binding.nativeFeedFlag && request.mode != Mode::Status && !hex64(request.nativeControlSha256))
        fail("native_control_sha256_required");
    if (request.mode != Mode::Status) rejectSymlink(directory / "ready.json", "maintenance state");
    Result result; result.mode = modeName(request.mode); result.source = request.source; result.generation = request.generation;
    result.native = native || binding.nativeFeedFlag;
    json_object* pendingRaw = nullptr;
    result.pendingRecovery = json_object_object_get_ex(value.get(), "controlMaintenance", &pendingRaw) && !json_object_is_type(pendingRaw, json_type_null);
    result.phase = text(value.get(), "phase");
    result.journalSha256 = sha256(readBytes(directory / "transaction.json", "maintenance state"));
    if (request.mode == Mode::Status) {
        // Native generations expose the authenticated payload identity, never the
        // legacy service.py/target.py files (which do not exist in that generation).
        result.controlHashes = native ? nativePayloadHashes(binding) : controlHashes(directory);
        result.ok = true;
        return result;
    }
    if (request.mode == Mode::Cleanup) {
        journal.cleanup();
        result.phase = "aborted"; result.journalSha256 = sha256(readBytes(directory / "transaction.json", "maintenance state"));
        result.controlHashes = native ? nativePayloadHashes(binding) : controlHashes(directory); result.ok = true; return result;
    }
    if (request.mode == Mode::Recover) {
        if (result.pendingRecovery) {
            if (native) {
                // Real native recovery: transaction-driven restore of the captured
                // old image/digest, never a foreign replacement.
                Json ready = parseJson(readBytes(directory / "ready.json", "maintenance required state"));
                auto validate = [&]{
                    Json latest = parseJson(journal.snapshot());
                    Json control = adopt(json_object_get(need(latest.get(), "nativeControl", json_type_object)));
                    controlHelpers(journal, controlBinding(journal, text(control.get(), "sha256")));
                    validateExistingTarget(journal, request.source, latest.get(), ready.get(), ops);
                };
                recoverNativeControlMaintenance(journal, directory, request.nativeControlSha256, ops, validate);
            }
            else recoverControlMaintenance(journal, directory, binding, request.nativeControlSha256, ops);
        } else {
            // recoverReady attests only the source control listener. Native
            // generations use the owned control binary; legacy generations keep the
            // Python PID1 probe and, for old native-feed journals, the loaded receipt.
            auto attest = [&](const std::string& id) {
                if (native) {
                    ops.run({"docker","exec",id,"/app/awg-feed","--verify-control-live","source",binding.payloadSha256,
                             "/migration/control-loaded-source.json"});
                    return;
                }
                ops.run({"docker","exec",id,"python","-c",kListenerProbe});
                if (binding.nativeFeedFlag)
                    ops.run({"docker","exec",id,"/app/awg-feed","--verify-control-loaded","source",request.nativeControlSha256,
                             "/migration/control-loaded-source.json"});
            };
            journal.recoverReady(attest);
        }
        result.phase = text(parseJson(journal.snapshot()).get(), "phase");
        result.journalSha256 = sha256(readBytes(directory / "transaction.json", "maintenance state"));
        result.pendingRecovery = false;
        result.controlHashes = native ? nativePayloadHashes(binding) : controlHashes(directory);
        result.ok = true; return result;
    }
    if (result.pendingRecovery) fail("control maintenance recovery required");
    if (request.mode == Mode::RestartControls) {
        controlHelpers(journal, binding);
        auto protectedHashes = protectedState(directory, true);
        checkControlState(journal, directory, ops, protectedHashes);
        if (native) {
            // Explicit native control: payload identity comes from the authenticated
            // journal binding, never from service.py/target.py or a self receipt.
            restartControls(journal, binding, nativePayloadHashes(binding), true, request.nativeControlSha256, ops);
            result.controlHashes = nativePayloadHashes(binding); result.ok = true;
            result.journalSha256 = sha256(readBytes(directory / "transaction.json", "maintenance state"));
            return result;
        }
        auto oldHashes = controlHashes(directory);
        json_object* pinnedRaw = nullptr;
        bool pinnedPresent = json_object_object_get_ex(value.get(), "controlRecipe", &pinnedRaw) && !json_object_is_type(pinnedRaw, json_type_null);
        if (!json_object_equal(mapJson(oldHashes).get(), pinnedPresent ? pinnedRaw : mapJson(oldHashes).get()) && (pinnedPresent || !isBaseline(oldHashes)))
            fail("control maintenance unknown baseline");
        restartControls(journal, binding, oldHashes, true, request.nativeControlSha256, ops);
        result.controlHashes = oldHashes; result.ok = true;
        result.journalSha256 = sha256(readBytes(directory / "transaction.json", "maintenance state"));
        return result;
    }
    // Mode::Maintain: the same ordered gates as maintenance.py.
    auto readyRaw = readBytes(directory / "ready.json", "maintenance required state");
    Json ready = parseJson(readyRaw);
    auto target = text(value.get(), "target");
    if (text(value.get(), "phase") != "ready" || text(value.get(), "source") != request.source
        || has(value.get(), "controlMaintenance")
        || integerAt(need(value.get(), "request", json_type_object), "generation") != request.generation
        || text(ready.get(), "containerId") != request.source || integerAt(ready.get(), "generation") != request.generation
        || text(ready.get(), "targetContainer") != target)
        fail("maintenance scope binding");
    std::vector<std::string> required{"transaction.json","ready.json","awg0.conf","awg0.native.conf","signing.pem","start.sh","grants.sqlite3"};
    // Native-control generations carry no Python proxy payload.
    if (!native) { required.push_back("service.py"); required.push_back("target.py"); }
    for (const auto& name : required) requireRegular(directory / name, "maintenance required state");
    auto backup = directory / ".control-maintenance";
    checkBackupPath(backup);
    controlHelpers(journal, binding);
    auto protectedHashes = protectedState(directory, true);
    validateExistingTarget(journal, request.source, value.get(), ready.get(), ops);
    std::map<std::string,std::string> candidate;
    if (!native) {
        for (const auto& name : std::vector<std::string>{"service.py","target.py"})
            candidate[name] = sha256(readBytes(request.recipeDirectory / name, "control maintenance recipe"));
        if (sameMap(candidate, controlHashes(directory)))
            checkLoadedControls(journal, binding, candidate, request.nativeControlSha256, ops);
    }
    auto validate = [&]{
        controlHelpers(journal, binding);
        if (!sameMap(protectedState(directory, true), protectedHashes)) fail("control maintenance protected state drift");
        validateExistingTarget(journal, request.source, parseJson(journal.snapshot()).get(), ready.get(), ops);
    };
    auto validateNative = [&]{
        Json latest = parseJson(journal.snapshot());
        Json control = adopt(json_object_get(need(latest.get(), "nativeControl", json_type_object)));
        controlHelpers(journal, controlBinding(journal, text(control.get(), "sha256")));
        if (!sameMap(protectedState(directory, true), protectedHashes)) fail("control maintenance protected state drift");
        validateExistingTarget(journal, request.source, latest.get(), ready.get(), ops);
    };
    if (native) {
        const auto candidate = sha256(readBytes(request.recipeDirectory / "awg-feed", "native control payload missing", kMaxControlPayload));
        if (candidate == binding.payloadSha256) {
            // Unchanged bytes stay a strict no-op under the same gates; a claimed
            // replacement that is not the current payload is a hard mismatch.
            if (!request.nativeControlReplacementSha256.empty() && request.nativeControlReplacementSha256 != candidate)
                fail("native_control_replacement_sha256_mismatch");
            checkLoadedControls(journal, binding, nativePayloadHashes(binding), binding.payloadSha256, ops);
            checkControlState(journal, directory, ops, protectedHashes);
            validateNative();
        } else {
            runNativeControlMaintenance(journal, directory, request.recipeDirectory, binding.payloadSha256,
                request.nativeControlReplacementSha256, request.controlStagingDirectory, ops, validateNative);
        }
        Json latest = parseJson(journal.snapshot());
        Json control = adopt(json_object_get(need(latest.get(), "nativeControl", json_type_object)));
        result.phase = text(latest.get(), "phase");
        result.controlHashes = nativePayloadHashes(controlBinding(journal, text(control.get(), "sha256")));
    } else {
        runControlMaintenance(journal, directory, request.recipeDirectory, binding.nativeFeedFlag, request.nativeControlSha256, ops, validate);
        auto expected = controlHashes(directory);
        checkLoadedControls(journal, binding, expected, request.nativeControlSha256, ops);
        result.phase = text(parseJson(journal.snapshot()).get(), "phase");
        result.controlHashes = expected;
    }
    result.journalSha256 = sha256(readBytes(directory / "transaction.json", "maintenance state"));
    result.ok = true;
    return result;
}
} // namespace amnezia::awgMigration::maintenance
