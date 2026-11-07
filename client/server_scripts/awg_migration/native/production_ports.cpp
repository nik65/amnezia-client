// Concrete production prepare adapters. They compose the already-reviewed
// bounded native primitives; they do not add a second process/network layer.
#include "production_ports.h"
#include "bounded_docker.h"
#include "network_observer.h"
#include "network_topology_runtime.h"
#include "policy_runtime.h"
#include "ready_runtime.h"
#include "source_config_runtime.h"
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace amnezia::awgMigration::prepareProduction {
namespace {
constexpr std::size_t kOneMiB = 1024 * 1024;
constexpr std::size_t kFourMiB = 4 * 1024 * 1024;

struct JsonDelete { void operator()(json_object *v) const noexcept { if (v) json_object_put(v); } };
using Json = std::unique_ptr<json_object, JsonDelete>;

[[noreturn]] void reject(const char *code) { throw prepare::PrepareError(code); }

std::string sha256Hex(const std::string &bytes) {
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest, &length, EVP_sha256(), nullptr) != 1)
        reject("migration_preparation_failed");
    std::ostringstream out;
    for (unsigned i = 0; i < length; ++i) out << std::hex << std::setfill('0') << std::setw(2) << unsigned(digest[i]);
    return out.str();
}

std::string runDocker(const std::vector<std::string> &argv, std::size_t limit, unsigned budget) {
    if (argv.empty() || argv.front() != "docker") reject("migration_preparation_failed");
    try { return runBoundedDockerWithBudget(argv, limit, budget); }
    catch (const BoundedDockerError &) { return std::string(); }
}

Json parseJson(const std::string &raw) {
    if (raw.empty() || raw.find('\0') != std::string::npos) reject("migration_preparation_failed");
    json_tokener *tok = json_tokener_new();
    if (!tok) reject("migration_preparation_failed");
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    json_object *value = json_tokener_parse_ex(tok, raw.data(), static_cast<int>(raw.size()));
    const bool bad = json_tokener_get_error(tok) != json_tokener_success;
    json_tokener_free(tok);
    if (bad || !value) { if (value) json_object_put(value); reject("migration_preparation_failed"); }
    return Json(value);
}

std::string stringMember(json_object *object, const char *key) {
    json_object *value = nullptr;
    if (!object || !json_object_is_type(object, json_type_object)
        || !json_object_object_get_ex(object, key, &value) || !value
        || !json_object_is_type(value, json_type_string)) reject("migration_preparation_failed");
    return std::string(json_object_get_string(value), static_cast<std::size_t>(json_object_get_string_len(value)));
}

void writeExclusive(const std::filesystem::path &path, const std::string &bytes, unsigned mode) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          static_cast<mode_t>(mode));
    if (fd < 0) reject("migration_preparation_failed");
    std::size_t done = 0;
    while (done < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + done, bytes.size() - done);
        if (n <= 0) { ::close(fd); reject("migration_preparation_failed"); }
        done += static_cast<std::size_t>(n);
    }
    if (::fchmod(fd, static_cast<mode_t>(mode)) != 0 || ::fsync(fd) != 0) {
        ::close(fd); reject("migration_preparation_failed");
    }
    ::close(fd);
}

std::string readFile(const std::filesystem::path &path, std::size_t limit) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) reject("native_feed_invalid");
    struct stat info {};
    if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0
        || static_cast<std::size_t>(info.st_size) > limit) { ::close(fd); reject("native_feed_invalid"); }
    std::string out(static_cast<std::size_t>(info.st_size), '\0');
    std::size_t done = 0;
    while (done < out.size()) {
        const ssize_t n = ::read(fd, out.data() + done, out.size() - done);
        if (n <= 0) { ::close(fd); reject("native_feed_invalid"); }
        done += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return out;
}

// Read one exact local data file for a read-only digest. Absence is not an
// error: the caller omits that expected feed and the sequencer's feed phase
// fails closed. No ownership claim is made for host data.
std::optional<std::string> dataFileSha256(const std::filesystem::path &path, std::size_t limit) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    struct stat before {};
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size < 0
        || static_cast<std::uint64_t>(before.st_size) > limit) { ::close(fd); return std::nullopt; }
    std::string raw(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t done = 0;
    while (done < raw.size()) {
        const ssize_t n = ::read(fd, raw.data() + done, raw.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ::close(fd); return std::nullopt; }
        done += static_cast<std::size_t>(n);
    }
    char extra = 0;
    struct stat after {};
    if (::read(fd, &extra, 1) != 0 || ::fstat(fd, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec
        || before.st_ctim.tv_sec != after.st_ctim.tv_sec
        || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) { ::close(fd); return std::nullopt; }
    ::close(fd);
    return sha256Hex(raw);
}

std::uint16_t le16(const std::string &raw, std::size_t at) {
    return static_cast<std::uint16_t>(static_cast<unsigned char>(raw[at])
        | (static_cast<std::uint16_t>(static_cast<unsigned char>(raw[at + 1])) << 8));
}
std::uint32_t le32(const std::string &raw, std::size_t at) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(raw[at]))
        | (static_cast<std::uint32_t>(static_cast<unsigned char>(raw[at + 1])) << 8)
        | (static_cast<std::uint32_t>(static_cast<unsigned char>(raw[at + 2])) << 16)
        | (static_cast<std::uint32_t>(static_cast<unsigned char>(raw[at + 3])) << 24);
}
std::uint64_t le64(const std::string &raw, std::size_t at) {
    return static_cast<std::uint64_t>(le32(raw, at))
        | (static_cast<std::uint64_t>(le32(raw, at + 4)) << 32);
}

// Static ELF64/LE capture validation, byte-for-byte the prepare.py loader
// contract: ET_EXEC, host machine, no PT_INTERP/PT_DYNAMIC, valid PT_LOAD
// congruence and an executable entry. The file itself never self-authorizes;
// the operator digest and the ownership/mode capture are checked separately.
void validateStaticElf(const std::string &raw) {
    struct utsname host {};
    if (::uname(&host) != 0) reject("native_feed_invalid");
    const std::string machine(host.machine);
    const std::uint16_t expectedMachine =
        machine == "x86_64" ? 62 : machine == "aarch64" ? 183 : 0;
    if (expectedMachine == 0 || raw.size() < 64
        || raw.compare(0, 7, std::string("\x7f" "ELF\x02\x01\x01", 7)) != 0
        || le16(raw, 18) != expectedMachine || le16(raw, 16) != 2) reject("native_feed_invalid");
    const std::uint64_t phoff = le64(raw, 32);
    const std::uint16_t phentsize = le16(raw, 54), phnum = le16(raw, 56);
    if (phentsize != 56 || phnum < 1 || phnum > 128 || phoff < 64
        || phoff + static_cast<std::uint64_t>(phentsize) * phnum > raw.size()
        || (static_cast<unsigned char>(raw[7]) != 0 && static_cast<unsigned char>(raw[7]) != 3)
        || static_cast<unsigned char>(raw[8]) != 0 || le32(raw, 20) != 1 || le16(raw, 52) != 64)
        reject("native_feed_invalid");
    const std::uint64_t entry = le64(raw, 24);
    const std::uint64_t page = expectedMachine == 183 ? 65536 : 4096;
    bool executableEntry = false;
    for (std::uint16_t i = 0; i < phnum; ++i) {
        const std::uint64_t at = phoff + static_cast<std::uint64_t>(i) * phentsize;
        const std::uint32_t kind = le32(raw, at), flags = le32(raw, at + 4);
        const std::uint64_t offset = le64(raw, at + 8), address = le64(raw, at + 16);
        const std::uint64_t fileSize = le64(raw, at + 32), memorySize = le64(raw, at + 40);
        const std::uint64_t alignment = le64(raw, at + 48);
        if (kind == 2 || kind == 3 || offset + fileSize > raw.size() || fileSize > memorySize)
            reject("native_feed_invalid");
        if (kind == 1) {
            if (address + memorySize < address || offset % page != address % page
                || (alignment > 1 && ((alignment & (alignment - 1)) != 0
                    || offset % alignment != address % alignment)))
                reject("native_feed_invalid");
            if ((flags & 1) != 0 && address <= entry && entry < address + fileSize)
                executableEntry = true;
        }
    }
    if (!executableEntry) reject("native_feed_invalid");
}

std::string readNativePayload(const std::filesystem::path &path, std::size_t limit,
                              uid_t owner, mode_t mode) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) reject("native_feed_invalid");
    struct stat before {};
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1
        || before.st_uid != owner || (before.st_mode & 07777) != static_cast<mode_t>(mode)
        || before.st_size < 64 || static_cast<std::uint64_t>(before.st_size) > limit) {
        ::close(fd); reject("native_feed_invalid");
    }
    std::string raw(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t done = 0;
    while (done < raw.size()) {
        const ssize_t n = ::read(fd, raw.data() + done, raw.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ::close(fd); reject("native_feed_invalid"); }
        done += static_cast<std::size_t>(n);
    }
    char extra = 0;
    struct stat after {};
    if (::read(fd, &extra, 1) != 0 || ::fstat(fd, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec
        || before.st_ctim.tv_sec != after.st_ctim.tv_sec
        || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) { ::close(fd); reject("native_feed_invalid"); }
    ::close(fd);
    return raw;
}

std::string pemOf(EVP_PKEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        if (bio) BIO_free(bio);
        reject("migration_preparation_failed");
    }
    char *data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    std::string out(data ? data : "", size > 0 ? static_cast<std::size_t>(size) : 0);
    BIO_free(bio);
    return out;
}

EVP_PKEY *loadOrCreateSigner(const std::filesystem::path &path) {
    if (std::filesystem::exists(path)) {
        FILE *file = std::fopen(path.c_str(), "rb");
        if (!file) reject("migration_preparation_failed");
        EVP_PKEY *key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
        std::fclose(file);
        if (!key) reject("migration_preparation_failed");
        return key;
    }
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY *key = nullptr;
    if (!context || EVP_PKEY_keygen_init(context) != 1 || EVP_PKEY_keygen(context, &key) != 1) {
        if (context) EVP_PKEY_CTX_free(context);
        if (key) EVP_PKEY_free(key);
        reject("migration_preparation_failed");
    }
    EVP_PKEY_CTX_free(context);
    const std::string pem = pemOf(key);
    writeExclusive(path, pem, 0600);
    return key;
}

std::string publicKeyBase64(EVP_PKEY *key) {
    const int derLength = i2d_PUBKEY(key, nullptr);
    if (derLength < 32) reject("migration_preparation_failed");
    std::string der(static_cast<std::size_t>(derLength), '\0');
    unsigned char *cursor = reinterpret_cast<unsigned char *>(der.data());
    if (i2d_PUBKEY(key, &cursor) != derLength) reject("migration_preparation_failed");
    const unsigned char *tail = reinterpret_cast<const unsigned char *>(der.data()) + (der.size() - 32);
    unsigned char encoded[64] {};
    const int length = EVP_EncodeBlock(encoded, tail, 32);
    if (length != 44) reject("migration_preparation_failed");
    return std::string(reinterpret_cast<char *>(encoded), static_cast<std::size_t>(length));
}

const char *identityFormat =
    "{\"id\":{{json .Id}},\"name\":{{json .Name}},\"image\":{{json .Image}},"
    "\"owner\":{{json (index .Config.Labels \"amnezia.migration.owner\")}},"
    "\"startedAt\":{{json .State.StartedAt}},\"running\":{{json .State.Running}}}";
const char *sourceIdentityFormat =
    "{\"id\":{{json .Id}},\"startedAt\":{{json .State.StartedAt}}}";
const std::vector<std::string> kParamNames = {
    "Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4",
    "HeaderProtectionKey","ContentPaddingAddition","RekeyAfterTime","RekeyTimeout",
    "RejectAfterTime","KeepaliveTimeout","MaxHandshakeAttempts","RandomTrailers","DisableCookies"};
} // namespace

ProductionPorts::ProductionPorts(std::filesystem::path root, std::filesystem::path nativeFeed,
                                 std::string nativeFeedSha256)
    : ProductionPorts(std::move(root), std::move(nativeFeed), std::move(nativeFeedSha256),
                      DataPaths{}, {}, {}) {}

ProductionPorts::ProductionPorts(std::filesystem::path root, std::filesystem::path nativeFeed,
                                 std::string nativeFeedSha256, DataPaths paths)
    : ProductionPorts(std::move(root), std::move(nativeFeed), std::move(nativeFeedSha256),
                      std::move(paths), {}, {}) {}

ProductionPorts::ProductionPorts(std::filesystem::path root, std::filesystem::path nativeFeed,
                                 std::string nativeFeedSha256, DataPaths paths,
                                 std::filesystem::path nativeCollector,
                                 std::string nativeCollectorSha256)
    : root_(std::move(root)), nativeFeed_(std::move(nativeFeed)), nativeFeedSha256_(std::move(nativeFeedSha256)),
      nativeCollector_(std::move(nativeCollector)),
      nativeCollectorSha256_(std::move(nativeCollectorSha256)), data_(std::move(paths)) {}

prepare::CommandResult ProductionPorts::command(const std::vector<std::string> &argv) {
    if (argv.empty() || argv.front() != "docker") return {1, "", "unsupported_command"};
    unsigned budget = 30;
    if (argv.size() > 1 && (argv[1] == "pull" || argv[1] == "create" || argv[1] == "run"
                            || argv[1] == "build")) budget = 180;
    else if (argv.size() > 1 && argv[1] == "inspect") budget = 10;
    try {
        std::string output = runBoundedDockerWithBudget(argv, kOneMiB, budget);
        // Docker's --format writes a terminating newline. Journal identity and
        // receipt fields require the exact immutable id token, matching the
        // Python call sites that .strip() the same command output.
        if (argv.size() == 6 && argv[1] == "image" && argv[2] == "inspect"
            && argv[3] == "--format" && argv[4] == "{{.Id}}") {
            while (!output.empty() && (output.back() == 10 || output.back() == 13)) output.pop_back();
        }
        return {0, output, ""};
    } catch (const BoundedDockerError &error) {
        if (error.kind == BoundedDockerFailureKind::Exit) return {1, "", "bounded_docker_exit"};
        return {124, "", "bounded_docker_unavailable"};
    }
}

void ProductionPorts::write(const std::filesystem::path &path, const std::string &bytes, unsigned mode) {
    if (!observed_ || (mode != 0600 && mode != 0755)) reject("migration_preparation_failed");
    const std::filesystem::path base = root_ / request_.source / std::to_string(request_.generation);
    std::error_code error;
    const auto canonicalBase = std::filesystem::weakly_canonical(base, error);
    const auto canonicalPath = std::filesystem::weakly_canonical(path, error);
    if (error || canonicalPath.string().compare(0, canonicalBase.string().size() + 1,
                                                canonicalBase.string() + "/") != 0)
        reject("write_outside_generation");
    writeExclusive(path, bytes, mode);
}

std::string ProductionPorts::signingPublicKey(const std::filesystem::path &directory) {
    if (!observed_) reject("migration_preparation_failed");
    const std::filesystem::path signer = directory.parent_path() / "signing.pem";
    EVP_PKEY *key = loadOrCreateSigner(signer);
    const std::string bytes = pemOf(key);
    const std::string result = publicKeyBase64(key);
    EVP_PKEY_free(key);
    writeExclusive(directory / "signing.pem", bytes, 0600);
    return result;
}

prepare::Readiness ProductionPorts::ready(const prepare::SourceObservation &source,
                                          const std::vector<std::string> &targetConfig,
                                          const std::string &serverKey, bool automatic) {
    if (!observed_ || targetConfig.empty()) return {false, "native_ready_not_observed"};
    try {
        const ReadyConfig target = parseConfig(targetConfig.front());
        Json parameters(json_object_new_object());
        for (const auto &name : kParamNames) {
            const auto it = target.Interface.find(name);
            if (it == target.Interface.end()) return {false, "native_ready_rejected"};
            json_object_object_add(parameters.get(), name.c_str(), json_object_new_string(it->second.c_str()));
        }
        const std::string targetName = request_.source + "-migration-" + std::to_string(request_.generation);
        Json pin = parseJson(pinJson(targetName));
        Json root(json_object_new_object());
        json_object_object_add(root.get(), "source", json_object_new_string(source.rawConfig.c_str()));
        json_object_object_add(root.get(), "target", json_object_new_string(targetConfig.front().c_str()));
        Json state(json_object_new_object());
        json_object_object_add(state.get(), "targetContainer", json_object_new_string(stringMember(pin.get(), "id").c_str()));
        json_object_object_add(state.get(), "serverPublicKey", json_object_new_string(serverKey.c_str()));
        json_object_object_add(state.get(), "parameters", parameters.release());
        json_object_object_add(root.get(), "ready", state.release());
        json_object_object_add(root.get(), "expected", json_object_get(pin.get()));
        json_object_object_add(root.get(), "automatic", json_object_new_boolean(automatic));
        struct Runner final : ProcessRunner {
            std::string run(const ProcessArgs &args) override {
                const unsigned budget = args.size() > 1 && args[1] == "inspect" ? 10 : 30;
                return runBoundedDockerWithBudget(args, kFourMiB, budget);
            }
        } runner;
        const std::string output = readyRuntimeRequest(
            json_object_to_json_string_ext(root.get(), JSON_C_TO_STRING_PLAIN), runner);
        return {output.find("\"result\":true") != std::string::npos, output};
    } catch (const std::exception &error) {
        return {false, error.what()};
    }
}

void ProductionPorts::capturePayloads(const std::string &feedSha256,
                                      const std::string &collectorSha256) {
    if (captured_) reject("native_payload_capture_repeated");
    if (feedSha256 != nativeFeedSha256_) reject("native_feed_invalid");
    if (collectorSha256 != nativeCollectorSha256_) reject("native_collector_invalid");
    std::string feed, collector;
    if (!feedSha256.empty()) {
        if (nativeFeed_.empty()) reject("native_feed_invalid");
        // Exact capture contract: regular single-link file, required owner/mode,
        // bounded size, stable inode across the read, operator digest, then the
        // static ELF64 header/program-header validation.
        feed = readNativePayload(nativeFeed_, 32 * 1024 * 1024, data_.feedOwner, data_.feedMode);
        if (sha256Hex(feed) != feedSha256) reject("native_feed_invalid");
        validateStaticElf(feed);
    }
    if (!collectorSha256.empty()) {
        if (nativeCollector_.empty()) reject("native_collector_invalid");
        try {
            collector = readNativePayload(nativeCollector_, 32 * 1024 * 1024,
                                          data_.feedOwner, data_.feedMode);
            if (sha256Hex(collector) != collectorSha256) reject("native_collector_invalid");
            validateStaticElf(collector);
        } catch (const prepare::PrepareError &) {
            // The shared capture primitive reports native_feed_invalid; the
            // collector role must fail closed under its own exact code.
            reject("native_collector_invalid");
        } catch (const std::exception &) {
            reject("native_collector_invalid");
        }
    }
    capturedFeedRaw_ = std::move(feed);
    capturedCollectorRaw_ = std::move(collector);
    capturedFeedSha256_ = feedSha256;
    capturedCollectorSha256_ = collectorSha256;
    captured_ = true;
}

const std::string &ProductionPorts::capturedFeed() {
    if (!captured_ || capturedFeedSha256_.empty() || capturedFeedSha256_ != nativeFeedSha256_)
        reject("native_feed_invalid");
    return capturedFeedRaw_;
}

const std::string &ProductionPorts::capturedCollector() {
    if (!captured_ || capturedCollectorSha256_.empty() ||
        capturedCollectorSha256_ != nativeCollectorSha256_)
        reject("native_collector_invalid");
    return capturedCollectorRaw_;
}

void ProductionPorts::installNativeFeed(const std::filesystem::path &directory, const std::string &sha256) {
    if (sha256.empty()) return;
    if (sha256 != nativeFeedSha256_ || sha256 != capturedFeedSha256_) reject("native_feed_invalid");
    writeExclusive(directory / "awg-feed", capturedFeed(), 0755);
}

std::filesystem::path ProductionPorts::stageNativeCollector(const std::filesystem::path &directory,
                                                            const std::string &sha256) {
    if (!observed_ || sha256.empty() || sha256 != nativeCollectorSha256_ ||
        sha256 != capturedCollectorSha256_)
        reject("native_collector_rejected");
    const std::string &raw = capturedCollector();
    const std::filesystem::path base = root_ / request_.source / std::to_string(request_.generation);
    std::error_code error;
    const auto canonicalBase = std::filesystem::weakly_canonical(base, error);
    const auto canonicalDirectory = std::filesystem::weakly_canonical(directory, error);
    if (error || canonicalDirectory != canonicalBase) reject("write_outside_generation");
    const std::filesystem::path context = directory / "logs-image";
    if (::mkdir(context.c_str(), 0700) != 0) reject("migration_preparation_failed");
    writeExclusive(context / "Dockerfile",
                   "FROM scratch\nCOPY amnezia-client-logs-collector /app/amnezia-client-logs-collector\n", 0600);
    writeExclusive(context / "amnezia-client-logs-collector", raw, 0755);
    return context;
}

std::filesystem::path ProductionPorts::stageNativeControl(const std::filesystem::path &directory,
                                                          const std::string &sha256) {
    if (!observed_ || sha256.empty() || sha256 != nativeFeedSha256_)
        reject("native_control_rejected");
    const std::string &raw = capturedFeed();
    if (sha256Hex(raw) != sha256) reject("native_control_rejected");
    const std::filesystem::path base = root_ / request_.source / std::to_string(request_.generation);
    std::error_code error;
    const auto canonicalBase = std::filesystem::weakly_canonical(base, error);
    const auto canonicalDirectory = std::filesystem::weakly_canonical(directory, error);
    if (error || canonicalDirectory != canonicalBase) reject("write_outside_generation");
    const std::filesystem::path context = directory / "control-image";
    if (::mkdir(context.c_str(), 0700) != 0) reject("migration_preparation_failed");
    writeExclusive(context / "Dockerfile", "FROM scratch\nCOPY awg-feed /app/awg-feed\n", 0600);
    writeExclusive(context / "awg-feed", raw, 0755);
    return context;
}

void ProductionPorts::verifyAutomaticPort(unsigned port) {
    class Lease final : public PortLease {
        int descriptor_ = -1;
    public:
        explicit Lease(UdpFamily family) {
            descriptor_ = ::socket(family == UdpFamily::V4 ? AF_INET : AF_INET6,
                                   SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (descriptor_ < 0) throw PlannerError("migration_udp_port_unavailable");
        }
        ~Lease() override { if (descriptor_ >= 0) ::close(descriptor_); }
        void ipv6Only() override {
            const int yes = 1;
            if (::setsockopt(descriptor_, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof yes))
                throw PlannerError("migration_udp_port_unavailable");
        }
        void bind(const std::string &address, unsigned value) override {
            if (address == "0.0.0.0") {
                sockaddr_in v4{}; v4.sin_family = AF_INET;
                v4.sin_port = htons(static_cast<std::uint16_t>(value));
                if (::bind(descriptor_, reinterpret_cast<const sockaddr *>(&v4), sizeof v4))
                    throw PlannerError("migration_udp_port_unavailable");
            } else if (address == "::") {
                sockaddr_in6 v6{}; v6.sin6_family = AF_INET6;
                v6.sin6_port = htons(static_cast<std::uint16_t>(value));
                if (::bind(descriptor_, reinterpret_cast<const sockaddr *>(&v6), sizeof v6))
                    throw PlannerError("migration_udp_port_unavailable");
            } else {
                throw PlannerError("migration_udp_port_unavailable");
            }
        }
    };
    class Probe final : public PortProbe {
    public:
        std::unique_ptr<PortLease> open(UdpFamily family) override {
            return std::make_unique<Lease>(family);
        }
    } probe;
    try {
        amnezia::awgMigration::verifyAutomaticPort(port, probe);
    } catch (...) {
        reject("migration_udp_port_unavailable");
    }
}

void ProductionPorts::planAutomatic(const std::filesystem::path &root,
                                    const prepare::Request &request,
                                    const prepare::SourceObservation &source,
                                    prepare::Request &resolved) {
    if ((request.source != "amnezia-awg" && request.source != "amnezia-awg2") ||
        source.rawConfig.empty() || root.empty())
        reject("migration_preparation_failed");
    const ReadyConfig config = parseConfig(source.rawConfig);
    const auto listen = config.Interface.find("ListenPort");
    if (listen == config.Interface.end() || listen->second.empty() || listen->second.size() > 5 ||
        !std::all_of(listen->second.begin(), listen->second.end(),
                     [](unsigned char c) { return c >= '0' && c <= '9'; }))
        reject("migration_preparation_failed");
    const unsigned sourcePort = static_cast<unsigned>(std::stoul(listen->second));
    if (sourcePort < 1 || sourcePort > 65535) reject("migration_preparation_failed");
    struct Runner final : ProcessRunner {
        std::string run(const ProcessArgs &args) override {
            if (args == ProcessArgs{"ss", "-H", "-uan"}) return runBoundedSs(kOneMiB);
            const unsigned budget = args.size() > 1 && args[1] == "pull" ? 180 : 30;
            return runBoundedDockerWithBudget(args, kFourMiB, budget);
        }
    } runner;
    try {
        const std::string image = resolveTrustedImage(runner);
        const UdpPorts occupied = occupiedUdpPorts(runner);
        const AutomaticRequest plan = automaticPlan(root, request.source, request.host, image,
                                                    source.rawConfig, sourcePort, occupied);
        resolved.image = plan.image;
        resolved.port = plan.port;
        resolved.generation = plan.generation;
        // Selected request state: later writes, control staging and journal
        // identity must follow the planned generation, not the generation-0
        // request that entered observe().
        request_ = resolved;
    } catch (const PlannerError &error) {
        reject(error.code());
    } catch (...) {
        reject("native_automatic_rejected");
    }
}

void ProductionPorts::pause(unsigned milliseconds) {
    if (milliseconds > 10000) milliseconds = 10000;
    ::usleep(milliseconds * 1000u);
}

std::string ProductionPorts::inspectIdentity(const std::string &name) {
    const std::string output = runDocker({"docker", "inspect", "--format", identityFormat, name}, kOneMiB, 10);
    if (output.empty()) reject("migration_preparation_failed");
    return output;
}

std::string ProductionPorts::pinJson(const std::string &name) {
    Json value = parseJson(inspectIdentity(name));
    for (const char *key : {"id", "name", "image", "owner", "startedAt"})
        (void)stringMember(value.get(), key);
    json_object_object_del(value.get(), "running");
    return json_object_to_json_string_ext(value.get(), JSON_C_TO_STRING_PLAIN);
}

std::string ProductionPorts::inspectId(const std::string &name) {
    return stringMember(parseJson(inspectIdentity(name)).get(), "id");
}

std::vector<std::string> ProductionPorts::ownedComments() {
    std::vector<std::string> comments;
    const std::filesystem::path sourceRoot = root_ / request_.source;
    std::error_code error;
    if (!std::filesystem::is_directory(sourceRoot, error)) return comments;
    for (const auto &entry : std::filesystem::directory_iterator(sourceRoot, error)) {
        if (error) reject("migration_preparation_failed");
        const auto journal = entry.path() / "transaction.json";
        if (!std::filesystem::exists(journal)) continue;
        const std::string raw = readFile(journal, kFourMiB);
        try { comments.push_back(stringMember(parseJson(raw).get(), "owner")); }
        catch (const prepare::PrepareError &) { reject("migration_preparation_failed"); }
    }
    return comments;
}

std::map<std::string, policy::Fields> ProductionPorts::networkBinding(const std::string &container,
                                                                     std::vector<std::string> *options) {
    json_object *request = json_object_new_object();
    json_object_object_add(request, "op", json_object_new_string("snapshot"));
    json_object_object_add(request, "container", json_object_new_string(container.c_str()));
    const std::string raw = json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN);
    json_object_put(request);
    Json root = parseJson(networkTopologyRuntimeRequest(raw, productionNetworkObserverRunner()));
    json_object *result = nullptr;
    if (!json_object_object_get_ex(root.get(), "result", &result) || !result)
        reject("unsupported_source_network_topology");
    std::map<std::string, policy::Fields> binding;
    json_object *bindingValue = nullptr;
    if (!json_object_object_get_ex(result, "binding", &bindingValue) || !bindingValue
        || !json_object_is_type(bindingValue, json_type_object)) reject("unsupported_source_network_topology");
    json_object_object_foreach(bindingValue, name, role) {
        policy::Fields fields;
        fields["networkId"] = stringMember(role, "networkId");
        fields["interface"] = stringMember(role, "interface");
        json_object *isDefault = nullptr;
        if (!json_object_object_get_ex(role, "default", &isDefault) || !isDefault
            || !json_object_is_type(isDefault, json_type_boolean)) reject("unsupported_source_network_topology");
        fields["default"] = json_object_get_boolean(isDefault) ? "1" : "0";
        binding[name] = std::move(fields);
    }
    if (options) {
        json_object *list = nullptr;
        if (!json_object_object_get_ex(result, "options", &list) || !list
            || !json_object_is_type(list, json_type_array)) reject("unsupported_source_network_topology");
        for (std::size_t i = 0; i < json_object_array_length(list); ++i) {
            json_object *item = json_object_array_get_idx(list, i);
            if (!item || !json_object_is_type(item, json_type_string)) reject("unsupported_source_network_topology");
            options->emplace_back(json_object_get_string(item));
        }
    }
    return binding;
}

prepare::SourceObservation ProductionPorts::observe(const prepare::Request &request) {
    request_ = request;
    observed_ = false;
    json_object *input = json_object_new_object();
    json_object_object_add(input, "op", json_object_new_string("read"));
    json_object_object_add(input, "source", json_object_new_string(request.source.c_str()));
    const std::string inputRaw = json_object_to_json_string_ext(input, JSON_C_TO_STRING_PLAIN);
    json_object_put(input);
    Json sourceResult = parseJson(sourceConfigRuntimeRequest(inputRaw, productionSourceConfigRunner()));
    json_object *result = nullptr;
    if (!json_object_object_get_ex(sourceResult.get(), "result", &result) || !result)
        reject("native_source_config_rejected");
    const std::string raw = stringMember(result, "raw");
    const ReadyConfig config = parseConfig(raw);
    const std::string iface = request.source == "amnezia-awg" ? "wg0" : "awg0";

    Json identity = parseJson(runDocker({"docker", "inspect", "--format", sourceIdentityFormat, request.source},
                                        kOneMiB, 10));
    prepare::SourceObservation observation;
    observation.sourceId = stringMember(identity.get(), "id");
    observation.startedAt = stringMember(identity.get(), "startedAt");
    observation.rawConfig = raw;
    observation.sourceIface = iface;
    observation.ownedComments = ownedComments();
    observation.snapshot = policy::namespaceSnapshot(policy::runReadOnlyDocker, request.source,
                                                      config.Interface, iface, observation.ownedComments);
    observation.networkBinding = networkBinding(request.source, &observation.networkOptions);
    // Read-only managed-policy epoch and exact local feed digests bound to the
    // observed NAT redirect ports. Both are observed from the real pinned
    // sources; neither is accepted from a staged receipt or request field.
    observation.epoch = policyEpoch();
    observation.expectedFeedSha = expectedFeedSha(observation.snapshot);
    sourceRaw_ = raw;
    observed_ = true;
    return observation;
}

std::optional<policy::Epoch> ProductionPorts::policyEpoch() {
    try {
        return policy::clientPolicyEpoch(data_.policyRoot.string());
    } catch (const policy::Error &error) {
        throw prepare::PrepareError(error.what());
    } catch (...) {
        throw prepare::PrepareError("policy_source_untrusted");
    }
}

std::map<std::string, std::string> ProductionPorts::expectedFeedSha(const policy::Snapshot &snapshot) {
    std::map<std::string, std::string> expected;
    for (const auto &rule : snapshot.nat) {
        for (const auto *port : {"17864", "17865"}) {
            if (rule.find(std::string("--dport ") + port + " ") == std::string::npos) continue;
            const std::filesystem::path source = std::string(port) == "17864"
                ? data_.policyRoot / "rules.json" : data_.updatesRoot / "manifest.json";
            const auto digest = dataFileSha256(source, 1024 * 1024);
            if (digest) expected[port] = *digest;
        }
    }
    return expected;
}

bool ProductionPorts::componentExists(const std::string &name) {
    const auto alphanumeric = [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    };
    const auto validName = [&](const std::string &value, bool alias) {
        if (value.empty() || value.size() > 128 || !alphanumeric(value.front())) return false;
        return std::all_of(value.begin(), value.end(), [&](unsigned char c) {
            return alphanumeric(c) || c == '_' || c == '.' || c == '-' || (alias && c == '/');
        });
    };
    if (!validName(name, false)) reject("component_observation_failed");
    std::string output;
    try {
        // A successful empty inventory establishes absence. Inspect failure
        // cannot distinguish absence from a daemon, permission or transport error.
        output = runBoundedDockerWithBudget(
            {"docker", "ps", "--all", "--filter", "name=" + name, "--format", "{{.Names}}"}, 128, 10);
    } catch (const BoundedDockerError &) { reject("component_observation_failed"); }
    if (output.find('\0') != std::string::npos) reject("component_observation_failed");
    bool found = false;
    std::istringstream rows(output);
    std::string row;
    while (std::getline(rows, row)) {
        std::size_t begin = 0;
        for (;;) {
            const auto end = row.find(',', begin);
            const auto observed = row.substr(begin, end == std::string::npos ? end : end - begin);
            if (!validName(observed, true)) reject("component_observation_failed");
            found = found || observed == name;
            if (end == std::string::npos) break;
            begin = end + 1;
        }
    }
    return found;
}

bool ProductionPorts::sourceControlBound() {
    if (!observed_) reject("migration_preparation_failed");
    const std::string output = runDocker(
        {"docker", "exec", request_.source, "cat", "/proc/net/tcp"}, kFourMiB, 30);
    if (output.empty()) reject("native_source_config_rejected");
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string slot, local;
        if (!(fields >> slot >> local)) continue;
        if (local.size() >= 5 && local.compare(local.size() - 5, 5, ":46A2") == 0) return true;
    }
    return false;
}

std::map<std::string, policy::Fields> ProductionPorts::binding(const std::string &container) {
    return networkBinding(container);
}

policy::Snapshot ProductionPorts::targetSnapshot(const std::string &container, const ReadyConfig &config,
                                                 const std::string &iface,
                                                 const std::vector<std::string> &owners) {
    return policy::namespaceSnapshot(policy::runReadOnlyDocker, container, config.Interface, iface, owners);
}
} // namespace amnezia::awgMigration::prepareProduction
