#include "control_loaded.h"

#include <json-c/json.h>
#include <openssl/evp.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>

#include <algorithm>
#include <array>
#include <memory>
#include <set>
#include <stdexcept>

namespace amnezia::awgMigration::controlPid1 {
namespace {
constexpr std::uint64_t maxExecutable = 32ull * 1024 * 1024;
constexpr std::uint32_t pemMode = 0755;

[[noreturn]] void reject() { throw std::runtime_error("native_control_rejected"); }

bool hex64(const std::string &value) {
    return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

std::uint16_t le16(const std::string &raw, std::size_t at) {
    if (at + 2 > raw.size()) reject();
    return static_cast<std::uint16_t>(static_cast<unsigned char>(raw[at])
                                      | static_cast<unsigned>(static_cast<unsigned char>(raw[at + 1])) << 8);
}
std::uint32_t le32(const std::string &raw, std::size_t at) {
    if (at + 4 > raw.size()) reject();
    return static_cast<std::uint32_t>(static_cast<unsigned char>(raw[at]))
        | static_cast<std::uint32_t>(static_cast<unsigned char>(raw[at + 1])) << 8
        | static_cast<std::uint32_t>(static_cast<unsigned char>(raw[at + 2])) << 16
        | static_cast<std::uint32_t>(static_cast<unsigned char>(raw[at + 3])) << 24;
}
std::uint64_t le64(const std::string &raw, std::size_t at) {
    if (at + 8 > raw.size()) reject();
    std::uint64_t value = 0;
    for (int i = 7; i >= 0; --i) value = (value << 8) | static_cast<unsigned char>(raw[at + static_cast<std::size_t>(i)]);
    return value;
}
std::string sha256(const std::string &bytes) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) reject();
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> guard(ctx, EVP_MD_CTX_free);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1
        || EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) != 1
        || EVP_DigestFinal_ex(ctx, digest.data(), &length) != 1 || length != 32) reject();
    static const char *digits = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned i = 0; i < length; ++i) {
        result.push_back(digits[digest[i] >> 4]);
        result.push_back(digits[digest[i] & 0x0f]);
    }
    return result;
}

using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;
Json own(json_object *value) {
    if (!value) reject();
    return Json(value, json_object_put);
}
json_object *member(json_object *root, const char *key, json_type type) {
    json_object *value = nullptr;
    if (!json_object_object_get_ex(root, key, &value) || !value || !json_object_is_type(value, type)) reject();
    return value;
}

struct UniqueKeys : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, UniqueKeys> {
    struct Frame {
        bool object;
        std::set<std::string> keys;
    };
    std::vector<Frame> stack;
    bool StartObject() {
        if (stack.size() >= 8) return false;
        stack.push_back({true, {}});
        return true;
    }
    bool StartArray() {
        if (stack.size() >= 8) return false;
        stack.push_back({false, {}});
        return true;
    }
    bool EndObject(rapidjson::SizeType) {
        if (stack.empty() || !stack.back().object) return false;
        stack.pop_back();
        return true;
    }
    bool EndArray(rapidjson::SizeType) {
        if (stack.empty() || stack.back().object) return false;
        stack.pop_back();
        return true;
    }
    bool Key(const char *value, rapidjson::SizeType length, bool) {
        if (stack.empty() || !stack.back().object) return false;
        std::string key(value, length);
        return key.find('\0') == std::string::npos && stack.back().keys.insert(std::move(key)).second;
    }
};

Json strictParse(const std::string &raw) {
    if (raw.empty() || raw.size() > 64 * 1024 || raw.find('\0') != std::string::npos) reject();
    rapidjson::MemoryStream stream(raw.data(), raw.size());
    rapidjson::Reader reader;
    UniqueKeys unique;
    if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, unique)
        || !unique.stack.empty() || stream.Tell() != raw.size()) reject();
    auto tok = std::unique_ptr<json_tokener, decltype(&json_tokener_free)>(json_tokener_new(), json_tokener_free);
    if (!tok) reject();
    json_tokener_set_flags(tok.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    auto root = own(json_tokener_parse_ex(tok.get(), raw.data(), static_cast<int>(raw.size())));
    if (json_tokener_get_error(tok.get()) != json_tokener_success
        || !json_object_is_type(root.get(), json_type_object)) reject();
    return root;
}

void requireElf(const std::string &raw, const std::string &machine, ElfFacts &facts) {
    const unsigned expectedMachine = machine == "x86_64" ? 62u : machine == "aarch64" ? 183u : 0u;
    if (raw.size() < 64 || expectedMachine == 0) reject();
    if (raw.compare(0, 7, std::string("\x7f""ELF\x02\x01\x01", 7)) != 0) reject();
    if (static_cast<unsigned char>(raw[7]) != 0 && static_cast<unsigned char>(raw[7]) != 3) reject();
    if (raw[8] != 0) reject();
    if (le16(raw, 16) != 2 || le16(raw, 18) != expectedMachine || le32(raw, 20) != 1) reject();
    if (le16(raw, 52) != 64) reject();
    const auto tableOffset = le64(raw, 32);
    const auto entry = le64(raw, 24);
    const auto tableSize = le16(raw, 54);
    const auto tableCount = le16(raw, 56);
    if (tableSize != 56 || tableCount < 1 || tableCount > 128 || tableOffset < 64 || tableOffset > raw.size()
        || tableCount > (raw.size() - tableOffset) / tableSize) reject();
    const std::uint64_t page = expectedMachine == 183 ? 65536ull : 4096ull;
    bool executable = false;
    for (std::uint16_t index = 0; index < tableCount; ++index) {
        const auto base = static_cast<std::size_t>(tableOffset) + static_cast<std::size_t>(index) * tableSize;
        const auto kind = le32(raw, base), flags = le32(raw, base + 4);
        const auto fileOffset = le64(raw, base + 8), address = le64(raw, base + 16);
        const auto fileSize = le64(raw, base + 32), memorySize = le64(raw, base + 40);
        const auto alignment = le64(raw, base + 48);
        if (kind == 2 || kind == 3) reject();
        if (fileOffset > raw.size() || fileSize > raw.size() - fileOffset || fileSize > memorySize) reject();
        if (kind == 1) {
            if (address > 0xffffffffffffffffull - memorySize || fileOffset % page != address % page) reject();
            if (alignment > 1 && ((alignment & (alignment - 1)) != 0 || fileOffset % alignment != address % alignment)) reject();
            if ((flags & 1u) != 0 && address <= entry && entry - address < fileSize) executable = true;
        }
    }
    if (!executable) reject();
    facts.machine = expectedMachine;
    facts.executableEntry = true;
}
} // namespace

ExecutableImage captureExecutable(const std::filesystem::path &path, const std::string &expectedSha256,
                                  CaptureOps &ops) {
    if (!hex64(expectedSha256)) reject();
    const int raw = ops.openNoFollow(path);
    if (raw < 0) reject();
    struct Closer {
        CaptureOps &ops;
        int fd;
        ~Closer() { ops.close(fd); }
    } closeRaw{ops, raw};
    const auto before = ops.identify(raw);
    if (!before.regular || before.uid != ops.currentUid() || before.nlink != 1
        || (before.mode & 07777u) != pemMode || before.size < 64 || before.size > maxExecutable) reject();
    std::string bytes;
    bytes.reserve(static_cast<std::size_t>(before.size));
    std::uint64_t remaining = before.size;
    while (remaining != 0) {
        const auto chunk = ops.readChunk(raw, static_cast<std::size_t>(std::min<std::uint64_t>(remaining, 128 * 1024)));
        if (chunk.empty() || chunk.size() > remaining) reject();
        bytes.append(chunk);
        remaining -= chunk.size();
    }
    if (ops.hasExtraByte(raw)) reject();
    const auto after = ops.identify(raw);
    if (before.device != after.device || before.inode != after.inode || before.size != after.size
        || before.mtimeNs != after.mtimeNs || before.ctimeNs != after.ctimeNs) reject();
    if (sha256(bytes) != expectedSha256) reject();

    ExecutableImage image;
    requireElf(bytes, ops.machine(), image.elf);
    const int sealed = ops.createSealedMemfd();
    if (sealed < 0) reject();
    auto release = [&]() {
        image.fd = -1;
        ops.close(sealed);
    };
    if (!ops.writeAll(sealed, bytes) || !ops.setMode0500(sealed) || !ops.sealAndVerify(sealed)) {
        release();
        reject();
    }
    image.sha256 = expectedSha256;
    image.bytes = std::move(bytes);
    image.identity = before;
    image.fd = sealed;
    return image;
}

std::string receiptJson(const LoadedControl &receipt) {
    if ((receipt.role != "source" && receipt.role != "target") || !hex64(receipt.sha256)
        || receipt.processStart.empty() || receipt.processStart.size() > 64 || receipt.fd < 3
        || receipt.fd >= 1048576) reject();
    auto root = own(json_object_new_object());
    if (json_object_object_add(root.get(), "kind", json_object_new_string(receiptKind)) != 0) reject();
    auto native = own(json_object_new_object());
    if (json_object_object_add(native.get(), "sha256", json_object_new_string(receipt.sha256.c_str())) != 0
        || json_object_object_add(native.get(), "fd", json_object_new_int(receipt.fd)) != 0
        || json_object_object_add(native.get(), "protocol", json_object_new_string(receiptProtocol)) != 0) reject();
    if (json_object_object_add(root.get(), "nativeControl", native.get()) != 0) reject();
    native.release();
    if (json_object_object_add(root.get(), "processStart", json_object_new_string(receipt.processStart.c_str())) != 0
        || json_object_object_add(root.get(), "role", json_object_new_string(receipt.role.c_str())) != 0) reject();
    const char *serialized = json_object_to_json_string_ext(root.get(), JSON_C_TO_STRING_PLAIN);
    if (!serialized) reject();
    return std::string(serialized);
}

void verifyLoadedControl(const std::string &receipt, const std::string &expectedRole,
                         const std::string &expectedSha256, AttestOps &ops) {
    if ((expectedRole != "source" && expectedRole != "target") || !hex64(expectedSha256)) reject();
    auto root = strictParse(receipt);
    // Legacy Python receipts and every other shape are unsupported here rather than
    // being silently accepted without the native transport they claim.
    json_object *legacy = nullptr;
    if (json_object_object_get_ex(root.get(), "hashes", &legacy)) {
        throw std::runtime_error("native_control_receipt_variant_unsupported");
    }
    if (json_object_object_length(root.get()) != 4) reject();
    const std::set<std::string> expectedKeys = {"kind", "nativeControl", "processStart", "role"};
    {
        json_object_object_foreach(root.get(), key, value) {
            (void)value;
            if (!expectedKeys.count(key)) reject();
        }
    }
    json_object *kind = member(root.get(), "kind", json_type_string);
    json_object *role = member(root.get(), "role", json_type_string);
    json_object *start = member(root.get(), "processStart", json_type_string);
    json_object *native = member(root.get(), "nativeControl", json_type_object);
    if (std::string(json_object_get_string(kind), static_cast<std::size_t>(json_object_get_string_len(kind))) != receiptKind) reject();
    if (std::string(json_object_get_string(role), static_cast<std::size_t>(json_object_get_string_len(role))) != expectedRole) reject();
    const std::string observedStart(json_object_get_string(start), static_cast<std::size_t>(json_object_get_string_len(start)));
    if (observedStart.empty() || observedStart.size() > 64 || observedStart.find('\0') != std::string::npos
        || observedStart != ops.processStart()) reject();
    if (json_object_object_length(native) != 3) reject();
    const std::set<std::string> nativeKeys = {"fd", "protocol", "sha256"};
    {
        json_object_object_foreach(native, key, value) {
            (void)value;
            if (!nativeKeys.count(key)) reject();
        }
    }
    json_object *digest = member(native, "sha256", json_type_string);
    json_object *fd = member(native, "fd", json_type_int);
    json_object *protocol = member(native, "protocol", json_type_string);
    const std::string observedSha(json_object_get_string(digest), static_cast<std::size_t>(json_object_get_string_len(digest)));
    const std::string observedProtocol(json_object_get_string(protocol), static_cast<std::size_t>(json_object_get_string_len(protocol)));
    if (observedSha != expectedSha256 || observedProtocol != receiptProtocol) reject();
    const auto descriptor = json_object_get_int64(fd);
    if (json_object_get_type(fd) != json_type_int || descriptor < 3 || descriptor >= 1048576) reject();
    const auto attested = ops.attest(static_cast<int>(descriptor));
    if (!attested.regular || attested.size < 64 || attested.size > maxExecutable
        || attested.seals != requiredSeals || attested.sha256 != expectedSha256) reject();
}
} // namespace amnezia::awgMigration::controlPid1
