#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace amnezia::awgMigration::controlPid1 {
// Narrow native PID1 variant of the control-loaded receipt.
// The legacy Python PID1 receipt (role/processStart/hashes/nativeControl with
// protocol control-json-v1) is NOT produced or accepted here: this process never
// loads service.py/target.py and never execs --control-json per request.
inline constexpr const char *receiptKind = "native-control-http-v1";
inline constexpr const char *receiptProtocol = "control-http-v1";

struct FileIdentity {
    bool regular = false;
    std::uint32_t mode = 0, uid = 0, nlink = 0;
    std::uint64_t device = 0, inode = 0, size = 0, mtimeNs = 0, ctimeNs = 0;
};
struct ElfFacts {
    unsigned machine = 0;
    bool executableEntry = false;
};
struct ExecutableImage {
    std::string sha256;
    std::string bytes; // held copy is only for tests/receipt; the sealed fd is authoritative
    FileIdentity identity;
    ElfFacts elf;
    int fd = -1;
    ExecutableImage() = default;
    ExecutableImage(const ExecutableImage &) = delete;
    ExecutableImage &operator=(const ExecutableImage &) = delete;
    ExecutableImage(ExecutableImage &&other) noexcept { *this = std::move(other); }
    ExecutableImage &operator=(ExecutableImage &&other) noexcept {
        if (this != &other) {
            sha256 = std::move(other.sha256);
            bytes = std::move(other.bytes);
            identity = other.identity;
            elf = other.elf;
            fd = other.fd;
            other.fd = -1;
        }
        return *this;
    }
};

// Every filesystem/proc/memfd boundary of capture and attestation. The real
// adapter lives in control_loaded_posix.cpp and is never linked into the inert
// unit runner; the runner supplies private fake fixtures only.
class CaptureOps {
public:
    virtual ~CaptureOps() = default;
    virtual int openNoFollow(const std::filesystem::path &path) = 0;
    virtual FileIdentity identify(int fd) = 0;
    virtual std::string readChunk(int fd, std::size_t limit) = 0;
    virtual bool hasExtraByte(int fd) = 0;
    virtual int createSealedMemfd() = 0;
    virtual bool writeAll(int fd, const std::string &bytes) = 0;
    virtual bool setMode0500(int fd) = 0;
    virtual bool sealAndVerify(int fd) = 0;
    virtual std::uint32_t currentUid() = 0;
    virtual std::string machine() = 0;
    virtual void close(int fd) = 0;
};

// Capture binds the held bytes to the caller-supplied expected digest. The
// digest comes from image/meta authority via trusted transport, never from the
// executable's own metadata or the receipt being written.
ExecutableImage captureExecutable(const std::filesystem::path &path, const std::string &expectedSha256,
                                  CaptureOps &ops);

struct LoadedControl {
    std::string role;
    std::string processStart;
    std::string sha256;
    int fd = -1;
};
std::string receiptJson(const LoadedControl &receipt);

class ReceiptSink {
public:
    virtual ~ReceiptSink() = default;
    // Commits bytes to directory/control-loaded-<role>.json atomically at mode 0600.
    virtual void commit(const std::filesystem::path &directory, const std::string &role, const std::string &bytes) = 0;
};

struct FdAttestation {
    bool regular = false;
    std::uint64_t size = 0;
    std::uint32_t seals = 0;
    std::string sha256;
};
class AttestOps {
public:
    virtual ~AttestOps() = default;
    virtual std::string processStart() = 0; // /proc/1/stat field 22 (kernel starttime)
    virtual FdAttestation attest(int fd) = 0;
};

// Throws std::runtime_error on any mismatch, including the legacy receipt variant,
// which is explicitly unsupported for a native PID1.
void verifyLoadedControl(const std::string &receipt, const std::string &expectedRole,
                         const std::string &expectedSha256, AttestOps &ops);
constexpr std::uint32_t requiredSeals = 0x1u | 0x2u | 0x4u | 0x8u; // SEAL|SHRINK|GROW|WRITE
} // namespace amnezia::awgMigration::controlPid1
