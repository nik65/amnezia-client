#pragma once
#include "transaction_journal.h"
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace amnezia::awgMigration::maintenance {
// Explicit maintenance surface selected by the reviewed native argv dispatcher.
// Existing feed argv and legacy generation semantics retain their meaning.
enum class Mode { Status, Cleanup, Recover, RestartControls, Maintain };

struct Request {
    Mode mode = Mode::Maintain;
    std::string source;
    std::int64_t generation = 0;
    std::string expectedJournalSha256;
    // Trusted image/meta authority for the native control executable. Required
    // iff the journal is a native generation. Never read from a receipt/self.
    // This is ALWAYS the authenticated CURRENT payload; its meaning is unchanged
    // by the control-only replacement transaction below.
    std::string nativeControlSha256;
    // Explicitly authenticated REPLACEMENT control payload. A distinct operator
    // assertion: it must equal the digest of the private candidate bytes and must
    // differ from nativeControlSha256. Required only for a changed payload.
    std::string nativeControlReplacementSha256;
    std::filesystem::path root = "/opt/amnezia/awg-migration";
    std::filesystem::path recipeDirectory;
    // Operator-owned private staging root for the bounded executable copy and the
    // owned local control-image build context. Required for a changed payload.
    std::filesystem::path controlStagingDirectory;
};

// The only OS/Docker/process/control boundary in this module. Production uses
// the existing bounded Docker adapter (maintenance_posix.cpp); inert tests use
// private fakes and never execute a process, Docker, socket or control call.
class Ops {
public:
    virtual ~Ops() = default;
    virtual std::string run(const std::vector<std::string>& argv) = 0; // stdout, throws on non-zero
    virtual std::uint32_t euid() = 0;
    virtual void sleepSeconds(unsigned seconds) = 0;
};

struct Result {
    bool ok = false;
    std::string mode;
    std::string source;
    std::int64_t generation = 0;
    std::string journalSha256;
    bool native = false;
    bool pendingRecovery = false;
    std::string phase;
    std::map<std::string, std::string> controlHashes;
};

Request parseRequest(const std::vector<std::string>& argv);
Result runMaintenance(const Request& request, Ops& ops);
std::string resultJson(const Result& result);

// Faithful journal.py maintain_controls transaction, including backup, persisted
// intent, per-mutation ownership revalidation, rollback and primary-error
// preservation. `validate` is the same injected boundary Python exposes; the
// production Maintain path always supplies the real target validator.
void runControlMaintenance(TransactionJournal& journal, const std::filesystem::path& directory,
    const std::filesystem::path& recipeDirectory, bool native, const std::string& nativeSha,
    Ops& ops, const std::function<void()>& validate);

// Explicit native-control replacement transaction. Independently authenticated
// new bytes, private bounded static-executable staging, an owned local control
// image build, persisted intent before any mutation, exact-owned helper
// recreation with live PID1/fd listener proof of the new immutable image, and a
// final journal commit. Any failure/uncertain reply restores the captured old
// image/digest without destroying a foreign replacement.
void runNativeControlMaintenance(TransactionJournal& journal, const std::filesystem::path& directory,
    const std::filesystem::path& recipeDirectory, const std::string& operatorSha,
    const std::string& replacementSha, const std::filesystem::path& stagingRoot, Ops& ops,
    const std::function<void()>& validate);

// Recovery of a persisted native control transaction (Mode::Recover and the
// admission gate for Maintain). Idempotent; never touches a foreign container.
void recoverNativeControlMaintenance(TransactionJournal& journal, const std::filesystem::path& directory,
    const std::string& operatorSha, Ops& ops, const std::function<void()>& validate);

// Defined in maintenance_posix.cpp (production only, never linked into tests).
int maintenanceMain(int argc, char** argv);
} // namespace amnezia::awgMigration::maintenance
