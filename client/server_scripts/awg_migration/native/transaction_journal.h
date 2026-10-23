#pragma once
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <json-c/json.h>

namespace amnezia::awgMigration {
struct CommandResult { int status = 0; std::string output, error; };
using JournalRunner = std::function<CommandResult(const std::vector<std::string>&)>;
using JournalFault = std::function<void(const std::string&)>;
class JournalError : public std::runtime_error { public: using std::runtime_error::runtime_error; };
// A single migration-root lock protects all sources and generations. No process runner
// is provided: integrating callers must explicitly inject their reviewed runner.
class TransactionJournal final {
public:
    TransactionJournal(const std::filesystem::path& directory, JournalRunner runner,
                       const std::string& initial = {}, JournalFault fault = {});
    ~TransactionJournal();
    TransactionJournal(const TransactionJournal&) = delete;
    TransactionJournal& operator=(const TransactionJournal&) = delete;
    void save(const std::string& phase = {});
    void plan(const std::string& name, const std::string& image);
    void record(const std::string& name);
    void cleanup();
    // The caller must supply a read-only PID1/socket attestor when a source
    // control exists. Missing attestation fails before any runner mutation.
    void recoverReady(const std::function<void(const std::string&)>& attestListener = {});
    void verifyRequest(const std::string& requestJson, const std::string& sourceBytes) const;
    std::string snapshot() const;
    static std::string sha256(const std::string& bytes);
private:
    using Json = std::shared_ptr<json_object>;
    std::filesystem::path directory_;
    int directoryFd_ = -1, lockFd_ = -1;
    Json value_;
    JournalRunner runner_;
    JournalFault fault_;
    Json inspect(const std::string& id) const;
    Json owned(const std::string& name) const;
    void sourceRules(bool remove);
    CommandResult command(std::vector<std::string> args) const;
    void checkpoint(const std::string& point) const;
    void validate() const;
};
}
