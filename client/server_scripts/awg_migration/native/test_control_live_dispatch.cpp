// Inert argv contract for the proposed --verify-control-live dispatcher input.
// Parses only; never invokes the actual entry, so no OS boundary is touched.
#include "control_live.h"

#include <iostream>
#include <string>
#include <vector>

using namespace amnezia::awgMigration::controlPid1;
namespace {
int failures = 0;
std::vector<std::string> storage;
std::vector<char *> pointers;
LiveArgv parse(std::initializer_list<const char *> args, std::string &role,
               std::string &sha, std::string &receipt) {
    storage.clear();
    pointers.clear();
    for (const char *arg : args) storage.emplace_back(arg);
    for (auto &arg : storage) pointers.push_back(&arg[0]);
    return parseVerifyControlLiveArgv(static_cast<int>(pointers.size()), pointers.data(), role, sha, receipt);
}
void check(const char *name, LiveArgv actual, LiveArgv expected) {
    std::cout << name << " actual=" << static_cast<int>(actual)
              << " expected=" << static_cast<int>(expected) << "\n";
    if (actual != expected) ++failures;
}
} // namespace

int main() {
    const std::string sha(64, 'a'), upper(64, 'A'), shortSha(63, 'a');
    std::string role, parsedSha, receipt;
    check("no-arguments", parse({}, role, parsedSha, receipt), LiveArgv::NotLive);
    check("existing-serve", parse({"prog", "--serve"}, role, parsedSha, receipt), LiveArgv::NotLive);
    check("missing-operands", parse({"prog", "--verify-control-live"}, role, parsedSha, receipt), LiveArgv::Invalid);
    check("bad-role", parse({"prog", "--verify-control-live", "helper", sha.c_str(), "r"}, role, parsedSha, receipt), LiveArgv::Invalid);
    check("uppercase-digest", parse({"prog", "--verify-control-live", "target", upper.c_str(), "r"}, role, parsedSha, receipt), LiveArgv::Invalid);
    check("short-digest", parse({"prog", "--verify-control-live", "target", shortSha.c_str(), "r"}, role, parsedSha, receipt), LiveArgv::Invalid);
    check("empty-receipt", parse({"prog", "--verify-control-live", "target", sha.c_str(), ""}, role, parsedSha, receipt), LiveArgv::Invalid);
    check("valid-live", parse({"prog", "--verify-control-live", "source", sha.c_str(), "/migration/x"}, role, parsedSha, receipt), LiveArgv::VerifyLive);
    if (role != "source" || parsedSha != sha || receipt != "/migration/x") {
        std::cerr << "valid operands not preserved\n";
        ++failures;
    }

    int status = 99;
    auto argv = [](std::initializer_list<const char *> args, std::vector<std::string> &own, std::vector<char *> &pointers) {
        own.clear();
        pointers.clear();
        for (const char *arg : args) own.emplace_back(arg);
        for (auto &arg : own) pointers.push_back(&arg[0]);
    };
    std::vector<std::string> own;
    std::vector<char *> ptrs;
    argv({"prog", "--serve"}, own, ptrs);
    if (runVerifyControlLiveArgv(static_cast<int>(ptrs.size()), ptrs.data(), status) || status != 99) {
        std::cerr << "not-live argv was consumed\n";
        ++failures;
    }
    argv({"prog", "--verify-control-live"}, own, ptrs);
    if (!runVerifyControlLiveArgv(static_cast<int>(ptrs.size()), ptrs.data(), status) || status != 2) {
        std::cerr << "invalid live argv not rejected with 2\n";
        ++failures;
    }
    return failures ? 1 : 0;
}
