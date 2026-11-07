#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace headless_anchor {
struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
// Library-only fixture seam. Production dispatch always uses these defaults;
// neither paths nor expected UID can be changed through argv or environment.
struct Policy {
    std::string root = "/var/lib/amnezia-headless-provisioning/native-anchor";
    std::string transactionRoot = "/var/lib/amnezia";
    uid_t expectedUid = 0;
    std::string lockPath = "/var/lib/amnezia/updates/update.lock";
    int lockFd = 9;
};
using Fault = std::function<void(const char*)>;
// The caller supplies an independently authenticated SHA256SUMS digest. This
// operation stores bytes and pins only: it never executes the source/worker.
// Production requires inherited fd9 matching the fixed provisioning lock inode.
// Its existing open-file-description is locked but never unlocked/closed here.
// An anchor-local lock also serializes writers; journal/marker absence is rechecked.
void install(const Policy&, const std::string& source,
             const std::string& expectedSha256, Fault = {});
}
