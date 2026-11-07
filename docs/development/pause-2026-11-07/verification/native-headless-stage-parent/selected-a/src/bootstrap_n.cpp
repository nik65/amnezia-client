
// Proposal K: native headless bootstrap/recovery trust boundary.
//
// Built on the byte-identical canonical provisioning verifier and the prior
// --stage-inputs / --validate-package modes (kept unchanged).  Adds:
//
//   --stage-helper
//       Root entry.  Authenticates the packaged native helper with OS-equivalent
//       byte checks (caller-pinned SHA256SUMS digest, exact one-row lookup,
//       helper SHA-256, ELF64/x86-64 header), then copies it into the caller's
//       root-owned 0700 private tree with O_EXCL and rehashes the staged inode.
//       The helper NEVER authenticates itself: the authority is the caller pin
//       produced by the Ed25519-verified signed manifest (lab.py
//       headless_runner_inputs -> linux-release-lab --checksums-sha256 ->
//       installer argument 5) or the in-product pinned-envelope path.  This
//       executable does not verify that pin's signature and does not claim to.
//   --check-helper
//       Same read-only authentication, no root gate and no copy (test/preflight).
//   --recovery-anchor
//       Root entry.  Validates a preexisting journal backup of amnezia-cli as a
//       recovery anchor: root-owned 0600 journal, exact backupDir schema,
//       record kind/hash, root-owned non-writable backup inode, hash equality.
//       Producer: backup_file + write_transaction_journal.  Consumer: recovery.
//       This mode only decides; it never execs the anchor.
//   --probe-host
//       Real host-probe executor (no longer executed=false): resolves required
//       commands, executes dpkg-query / dpkg --compare-versions /
//       dpkg --print-architecture through absolute argv (no shell), and emits
//       the per-probe result.  Tests exercise the same executor only on an
//       owned compiled fixture; no real dpkg probe is run in this attempt.
//
// Dangerous boundaries: no installer run, no packaged ELF exec, no root FS
// acceptance, no namespace/root wrapper, no service/network/socket/proc use.
// Root-ownership acceptance is modeled in the unit driver; the product modes
// enforce it on real stat metadata and are expected to refuse in this non-root
// attempt (recorded RED).

#include "preauth_modes.cpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <map>
#include <poll.h>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr uint64_t kMaxChecksumsBytes = 1024ull * 1024ull;
constexpr uint64_t kMaxHelperBytes = 64ull * 1024ull * 1024ull;
constexpr uint64_t kMaxJournalBytes = 1024ull * 1024ull;
constexpr uint64_t kMaxProbeOutputBytes = 64ull * 1024ull;
constexpr const char *kGateTool = "amnezia-headless-bootstrap-gate-v1";
constexpr const char *kAnchorTool = "amnezia-headless-recovery-anchor-v1";

struct Refusal : public std::runtime_error {
  Refusal(int exit_code, const std::string &message)
      : std::runtime_error(message), code(exit_code) {}
  int code;
};

[[noreturn]] void refuse(int exit_code, const std::string &message) {
  throw Refusal(exit_code, message);
}

std::string canonical_sha256(const std::string &value, const char *label) {
  if (!is_lower_hex_64(value)) {
    refuse(20, std::string(label) + " must be 64 lowercase hexadecimal characters");
  }
  return value;
}

struct FileBytes {
  std::string bytes;
  struct stat metadata {};
  std::string sha256;
};

FileBytes read_regular_bytes(const std::string &path, uint64_t maximum,
                             const char *label) {
  struct stat before {};
  if (::lstat(path.c_str(), &before) != 0) {
    refuse(21, std::string(label) + " is missing");
  }
  if (!S_ISREG(before.st_mode)) {
    refuse(21, std::string(label) + " must be a regular file");
  }
  int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) {
    refuse(21, std::string(label) + " cannot be opened without following links");
  }
  struct stat opened {};
  if (::fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
      opened.st_dev != before.st_dev || opened.st_ino != before.st_ino ||
      opened.st_size != before.st_size) {
    ::close(fd);
    refuse(21, std::string(label) + " changed before it could be read");
  }
  if (opened.st_size < 0 || static_cast<uint64_t>(opened.st_size) > maximum) {
    ::close(fd);
    refuse(21, std::string(label) + " exceeds its size bound");
  }
  FileBytes result;
  result.metadata = opened;
  result.bytes.reserve(static_cast<size_t>(opened.st_size));
  char buffer[65536];
  while (true) {
    const ssize_t count = ::read(fd, buffer, sizeof(buffer));
    if (count < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      refuse(21, std::string(label) + " read failed");
    }
    if (count == 0) break;
    result.bytes.append(buffer, static_cast<size_t>(count));
    if (result.bytes.size() > maximum) {
      ::close(fd);
      refuse(21, std::string(label) + " exceeds its size bound");
    }
  }
  struct stat after {};
  if (::fstat(fd, &after) != 0 || after.st_dev != opened.st_dev ||
      after.st_ino != opened.st_ino || after.st_size != opened.st_size) {
    ::close(fd);
    refuse(21, std::string(label) + " changed while it was read");
  }
  ::close(fd);
  result.sha256 = sha256_bytes(result.bytes);
  return result;
}

std::string lower_ascii(std::string value) {
  for (char &c : value) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return value;
}

bool safe_package_name(const std::string &name) {
  if (name.empty() || name.size() > 64) return false;
  for (char c : name) {
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
      return false;
    }
  }
  return name != "." && name != "..";
}

// Strict parse of the production SHA256SUMS format: "<64 lowercase hex>  <name>".
// Exactly one row per known package member; any duplicate, unknown name, CR,
// leading/trailing space or malformed digest is refused.
std::map<std::string, std::string> parse_sha256sums(const std::string &text) {
  const std::set<std::string> known = {
      "install_headless.sh", "amneziad", "amnezia-cli", "amneziad.service",
      "package-manifest.json", "runtime-dependencies.json",
      "runtime-dependencies.txt", "SHA256SUMS", "amnezia-headless-fs"};
  std::map<std::string, std::string> rows;
  std::istringstream stream(text);
  std::string line;
  size_t lines = 0;
  while (std::getline(stream, line)) {
    ++lines;
    if (line.size() < 67 || line.find('\r') != std::string::npos) {
      refuse(22, "SHA256SUMS has a malformed line");
    }
    const std::string digest = line.substr(0, 64);
    if (!is_lower_hex_64(digest) || line[64] != ' ' || line[65] != ' ') {
      refuse(22, "SHA256SUMS has a malformed digest field");
    }
    const std::string name = line.substr(66);
    if (!safe_package_name(name) || known.count(name) == 0) {
      refuse(22, "SHA256SUMS names an unknown package member");
    }
    if (rows.count(name) != 0) {
      refuse(22, "SHA256SUMS has a duplicate member");
    }
    rows.emplace(name, digest);
  }
  if (lines == 0) refuse(22, "SHA256SUMS is empty");
  return rows;
}

bool elf64_x86_64(const std::string &bytes) {
  if (bytes.size() < 64) return false;
  const unsigned char *b = reinterpret_cast<const unsigned char *>(bytes.data());
  if (b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F') return false;
  if (b[4] != 2 || b[5] != 1 || b[6] != 1) return false;  // ELF64, LE, EV_CURRENT
  const uint16_t type = static_cast<uint16_t>(b[16] | (b[17] << 8));
  const uint16_t machine = static_cast<uint16_t>(b[18] | (b[19] << 8));
  return (type == 2 || type == 3) && machine == 62;  // ET_EXEC/ET_DYN, x86-64
}

struct HelperAuth {
  std::string name;
  std::string expected_pin;
  std::string checksums_sha256;
  std::string helper_sha256;
  FileBytes helper;
};

HelperAuth authenticate_helper(const std::string &source_root,
                               const std::string &requested_name,
                               const std::string &expected_pin_text) {
  const std::string name = requested_name;
  if (name != "amnezia-headless-fs" && name != "amnezia-cli") {
    refuse(20, "helper name is not an authenticated package variant");
  }
  const std::string pin = canonical_sha256(expected_pin_text, "expected checksums digest");
  const std::string sums_path = source_root + "/SHA256SUMS";
  const FileBytes sums = read_regular_bytes(sums_path, kMaxChecksumsBytes, "SHA256SUMS");
  if (sums.sha256 != pin) {
    refuse(22, "SHA256SUMS does not match the caller-pinned signed-manifest digest");
  }
  const auto rows = parse_sha256sums(sums.bytes);
  const auto row = rows.find(name);
  if (row == rows.end()) {
    refuse(22, "the requested helper has no authenticated checksum row");
  }
  FileBytes helper = read_regular_bytes(source_root + "/" + name, kMaxHelperBytes,
                                        "native helper");
  if (helper.sha256 != row->second) {
    refuse(22, "native helper bytes do not match the authenticated checksum row");
  }
  if (!elf64_x86_64(helper.bytes)) {
    refuse(23, "native helper is not an ELF64 little-endian x86-64 executable");
  }
  HelperAuth auth;
  auth.name = name;
  auth.expected_pin = pin;
  auth.checksums_sha256 = sums.sha256;
  auth.helper_sha256 = helper.sha256;
  auth.helper = std::move(helper);
  return auth;
}

void write_all(int fd, const std::string &data) {
  size_t offset = 0;
  while (offset < data.size()) {
    const ssize_t count = ::write(fd, data.data() + offset, data.size() - offset);
    if (count < 0) {
      if (errno == EINTR) continue;
      refuse(21, "write failed");
    }
    offset += static_cast<size_t>(count);
  }
}

void fsync_fd(int fd, const char *label) {
  if (::fsync(fd) != 0) refuse(21, std::string(label) + " fsync failed");
}

void fsync_dir(const std::string &path) {
  int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) refuse(21, "directory cannot be opened for fsync: " + path);
  fsync_fd(fd, "directory");
  ::close(fd);
}

bool root_private_dir_ok(bool is_directory, bool is_symlink, uid_t owner,
                         mode_t mode) {
  return is_directory && !is_symlink && owner == 0 &&
         (mode & 07777u) == 0700u;
}

bool root_private_file_ok(bool is_regular, bool is_symlink, uid_t owner,
                          mode_t mode) {
  return is_regular && !is_symlink && owner == 0 && (mode & 022u) == 0;
}

void require_root_private_dir(const std::string &path) {
  struct stat metadata {};
  if (::lstat(path.c_str(), &metadata) != 0) {
    refuse(24, "private input root is missing: " + path);
  }
  if (!root_private_dir_ok(S_ISDIR(metadata.st_mode), S_ISLNK(metadata.st_mode),
                           metadata.st_uid, metadata.st_mode)) {
    refuse(24, "private input root must be a root-owned non-symlink 0700 directory");
  }
}

struct StageRecord {
  std::string target;
  std::string sha256;
  uint64_t device = 0;
  uint64_t inode = 0;
  uint64_t size = 0;
  uint32_t mode = 0;
  uid_t owner = 0;
};

// Copy primitive.  It performs no root-ownership acceptance: the product
// wrapper below does that before and after this function, and the inert unit
// driver calls this primitive directly on an owned directory so the dangerous
// root boundary is fenced before test entry.
StageRecord copy_helper_bytes(const HelperAuth &auth, const std::string &private_root) {
  const std::string package_dir = private_root + "/bootstrap-helper";
  struct stat directory_metadata {};
  if (::lstat(package_dir.c_str(), &directory_metadata) == 0) {
    if (!S_ISDIR(directory_metadata.st_mode) ||
        S_ISLNK(directory_metadata.st_mode)) {
      refuse(24, "bootstrap helper directory has unsafe metadata");
    }
  } else if (errno == ENOENT) {
    if (::mkdir(package_dir.c_str(), 0700) != 0) {
      refuse(21, "cannot create the bootstrap helper directory");
    }
    if (::chmod(package_dir.c_str(), 0700) != 0) {
      refuse(21, "cannot protect the bootstrap helper directory");
    }
    fsync_dir(private_root);
  } else {
    refuse(21, "bootstrap helper directory cannot be inspected");
  }
  const std::string target = package_dir + "/" + auth.name;
  const int fd = ::open(target.c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0755);
  if (fd < 0) {
    refuse(21, "bootstrap helper target already exists or cannot be created");
  }
  try {
    write_all(fd, auth.helper.bytes);
    fsync_fd(fd, "bootstrap helper");
    if (::fchmod(fd, 0755) != 0) refuse(21, "cannot set the staged helper mode");
  } catch (...) {
    ::close(fd);
    ::unlink(target.c_str());
    throw;
  }
  struct stat staged {};
  if (::fstat(fd, &staged) != 0) {
    ::close(fd);
    ::unlink(target.c_str());
    refuse(21, "cannot stat the staged helper inode");
  }
  ::close(fd);
  const FileBytes reread = read_regular_bytes(target, kMaxHelperBytes, "staged native helper");
  if (reread.sha256 != auth.helper_sha256 ||
      reread.metadata.st_size != auth.helper.metadata.st_size) {
    ::unlink(target.c_str());
    refuse(22, "staged helper bytes changed after the authenticated copy");
  }
  fsync_dir(package_dir);
  StageRecord record;
  record.target = target;
  record.sha256 = reread.sha256;
  record.device = static_cast<uint64_t>(staged.st_dev);
  record.inode = static_cast<uint64_t>(staged.st_ino);
  record.size = static_cast<uint64_t>(staged.st_size);
  record.mode = 0755;
  record.owner = staged.st_uid;
  return record;
}

StageRecord stage_helper_copy(const HelperAuth &auth, const std::string &source_path,
                              const std::string &private_root) {
  require_root_private_dir(private_root);
  const StageRecord record = copy_helper_bytes(auth, private_root);
  struct stat staged {};
  if (::lstat(record.target.c_str(), &staged) != 0) {
    refuse(24, "staged helper disappeared before ownership acceptance");
  }
  if (!root_private_file_ok(S_ISREG(staged.st_mode), S_ISLNK(staged.st_mode),
                            staged.st_uid, staged.st_mode) ||
      (staged.st_mode & 07777u) != 0755u) {
    ::unlink(record.target.c_str());
    refuse(24, "staged helper is not exactly root-owned non-writable mode 0755");
  }
  (void)source_path;
  return record;
}

std::string helper_json(const HelperAuth &auth, const StageRecord *stage) {
  std::string out = "{";
  out += "\"schema\":1,";
  out += "\"tool\":" + quote_json(kGateTool) + ",";
  out += "\"selfAuthenticated\":false,";
  out += "\"authority\":\"caller-pinned-signed-manifest-checksums-sha256\",";
  out += "\"helperName\":" + quote_json(auth.name) + ",";
  out += "\"expectedChecksumsSha256\":" + quote_json(auth.expected_pin) + ",";
  out += "\"checksumsSha256\":" + quote_json(auth.checksums_sha256) + ",";
  out += "\"helperSha256\":" + quote_json(auth.helper_sha256) + ",";
  out += "\"helperSize\":" + std::to_string(auth.helper.metadata.st_size) + ",";
  out += "\"elf64X86_64\":true";
  if (stage != nullptr) {
    out += ",\"staged\":true,";
    out += "\"stagedPath\":" + quote_json(stage->target) + ",";
    out += "\"stagedSha256\":" + quote_json(stage->sha256) + ",";
    out += "\"stagedDevice\":" + std::to_string(stage->device) + ",";
    out += "\"stagedInode\":" + std::to_string(stage->inode) + ",";
    out += "\"stagedSize\":" + std::to_string(stage->size) + ",";
    out += "\"stagedMode\":" + std::to_string(stage->mode) + ",";
    out += "\"stagedOwner\":" + std::to_string(static_cast<unsigned>(stage->owner));
  } else {
    out += ",\"staged\":false";
  }
  out += "}\n";
  return out;
}

void write_bootstrap_receipt(const std::string &private_root, const std::string &payload) {
  const std::string target = private_root + "/bootstrap-gate-receipt.json";
  const std::string temporary =
      private_root + "/.bootstrap-gate-receipt." + std::to_string(::getpid()) + ".tmp";
  const int fd = ::open(temporary.c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) refuse(21, "cannot create the bootstrap gate receipt");
  try {
    write_all(fd, payload);
    fsync_fd(fd, "bootstrap gate receipt");
  } catch (...) {
    ::close(fd);
    ::unlink(temporary.c_str());
    throw;
  }
  ::close(fd);
  if (::rename(temporary.c_str(), target.c_str()) != 0) {
    ::unlink(temporary.c_str());
    refuse(21, "cannot publish the bootstrap gate receipt");
  }
  fsync_dir(private_root);
}

int run_stage_helper(int argc, char **argv) {
  static const std::vector<std::string> allowed = {
      "--source-root", "--private-root", "--helper-name",
      "--expected-checksums-sha256"};
  const auto args = parse_mode_arguments(argc, argv, allowed, "");
  const std::string source_root = required_argument(args, "--source-root", "");
  const std::string private_root = required_argument(args, "--private-root", "");
  const std::string helper_name = required_argument(args, "--helper-name", "");
  const std::string pin = required_argument(args, "--expected-checksums-sha256", "");
  require_root_private_dir(private_root);
  const HelperAuth auth = authenticate_helper(source_root, helper_name, pin);
  const StageRecord stage = stage_helper_copy(auth, source_root + "/" + helper_name, private_root);
  const std::string payload = helper_json(auth, &stage);
  write_bootstrap_receipt(private_root, payload);
  std::fputs(payload.c_str(), stdout);
  return 0;
}

int run_check_helper(int argc, char **argv) {
  static const std::vector<std::string> allowed = {
      "--source-root", "--helper-name", "--expected-checksums-sha256"};
  const auto args = parse_mode_arguments(argc, argv, allowed, "");
  const HelperAuth auth = authenticate_helper(
      required_argument(args, "--source-root", ""),
      required_argument(args, "--helper-name", ""),
      required_argument(args, "--expected-checksums-sha256", ""));
  std::fputs(helper_json(auth, nullptr).c_str(), stdout);
  return 0;
}

struct AnchorFacts {
  bool journal_regular = false;
  bool journal_symlink = false;
  uid_t journal_owner = 1;
  mode_t journal_mode = 0644;
  bool journal_schema_ok = false;
  bool record_present = false;
  bool record_regular = false;
  bool record_hash_canonical = false;
  bool backup_path_ok = false;
  bool anchor_regular = false;
  bool anchor_symlink = false;
  uid_t anchor_owner = 1;
  mode_t anchor_mode = 0644;
  bool anchor_hash_matches_record = false;
  bool anchor_hash_matches_expected = true;
};

bool recovery_anchor_accept(const AnchorFacts &facts, std::string *reason) {
  if (!facts.journal_regular || facts.journal_symlink ||
      facts.journal_owner != 0 || (facts.journal_mode & 07777u) != 0600u) {
    if (reason) *reason = "journal is not a root-owned non-symlink 0600 regular file";
    return false;
  }
  if (!facts.journal_schema_ok || !facts.record_present ||
      !facts.record_regular || !facts.record_hash_canonical) {
    if (reason) *reason = "journal does not carry an exact regular amnezia-cli backup record";
    return false;
  }
  if (!facts.backup_path_ok) {
    if (reason) *reason = "journal backupDir is outside the fixed transaction root";
    return false;
  }
  if (!facts.anchor_regular || facts.anchor_symlink ||
      !root_private_file_ok(facts.anchor_regular, facts.anchor_symlink,
                            facts.anchor_owner, facts.anchor_mode)) {
    if (reason) *reason = "recovery anchor is not a root-owned non-writable regular file";
    return false;
  }
  if (!facts.anchor_hash_matches_record) {
    if (reason) *reason = "recovery anchor hash does not match the journal producer record";
    return false;
  }
  if (!facts.anchor_hash_matches_expected) {
    if (reason) *reason = "recovery anchor hash does not match the caller-pinned hash";
    return false;
  }
  return true;
}

bool fixed_backup_dir(const std::string &value) {
  static const std::string prefix =
      "/var/lib/amnezia/.headless-provisioning-transactions/transaction.";
  if (value.compare(0, prefix.size(), prefix) != 0 || value.size() <= prefix.size()) {
    return false;
  }
  for (size_t i = prefix.size(); i < value.size(); ++i) {
    const char c = value[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9'))) {
      return false;
    }
  }
  return true;
}

int run_recovery_anchor(int argc, char **argv) {
  static const std::vector<std::string> allowed = {
      "--journal", "--anchor", "--expected-anchor-sha256"};
  const auto args = parse_mode_arguments(argc, argv, allowed, "");
  const std::string journal_path = required_argument(args, "--journal", "");
  const FileBytes journal = read_regular_bytes(journal_path, kMaxJournalBytes,
                                               "recovery journal");
  AnchorFacts facts;
  facts.journal_regular = true;
  facts.journal_owner = journal.metadata.st_uid;
  facts.journal_mode = journal.metadata.st_mode;
  std::string backup_dir;
  try {
    const Json root = parse_json(journal.bytes);
    require_object(root, "recovery journal");
    facts.journal_schema_ok =
        require_integer(root, "schema", "recovery journal") == 1;
    const Json &files = require_field(root, "backupFiles", "recovery journal");
    require_object(files, "recovery journal backupFiles");
    const Json *record = files.get("amnezia-cli");
    if (record != nullptr) {
      require_object(*record, "recovery journal amnezia-cli record");
      const Json &present = require_field(*record, "present", "amnezia-cli record");
      const std::string kind = require_string(*record, "kind", "amnezia-cli record");
      facts.record_present = present.kind == Json::Kind::Bool && present.boolean;
      facts.record_regular = kind == "regular";
      facts.record_hash_canonical =
          is_lower_hex_64(require_string(*record, "sha256", "amnezia-cli record"));
    }
    backup_dir = require_string(root, "backupDir", "recovery journal");
    facts.backup_path_ok = fixed_backup_dir(backup_dir);
  } catch (const std::exception &) {
    facts.journal_schema_ok = false;
  }
  const std::string derived_anchor = backup_dir + "/amnezia-cli";
  const std::string anchor_path =
      optional_argument(args, "--anchor").empty() ? derived_anchor
                                                   : optional_argument(args, "--anchor");
  const std::string expected =
      optional_argument(args, "--expected-anchor-sha256");
  if (!expected.empty()) canonical_sha256(expected, "expected anchor digest");
  struct stat anchor_metadata {};
  if (::lstat(anchor_path.c_str(), &anchor_metadata) == 0) {
    facts.anchor_regular = S_ISREG(anchor_metadata.st_mode);
    facts.anchor_symlink = S_ISLNK(anchor_metadata.st_mode);
    facts.anchor_owner = anchor_metadata.st_uid;
    facts.anchor_mode = anchor_metadata.st_mode;
    try {
      const FileBytes anchor = read_regular_bytes(anchor_path, kMaxHelperBytes,
                                                  "recovery anchor");
      const auto &record = std::string();
      (void)record;
      const Json root = parse_json(journal.bytes);
      const Json *record_value =
          require_field(root, "backupFiles", "recovery journal").get("amnezia-cli");
      if (record_value != nullptr) {
        facts.anchor_hash_matches_record =
            anchor.sha256 == require_string(*record_value, "sha256", "amnezia-cli record");
      }
      facts.anchor_hash_matches_expected =
          expected.empty() || anchor.sha256 == expected;
    } catch (const std::exception &) {
      facts.anchor_hash_matches_record = false;
      facts.anchor_hash_matches_expected = false;
    }
  }
  std::string reason;
  const bool accepted = recovery_anchor_accept(facts, &reason);
  std::string out = "{";
  out += "\"schema\":1,\"tool\":" + quote_json(kAnchorTool) + ",";
  out += "\"accepted\":" + std::string(accepted ? "true" : "false") + ",";
  out += "\"selfAuthenticated\":false,";
  out += "\"producer\":\"backup_file+write_transaction_journal\",";
  out += "\"consumer\":\"recovery\",";
  out += "\"journal\":" + quote_json(journal_path) + ",";
  out += "\"anchor\":" + quote_json(anchor_path) + ",";
  out += "\"reason\":" + quote_json(accepted ? std::string("ok") : reason) + "}\n";
  std::fputs(out.c_str(), stdout);
  return accepted ? 0 : 25;
}

#include "host_runtime.inc"

}  // namespace

#ifdef AMNEZIA_BOOTSTRAP_UNIT_DRIVER

// Inert compiled test driver.  Dangerous boundaries are fenced BEFORE entry:
// it never calls run_stage_helper (root gate), run_recovery_anchor (root
// journal/anchor), or run_probe_host (real dpkg).  It calls the actual
// authentication/copy primitives on owned files and run_probe only on an owned
// compiled fixture.  Root ownership is tested as an explicit metadata model.
int main(int argc, char **argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s PROBE_FIXTURE WORKDIR\n", argv[0]);
    return 2;
  }
  const std::string fixture = argv[1];
  const std::string workdir = argv[2];
  int failures = 0;
  auto check = [&](bool value, const char *label) {
    std::printf("%s %s\n", value ? "PASS" : "FAIL", label);
    if (!value) ++failures;
  };

  check(root_private_dir_ok(true, false, 0, 0700), "model_root_dir_accepts_0_0700");
  check(!root_private_dir_ok(true, false, 1000, 0700), "model_root_dir_rejects_nonroot");
  check(!root_private_dir_ok(true, false, 0, 0755), "model_root_dir_rejects_world_exec");
  check(!root_private_dir_ok(true, true, 0, 0700), "model_root_dir_rejects_symlink");
  check(root_private_file_ok(true, false, 0, 0755), "model_root_file_accepts_0755");
  check(!root_private_file_ok(true, false, 0, 0775), "model_root_file_rejects_group_write");

  AnchorFacts good;
  good.journal_regular = true;
  good.journal_owner = 0;
  good.journal_mode = 0100600;
  good.journal_schema_ok = true;
  good.record_present = true;
  good.record_regular = true;
  good.record_hash_canonical = true;
  good.backup_path_ok = true;
  good.anchor_regular = true;
  good.anchor_owner = 0;
  good.anchor_mode = 0100755;
  good.anchor_hash_matches_record = true;
  std::string reason;
  check(recovery_anchor_accept(good, &reason), "model_anchor_accepts_exact_record");
  AnchorFacts bad_owner = good;
  bad_owner.anchor_owner = 1000;
  check(!recovery_anchor_accept(bad_owner, &reason), "model_anchor_rejects_nonroot");
  AnchorFacts bad_hash = good;
  bad_hash.anchor_hash_matches_record = false;
  check(!recovery_anchor_accept(bad_hash, &reason), "model_anchor_rejects_hash_mismatch");
  AnchorFacts bad_journal = good;
  bad_journal.journal_mode = 0100644;
  check(!recovery_anchor_accept(bad_journal, &reason), "model_anchor_rejects_journal_mode");

  const ProbeResult ok = run_probe({fixture, "ok"});
  check(ok.exit_code == 0 && ok.output == "install ok installed\t1.2.3\n",
        "probe_executor_captures_owned_fixture");
  const ProbeResult fail = run_probe({fixture, "fail"});
  check(fail.exit_code == 7 && fail.output == "fixture failure\n",
        "probe_executor_propagates_failed_work_exit");
  const ProbeResult missing = run_probe({workdir + "/absent-probe"});
  check(missing.exit_code == 127, "probe_executor_refuses_missing_absolute_binary");
  bool rejected_relative = false;
  try {
    run_probe({"true"});
  } catch (const std::exception &) {
    rejected_relative = true;
  } catch (...) {
    rejected_relative = true;
  }
  check(rejected_relative, "probe_executor_rejects_relative_argv");

  const std::string source_root = workdir + "/source";
  const std::string private_root = workdir + "/private";
  for (const std::string &directory : {source_root, private_root}) {
    if (::mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) {
      std::fprintf(stderr, "cannot create owned test directories\n");
      return 2;
    }
  }
  std::string fixture_bytes;
  {
    FileBytes bytes = read_regular_bytes(fixture, kMaxHelperBytes, "fixture source");
    fixture_bytes = bytes.bytes;
  }
  const std::string helper_path = source_root + "/amnezia-headless-fs";
  {
    const int fd = ::open(helper_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0755);
    if (fd < 0) { std::fprintf(stderr, "cannot write helper fixture\n"); return 2; }
    write_all(fd, fixture_bytes);
    ::close(fd);
  }
  const std::string helper_sha = sha256_bytes(fixture_bytes);
  const std::string sums = helper_sha + "  amnezia-headless-fs\n";
  {
    const int fd = ::open((source_root + "/SHA256SUMS").c_str(),
                          O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { std::fprintf(stderr, "cannot write sums fixture\n"); return 2; }
    write_all(fd, sums);
    ::close(fd);
  }
  const std::string pin = sha256_bytes(sums);
  HelperAuth auth = authenticate_helper(source_root, "amnezia-headless-fs", pin);
  check(auth.helper_sha256 == helper_sha, "authenticate_helper_accepts_pinned_bytes");
  bool wrong_pin_rejected = false;
  try {
    authenticate_helper(source_root, "amnezia-headless-fs", std::string(64, 'a'));
  } catch (const Refusal &error) {
    wrong_pin_rejected = error.code == 22;
  }
  check(wrong_pin_rejected, "authenticate_helper_refuses_wrong_caller_pin");
  {
    const int fd = ::open((source_root + "/amnezia-headless-fs").c_str(),
                          O_WRONLY | O_APPEND);
    if (fd >= 0) { write_all(fd, "x"); ::close(fd); }
  }
  bool changed_bytes_rejected = false;
  try {
    authenticate_helper(source_root, "amnezia-headless-fs", pin);
  } catch (const Refusal &error) {
    changed_bytes_rejected = error.code == 22;
  }
  check(changed_bytes_rejected, "authenticate_helper_refuses_changed_bytes");
  {
    const int fd = ::open((source_root + "/amnezia-headless-fs").c_str(),
                          O_WRONLY | O_TRUNC);
    if (fd < 0) { std::fprintf(stderr, "cannot restore helper fixture\n"); return 2; }
    write_all(fd, fixture_bytes);
    ::close(fd);
  }
  auth = authenticate_helper(source_root, "amnezia-headless-fs", pin);
  StageRecord stage = copy_helper_bytes(auth, private_root);
  check(stage.sha256 == helper_sha && stage.size == fixture_bytes.size(),
        "stage_copy_preserves_authenticated_bytes");
  const FileBytes staged_read = read_regular_bytes(stage.target, kMaxHelperBytes,
                                                   "staged helper");
  check(staged_read.sha256 == helper_sha, "stage_copy_rehash_matches");
  const std::string receipt = helper_json(auth, &stage);
  check(receipt.find("\"selfAuthenticated\":false") != std::string::npos,
        "gate_receipt_declares_no_self_authentication");
  check(receipt.find("\"stagedInode\"") != std::string::npos,
        "gate_receipt_binds_staged_inode");

  std::printf("FAILURES %d\n", failures);
  return failures == 0 ? 0 : 1;
}

#elif defined(AMNEZIA_BOOTSTRAP_TRANSPORT_DRIVER)

// Test-only driver for the bounded transport on an owned pure worker.  It is
// never part of the product binary and never invokes run_probe_host.
int main(int argc, char **argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s WORKER MODE [MARKER] [BUDGET_MS]\n", argv[0]);
    return 2;
  }
  const std::string worker = argv[1];
  const std::string mode = argv[2];
  const std::string marker = argc >= 4 ? argv[3] : std::string();
  const long budget = argc >= 5 ? std::strtol(argv[4], nullptr, 10) : 1200;
  if (worker.empty() || worker[0] != '/') {
    std::fprintf(stderr, "worker must be an absolute owned path\n");
    return 2;
  }
  std::vector<std::string> command;
  if (mode == "exit23") command = {worker, "emit_exit23"};
  else if (mode == "stderr") command = {worker, "emit_stderr"};
  else if (mode == "overflow") command = {worker, "emit_overflow"};
  else if (mode == "sleep") command = {worker, "emit_sleep", marker};
  else if (mode == "missing") command = {worker + "-absent"};
  else if (mode == "relative") command = {"true"};
  else { std::fprintf(stderr, "unknown transport mode\n"); return 2; }
  const WorkDeadline deadline = WorkDeadline::from_now(
      std::chrono::milliseconds(budget > 0 ? budget : 1200),
      std::chrono::milliseconds(1500));
  try {
    const ProbeResult result = run_probe_bounded(command, deadline);
    std::printf("RESULT exit=%d signaled=%d truncated=%d timed_out=%d out_len=%zu err_len=%zu out=%s\n",
                result.exit_code, result.signaled ? 1 : 0, result.truncated ? 1 : 0,
                result.timed_out ? 1 : 0, result.output.size(), result.stderr_output.size(),
                result.output.c_str());
    return 0;
  } catch (const Refusal &error) {
    std::printf("REFUSED code=%d msg=%s\n", error.code, error.what());
    return error.code;
  }
}

#elif !defined(AMNEZIA_BOOTSTRAP_NO_MAIN)

int main(int argc, char **argv) {
  try {
    if (argc >= 2 && std::string(argv[1]) == "--stage-helper") {
      return run_stage_helper(argc, argv);
    }
    if (argc >= 2 && std::string(argv[1]) == "--check-helper") {
      return run_check_helper(argc, argv);
    }
    if (argc >= 2 && std::string(argv[1]) == "--recovery-anchor") {
      return run_recovery_anchor(argc, argv);
    }
    if (argc >= 2 && std::string(argv[1]) == "--probe-host") {
      return run_probe_host(argc, argv);
    }
    return prior_preauth_modes_main(argc, argv);
  } catch (const Refusal &error) {
    std::fprintf(stderr, "bootstrap-refused: %s\n", error.what());
    return error.code;
  } catch (const UsageError &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 20;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "bootstrap-error: %s\n", error.what());
    return 21;
  }
}

#endif
