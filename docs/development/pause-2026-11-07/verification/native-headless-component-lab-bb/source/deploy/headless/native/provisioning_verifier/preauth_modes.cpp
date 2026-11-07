// Amnezia headless pre-auth input staging and package/receipt/runtime
// metadata validation, added as narrow modes on top of the copied native
// provisioning verifier (src/verify_provisioning.cpp, SHA-256
// cf8ef35c9040c03f219cab83d8385c673f603cbd362e5f17c0da3aa31f391d6b,
// copied byte-identically from the integration candidate).
//
// Contract sources (read-only):
//   deploy/headless/install_headless.sh (SHA-256 61fab91a...), function-area
//   pre-auth staging heredoc and the package/receipt/runtime metadata
//   heredocs, plus deploy/headless/verify_provisioning_bundle.py.
//
// Added modes:
//   --stage-inputs
//       Pre-auth staging of already-extracted package inputs into a private
//       root-owned 0700 directory, consuming the four authenticated operator
//       hash arguments.  Copies exactly the fixed production file set (+ the
//       declared native helper), never scans the source directory for extra
//       names, never extracts an archive, never executes a packaged binary.
//   --validate-package
//       Strict package-manifest / runtime-dependencies / GitHub-free receipt
//       metadata validation against the same authenticated operator hashes.
//       Host probes (command presence, dpkg version minimums, architecture,
//       readelf/ldd/--version) are NEVER executed: the mode emits a
//       deterministic probe plan with hostProbesExecuted=false and
//       releaseAccepted=false, preserving fail-closed semantics.
//
// The legacy verifier path (no new mode flag) is dispatched unchanged, so the
// existing 17 fixture semantics are preserved bit-for-bit.

#define main legacy_provisioning_verifier_main
#include "verify_provisioning.cpp"
#undef main

#include <cstdint>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr uint64_t kMaxStagedInputBytes = 8ull * 1024ull * 1024ull;
constexpr uint64_t kMaxStagedReceiptBytes = 256ull * 1024ull;
constexpr uint64_t kMaxStagedKeyBytes = 64ull * 1024ull;
constexpr const char *kStageTool = "amnezia-preauth-stage-v1";
constexpr const char *kMetadataTool = "amnezia-preauth-metadata-v1";

struct UsageError : public std::runtime_error {
  explicit UsageError(const std::string &message) : std::runtime_error(message) {}
};

std::string join_path(const std::string &directory, const std::string &name) {
  return directory + "/" + name;
}

std::string normalize_hash64(const std::string &value, const char *label) {
  if (value.size() != 64) {
    fail(std::string(label) + " must be 64 hexadecimal characters");
  }
  std::string normalized;
  normalized.reserve(64);
  for (char c : value) {
    if (c >= '0' && c <= '9') {
      normalized.push_back(c);
    } else if (c >= 'a' && c <= 'f') {
      normalized.push_back(c);
    } else if (c >= 'A' && c <= 'F') {
      normalized.push_back(static_cast<char>(c - 'A' + 'a'));
    } else {
      fail(std::string(label) + " must be 64 hexadecimal characters");
    }
  }
  return normalized;
}

std::map<std::string, std::string> parse_mode_arguments(
    int argc, char **argv, const std::vector<std::string> &allowed,
    const char *mode_usage) {
  std::map<std::string, std::string> parsed;
  for (int index = 2; index < argc; ++index) {
    const std::string argument = argv[index];
    bool known = false;
    for (const auto &name : allowed) {
      if (argument == name) {
        known = true;
        break;
      }
    }
    if (!known) {
      throw UsageError("unknown argument for this mode: " + argument);
    }
    if (index + 1 >= argc) {
      throw UsageError("missing value for " + argument);
    }
    if (parsed.count(argument) != 0) {
      throw UsageError("duplicate argument: " + argument);
    }
    parsed[argument] = argv[++index];
  }
  (void)mode_usage;
  return parsed;
}

const std::string &required_argument(const std::map<std::string, std::string> &args,
                                    const std::string &name,
                                    const char *mode_usage) {
  const auto found = args.find(name);
  if (found == args.end() || found->second.empty()) {
    throw UsageError("missing required argument: " + name + "\n" + mode_usage);
  }
  return found->second;
}

std::string optional_argument(const std::map<std::string, std::string> &args,
                              const std::string &name) {
  const auto found = args.find(name);
  return found == args.end() ? std::string() : found->second;
}

bool is_regular_nofollow(const std::string &path) {
  struct stat metadata {};
  if (::lstat(path.c_str(), &metadata) != 0) return false;
  return S_ISREG(metadata.st_mode);
}

uint32_t must_be_regular_mode(const std::string &path, const char *label) {
  struct stat metadata {};
  if (::lstat(path.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
    fail(std::string(label) + " must be a regular file");
  }
  return static_cast<uint32_t>(metadata.st_mode & 07777u);
}

std::string read_bounded_file(const std::string &path, uint64_t maximum,
                              const char *label) {
  int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) fail(std::string(label) + " must be a regular file");
  struct stat before {};
  if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
      before.st_size < 0 ||
      static_cast<uint64_t>(before.st_size) > maximum) {
    ::close(fd);
    fail(std::string(label) + " must be a regular file within the size limit");
  }
  std::string bytes;
  bytes.reserve(static_cast<size_t>(before.st_size));
  char buffer[64 * 1024];
  while (true) {
    ssize_t count = ::read(fd, buffer, sizeof(buffer));
    if (count < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      fail(std::string("unable to read ") + label);
    }
    if (count == 0) break;
    bytes.append(buffer, static_cast<size_t>(count));
    if (bytes.size() > maximum) {
      ::close(fd);
      fail(std::string(label) + " exceeds the size limit");
    }
  }
  struct stat after {};
  if (::fstat(fd, &after) != 0 || !same_file_identity(before, after) ||
      static_cast<uint64_t>(after.st_size) != bytes.size()) {
    ::close(fd);
    fail(std::string(label) + " changed while it was being read");
  }
  ::close(fd);
  return bytes;
}

std::string digest_file(const std::string &path, uint64_t maximum,
                        const char *label) {
  return sha256_bytes(read_bounded_file(path, maximum, label));
}

struct StagedEntry {
  std::string name;
  uint32_t mode = 0;
  uint64_t size = 0;
  std::string sha256;
};

// Byte-identical port of the production staging copy: O_NOFOLLOW source,
// dev/ino/size stability, O_EXCL 0600 target, streaming digest, fsync,
// fchmod(source mode & 0777), then an independent size+digest re-read.
StagedEntry stage_copy_source(const std::string &source, const std::string &target,
                              const std::string &name, uint64_t maximum,
                              const char *label) {
  struct stat before {};
  if (::lstat(source.c_str(), &before) != 0 || !S_ISREG(before.st_mode)) {
    fail(std::string(label) + " must be a regular file");
  }
  if (static_cast<uint64_t>(before.st_size) > maximum) {
    fail(std::string(label) + " exceeds the size limit");
  }
  int source_fd = ::open(source.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (source_fd < 0) fail(std::string(label) + " must be a regular file");
  struct stat opened {};
  if (::fstat(source_fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
      opened.st_dev != before.st_dev || opened.st_ino != before.st_ino ||
      opened.st_size != before.st_size) {
    ::close(source_fd);
    fail(std::string(label) + " changed while it was being copied");
  }
  int target_fd = ::open(target.c_str(),
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         0600);
  if (target_fd < 0) {
    ::close(source_fd);
    fail(std::string("unable to create a private copy of ") + label);
  }
  Sha256 hash;
  uint64_t total = 0;
  bool failed = false;
  std::string message;
  std::vector<char> buffer(1024 * 1024);
  while (!failed) {
    ssize_t count = ::read(source_fd, buffer.data(), buffer.size());
    if (count < 0) {
      if (errno == EINTR) continue;
      failed = true;
      message = std::string("unable to read ") + label;
      break;
    }
    if (count == 0) break;
    hash.update(buffer.data(), static_cast<size_t>(count));
    total += static_cast<uint64_t>(count);
    if (total > maximum) {
      failed = true;
      message = std::string(label) + " exceeds the size limit";
      break;
    }
    try {
      write_all(target_fd, buffer.data(), static_cast<size_t>(count),
                "private copy");
    } catch (const Failure &error) {
      failed = true;
      message = error.what();
    }
  }
  struct stat after {};
  if (!failed && (::fstat(source_fd, &after) != 0 ||
                  !same_file_identity(before, after) ||
                  total != static_cast<uint64_t>(before.st_size))) {
    failed = true;
    message = std::string(label) + " changed while it was being copied";
  }
  if (!failed && ::fsync(target_fd) != 0) {
    failed = true;
    message = "unable to flush the private copy";
  }
  if (!failed && ::fchmod(target_fd, static_cast<mode_t>(opened.st_mode & 0777u)) != 0) {
    failed = true;
    message = "unable to apply the original mode to the private copy";
  }
  ::close(target_fd);
  ::close(source_fd);
  if (failed) {
    ::unlink(target.c_str());
    fail(message);
  }
  const std::string expected_digest = hash.finish();
  struct stat copied {};
  if (::lstat(target.c_str(), &copied) != 0 || !S_ISREG(copied.st_mode) ||
      static_cast<uint64_t>(copied.st_size) != total ||
      digest_file(target, maximum, "private copy") != expected_digest) {
    ::unlink(target.c_str());
    fail(std::string("private ") + label +
         " copy has an unexpected hash or size");
  }
  return {name, static_cast<uint32_t>(copied.st_mode & 0777u), total,
          expected_digest};
}

bool private_root_metadata_ok(const struct stat &metadata) {
  return S_ISDIR(metadata.st_mode) && metadata.st_uid == 0 &&
         (metadata.st_mode & 0777u) == 0700u;
}

void require_private_root(const std::string &root) {
  struct stat metadata {};
  if (::lstat(root.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode)) {
    fail("private package-input directory must be a root-owned regular "
         "directory with mode 0700");
  }
  if (metadata.st_uid != 0 || (metadata.st_mode & 0777u) != 0700u) {
    fail("private package-input directory must be root-owned and mode 0700");
  }
}

std::string json_string(const std::string &value) { return quote_json(value); }

std::string mode_octal(uint32_t mode) {
  char text[8];
  std::snprintf(text, sizeof(text), "%04o",
                static_cast<unsigned>(mode & 0777u));
  return text;
}

std::string stage_receipt_json(const std::string &expected_key,
                               const std::string &expected_manifest,
                               const std::string &expected_checksums,
                               const std::string &expected_signed_manifest,
                               const std::string &native_helper,
                               const NativeVerifierRole &verifier_role,
                               uint64_t private_root_uid,
                               std::vector<StagedEntry> entries,
                               const std::vector<std::string> &package_files) {
  std::sort(entries.begin(), entries.end(),
            [](const StagedEntry &left, const StagedEntry &right) {
              return left.name < right.name;
            });
  std::string out = "{";
  out += "\"expectedChecksumsSha256\":" + json_string(expected_checksums) + ",";
  out += "\"expectedKeySha256\":" + json_string(expected_key) + ",";
  out += "\"expectedPackageManifestSha256\":" + json_string(expected_manifest) + ",";
  out += "\"expectedSignedManifestSha256\":" +
         json_string(expected_signed_manifest) + ",";
  out += "\"files\":[";
  for (size_t index = 0; index < entries.size(); ++index) {
    if (index != 0) out += ",";
    out += "{\"mode\":" + json_string(mode_octal(entries[index].mode)) +
           ",\"name\":" + json_string(entries[index].name) +
           ",\"sha256\":" + json_string(entries[index].sha256) +
           ",\"size\":" + std::to_string(entries[index].size) + "}";
  }
  out += "],\"nativeHelper\":" + json_string(native_helper) + ",";
  if (verifier_role.present) {
    out += "\"nativeVerifier\":{\"path\":" +
        json_string(kNativeVerifier) + ",\"sha256\":" +
        json_string(verifier_role.sha256) + ",\"size\":" +
        std::to_string(verifier_role.size) + "},";
  }
  out += "\"packageFiles\":[";
  for (size_t index = 0; index < package_files.size(); ++index) {
    if (index != 0) out += ",";
    out += json_string(package_files[index]);
  }
  out += "],\"privateRootMode\":\"0700\",\"privateRootUid\":" +
         std::to_string(private_root_uid) + ",";
  out += "\"schema\":1,\"staged\":true,\"tool\":" + json_string(kStageTool) +
         "}\n";
  return out;
}

std::string require_checksum_row(const std::string &root, const std::string &name,
                                 const std::string &expected) {
  const std::string text = read_bounded_file(join_path(root, "SHA256SUMS"),
                                             kMaxStagedInputBytes,
                                             "package checksums");
  size_t start = 0;
  std::string found;
  while (start < text.size()) {
    size_t end = text.find('\n', start);
    if (end == std::string::npos) end = text.size();
    const std::string line = text.substr(start, end - start);
    start = end + 1;
    if (line.empty()) continue;
    if (line.size() < 67 || line[64] != ' ' || line[65] != ' ') {
      fail("package checksum line is not canonical");
    }
    const std::string digest = line.substr(0, 64);
    if (!is_lower_hex_64(digest)) fail("package checksum line is not canonical");
    if (line.substr(66) != name) continue;
    if (!found.empty()) fail("package checksum line is duplicated");
    found = digest;
  }
  if (found.empty() || found != expected) {
    fail("native verifier checksum entry is missing or does not match the "
         "signed role binding");
  }
  return found;
}

// The declared nativeVerifier role is staged only when the signed manifest
// declares it.  Its source must be an exact regular 0755 inode whose bytes and
// size equal the role binding and whose SHA256SUMS row equals the same digest.
StagedEntry stage_native_verifier(const std::string &source_root,
                                  const std::string &package_dir,
                                  const NativeVerifierRole &role,
                                  std::vector<std::string> &created,
                                  std::vector<std::string> &package_files) {
  const std::string source = join_path(source_root, kNativeVerifier);
  if (!role.present) {
    struct stat metadata {};
    if (::lstat(source.c_str(), &metadata) == 0) {
      fail("native verifier is present but not declared");
    }
    return {};
  }
  require_checksum_row(source_root, kNativeVerifier, role.sha256);
  if (must_be_regular_mode(source, "native provisioning verifier") != 0755u) {
    fail("native verifier mode is not exactly 0755");
  }
  struct stat metadata {};
  if (::lstat(source.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      static_cast<uint64_t>(metadata.st_size) != role.size) {
    fail("native verifier does not match the signed role size");
  }
  if (digest_file(source, kMaxStagedInputBytes, "native verifier") != role.sha256) {
    fail("native verifier does not match the signed role binding");
  }
  const std::string target = join_path(package_dir, kNativeVerifier);
  created.push_back(target);
  package_files.push_back(kNativeVerifier);
  const StagedEntry staged = stage_copy_source(source, target, kNativeVerifier,
                                              kMaxStagedInputBytes,
                                              "native verifier");
  if (staged.mode != 0755u || staged.size != role.size ||
      staged.sha256 != role.sha256) {
    fail("private native verifier copy does not match the signed role binding");
  }
  return staged;
}

const char *kStageUsage =
    "usage: <program> --stage-inputs --source-root DIR --private-root DIR "
    "--public-key PATH --verified-receipt PATH "
    "--expected-public-key-sha256 HEX "
    "--expected-package-manifest-sha256 HEX "
    "--expected-checksums-sha256 HEX "
    "--expected-signed-manifest-sha256 HEX [--receipt-out PATH]\n";

int run_stage_inputs(int argc, char **argv) {
  const std::vector<std::string> allowed = {
      "--source-root",
      "--private-root",
      "--public-key",
      "--verified-receipt",
      "--expected-public-key-sha256",
      "--expected-package-manifest-sha256",
      "--expected-checksums-sha256",
      "--expected-signed-manifest-sha256",
      "--receipt-out",
  };
  const auto args = parse_mode_arguments(argc, argv, allowed, kStageUsage);
  const std::string source_root = required_argument(args, "--source-root", kStageUsage);
  const std::string private_root = required_argument(args, "--private-root", kStageUsage);
  const std::string public_key = required_argument(args, "--public-key", kStageUsage);
  const std::string verified_receipt =
      required_argument(args, "--verified-receipt", kStageUsage);
  const std::string expected_key = normalize_hash64(
      required_argument(args, "--expected-public-key-sha256", kStageUsage),
      "expected public-key fingerprint");
  const std::string expected_manifest = normalize_hash64(
      required_argument(args, "--expected-package-manifest-sha256", kStageUsage),
      "expected package-manifest fingerprint");
  const std::string expected_checksums = normalize_hash64(
      required_argument(args, "--expected-checksums-sha256", kStageUsage),
      "expected checksums fingerprint");
  const std::string expected_signed_manifest = normalize_hash64(
      required_argument(args, "--expected-signed-manifest-sha256", kStageUsage),
      "expected signed-manifest fingerprint");
  const std::string receipt_out = optional_argument(args, "--receipt-out");

  require_private_root(private_root);
  const std::string package_dir = join_path(private_root, "package");
  if (::mkdir(package_dir.c_str(), 0700) != 0) {
    fail("unable to create the private package directory");
  }
  std::vector<std::string> created = {package_dir};
  auto cleanup = [&created]() {
    for (auto it = created.rbegin(); it != created.rend(); ++it) {
      struct stat metadata {};
      if (::lstat(it->c_str(), &metadata) != 0) continue;
      if (S_ISDIR(metadata.st_mode)) {
        ::rmdir(it->c_str());
      } else {
        ::unlink(it->c_str());
      }
    }
  };
  try {
    std::vector<StagedEntry> entries;
    std::vector<std::string> package_files = base_package_files();
    for (const auto &name : base_package_files()) {
      const std::string target = join_path(package_dir, name);
      created.push_back(target);
      entries.push_back(stage_copy_source(join_path(source_root, name), target,
                                          name, kMaxStagedInputBytes,
                                          name.c_str()));
    }
    const Json manifest =
        parse_json(read_bounded_file(join_path(package_dir, "package-manifest.json"),
                                     kMaxStagedInputBytes, "package manifest"));
    require_object(manifest, "headless package-manifest.json");
    const NativeVerifierRole verifier_role = require_native_verifier_role(manifest);
    std::string native_helper;
    const Json *native = manifest.get("nativeHelper");
    if (native != nullptr) {
      if (native->kind != Json::Kind::String ||
          (native->text != kNativeHelper && native->text != kNativeCli)) {
        fail("unknown native provisioning helper");
      }
      native_helper = native->text;
    }
    if (native_helper == kNativeHelper) {
      const std::string target = join_path(package_dir, kNativeHelper);
      created.push_back(target);
      entries.push_back(stage_copy_source(join_path(source_root, kNativeHelper),
                                          target, kNativeHelper,
                                          kMaxStagedInputBytes,
                                          "native helper"));
      package_files.push_back(kNativeHelper);
    }
    stage_native_verifier(source_root, package_dir, verifier_role, created,
                          package_files);
    const std::string staged_key = join_path(private_root, "update-public-key.pem");
    created.push_back(staged_key);
    entries.push_back(stage_copy_source(public_key, staged_key,
                                        "update-public-key.pem",
                                        kMaxStagedKeyBytes, "public key"));
    const std::string staged_receipt =
        join_path(private_root, "verified-receipt.json");
    created.push_back(staged_receipt);
    entries.push_back(stage_copy_source(verified_receipt, staged_receipt,
                                        "verified-receipt.json",
                                        kMaxStagedReceiptBytes,
                                        "verified receipt"));

    if (digest_file(join_path(package_dir, "package-manifest.json"),
                    kMaxStagedInputBytes, "package manifest") != expected_manifest) {
      fail("package manifest fingerprint does not match the trusted release receipt");
    }
    if (digest_file(join_path(package_dir, "SHA256SUMS"), kMaxStagedInputBytes,
                    "package checksums") != expected_checksums) {
      fail("package checksums fingerprint does not match the trusted release receipt");
    }
    if (digest_file(staged_key, kMaxStagedKeyBytes, "public key") != expected_key) {
      fail("private trust-anchor fingerprint does not match the trusted release receipt");
    }
    require_private_root(private_root);

    struct stat root_metadata {};
    if (::lstat(private_root.c_str(), &root_metadata) != 0) {
      fail("private package-input directory disappeared");
    }
    const std::string receipt = stage_receipt_json(
        expected_key, expected_manifest, expected_checksums,
        expected_signed_manifest, native_helper, verifier_role,
        static_cast<uint64_t>(root_metadata.st_uid), entries, package_files);
    if (!receipt_out.empty()) {
      write_receipt(receipt_out, receipt);
      std::printf("staged receipt: %s\n", receipt_out.c_str());
    }
    std::printf("staged private provisioning inputs: %s\n", package_dir.c_str());
    std::printf("staged package files: %zu\n", package_files.size());
    return 0;
  } catch (...) {
    cleanup();
    throw;
  }
}

// ---------------------------------------------------------------------------
// Package / receipt / runtime metadata validation

void require_package_manifest_contract(const Json &manifest) {
  const char *what = "headless package-manifest.json";
  require_object(manifest, what);
  const Json *native = manifest.get("nativeHelper");
  const NativeVerifierRole verifier_role = require_native_verifier_role(manifest);
  std::vector<std::string> expected_keys = {
      "schema",         "version",        "platform",     "installModes",
      "artifacts",      "service",        "servicePaths", "trustAnchor",
      "runtimeManifest", "checksums",     "runtimeText",
  };
  if (native != nullptr) {
    if (native->kind != Json::Kind::String ||
        (native->text != kNativeHelper && native->text != kNativeCli)) {
      fail("invalid native helper");
    }
    expected_keys.push_back("nativeHelper");
  }
  if (verifier_role.present) expected_keys.push_back("nativeVerifier");
  require_exact_keys(manifest, expected_keys, what);
  if (require_integer(manifest, "schema", what) != 2) {
    fail("invalid package-manifest.json");
  }
  validate_release_version(require_string(manifest, "version", what), what);
  if (require_string(manifest, "platform", what) != "linux-headless-x64") {
    fail("invalid package artifact/service contract");
  }
  require_string_array(require_field(manifest, "installModes", what),
                       {"fresh", "upgrade"}, what);
  require_string_array(require_field(manifest, "artifacts", what),
                       {"amneziad", "amnezia-cli", "amneziad.service"}, what);
  require_string_array(
      require_field(manifest, "servicePaths", what),
      {"/etc/systemd/system/amneziad.service",
       "/run/systemd/system/amneziad.service",
       "/usr/local/lib/systemd/system/amneziad.service",
       "/usr/lib/systemd/system/amneziad.service",
       "/lib/systemd/system/amneziad.service"},
      what);
  if (require_string(manifest, "service", what) != "amneziad.service" ||
      require_string(manifest, "trustAnchor", what) !=
          "external-ed25519-sha256-receipt" ||
      require_string(manifest, "runtimeManifest", what) !=
          "runtime-dependencies.json" ||
      require_string(manifest, "checksums", what) != "SHA256SUMS" ||
      require_string(manifest, "runtimeText", what) !=
          "runtime-dependencies.txt") {
    fail("invalid package references");
  }
}

struct RuntimeContract {
  std::vector<std::string> required_commands;
  std::vector<std::pair<std::string, std::vector<std::string>>> backend_modes;
  std::vector<std::pair<std::vector<std::string>, std::string>> packages;
  std::string release_version_id;
};

RuntimeContract require_runtime_contract(const Json &runtime,
                                         const std::string &ubuntu_id,
                                         const std::string &version_id,
                                         const std::string &codename) {
  const char *what = "runtime-dependencies.json";
  require_object(runtime, what);
  require_exact_keys(runtime,
                     {"schema", "distribution", "architectures", "releases",
                      "commands"},
                     what);
  if (require_integer(runtime, "schema", what) != 2 ||
      require_string(runtime, "distribution", what) != "ubuntu") {
    fail("invalid runtime host contract");
  }
  require_string_array(require_field(runtime, "architectures", what),
                       {"amd64"}, what);

  const Json &releases = require_field(runtime, "releases", what);
  if (releases.kind != Json::Kind::Array) {
    fail("invalid runtime host contract");
  }
  const Json *matched = nullptr;
  for (const auto &release : releases.array) {
    require_object(release, "runtime release entry");
    const std::string release_version =
        require_string(release, "versionId", "runtime release entry");
    const Json &codenames =
        require_field(release, "codenames", "runtime release entry");
    const std::vector<std::string> names =
        require_string_array(codenames, "runtime release codenames");
    if (release_version != version_id) continue;
    for (const auto &name : names) {
      if (name == codename) {
        matched = &release;
        break;
      }
    }
    if (matched != nullptr) break;
  }
  if (matched == nullptr) {
    fail("unsupported Ubuntu release/codename: " + version_id + "/" + codename);
  }
  if (ubuntu_id != "ubuntu") {
    fail("headless provisioning requires supported Ubuntu metadata");
  }

  const Json &commands = require_field(runtime, "commands", what);
  require_object(commands, "runtime command contract");
  require_exact_keys(commands, {"required", "backendModes"},
                     "runtime command contract");
  RuntimeContract contract;
  contract.release_version_id = version_id;
  contract.required_commands =
      require_string_array(require_field(commands, "required", what),
                           "runtime required commands");
  if (contract.required_commands.empty()) {
    fail("invalid runtime command contract");
  }
  for (const auto &command : contract.required_commands) {
    if (command.empty()) fail("invalid runtime command contract");
  }
  const Json &modes = require_field(commands, "backendModes", what);
  if (modes.kind != Json::Kind::Array || modes.array.empty()) {
    fail("invalid backend mode contract");
  }
  for (const auto &mode : modes.array) {
    require_object(mode, "backend mode");
    require_exact_keys(mode, {"mode", "alternatives"}, "backend mode");
    const std::string name = require_string(mode, "mode", "backend mode");
    const std::vector<std::string> alternatives =
        require_string_array(require_field(mode, "alternatives", "backend mode"),
                             "backend mode alternatives");
    if (name.empty() || alternatives.empty()) {
      fail("invalid backend mode contract");
    }
    for (const auto &alternative : alternatives) {
      if (alternative.empty()) fail("invalid backend mode contract");
    }
    contract.backend_modes.emplace_back(name, alternatives);
  }

  const Json &packages = require_field(*matched, "packages", "runtime release entry");
  if (packages.kind != Json::Kind::Array) {
    fail("invalid runtime package entry");
  }
  for (const auto &package : packages.array) {
    require_object(package, "runtime package entry");
    require_exact_keys(package, {"alternatives", "minimum", "reason"},
                       "runtime package entry");
    const std::vector<std::string> alternatives = require_string_array(
        require_field(package, "alternatives", "runtime package entry"),
        "runtime package alternatives");
    const std::string minimum =
        require_string(package, "minimum", "runtime package entry");
    const std::string reason =
        require_string(package, "reason", "runtime package entry");
    if (alternatives.empty() || minimum.empty() || reason.empty()) {
      fail("invalid runtime package entry");
    }
    for (const auto &alternative : alternatives) {
      if (alternative.empty()) fail("invalid runtime package entry");
    }
    contract.packages.emplace_back(alternatives, minimum);
  }
  return contract;
}

struct ReceiptIdentity {
  std::string version;
  std::string package_version;
  std::vector<std::string> package_files;
};

ReceiptIdentity require_receipt_identity(const std::string &receipt_path,
                                        const std::string &package_root,
                                        const std::string &public_key,
                                        const std::string &expected_key,
                                        const std::string &expected_manifest,
                                        const std::string &expected_checksums,
                                        const std::string &expected_signed_manifest,
                                        const std::vector<std::string> &expected_files) {
  const std::string text =
      read_bounded_file(receipt_path, kMaxStagedReceiptBytes, "verified receipt");
  const Json receipt = parse_json(text);
  const char *what = "verified receipt";
  require_object(receipt, what);
  require_exact_keys(receipt,
                     {"schema",        "tool",          "verified",
                      "manifestSha256", "publicKeySha256", "archiveSha256",
                      "archiveSize",   "version",       "packageVersion",
                      "packageFiles",  "packageManifestSha256",
                      "checksumsSha256"},
                     what);
  if (require_integer(receipt, "schema", what) != 1 ||
      require_string(receipt, "tool", what) != "amnezia-verify-provisioning-v1") {
    fail("receipt is not trusted");
  }
  const Json &verified = require_field(receipt, "verified", what);
  if (verified.kind != Json::Kind::Bool || !verified.boolean) {
    fail("receipt is not trusted");
  }
  for (const char *key : {"manifestSha256", "publicKeySha256", "archiveSha256",
                          "packageManifestSha256", "checksumsSha256"}) {
    if (!is_lower_hex_64(require_string(receipt, key, what))) {
      fail("receipt digest is not canonical");
    }
  }
  const std::string receipt_key = require_string(receipt, "publicKeySha256", what);
  const std::string receipt_manifest = require_string(receipt, "manifestSha256", what);
  const int64_t archive_size = require_integer(receipt, "archiveSize", what);
  if (receipt_key != expected_key ||
      digest_file(public_key, kMaxStagedKeyBytes, "public key") != expected_key ||
      receipt_manifest != expected_signed_manifest || archive_size <= 0) {
    fail("receipt trust anchor, signed manifest, or archive identity is invalid");
  }
  const std::string version = require_string(receipt, "version", what);
  const std::string package_version =
      require_string(receipt, "packageVersion", what);
  const std::vector<std::string> files =
      require_string_array(require_field(receipt, "packageFiles", what),
                           "receipt packageFiles");
  if (files != expected_files || package_version != version) {
    fail("receipt package identity is not exact");
  }
  if (require_string(receipt, "packageManifestSha256", what) != expected_manifest ||
      require_string(receipt, "checksumsSha256", what) != expected_checksums) {
    fail("receipt inner hashes do not match trusted arguments");
  }
  if (digest_file(join_path(package_root, "package-manifest.json"),
                  kMaxStagedInputBytes, "package manifest") != expected_manifest ||
      digest_file(join_path(package_root, "SHA256SUMS"), kMaxStagedInputBytes,
                  "package checksums") != expected_checksums) {
    fail("package does not match verified receipt");
  }
  return {version, package_version, files};
}

std::map<std::string, std::string> require_checksums(const std::string &package_root,
                                                     const std::vector<std::string> &covered) {
  const std::string text = read_bounded_file(join_path(package_root, "SHA256SUMS"),
                                             kMaxStagedInputBytes,
                                             "package checksums");
  std::map<std::string, std::string> rows;
  size_t start = 0;
  const std::set<std::string> allowed(covered.begin(), covered.end());
  while (start < text.size()) {
    size_t end = text.find('\n', start);
    if (end == std::string::npos) end = text.size();
    const std::string line = text.substr(start, end - start);
    start = end + 1;
    if (line.empty()) continue;
    if (line.size() < 64 + 2 + 1) fail("package checksum line is not canonical");
    const std::string digest = line.substr(0, 64);
    if (!is_lower_hex_64(digest) || line[64] != ' ' || line[65] != ' ') {
      fail("package checksum line is not canonical");
    }
    const std::string name = line.substr(66);
    if (name.empty() || allowed.count(name) == 0) {
      fail("package checksum line covers an unexpected member");
    }
    if (!rows.emplace(name, digest).second) {
      fail("package checksum line is duplicated");
    }
  }
  if (rows.size() != covered.size()) {
    fail("package checksum set does not cover every package file");
  }
  for (const auto &row : rows) {
    if (digest_file(join_path(package_root, row.first), kMaxStagedInputBytes,
                    "package member") != row.second) {
      fail("package member does not match authenticated checksums");
    }
  }
  return rows;
}

std::string probe_plan_json(const RuntimeContract &contract) {
  std::string out = "{\"architecture\":\"amd64\",\"backendModes\":[";
  for (size_t index = 0; index < contract.backend_modes.size(); ++index) {
    if (index != 0) out += ",";
    out += "{\"alternatives\":[";
    const auto &alternatives = contract.backend_modes[index].second;
    for (size_t inner = 0; inner < alternatives.size(); ++inner) {
      if (inner != 0) out += ",";
      out += json_string(alternatives[inner]);
    }
    out += "],\"mode\":" + json_string(contract.backend_modes[index].first) + "}";
  }
  out += "],\"deferredContracts\":[";
  const std::vector<std::string> deferred = {
      "required-command-presence", "vpn-backend-mode-presence",
      "dpkg-version-minimums", "dpkg-architecture-amd64",
      "readelf-elf64-x86-64", "ldd-shared-library-closure",
      "binary-version-probe"};
  for (size_t index = 0; index < deferred.size(); ++index) {
    if (index != 0) out += ",";
    out += json_string(deferred[index]);
  }
  out += "],\"dpkgPackages\":[";
  for (size_t index = 0; index < contract.packages.size(); ++index) {
    if (index != 0) out += ",";
    out += "{\"alternatives\":[";
    const auto &alternatives = contract.packages[index].first;
    for (size_t inner = 0; inner < alternatives.size(); ++inner) {
      if (inner != 0) out += ",";
      out += json_string(alternatives[inner]);
    }
    out += "],\"minimum\":" + json_string(contract.packages[index].second) + "}";
  }
  out += "],\"executed\":false,\"requiredCommands\":[";
  for (size_t index = 0; index < contract.required_commands.size(); ++index) {
    if (index != 0) out += ",";
    out += json_string(contract.required_commands[index]);
  }
  out += "]}";
  return out;
}

const char *kValidateUsage =
    "usage: <program> --validate-package --package-root DIR --receipt PATH "
    "--public-key PATH --ubuntu-id ID --ubuntu-version-id VERSION_ID "
    "--ubuntu-codename CODENAME "
    "--expected-public-key-sha256 HEX "
    "--expected-package-manifest-sha256 HEX "
    "--expected-checksums-sha256 HEX "
    "--expected-signed-manifest-sha256 HEX [--receipt-out PATH]\n";

int run_validate_package(int argc, char **argv) {
  const std::vector<std::string> allowed = {
      "--package-root",
      "--receipt",
      "--public-key",
      "--ubuntu-id",
      "--ubuntu-version-id",
      "--ubuntu-codename",
      "--expected-public-key-sha256",
      "--expected-package-manifest-sha256",
      "--expected-checksums-sha256",
      "--expected-signed-manifest-sha256",
      "--receipt-out",
  };
  const auto args = parse_mode_arguments(argc, argv, allowed, kValidateUsage);
  const std::string package_root =
      required_argument(args, "--package-root", kValidateUsage);
  const std::string receipt_path = required_argument(args, "--receipt", kValidateUsage);
  const std::string public_key = required_argument(args, "--public-key", kValidateUsage);
  const std::string ubuntu_id = required_argument(args, "--ubuntu-id", kValidateUsage);
  const std::string version_id =
      required_argument(args, "--ubuntu-version-id", kValidateUsage);
  const std::string codename =
      required_argument(args, "--ubuntu-codename", kValidateUsage);
  const std::string expected_key = normalize_hash64(
      required_argument(args, "--expected-public-key-sha256", kValidateUsage),
      "expected public-key fingerprint");
  const std::string expected_manifest = normalize_hash64(
      required_argument(args, "--expected-package-manifest-sha256", kValidateUsage),
      "expected package-manifest fingerprint");
  const std::string expected_checksums = normalize_hash64(
      required_argument(args, "--expected-checksums-sha256", kValidateUsage),
      "expected checksums fingerprint");
  const std::string expected_signed_manifest = normalize_hash64(
      required_argument(args, "--expected-signed-manifest-sha256", kValidateUsage),
      "expected signed-manifest fingerprint");
  const std::string receipt_out = optional_argument(args, "--receipt-out");

  if (ubuntu_id != "ubuntu" || version_id.empty() || codename.empty()) {
    fail("headless provisioning requires supported Ubuntu metadata with "
         "VERSION_CODENAME");
  }
  struct stat root_metadata {};
  if (::lstat(package_root.c_str(), &root_metadata) != 0 ||
      !S_ISDIR(root_metadata.st_mode)) {
    fail("package root must be a regular directory");
  }

  const Json manifest =
      parse_json(read_bounded_file(join_path(package_root, "package-manifest.json"),
                                   kMaxStagedInputBytes, "package manifest"));
  require_package_manifest_contract(manifest);
  const NativeVerifierRole verifier_role = require_native_verifier_role(manifest);
  std::string native_helper;
  const Json *native = manifest.get("nativeHelper");
  if (native != nullptr) native_helper = native->text;

  const Json runtime = parse_json(read_bounded_file(
      join_path(package_root, "runtime-dependencies.json"), kMaxStagedInputBytes,
      "runtime dependencies"));
  const RuntimeContract contract =
      require_runtime_contract(runtime, ubuntu_id, version_id, codename);

  std::vector<std::string> expected_files = base_package_files();
  if (native_helper == kNativeHelper) expected_files.push_back(kNativeHelper);
  if (verifier_role.present) expected_files.push_back(kNativeVerifier);
  struct stat verifier_presence {};
  if (!verifier_role.present &&
      ::lstat(join_path(package_root, kNativeVerifier).c_str(),
              &verifier_presence) == 0) {
    fail("native verifier is present but not declared");
  }
  for (const auto &name : expected_files) {
    if (!is_regular_nofollow(join_path(package_root, name))) {
      fail("missing package member: " + name);
    }
  }

  const ReceiptIdentity identity = require_receipt_identity(
      receipt_path, package_root, public_key, expected_key, expected_manifest,
      expected_checksums, expected_signed_manifest, expected_files);
  if (require_string(manifest, "version", "headless package-manifest.json") !=
      identity.version) {
    fail("package version/artifacts do not match receipt");
  }
  require_string_array(
      require_field(manifest, "artifacts", "headless package-manifest.json"),
      {"amneziad", "amnezia-cli", "amneziad.service"},
      "headless package-manifest.json");
  for (const auto &name : expected_files) {
    if (!is_regular_nofollow(join_path(package_root, name))) {
      fail("package member is not a regular file");
    }
  }

  std::vector<std::string> covered;
  for (const auto &name : expected_files) {
    if (name != "SHA256SUMS") covered.push_back(name);
  }
  const auto rows = require_checksums(package_root, covered);
  if (!native_helper.empty()) {
    const auto row = rows.find(native_helper);
    if (row == rows.end()) {
      fail("native helper checksum entry is missing or ambiguous");
    }
    const uint32_t helper_mode =
        must_be_regular_mode(join_path(package_root, native_helper),
                             "authenticated native provisioning helper");
    if (helper_mode != 0755u) {
      fail("native helper/CLI mode is not exactly 0755");
    }
  }
  if (verifier_role.present) {
    const auto row = rows.find(kNativeVerifier);
    if (row == rows.end() || row->second != verifier_role.sha256) {
      fail("native verifier checksum entry is missing or does not match the "
           "signed role binding");
    }
    const std::string verifier_path = join_path(package_root, kNativeVerifier);
    struct stat verifier_metadata {};
    if (::lstat(verifier_path.c_str(), &verifier_metadata) != 0 ||
        !S_ISREG(verifier_metadata.st_mode) ||
        static_cast<uint64_t>(verifier_metadata.st_size) != verifier_role.size) {
      fail("native verifier does not match the signed role size");
    }
    if (must_be_regular_mode(verifier_path,
                             "authenticated native provisioning verifier") !=
        0755u) {
      fail("native verifier mode is not exactly 0755");
    }
    if (digest_file(verifier_path, kMaxStagedInputBytes, "native verifier") !=
        verifier_role.sha256) {
      fail("native verifier does not match the signed role binding");
    }
  }

  struct stat root_after {};
  if (::lstat(package_root.c_str(), &root_after) != 0 ||
      !S_ISDIR(root_after.st_mode)) {
    fail("package root changed during validation");
  }
  std::string output = "{";
  output += "\"hostProbesExecuted\":false,";
  output += "\"nativeHelper\":" + json_string(native_helper) + ",";
  if (verifier_role.present) {
    output += "\"nativeVerifier\":{\"path\":" +
        json_string(kNativeVerifier) + ",\"sha256\":" +
        json_string(verifier_role.sha256) + ",\"size\":" +
        std::to_string(verifier_role.size) + "},";
  }
  output += "\"packageFiles\":[";
  for (size_t index = 0; index < expected_files.size(); ++index) {
    if (index != 0) output += ",";
    output += json_string(expected_files[index]);
  }
  output += "],\"packageVersion\":" + json_string(identity.package_version) + ",";
  output += "\"probePlan\":" + probe_plan_json(contract) + ",";
  output += "\"receiptSha256\":" +
            json_string(digest_file(receipt_path, kMaxStagedReceiptBytes,
                                    "verified receipt")) +
            ",";
  output += "\"releaseAccepted\":false,";
  output += "\"runtimeRelease\":{\"codename\":" + json_string(codename) +
            ",\"versionId\":" + json_string(contract.release_version_id) + "},";
  output += "\"schema\":1,\"structuralValidated\":true,";
  output += "\"tool\":" + json_string(kMetadataTool) + ",";
  output += "\"version\":" + json_string(identity.version) + "}\n";
  if (!receipt_out.empty()) {
    write_receipt(receipt_out, output);
    std::printf("metadata receipt: %s\n", receipt_out.c_str());
  }
  std::printf("validated package metadata (host probes deferred): %s\n",
              identity.version.c_str());
  std::printf("runtime probe plan: %zu commands, %zu backend modes, %zu package "
              "entries (executed=false)\n",
              contract.required_commands.size(), contract.backend_modes.size(),
              contract.packages.size());
  return 0;
}

void print_mode_usage(const char *program) {
  std::printf("usage: %s [legacy verification] --manifest PATH --public-key PATH "
              "--expected-public-key-sha256 HEX --provisioning PATH "
              "[--receipt-out PATH]\n",
              program);
  std::printf("%s", kStageUsage);
  std::printf("%s", kValidateUsage);
  std::printf("verify-only: no archive is extracted, no packaged binary is "
              "executed, no host probe is run\n");
}

int dispatch_mode(int argc, char **argv) {
  bool wants_stage = false;
  bool wants_validate = false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--stage-inputs") wants_stage = true;
    if (argument == "--validate-package") wants_validate = true;
  }
  if (!wants_stage && !wants_validate) {
    return legacy_provisioning_verifier_main(argc, argv);
  }
  if (wants_stage && wants_validate) {
    std::fprintf(stderr, "refused: select exactly one new mode\n");
    return 2;
  }
  try {
    return wants_stage ? run_stage_inputs(argc, argv)
                       : run_validate_package(argc, argv);
  } catch (const UsageError &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 2;
  } catch (const Failure &error) {
    std::fprintf(stderr, "pre-auth staging/validation failed: %s\n", error.what());
    return 1;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "pre-auth staging/validation failed: %s\n", error.what());
    return 1;
  } catch (...) {
    std::fprintf(stderr, "pre-auth staging/validation failed\n");
    return 1;
  }
}

}  // namespace

// Proposal K copy delta (one line): the prior dispatch is called by the
// extended dispatcher instead of owning main.
int prior_preauth_modes_main(int argc, char **argv) {
  // --help / -h stay on the legacy path so the existing public CLI contract is
  // unchanged; the additive modes have their own opt-in help switch.
  for (int index = 1; index < argc; ++index) {
    if (std::string(argv[index]) == "--help-modes") {
      print_mode_usage(argv[0]);
      return 0;
    }
  }
  return dispatch_mode(argc, argv);
}
