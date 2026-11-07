// Test-owned pure-data driver for the shared nativeVerifier role binding.
//
// It models the UID0 private-root metadata gate explicitly (never a root
// wrapper) and then exercises the exact stage role checks on an owned UID1000
// private filesystem.  Nothing here is a product entry, installer, service,
// host probe or packaged ELF execution.
#include "../src/preauth_modes.cpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool ok, const char *name) {
  std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) ++failures;
}

bool expect_failure(void (*fn)(), const char *name) {
  try {
    fn();
  } catch (const std::exception &) {
    check(true, name);
    return true;
  } catch (...) {
    check(true, name);
    return true;
  }
  check(false, name);
  return false;
}

std::string read_all(const std::string &path) {
  FILE *file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) return std::string();
  std::string data;
  char buffer[4096];
  size_t count;
  while ((count = std::fread(buffer, 1, sizeof(buffer), file)) != 0) {
    data.append(buffer, count);
  }
  std::fclose(file);
  return data;
}

void write_all(const std::string &path, const std::string &data, uint32_t mode) {
  FILE *file = std::fopen(path.c_str(), "wb");
  if (file == nullptr) throw std::runtime_error("open failed");
  if (!data.empty() && std::fwrite(data.data(), 1, data.size(), file) != data.size()) {
    std::fclose(file);
    throw std::runtime_error("write failed");
  }
  std::fclose(file);
  if (::chmod(path.c_str(), mode) != 0) throw std::runtime_error("chmod failed");
}

std::string sha256_of(const std::string &data) {
  Sha256 hash;
  hash.update(data.data(), data.size());
  return hash.finish();
}

std::string sums_row(const std::string &digest, const std::string &name) {
  return digest + "  " + name + "\n";
}

struct Fixture {
  std::string root;
  std::string package;
  std::string verifier;
  std::string sums;
  std::string payload = "native verifier role bytes\n";
  NativeVerifierRole role;
};

Fixture make_fixture(const std::string &root, bool declared, uint32_t mode = 0755) {
  Fixture fixture;
  fixture.root = root;
  fixture.package = root + "/package";
  ::mkdir(root.c_str(), 0777);
  ::mkdir(fixture.package.c_str(), 0777);
  fixture.verifier = fixture.package + "/" + kNativeVerifier;
  fixture.sums = fixture.package + "/SHA256SUMS";
  write_all(fixture.verifier, fixture.payload, mode);
  fixture.role.present = declared;
  fixture.role.sha256 = sha256_of(fixture.payload);
  fixture.role.size = fixture.payload.size();
  write_all(fixture.sums, sums_row(fixture.role.sha256, kNativeVerifier), 0600);
  ::mkdir((fixture.package + "/staged").c_str(), 0777);
  return fixture;
}

void run_stage(const Fixture &fixture) {
  std::vector<std::string> created;
  std::vector<std::string> files;
  const StagedEntry entry = stage_native_verifier(
      fixture.package, fixture.package + "/staged", fixture.role, created, files);
  (void)entry;
}

void stage_into(const std::string &source, const std::string &target) {
  stage_copy_source(source, target, "probe", 1024 * 1024, "probe");
}

}  // namespace

int main(int argc, char **argv) {
  if (argc >= 3 && std::string(argv[2]) == "fd-read") {
    try {
      read_bounded_file(argv[1], 1024 * 1024, "probe");
    } catch (...) {
      std::printf("FDHOOK_REFUSED\n");
      return 0;
    }
    std::printf("FDHOOK_OPEN_SUCCEEDED\n");
    return 1;
  }
  if (argc >= 3 && std::string(argv[2]) == "fd-copy") {
    try {
      stage_into(argv[1], std::string(argv[1]) + ".copy");
    } catch (...) {
      std::printf("FDHOOK_REFUSED\n");
      return 0;
    }
    std::printf("FDHOOK_OPEN_SUCCEEDED\n");
    return 1;
  }
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s WORKROOT [fd-read|fd-copy PATH]\n", argv[0]);
    return 2;
  }
  const std::string work = argv[1];
  ::mkdir(work.c_str(), 0700);
  const std::string package = work + "/package";
  ::mkdir(package.c_str(), 0700);
  ::mkdir((package + "/staged").c_str(), 0700);

  // UID0 private-root metadata model (explicit, before any real entry).
  struct stat model {};
  model.st_mode = S_IFDIR | 0700;
  model.st_uid = 0;
  check(private_root_metadata_ok(model), "MODEL_uid0_0700_dir_accepted");
  model.st_uid = 1000;
  check(!private_root_metadata_ok(model), "MODEL_uid1000_dir_rejected");
  model.st_uid = 0;
  model.st_mode = S_IFDIR | 0755;
  check(!private_root_metadata_ok(model), "MODEL_uid0_0755_dir_rejected");
  model.st_mode = S_IFREG | 0700;
  check(!private_root_metadata_ok(model), "MODEL_uid0_0700_regular_rejected");

  // Role JSON boundary.
  check(!require_native_verifier_role(parse_json("{}")).present,
        "ROLE_absent_legacy_ok");
  const std::string hex64(64, 'a');
  const std::string body = "{\"path\":\"" + std::string(kNativeVerifier) +
                           "\",\"sha256\":\"" + hex64 + "\",\"size\":3}";
  const std::string valid = "{\"nativeVerifier\":" + body + "}";
  check(require_native_verifier_role(parse_json(valid)).present,
        "ROLE_exact_object_accepted");
  const std::vector<std::string> bad = {
      "{\"nativeVerifier\":{\"path\":\"wrong\",\"sha256\":\"" + hex64 + "\",\"size\":3}}",
      "{\"nativeVerifier\":{\"path\":\"" + std::string(kNativeVerifier) + "\",\"sha256\":\"" + hex64 + "\",\"size\":true}}",
      "{\"nativeVerifier\":{\"path\":\"" + std::string(kNativeVerifier) + "\",\"sha256\":\"" + hex64 + "\",\"size\":3,\"mode\":\"0755\"}}",
      "{\"nativeVerifier\":{\"path\":\"" + std::string(kNativeVerifier) + "\",\"sha256\":\"" + std::string(64, 'A') + "\",\"size\":3}}",
      "{\"nativeVerifier\":{\"path\":\"" + std::string(kNativeVerifier) + "\",\"sha256\":\"" + hex64 + "\",\"size\":0}}",
      "{\"nativeVerifier\":{\"path\":\"" + std::string(kNativeVerifier) + "\",\"sha256\":\"" + hex64 + "\",\"size\":8388609}}",
      "{\"nativeVerifier\":[]}",
      "{\"nativeVerifier\":true}"};
  for (size_t index = 0; index < bad.size(); ++index) {
    bool refused = false;
    try {
      require_native_verifier_role(parse_json(bad[index]));
    } catch (...) {
      refused = true;
    }
    check(refused, ("ROLE_bad_" + std::to_string(index) + "_rejected").c_str());
  }

  // Exact stage role checks on an owned UID1000 filesystem.
  Fixture good = make_fixture(work + "/good", true);
  std::vector<std::string> created;
  std::vector<std::string> files;
  bool staged = false;
  try {
    const StagedEntry entry = stage_native_verifier(
        good.package, good.package + "/staged", good.role, created, files);
    const std::string staged_path = good.package + "/staged/" + kNativeVerifier;
    struct stat metadata {};
    staged = entry.size == good.role.size && entry.sha256 == good.role.sha256 &&
             files.size() == 1 && files[0] == kNativeVerifier &&
             ::lstat(staged_path.c_str(), &metadata) == 0 &&
             S_ISREG(metadata.st_mode) &&
             (metadata.st_mode & 0777u) == 0755u &&
             read_all(staged_path) == good.payload;
  } catch (...) {
    staged = false;
  }
  check(staged, "STAGE_declared_role_copied_exact_0755");

  Fixture wrong_mode = make_fixture(work + "/wrong-mode", true, 0644);
  bool refused = false;
  try { run_stage(wrong_mode); } catch (...) { refused = true; }
  check(refused, "STAGE_role_mode_0644_rejected");

  Fixture wrong_size = make_fixture(work + "/wrong-size", true);
  wrong_size.role.size += 1;
  refused = false;
  try { run_stage(wrong_size); } catch (...) { refused = true; }
  check(refused, "STAGE_role_size_mismatch_rejected");

  Fixture wrong_sha = make_fixture(work + "/wrong-sha", true);
  wrong_sha.role.sha256 = std::string(64, 'b');
  refused = false;
  try { run_stage(wrong_sha); } catch (...) { refused = true; }
  check(refused, "STAGE_role_sha_mismatch_rejected");

  Fixture bad_row = make_fixture(work + "/bad-row", true);
  write_all(bad_row.sums, sums_row(std::string(64, 'c'), kNativeVerifier), 0600);
  refused = false;
  try { run_stage(bad_row); } catch (...) { refused = true; }
  check(refused, "STAGE_role_checksum_row_mismatch_rejected");

  Fixture missing = make_fixture(work + "/missing", true);
  ::unlink(missing.verifier.c_str());
  refused = false;
  try { run_stage(missing); } catch (...) { refused = true; }
  check(refused, "STAGE_role_missing_member_rejected");

  Fixture symlink = make_fixture(work + "/symlink", true);
  const std::string link_target = symlink.package + "/target";
  write_all(link_target, symlink.payload, 0755);
  ::unlink(symlink.verifier.c_str());
  if (::symlink(link_target.c_str(), symlink.verifier.c_str()) != 0) return 2;
  refused = false;
  try { run_stage(symlink); } catch (...) { refused = true; }
  check(refused, "STAGE_role_symlink_member_rejected");

  Fixture undeclared_present = make_fixture(work + "/undeclared-present", false);
  refused = false;
  try { run_stage(undeclared_present); } catch (...) { refused = true; }
  check(refused, "STAGE_undeclared_role_present_rejected");

  Fixture undeclared_absent = make_fixture(work + "/undeclared-absent", false);
  ::unlink(undeclared_absent.verifier.c_str());
  write_all(undeclared_absent.sums, "", 0600);
  bool legacy_noop = false;
  try {
    const StagedEntry entry = stage_native_verifier(
        undeclared_absent.package, undeclared_absent.package + "/staged",
        undeclared_absent.role, created, files);
    legacy_noop = !entry.name.empty() ? false : true;
  } catch (...) {
    legacy_noop = false;
  }
  check(legacy_noop, "STAGE_undeclared_absent_legacy_noop");

  std::printf("FAILURES %d\n", failures);
  return failures == 0 ? 0 : 1;
}
