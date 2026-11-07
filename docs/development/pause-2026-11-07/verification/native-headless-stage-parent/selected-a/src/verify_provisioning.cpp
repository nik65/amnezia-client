// Amnezia headless provisioning receipt verifier (native, verify-only).
//
// Independent C++ port of deploy/headless/verify_provisioning_bundle.py plus
// the archive/manifest contract implemented by deploy/selfhosted_updates/
// make_manifest.py.  It consumes a signed self-hosted update manifest, the
// pinned Ed25519 public key and the provisioning tar.gz, and emits the exact
// schema-1 receipt consumed by install_headless.sh.
//
// This tool is verify-only by design: it never extracts the archive, never
// executes the packaged installer and has no --run-installer option.  It does
// not authenticate itself; the caller supplies the pinned expected key digest.
//
// Build: g++ -std=c++17 -O2 -Wall -Wextra -o build/bin/... src/*.cpp -lcrypto -lz
// Runtime dependencies: libcrypto (OpenSSL 3) and zlib, both already required
// by the headless package runtime contract.

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <zlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr uint64_t kMaxManifestBytes = 1024ull * 1024ull;
constexpr uint64_t kMaxPublicKeyBytes = 64ull * 1024ull;
constexpr uint64_t kMaxArchiveBytes = 512ull * 1024ull * 1024ull;
constexpr uint64_t kMaxMemberBytes = 8ull * 1024ull * 1024ull;
constexpr uint64_t kMaxDecompressedBytes = 128ull * 1024ull * 1024ull;
constexpr uint64_t kMaxTarExtensionBytes = 64ull * 1024ull;
constexpr uint64_t kMaxVersionComponent = 2147483647ull;

const char *const kProvisioningFormat = "amnezia-headless-provisioning-tar-v1";
const char *const kArtifactFormat = "amnezia-headless-tar-v1";
const char *const kNativeHelper = "amnezia-headless-fs";
const char *const kNativeCli = "amnezia-cli";
const char *const kNativeVerifier = "amnezia-verify-provisioning-native";

struct Failure : public std::runtime_error {
  explicit Failure(const std::string &message) : std::runtime_error(message) {}
};

[[noreturn]] void fail(const std::string &message) { throw Failure(message); }

const std::vector<std::string> &base_package_files() {
  static const std::vector<std::string> files = {
      "install_headless.sh",       "amneziad",
      "amnezia-cli",               "amneziad.service",
      "package-manifest.json",     "runtime-dependencies.json",
      "runtime-dependencies.txt",  "SHA256SUMS",
  };
  return files;
}

bool is_lower_hex_64(const std::string &value) {
  if (value.size() != 64) return false;
  for (char c : value) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

std::string hex_lower(const unsigned char *data, size_t size) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  out.resize(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out[i * 2] = digits[data[i] >> 4];
    out[i * 2 + 1] = digits[data[i] & 0x0F];
  }
  return out;
}

class Sha256 {
 public:
  Sha256() : ctx_(EVP_MD_CTX_new()) {
    if (ctx_ == nullptr || EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1) {
      fail("unable to initialize SHA-256");
    }
  }
  Sha256(const Sha256 &) = delete;
  Sha256 &operator=(const Sha256 &) = delete;
  ~Sha256() { EVP_MD_CTX_free(ctx_); }

  void update(const void *data, size_t size) {
    if (size != 0 && EVP_DigestUpdate(ctx_, data, size) != 1) {
      fail("unable to update SHA-256");
    }
  }
  std::string finish() {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(ctx_, digest, &length) != 1 || length != 32) {
      fail("unable to finalize SHA-256");
    }
    return hex_lower(digest, length);
  }

 private:
  EVP_MD_CTX *ctx_;
};

std::string sha256_bytes(const std::string &data) {
  Sha256 hash;
  hash.update(data.data(), data.size());
  return hash.finish();
}

bool same_file_identity(const struct stat &before, const struct stat &after) {
  return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
         before.st_size == after.st_size &&
         before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
}

void write_all(int fd, const char *data, size_t size, const char *label) {
  size_t written = 0;
  while (written < size) {
    ssize_t result = ::write(fd, data + written, size - written);
    if (result < 0) {
      if (errno == EINTR) continue;
      fail(std::string("unable to write ") + label);
    }
    written += static_cast<size_t>(result);
  }
}

struct FileData {
  std::string bytes;
  uint64_t size = 0;
};

FileData read_regular_file(const std::string &path, uint64_t maximum,
                           const char *label, bool allow_empty) {
  int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) fail(std::string(label) + " must be a regular file");
  struct stat before {};
  if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
      before.st_size < 0 ||
      (before.st_size == 0 && !allow_empty) ||
      static_cast<uint64_t>(before.st_size) > maximum) {
    ::close(fd);
    fail(std::string(label) + " must be a regular file within the size limit");
  }
  FileData result;
  result.bytes.reserve(static_cast<size_t>(before.st_size));
  char buffer[1024 * 1024];
  while (true) {
    ssize_t count = ::read(fd, buffer, sizeof(buffer));
    if (count < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      fail(std::string("unable to read ") + label);
    }
    if (count == 0) break;
    result.bytes.append(buffer, static_cast<size_t>(count));
    if (result.bytes.size() > maximum) {
      ::close(fd);
      fail(std::string(label) + " exceeds the size limit");
    }
  }
  struct stat after {};
  if (::fstat(fd, &after) != 0 || !same_file_identity(before, after) ||
      static_cast<uint64_t>(after.st_size) != result.bytes.size()) {
    ::close(fd);
    fail(std::string(label) + " changed while it was being read");
  }
  ::close(fd);
  result.size = result.bytes.size();
  return result;
}

struct HashedFile {
  uint64_t size = 0;
  std::string sha256;
};

HashedFile hash_regular_file(const std::string &path, uint64_t maximum,
                             const char *label) {
  int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) fail(std::string(label) + " must be a regular file");
  struct stat before {};
  if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
      before.st_size <= 0 ||
      static_cast<uint64_t>(before.st_size) > maximum) {
    ::close(fd);
    fail(std::string(label) + " must be a regular file within the size limit");
  }
  Sha256 hash;
  uint64_t total = 0;
  char buffer[1024 * 1024];
  while (true) {
    ssize_t count = ::read(fd, buffer, sizeof(buffer));
    if (count < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      fail(std::string("unable to read ") + label);
    }
    if (count == 0) break;
    hash.update(buffer, static_cast<size_t>(count));
    total += static_cast<uint64_t>(count);
    if (total > maximum) {
      ::close(fd);
      fail(std::string(label) + " exceeds the size limit");
    }
  }
  struct stat after {};
  if (::fstat(fd, &after) != 0 || !same_file_identity(before, after) ||
      static_cast<uint64_t>(after.st_size) != total) {
    ::close(fd);
    fail(std::string(label) + " changed while it was being read");
  }
  ::close(fd);
  return {total, hash.finish()};
}

struct CopyResult {
  std::string path;
  uint64_t size = 0;
  std::string sha256;
};

CopyResult copy_to_private(const std::string &source, const std::string &directory,
                           const std::string &name, uint64_t maximum,
                           const char *label) {
  int source_fd = ::open(source.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (source_fd < 0) fail(std::string(label) + " must be a regular file");
  struct stat before {};
  if (::fstat(source_fd, &before) != 0 || !S_ISREG(before.st_mode) ||
      before.st_size <= 0 ||
      static_cast<uint64_t>(before.st_size) > maximum) {
    ::close(source_fd);
    fail(std::string(label) + " must be a regular file within the size limit");
  }
  const std::string destination = directory + "/" + name;
  int target_fd = ::open(destination.c_str(),
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (target_fd < 0) {
    ::close(source_fd);
    fail(std::string("unable to create a private copy of ") + label);
  }
  Sha256 hash;
  uint64_t total = 0;
  std::vector<char> buffer(1024 * 1024);
  bool failed = false;
  std::string failure_message;
  while (true) {
    ssize_t count = ::read(source_fd, buffer.data(), buffer.size());
    if (count < 0) {
      if (errno == EINTR) continue;
      failed = true;
      failure_message = std::string("unable to read ") + label;
      break;
    }
    if (count == 0) break;
    hash.update(buffer.data(), static_cast<size_t>(count));
    total += static_cast<uint64_t>(count);
    if (total > maximum) {
      failed = true;
      failure_message = std::string(label) + " exceeds the size limit";
      break;
    }
    try {
      write_all(target_fd, buffer.data(), static_cast<size_t>(count), "private copy");
    } catch (const Failure &error) {
      failed = true;
      failure_message = error.what();
      break;
    }
  }
  struct stat after {};
  if (!failed &&
      (::fstat(source_fd, &after) != 0 || !same_file_identity(before, after) ||
       total != static_cast<uint64_t>(before.st_size))) {
    failed = true;
    failure_message = std::string(label) + " changed while it was being copied";
  }
  if (!failed && ::fsync(target_fd) != 0) {
    failed = true;
    failure_message = "unable to flush the private copy";
  }
  ::close(target_fd);
  ::close(source_fd);
  const std::string digest = hash.finish();
  if (!failed) {
    try {
      const HashedFile private_hash =
          hash_regular_file(destination, maximum, "private copy");
      if (private_hash.size != total || private_hash.sha256 != digest) {
        failed = true;
        failure_message = std::string("private ") + label +
                          " copy has an unexpected size or digest";
      }
    } catch (const Failure &error) {
      failed = true;
      failure_message = error.what();
    }
  }
  if (failed) {
    ::unlink(destination.c_str());
    fail(failure_message);
  }
  return {destination, total, digest};
}

class PrivateDirectory {
 public:
  PrivateDirectory() {
    const char *configured = std::getenv("TMPDIR");
    std::string base = (configured != nullptr && *configured != '\0')
                           ? std::string(configured)
                           : std::string("/tmp");
    std::string pattern = base + "/amnezia-native-verify-XXXXXX";
    std::vector<char> writable(pattern.begin(), pattern.end());
    writable.push_back('\0');
    if (::mkdtemp(writable.data()) == nullptr) {
      fail("unable to create a private verification directory");
    }
    path_ = writable.data();
    ::chmod(path_.c_str(), 0700);
  }
  PrivateDirectory(const PrivateDirectory &) = delete;
  PrivateDirectory &operator=(const PrivateDirectory &) = delete;
  ~PrivateDirectory() {
    for (const char *name :
         {"manifest.json", "update-public-key.pem", "provisioning.tar.gz"}) {
      ::unlink((path_ + "/" + name).c_str());
    }
    ::rmdir(path_.c_str());
  }
  const std::string &path() const { return path_; }

 private:
  std::string path_;
};

// ---------------------------------------------------------------------------
// Strict JSON (objects/arrays/strings/integers, duplicate-key rejection)

struct Json {
  enum class Kind { Null, Bool, Int, Double, String, Array, Object };
  Kind kind = Kind::Null;
  bool boolean = false;
  int64_t integer = 0;
  double number = 0;
  std::string text;
  std::vector<Json> array;
  std::vector<std::pair<std::string, Json>> object;

  const Json *get(const std::string &key) const {
    if (kind != Kind::Object) return nullptr;
    for (const auto &entry : object) {
      if (entry.first == key) return &entry.second;
    }
    return nullptr;
  }
};

class JsonParser {
 public:
  explicit JsonParser(const std::string &text) : text_(text) {}

  Json parse_document() {
    Json value = parse_value();
    skip_whitespace();
    if (position_ != text_.size()) error("trailing data");
    return value;
  }

 private:
  const std::string &text_;
  size_t position_ = 0;
  int depth_ = 0;
  size_t nodes_ = 0;

  [[noreturn]] void error(const std::string &message) {
    fail("invalid JSON: " + message + " at byte " +
         std::to_string(position_));
  }
  void skip_whitespace() {
    while (position_ < text_.size()) {
      const char c = text_[position_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++position_;
      } else {
        break;
      }
    }
  }
  char peek() {
    if (position_ >= text_.size()) error("unexpected end of input");
    return text_[position_];
  }
  char take() {
    if (position_ >= text_.size()) error("unexpected end of input");
    return text_[position_++];
  }
  void expect(char expected) {
    if (position_ >= text_.size() || text_[position_] != expected) {
      error(std::string("expected '") + expected + "'");
    }
    ++position_;
  }
  static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  }
  void append_utf8(std::string &out, uint32_t code_point) {
    if (code_point <= 0x7F) {
      out.push_back(static_cast<char>(code_point));
    } else if (code_point <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0 | (code_point >> 6)));
      out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    } else if (code_point <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0 | (code_point >> 12)));
      out.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (code_point >> 18)));
      out.push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
    }
  }
  std::string parse_string() {
    expect('"');
    std::string out;
    while (true) {
      if (position_ >= text_.size()) error("unterminated string");
      unsigned char c = static_cast<unsigned char>(text_[position_++]);
      if (c == '"') break;
      if (c == '\\') {
        const char escape = take();
        switch (escape) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            uint32_t code_point = 0;
            for (int i = 0; i < 4; ++i) {
              const int digit = hex_digit(take());
              if (digit < 0) error("invalid unicode escape");
              code_point = (code_point << 4) | static_cast<uint32_t>(digit);
            }
            if (code_point >= 0xD800 && code_point <= 0xDBFF) {
              if (take() != '\\' || take() != 'u') {
                error("unpaired high surrogate");
              }
              uint32_t low = 0;
              for (int i = 0; i < 4; ++i) {
                const int digit = hex_digit(take());
                if (digit < 0) error("invalid unicode escape");
                low = (low << 4) | static_cast<uint32_t>(digit);
              }
              if (low < 0xDC00 || low > 0xDFFF) error("invalid low surrogate");
              code_point = 0x10000 + ((code_point - 0xD800) << 10) +
                           (low - 0xDC00);
            } else if (code_point >= 0xDC00 && code_point <= 0xDFFF) {
              error("unpaired low surrogate");
            }
            append_utf8(out, code_point);
            break;
          }
          default:
            error("invalid escape sequence");
        }
        continue;
      }
      if (c < 0x20) error("control character in string");
      if (c < 0x80) {
        out.push_back(static_cast<char>(c));
        continue;
      }
      int continuation = 0;
      uint32_t code_point = 0;
      if ((c & 0xE0) == 0xC0) {
        continuation = 1;
        code_point = c & 0x1F;
      } else if ((c & 0xF0) == 0xE0) {
        continuation = 2;
        code_point = c & 0x0F;
      } else if ((c & 0xF8) == 0xF0) {
        continuation = 3;
        code_point = c & 0x07;
      } else {
        error("invalid UTF-8 lead byte");
      }
      for (int i = 0; i < continuation; ++i) {
        if (position_ >= text_.size()) error("truncated UTF-8 sequence");
        const unsigned char next =
            static_cast<unsigned char>(text_[position_++]);
        if ((next & 0xC0) != 0x80) error("invalid UTF-8 continuation");
        code_point = (code_point << 6) | (next & 0x3F);
      }
      if ((continuation == 1 && code_point < 0x80) ||
          (continuation == 2 && code_point < 0x800) ||
          (continuation == 3 && code_point < 0x10000) ||
          code_point > 0x10FFFF || (code_point >= 0xD800 && code_point <= 0xDFFF)) {
        error("non-canonical UTF-8 sequence");
      }
      out.push_back(static_cast<char>(c));
      for (int i = 0; i < continuation; ++i) {
        out.push_back(text_[position_ - continuation + i]);
      }
    }
    return out;
  }
  Json parse_number() {
    const size_t start = position_;
    if (peek() == '-') ++position_;
    if (position_ >= text_.size()) error("truncated number");
    if (text_[position_] == '0') {
      ++position_;
      if (position_ < text_.size() && text_[position_] >= '0' &&
          text_[position_] <= '9') {
        error("leading zero in number");
      }
    } else if (text_[position_] >= '1' && text_[position_] <= '9') {
      while (position_ < text_.size() && text_[position_] >= '0' &&
             text_[position_] <= '9') {
        ++position_;
      }
    } else {
      error("invalid number");
    }
    bool is_integer = true;
    if (position_ < text_.size() && text_[position_] == '.') {
      is_integer = false;
      ++position_;
      if (position_ >= text_.size() || text_[position_] < '0' ||
          text_[position_] > '9') {
        error("invalid fraction");
      }
      while (position_ < text_.size() && text_[position_] >= '0' &&
             text_[position_] <= '9') {
        ++position_;
      }
    }
    if (position_ < text_.size() &&
        (text_[position_] == 'e' || text_[position_] == 'E')) {
      is_integer = false;
      ++position_;
      if (position_ < text_.size() &&
          (text_[position_] == '+' || text_[position_] == '-')) {
        ++position_;
      }
      if (position_ >= text_.size() || text_[position_] < '0' ||
          text_[position_] > '9') {
        error("invalid exponent");
      }
      while (position_ < text_.size() && text_[position_] >= '0' &&
             text_[position_] <= '9') {
        ++position_;
      }
    }
    const std::string token = text_.substr(start, position_ - start);
    Json value;
    if (is_integer) {
      errno = 0;
      char *end = nullptr;
      const long long number = std::strtoll(token.c_str(), &end, 10);
      if (errno == 0 && end != nullptr && *end == '\0') {
        value.kind = Json::Kind::Int;
        value.integer = static_cast<int64_t>(number);
        return value;
      }
    }
    errno = 0;
    char *end = nullptr;
    const double number = std::strtod(token.c_str(), &end);
    if (end == nullptr || *end != '\0' || !std::isfinite(number)) {
      error("number is not representable");
    }
    value.kind = Json::Kind::Double;
    value.number = number;
    return value;
  }
  Json parse_value() {
    skip_whitespace();
    if (++nodes_ > 200000) error("document is too large");
    const char c = peek();
    if (c == '{' || c == '[') {
      if (++depth_ > 64) error("nesting is too deep");
      Json value;
      if (c == '{') {
        value.kind = Json::Kind::Object;
        ++position_;
        skip_whitespace();
        if (peek() == '}') {
          ++position_;
        } else {
          while (true) {
            skip_whitespace();
            std::string key = parse_string();
            for (const auto &entry : value.object) {
              if (entry.first == key) error("duplicate object key: " + key);
            }
            skip_whitespace();
            expect(':');
            Json item = parse_value();
            value.object.emplace_back(std::move(key), std::move(item));
            skip_whitespace();
            const char separator = take();
            if (separator == '}') break;
            if (separator != ',') error("expected ',' or '}'");
          }
        }
      } else {
        value.kind = Json::Kind::Array;
        ++position_;
        skip_whitespace();
        if (peek() == ']') {
          ++position_;
        } else {
          while (true) {
            value.array.push_back(parse_value());
            skip_whitespace();
            const char separator = take();
            if (separator == ']') break;
            if (separator != ',') error("expected ',' or ']'");
          }
        }
      }
      --depth_;
      return value;
    }
    if (c == '"') {
      Json value;
      value.kind = Json::Kind::String;
      value.text = parse_string();
      return value;
    }
    if (c == 't' && text_.compare(position_, 4, "true") == 0) {
      position_ += 4;
      Json value;
      value.kind = Json::Kind::Bool;
      value.boolean = true;
      return value;
    }
    if (c == 'f' && text_.compare(position_, 5, "false") == 0) {
      position_ += 5;
      Json value;
      value.kind = Json::Kind::Bool;
      value.boolean = false;
      return value;
    }
    if (c == 'n' && text_.compare(position_, 4, "null") == 0) {
      position_ += 4;
      return Json();
    }
    return parse_number();
  }
};

Json parse_json(const std::string &text) {
  JsonParser parser(text);
  return parser.parse_document();
}

const Json &require_object(const Json &value, const char *what) {
  if (value.kind != Json::Kind::Object) {
    fail(std::string(what) + " must be a JSON object");
  }
  return value;
}

const Json &require_field(const Json &object, const char *key,
                          const char *what) {
  const Json *field = object.get(key);
  if (field == nullptr) {
    fail(std::string(what) + " is missing the field: " + std::string(key));
  }
  return *field;
}

std::string require_string(const Json &object, const char *key,
                           const char *what) {
  const Json &field = require_field(object, key, what);
  if (field.kind != Json::Kind::String) {
    fail(std::string(what) + " field " + std::string(key) + " must be a string");
  }
  return field.text;
}

int64_t require_integer(const Json &object, const char *key,
                        const char *what) {
  const Json &field = require_field(object, key, what);
  if (field.kind != Json::Kind::Int) {
    fail(std::string(what) + " field " + std::string(key) + " must be an integer");
  }
  return field.integer;
}

void require_exact_keys(const Json &object,
                        const std::vector<std::string> &keys,
                        const char *what) {
  require_object(object, what);
  if (object.object.size() != keys.size()) {
    fail(std::string(what) + " has an invalid exact key set");
  }
  for (const auto &key : keys) {
    if (object.get(key) == nullptr) {
      fail(std::string(what) + " has an invalid exact key set");
    }
  }
}

void require_string_array(const Json &value,
                          const std::vector<std::string> &expected,
                          const char *what) {
  if (value.kind != Json::Kind::Array || value.array.size() != expected.size()) {
    fail(std::string(what) + " is not the exact expected string list");
  }
  for (size_t i = 0; i < expected.size(); ++i) {
    if (value.array[i].kind != Json::Kind::String ||
        value.array[i].text != expected[i]) {
      fail(std::string(what) + " is not the exact expected string list");
    }
  }
}

std::vector<std::string> require_string_array(const Json &value,
                                              const char *what) {
  if (value.kind != Json::Kind::Array) {
    fail(std::string(what) + " must be a JSON array");
  }
  std::vector<std::string> result;
  result.reserve(value.array.size());
  for (const auto &entry : value.array) {
    if (entry.kind != Json::Kind::String) {
      fail(std::string(what) + " must contain only strings");
    }
    result.push_back(entry.text);
  }
  return result;
}

bool is_false_or_absent(const Json &object, const std::string &key) {
  const Json *field = object.get(key);
  return field == nullptr ||
         (field->kind == Json::Kind::Bool && !field->boolean);
}

// ---------------------------------------------------------------------------
// Strict base64 (standard with canonical padding, or unpadded URL-safe)

int base64_value(char c, bool url_safe) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (url_safe) {
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
  }
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

std::string base64_decode(const std::string &input, bool url_safe,
                          bool padded, const char *what) {
  if (input.empty()) fail(std::string(what) + " is empty");
  size_t padding = 0;
  size_t length = input.size();
  if (padded) {
    if (length % 4 != 0) fail(std::string(what) + " is not valid base64");
    while (length > 0 && input[length - 1] == '=') {
      ++padding;
      --length;
    }
    if (padding > 2) fail(std::string(what) + " is not valid base64");
    const size_t expected_padding = (4 - (length % 4)) % 4;
    if (padding != expected_padding) {
      fail(std::string(what) + " is not valid base64");
    }
  } else if (input.find('=') != std::string::npos) {
    fail(std::string(what) + " is not valid unpadded base64url");
  }
  if (length % 4 == 1) fail(std::string(what) + " is not valid base64");
  std::string output;
  output.reserve(length * 3 / 4);
  uint32_t accumulator = 0;
  int bits = 0;
  for (size_t i = 0; i < length; ++i) {
    const int value = base64_value(input[i], url_safe);
    if (value < 0) fail(std::string(what) + " is not valid base64");
    accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output.push_back(static_cast<char>((accumulator >> bits) & 0xFF));
    }
  }
  if (bits > 0 && (accumulator & ((1u << bits) - 1u)) != 0) {
    fail(std::string(what) + " has non-canonical trailing bits");
  }
  return output;
}

void verify_ed25519(const std::string &public_key_bytes,
                    const std::string &payload, const std::string &signature) {
  BIO *bio = BIO_new_mem_buf(public_key_bytes.data(),
                             static_cast<int>(public_key_bytes.size()));
  if (bio == nullptr) fail("unable to parse the public key");
  EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (key == nullptr) fail("public key is not a readable PEM public key");
  if (EVP_PKEY_get_base_id(key) != EVP_PKEY_ED25519) {
    EVP_PKEY_free(key);
    fail("public key is not an Ed25519 public key");
  }
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  bool ok = context != nullptr &&
            EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1;
  if (ok) {
    ok = EVP_DigestVerify(
             context,
             reinterpret_cast<const unsigned char *>(signature.data()),
             signature.size(),
             reinterpret_cast<const unsigned char *>(payload.data()),
             payload.size()) == 1;
  }
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  if (!ok) {
    fail("signed update manifest signature verification failed");
  }
}

// ---------------------------------------------------------------------------
// Bounded gzip/tar reader (GNU tar and ustar dialects, PAX path records)

class GzReader {
 public:
  GzReader(int fd, uint64_t maximum) : fd_(fd), maximum_(maximum) {
    std::memset(&stream_, 0, sizeof(stream_));
    stream_.zalloc = Z_NULL;
    stream_.zfree = Z_NULL;
    stream_.opaque = Z_NULL;
    if (inflateInit2(&stream_, 16 + MAX_WBITS) != Z_OK) {
      ::close(fd_);
      fd_ = -1;
      fail("unable to initialize the gzip decoder");
    }
  }
  GzReader(const GzReader &) = delete;
  GzReader &operator=(const GzReader &) = delete;
  ~GzReader() {
    inflateEnd(&stream_);
    if (fd_ >= 0) ::close(fd_);
  }

  size_t read(unsigned char *output, size_t length) {
    size_t produced = 0;
    while (produced < length) {
      if (stream_end_) break;
      if (stream_.avail_in == 0 && !source_eof_) fill_input();
      const size_t before = produced;
      stream_.next_out = output + produced;
      stream_.avail_out = static_cast<uInt>(length - produced);
      const int status = inflate(&stream_, Z_NO_FLUSH);
      produced = length - stream_.avail_out;
      total_produced_ += produced - before;
      if (total_produced_ > maximum_) {
        fail("provisioning archive expands beyond the verification limit");
      }
      if (status == Z_STREAM_END) {
        stream_end_ = true;
        break;
      }
      if (status != Z_OK && status != Z_BUF_ERROR) {
        fail("provisioning archive gzip stream is invalid or truncated");
      }
      if (produced == before) {
        if (status == Z_BUF_ERROR || (source_eof_ && stream_.avail_in == 0)) {
          fail("provisioning archive gzip stream is truncated");
        }
      }
    }
    return produced;
  }

  void read_exact(unsigned char *output, size_t length, const char *what) {
    size_t offset = 0;
    while (offset < length) {
      const size_t count = read(output + offset, length - offset);
      if (count == 0) fail(std::string("truncated ") + what);
      offset += count;
    }
  }

  void skip(uint64_t length) {
    unsigned char buffer[64 * 1024];
    while (length > 0) {
      const size_t chunk = static_cast<size_t>(
          std::min<uint64_t>(length, sizeof(buffer)));
      read_exact(buffer, chunk, "tar padding");
      length -= chunk;
    }
  }

 private:
  void fill_input() {
    ssize_t count;
    do {
      count = ::read(fd_, input_, sizeof(input_));
    } while (count < 0 && errno == EINTR);
    if (count < 0) fail("unable to read the provisioning archive");
    if (count == 0) {
      source_eof_ = true;
      return;
    }
    stream_.next_in = input_;
    stream_.avail_in = static_cast<uInt>(count);
  }

  int fd_;
  uint64_t maximum_;
  uint64_t total_produced_ = 0;
  z_stream stream_{};
  unsigned char input_[64 * 1024]{};
  bool source_eof_ = false;
  bool stream_end_ = false;
};

struct TarMember {
  uint32_t mode = 0;
  uint64_t size = 0;
  std::string sha256;
  std::string data;
  bool has_data = false;
};

std::string tar_text(const unsigned char *field, size_t length) {
  size_t used = 0;
  while (used < length && field[used] != 0) ++used;
  return std::string(reinterpret_cast<const char *>(field), used);
}

uint64_t tar_octal(const unsigned char *field, size_t length, const char *what) {
  size_t index = 0;
  while (index < length && (field[index] == ' ' || field[index] == 0)) ++index;
  if (index < length && (field[index] & 0x80) != 0) {
    fail(std::string("unsupported base-256 tar header field: ") + what);
  }
  uint64_t value = 0;
  bool any = false;
  while (index < length && field[index] >= '0' && field[index] <= '7') {
    any = true;
    if (value > (std::numeric_limits<uint64_t>::max() >> 3)) {
      fail(std::string("tar header field overflows: ") + what);
    }
    value = (value << 3) | static_cast<uint64_t>(field[index] - '0');
    ++index;
  }
  while (index < length && (field[index] == ' ' || field[index] == 0)) ++index;
  if (!any || index != length) {
    fail(std::string("invalid tar header field: ") + what);
  }
  return value;
}

bool all_zero(const unsigned char *block, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    if (block[i] != 0) return false;
  }
  return true;
}

bool verify_tar_checksum(const unsigned char *block) {
  const uint64_t stored = tar_octal(block + 148, 8, "checksum");
  uint64_t unsigned_sum = 0;
  int64_t signed_sum = 0;
  for (size_t i = 0; i < 512; ++i) {
    const unsigned char value = (i >= 148 && i < 156) ? ' ' : block[i];
    unsigned_sum += value;
    signed_sum += static_cast<int8_t>(value);
  }
  return unsigned_sum == stored ||
         (signed_sum >= 0 && static_cast<uint64_t>(signed_sum) == stored);
}

bool safe_member_name(const std::string &name) {
  if (name.empty() || name[0] == '/') return false;
  const size_t slash = name.find('/');
  if (slash == std::string::npos) return false;
  const std::string directory = name.substr(0, slash);
  const std::string leaf = name.substr(slash + 1);
  if (directory != "headless-package") return false;
  if (leaf.empty() || leaf == "." || leaf == "..") return false;
  if (leaf.find('/') != std::string::npos) return false;
  if (name != "headless-package/" + leaf) return false;
  return true;
}

void read_tar_data(GzReader &reader, uint64_t size, Sha256 &hash,
                   std::string *keep) {
  unsigned char buffer[64 * 1024];
  uint64_t remaining = size;
  while (remaining > 0) {
    const size_t chunk =
        static_cast<size_t>(std::min<uint64_t>(remaining, sizeof(buffer)));
    reader.read_exact(buffer, chunk, "tar member");
    hash.update(buffer, chunk);
    if (keep != nullptr) keep->append(reinterpret_cast<char *>(buffer), chunk);
    remaining -= chunk;
  }
  reader.skip((512 - (size % 512)) % 512);
}

std::optional<std::string> parse_pax_path(const std::string &data) {
  std::optional<std::string> path;
  size_t position = 0;
  while (position < data.size()) {
    const size_t space = data.find(' ', position);
    if (space == std::string::npos || space == position ||
        space - position > 18) {
      fail("malformed PAX extended header in provisioning archive");
    }
    uint64_t length = 0;
    for (size_t i = position; i < space; ++i) {
      if (data[i] < '0' || data[i] > '9') {
        fail("malformed PAX extended header in provisioning archive");
      }
      length = length * 10 + static_cast<uint64_t>(data[i] - '0');
      if (length > kMaxTarExtensionBytes) {
        fail("PAX extended header is too large");
      }
    }
    if (length == 0 || position + length > data.size()) {
      fail("malformed PAX extended header in provisioning archive");
    }
    const std::string record =
        data.substr(space + 1, position + length - space - 1);
    if (record.empty() || record.back() != '\n') {
      fail("malformed PAX extended header record");
    }
    const std::string body = record.substr(0, record.size() - 1);
    const size_t equals = body.find('=');
    if (equals == std::string::npos) {
      fail("malformed PAX extended header record");
    }
    const std::string key = body.substr(0, equals);
    if (key == "path") path = body.substr(equals + 1);
    position += length;
  }
  return path;
}

std::map<std::string, TarMember> parse_tar(GzReader &reader) {
  std::map<std::string, TarMember> members;
  std::optional<std::string> pending_name;
  bool saw_end = false;
  while (true) {
    unsigned char block[512];
    const size_t count = reader.read(block, sizeof(block));
    if (count == 0) break;
    if (count != sizeof(block)) fail("truncated tar header");
    if (all_zero(block, sizeof(block))) {
      saw_end = true;
      break;
    }
    if (!verify_tar_checksum(block)) {
      fail("tar header checksum mismatch");
    }
    if (std::memcmp(block + 257, "ustar", 5) != 0) {
      fail("provisioning archive is not a ustar/GNU tar");
    }
    const char type = static_cast<char>(block[156]);
    const uint64_t size = tar_octal(block + 124, 12, "size");
    std::string header_name = tar_text(block, 100);
    const std::string prefix = tar_text(block + 345, 155);
    if (!prefix.empty()) header_name = prefix + "/" + header_name;

    if (type == 'L' || type == 'x') {
      if (size > kMaxTarExtensionBytes) {
        fail("tar extension header is too large");
      }
      Sha256 ignored;
      std::string data;
      data.reserve(static_cast<size_t>(size));
      read_tar_data(reader, size, ignored, &data);
      if (type == 'L') {
        const size_t terminator = data.find('\0');
        if (terminator == std::string::npos) {
          fail("tar long name is not NUL terminated");
        }
        pending_name = data.substr(0, terminator);
      } else {
        const std::optional<std::string> path = parse_pax_path(data);
        if (path.has_value()) pending_name = path;
      }
      continue;
    }

    const std::string name = pending_name.has_value() ? *pending_name : header_name;
    pending_name.reset();

    if (type == '5') {
      if (size != 0 ||
          (name != "headless-package" && name != "headless-package/")) {
        fail("unsafe headless provisioning tar member: " + name);
      }
      continue;
    }
    if (type != '0' && type != '\0') {
      fail("unsafe or unsupported tar member type in provisioning archive");
    }
    if (!safe_member_name(name)) {
      fail("unsafe headless provisioning tar member: " + name);
    }
    if (size > kMaxMemberBytes) {
      fail("headless provisioning member is too large: " + name);
    }
    if (members.find(name) != members.end()) {
      fail("duplicate headless provisioning tar member: " + name);
    }
    TarMember member;
    member.mode = static_cast<uint32_t>(tar_octal(block + 100, 8, "mode") & 07777);
    member.size = size;
    member.has_data =
        name == "headless-package/package-manifest.json" ||
        name == "headless-package/SHA256SUMS";
    if (member.has_data) member.data.reserve(static_cast<size_t>(size));
    Sha256 hash;
    read_tar_data(reader, size, hash, member.has_data ? &member.data : nullptr);
    member.sha256 = hash.finish();
    members.emplace(name, std::move(member));
  }
  if (!saw_end) fail("provisioning archive is missing its end-of-archive marker");
  if (pending_name.has_value()) {
    fail("tar long-name header has no following member");
  }
  unsigned char buffer[64 * 1024];
  while (true) {
    const size_t count = reader.read(buffer, sizeof(buffer));
    if (count == 0) break;
    if (!all_zero(buffer, count)) {
      fail("trailing data after the tar end-of-archive marker");
    }
  }
  return members;
}

// ---------------------------------------------------------------------------
// Signed manifest and inner package contract

void validate_release_version(const std::string &version, const char *what) {
  std::vector<std::string> parts;
  size_t start = 0;
  while (true) {
    const size_t dot = version.find('.', start);
    parts.push_back(version.substr(start, dot == std::string::npos
                                               ? std::string::npos
                                               : dot - start));
    if (dot == std::string::npos) break;
    start = dot + 1;
  }
  bool valid = parts.size() == 4;
  for (const auto &part : parts) {
    if (!valid) break;
    if (part.empty() || part.size() > 10) {
      valid = false;
      break;
    }
    if (part.size() > 1 && part[0] == '0') {
      valid = false;
      break;
    }
    uint64_t value = 0;
    for (char c : part) {
      if (c < '0' || c > '9') {
        valid = false;
        break;
      }
      value = value * 10 + static_cast<uint64_t>(c - '0');
      if (value > kMaxVersionComponent) {
        valid = false;
        break;
      }
    }
  }
  if (!valid) {
    fail(std::string(what) +
         " must be a release version in canonical x.y.z.w numeric format "
         "without leading-zero components");
  }
}

// Shared strict nativeVerifier role binding.  The archive checker and the
// pre-auth stage/validate consumers all use exactly this validator so the
// signed package-manifest role has one authority.
struct NativeVerifierRole {
  bool present = false;
  std::string sha256;
  uint64_t size = 0;
};

NativeVerifierRole require_native_verifier_role(const Json &manifest) {
  NativeVerifierRole role;
  const Json *verifier = manifest.get("nativeVerifier");
  if (verifier == nullptr) return role;
  const char *what = "headless package-manifest.json nativeVerifier";
  if (verifier->kind != Json::Kind::Object) {
    fail("headless package-manifest.json has an invalid nativeVerifier role");
  }
  require_exact_keys(*verifier, {"path", "sha256", "size"}, what);
  if (require_string(*verifier, "path", what) != kNativeVerifier) {
    fail("headless package-manifest.json has an invalid nativeVerifier role");
  }
  role.sha256 = require_string(*verifier, "sha256", what);
  const int64_t declared_size = require_integer(*verifier, "size", what);
  if (!is_lower_hex_64(role.sha256) || declared_size <= 0 ||
      static_cast<uint64_t>(declared_size) > kMaxMemberBytes) {
    fail("headless package-manifest.json has an invalid nativeVerifier role");
  }
  role.size = static_cast<uint64_t>(declared_size);
  role.present = true;
  return role;
}

struct InnerReceipt {
  std::string version;
  std::vector<std::string> files;
  std::string package_manifest_sha256;
  std::string checksums_sha256;
};

InnerReceipt inspect_inner_package(
    const std::map<std::string, TarMember> &members,
    const std::optional<std::string> &expected_version) {
  const auto manifest_member =
      members.find("headless-package/package-manifest.json");
  if (manifest_member == members.end() || !manifest_member->second.has_data) {
    fail("headless provisioning archive has no package-manifest.json");
  }
  const Json manifest = parse_json(manifest_member->second.data);
  require_object(manifest, "headless package-manifest.json");

  const Json *native = manifest.get("nativeHelper");
  bool has_native = native != nullptr;
  if (has_native) {
    if (native->kind != Json::Kind::String ||
        (native->text != kNativeHelper && native->text != kNativeCli)) {
      fail("headless package-manifest.json has an invalid exact package contract");
    }
  }
  const NativeVerifierRole verifier_role = require_native_verifier_role(manifest);
  const bool has_verifier = verifier_role.present;
  const std::string &verifier_sha = verifier_role.sha256;
  const uint64_t verifier_size = verifier_role.size;
  std::vector<std::string> expected_keys = {
      "schema",      "version",     "platform",      "installModes",
      "artifacts",   "service",     "servicePaths",  "trustAnchor",
      "runtimeManifest", "checksums", "runtimeText",
  };
  if (has_native) expected_keys.push_back("nativeHelper");
  if (has_verifier) expected_keys.push_back("nativeVerifier");
  require_exact_keys(manifest, expected_keys,
                     "headless package-manifest.json");

  if (require_integer(manifest, "schema", "headless package-manifest.json") != 2 ||
      require_string(manifest, "platform", "headless package-manifest.json") !=
          "linux-headless-x64" ||
      require_string(manifest, "service", "headless package-manifest.json") !=
          "amneziad.service" ||
      require_string(manifest, "trustAnchor", "headless package-manifest.json") !=
          "external-ed25519-sha256-receipt" ||
      require_string(manifest, "runtimeManifest",
                     "headless package-manifest.json") !=
          "runtime-dependencies.json" ||
      require_string(manifest, "checksums", "headless package-manifest.json") !=
          "SHA256SUMS" ||
      require_string(manifest, "runtimeText", "headless package-manifest.json") !=
          "runtime-dependencies.txt") {
    fail("headless package-manifest.json has an invalid exact package contract");
  }
  require_string_array(require_field(manifest, "installModes",
                                     "headless package-manifest.json"),
                       {"fresh", "upgrade"},
                       "headless package-manifest.json installModes");
  require_string_array(require_field(manifest, "artifacts",
                                     "headless package-manifest.json"),
                       {"amneziad", "amnezia-cli", "amneziad.service"},
                       "headless package-manifest.json artifacts");
  require_string_array(
      require_field(manifest, "servicePaths", "headless package-manifest.json"),
      {"/etc/systemd/system/amneziad.service",
       "/run/systemd/system/amneziad.service",
       "/usr/local/lib/systemd/system/amneziad.service",
       "/usr/lib/systemd/system/amneziad.service",
       "/lib/systemd/system/amneziad.service"},
      "headless package-manifest.json servicePaths");

  const std::string package_version =
      require_string(manifest, "version", "headless package-manifest.json");
  validate_release_version(package_version,
                           "headless package-manifest.json version");
  if (expected_version.has_value() && package_version != *expected_version) {
    fail("headless provisioning package version " + package_version +
         " does not match release " + *expected_version);
  }

  std::vector<std::string> files = base_package_files();
  if (has_native && native->text == kNativeHelper) {
    files.push_back(kNativeHelper);
  }
  if (has_verifier) files.push_back(kNativeVerifier);
  if (members.size() != files.size()) {
    fail("headless provisioning archive has an unexpected file set");
  }
  for (const auto &name : files) {
    if (members.find("headless-package/" + name) == members.end()) {
      fail("headless provisioning archive has an unexpected file set");
    }
  }

  if (has_native && native->text == kNativeHelper &&
      members.at("headless-package/" + std::string(kNativeHelper)).mode != 0755) {
    fail("native provisioning helper must have mode 0755");
  }
  if (has_native && native->text == kNativeCli &&
      members.at("headless-package/" + std::string(kNativeCli)).mode != 0755) {
    fail("native provisioning CLI must have mode 0755");
  }
  if (has_verifier) {
    const TarMember &member =
        members.at("headless-package/" + std::string(kNativeVerifier));
    if (member.mode != 0755) {
      fail("native provisioning verifier must have mode 0755");
    }
    if (member.size != verifier_size || member.sha256 != verifier_sha) {
      fail("native provisioning verifier does not match the signed role binding");
    }
  }

  const auto sums_member = members.find("headless-package/SHA256SUMS");
  if (sums_member == members.end() || !sums_member->second.has_data) {
    fail("headless provisioning archive has no SHA256SUMS");
  }
  const std::string &sums = sums_member->second.data;
  std::map<std::string, std::string> checksums;
  size_t position = 0;
  while (position < sums.size()) {
    size_t newline = sums.find('\n', position);
    if (newline == std::string::npos) newline = sums.size();
    const std::string line = sums.substr(position, newline - position);
    if (line.empty()) {
      fail("headless provisioning SHA256SUMS is not a strict checksum receipt");
    }
    if (line.size() < 67 || line[64] != ' ' || line[65] != ' ') {
      fail("headless provisioning SHA256SUMS is not a strict checksum receipt");
    }
    const std::string digest = line.substr(0, 64);
    const std::string name = line.substr(66);
    if (!is_lower_hex_64(digest) || name.empty() ||
        name.find_first_of("\t\r\n") != std::string::npos ||
        name.find('\0') != std::string::npos) {
      fail("headless provisioning SHA256SUMS is not a strict checksum receipt");
    }
    if (!checksums.emplace(name, digest).second) {
      fail("headless provisioning SHA256SUMS has a duplicate entry");
    }
    position = newline == sums.size() ? sums.size() : newline + 1;
  }
  if (checksums.size() != files.size() - 1) {
    fail("headless provisioning SHA256SUMS does not cover the exact package files");
  }
  for (const auto &name : files) {
    if (name == "SHA256SUMS") continue;
    const auto entry = checksums.find(name);
    if (entry == checksums.end()) {
      fail("headless provisioning SHA256SUMS does not cover the exact package files");
    }
    if (has_verifier && name == kNativeVerifier && entry->second != verifier_sha) {
      fail("native provisioning verifier does not match the signed role binding");
    }
    const auto member = members.find("headless-package/" + name);
    if (member == members.end() || member->second.sha256 != entry->second) {
      fail("headless provisioning inner checksum mismatch: " + name);
    }
  }

  return {
      package_version,
      files,
      sha256_bytes(manifest_member->second.data),
      sha256_bytes(sums),
  };
}

struct Receipt {
  std::string manifest_sha256;
  std::string public_key_sha256;
  std::string archive_sha256;
  uint64_t archive_size = 0;
  std::string version;
  std::string package_version;
  std::vector<std::string> package_files;
  std::string package_manifest_sha256;
  std::string checksums_sha256;
};

std::string normalize_fingerprint(const std::string &value) {
  if (value.size() != 64) {
    fail("expected public-key fingerprint must be 64 hexadecimal characters");
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
      fail("expected public-key fingerprint must be 64 hexadecimal characters");
    }
  }
  return normalized;
}

Receipt verify_bundle(const std::string &manifest_path,
                      const std::string &public_key_path,
                      const std::string &archive_path,
                      const std::string &expected_fingerprint) {
  const std::string pinned_fingerprint = normalize_fingerprint(expected_fingerprint);
  PrivateDirectory private_directory;
  const CopyResult manifest_copy =
      copy_to_private(manifest_path, private_directory.path(), "manifest.json",
                      kMaxManifestBytes, "manifest");
  const CopyResult key_copy = copy_to_private(
      public_key_path, private_directory.path(), "update-public-key.pem",
      kMaxPublicKeyBytes, "public key");
  const CopyResult archive_copy = copy_to_private(
      archive_path, private_directory.path(), "provisioning.tar.gz",
      kMaxArchiveBytes, "provisioning archive");

  const FileData manifest_data =
      read_regular_file(manifest_copy.path, kMaxManifestBytes, "manifest", false);
  const FileData key_data = read_regular_file(
      key_copy.path, kMaxPublicKeyBytes, "public key", false);
  if (key_data.size != key_copy.size ||
      sha256_bytes(key_data.bytes) != key_copy.sha256) {
    fail("private public key changed after verification");
  }
  if (sha256_bytes(key_data.bytes) != pinned_fingerprint) {
    fail("public key fingerprint does not match the pinned expected fingerprint");
  }

  const Json envelope = parse_json(manifest_data.bytes);
  require_exact_keys(envelope,
                     {"signatureAlgorithm", "payload", "schema", "signature"},
                     "update manifest envelope");
  if (require_string(envelope, "schema", "update manifest envelope") !=
      "amnezia-selfhosted-update-v1") {
    fail("unexpected update manifest schema");
  }
  if (require_string(envelope, "signatureAlgorithm",
                     "update manifest envelope") != "Ed25519") {
    fail("unexpected update manifest signature algorithm");
  }
  const std::string encoded_payload =
      require_string(envelope, "payload", "update manifest envelope");
  for (char c : encoded_payload) {
    const bool allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                         (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!allowed) fail("update manifest payload is not strict unpadded base64url");
  }
  const std::string payload_bytes =
      base64_decode(encoded_payload, true, false, "update manifest payload");
  const std::string signature = base64_decode(
      require_string(envelope, "signature", "update manifest envelope"), false,
      true, "update manifest signature");
  if (signature.size() != 64) {
    fail("update manifest signature is not a 64-byte Ed25519 signature");
  }
  verify_ed25519(key_data.bytes, payload_bytes, signature);

  const Json payload = parse_json(payload_bytes);
  require_object(payload, "update manifest payload");
  const std::string version =
      require_string(payload, "version", "update manifest payload");
  validate_release_version(version, "update manifest payload version");
  const Json &platforms =
      require_field(payload, "platforms", "update manifest payload");
  require_object(platforms, "update manifest platforms");
  const Json *artifact = platforms.get("linux-headless-x64");
  if (artifact == nullptr || artifact->kind != Json::Kind::Object ||
      !is_false_or_absent(*artifact, "openExternal")) {
    fail("signed manifest does not contain an exact Linux headless provisioning contract");
  }
  const std::string artifact_format =
      require_string(*artifact, "format", "signed Linux headless artifact");
  if (artifact_format != kArtifactFormat) {
    fail("signed manifest contains invalid inner provisioning metadata");
  }
  if (require_string(*artifact, "sha256", "signed Linux headless artifact").empty() ||
      require_integer(*artifact, "size", "signed Linux headless artifact") <= 0) {
    fail("signed manifest contains invalid headless artifact metadata");
  }

  const Json &provisioning =
      require_field(payload, "headlessProvisioning", "update manifest payload");
  require_exact_keys(provisioning,
                     {"url", "sha256", "size", "format", "version",
                      "packageManifestSha256", "checksumsSha256",
                      "packageVersion", "packageFiles"},
                     "signed manifest headlessProvisioning");
  const std::string provisioning_sha =
      require_string(provisioning, "sha256", "signed manifest headlessProvisioning");
  const int64_t provisioning_size =
      require_integer(provisioning, "size", "signed manifest headlessProvisioning");
  if (!is_lower_hex_64(provisioning_sha) || provisioning_size <= 0 ||
      require_string(provisioning, "format",
                     "signed manifest headlessProvisioning") !=
          kProvisioningFormat ||
      require_string(provisioning, "version",
                     "signed manifest headlessProvisioning") != version ||
      require_string(provisioning, "packageVersion",
                     "signed manifest headlessProvisioning") != version) {
    fail("signed manifest does not contain an exact Linux headless provisioning contract");
  }
  const std::vector<std::string> provisioning_files = require_string_array(
      require_field(provisioning, "packageFiles",
                    "signed manifest headlessProvisioning"),
      "signed manifest headlessProvisioning packageFiles");

  if (archive_copy.size != static_cast<uint64_t>(provisioning_size) ||
      archive_copy.sha256 != provisioning_sha) {
    fail("provisioning archive hash or size does not match the signed manifest");
  }

  const int archive_fd =
      ::open(archive_copy.path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (archive_fd < 0) fail("unable to open the private provisioning archive");
  GzReader reader(archive_fd, kMaxDecompressedBytes);
  const std::map<std::string, TarMember> members = parse_tar(reader);
  const InnerReceipt inner = inspect_inner_package(members, version);

  if (require_string(provisioning, "packageManifestSha256",
                     "signed manifest headlessProvisioning") !=
          inner.package_manifest_sha256 ||
      require_string(provisioning, "checksumsSha256",
                     "signed manifest headlessProvisioning") !=
          inner.checksums_sha256) {
    fail("signed manifest inner provisioning receipt mismatch");
  }
  if (provisioning_files != inner.files) {
    fail("signed manifest inner provisioning receipt mismatch: packageFiles");
  }

  // Re-bind the immutable private copies immediately before emitting a
  // receipt.  Never re-read the operator-facing paths after verification.
  const HashedFile final_manifest = hash_regular_file(
      manifest_copy.path, kMaxManifestBytes, "private manifest");
  const HashedFile final_key = hash_regular_file(
      key_copy.path, kMaxPublicKeyBytes, "private public key");
  const HashedFile final_archive = hash_regular_file(
      archive_copy.path, kMaxArchiveBytes, "private provisioning archive");
  const std::string manifest_sha = sha256_bytes(manifest_data.bytes);
  const std::string key_sha = sha256_bytes(key_data.bytes);
  if (final_manifest.sha256 != manifest_sha ||
      final_manifest.size != manifest_data.size ||
      final_key.sha256 != key_sha ||
      final_archive.sha256 != archive_copy.sha256 ||
      final_archive.size != archive_copy.size) {
    fail("private provisioning inputs changed after verification");
  }

  return {
      manifest_sha,
      key_copy.sha256,
      archive_copy.sha256,
      archive_copy.size,
      version,
      inner.version,
      inner.files,
      inner.package_manifest_sha256,
      inner.checksums_sha256,
  };
}

std::string quote_json(const std::string &value) {
  std::string out = "\"";
  for (unsigned char c : value) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char escaped[7];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", c);
          out += escaped;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out += "\"";
  return out;
}

std::string receipt_json(const Receipt &receipt) {
  std::string out = "{";
  out += "\"archiveSha256\":" + quote_json(receipt.archive_sha256) + ",";
  out += "\"archiveSize\":" + std::to_string(receipt.archive_size) + ",";
  out += "\"checksumsSha256\":" + quote_json(receipt.checksums_sha256) + ",";
  out += "\"manifestSha256\":" + quote_json(receipt.manifest_sha256) + ",";
  out += "\"packageFiles\":[";
  for (size_t i = 0; i < receipt.package_files.size(); ++i) {
    if (i != 0) out += ",";
    out += quote_json(receipt.package_files[i]);
  }
  out += "],";
  out += "\"packageManifestSha256\":" +
         quote_json(receipt.package_manifest_sha256) + ",";
  out += "\"packageVersion\":" + quote_json(receipt.package_version) + ",";
  out += "\"publicKeySha256\":" + quote_json(receipt.public_key_sha256) + ",";
  out += "\"schema\":1,";
  out += "\"tool\":\"amnezia-verify-provisioning-v1\",";
  out += "\"verified\":true,";
  out += "\"version\":" + quote_json(receipt.version);
  out += "}\n";
  return out;
}

void write_receipt(const std::string &path, const std::string &contents) {
  fs::path target(path);
  if (target.has_parent_path()) {
    std::error_code error;
    fs::create_directories(target.parent_path(), error);
    if (error) fail("unable to create the receipt directory");
  }
  const std::string temporary =
      path + ".tmp." + std::to_string(static_cast<long long>(::getpid()));
  int fd = ::open(temporary.c_str(),
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) fail("unable to create the receipt");
  bool ok = true;
  try {
    write_all(fd, contents.data(), contents.size(), "receipt");
    if (::fsync(fd) != 0) ok = false;
  } catch (const Failure &) {
    ok = false;
  }
  ::close(fd);
  if (!ok || ::rename(temporary.c_str(), path.c_str()) != 0) {
    ::unlink(temporary.c_str());
    fail("unable to write the receipt");
  }
}

void print_usage(const char *program) {
  std::printf(
      "usage: %s --manifest PATH --public-key PATH "
      "--expected-public-key-sha256 HEX --provisioning PATH "
      "[--receipt-out PATH]\n"
      "verify-only: the provisioning archive is never extracted and no "
      "installer is executed\n",
      program);
}

}  // namespace

int main(int argc, char **argv) {
  std::string manifest_path;
  std::string public_key_path;
  std::string expected_fingerprint;
  std::string archive_path;
  std::string receipt_path;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    auto value_for = [&](const char *option) -> std::string {
      if (index + 1 >= argc) {
        std::fprintf(stderr, "missing value for %s\n", option);
        std::exit(2);
      }
      return argv[++index];
    };
    if (argument == "--run-installer" || argument == "--installer-arg") {
      std::fprintf(stderr,
                   "refused: this verifier is verify-only; installer execution "
                   "is not supported\n");
      return 2;
    }
    if (argument == "--manifest") {
      manifest_path = value_for("--manifest");
    } else if (argument == "--public-key") {
      public_key_path = value_for("--public-key");
    } else if (argument == "--expected-public-key-sha256") {
      expected_fingerprint = value_for("--expected-public-key-sha256");
    } else if (argument == "--provisioning") {
      archive_path = value_for("--provisioning");
    } else if (argument == "--receipt-out") {
      receipt_path = value_for("--receipt-out");
    } else if (argument == "--help" || argument == "-h") {
      print_usage(argv[0]);
      return 0;
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", argument.c_str());
      print_usage(argv[0]);
      return 2;
    }
  }
  if (manifest_path.empty() || public_key_path.empty() ||
      expected_fingerprint.empty() || archive_path.empty()) {
    std::fprintf(stderr,
                 "missing required arguments: --manifest, --public-key, "
                 "--expected-public-key-sha256 and --provisioning are required\n");
    print_usage(argv[0]);
    return 2;
  }

  try {
    const Receipt receipt = verify_bundle(manifest_path, public_key_path,
                                          archive_path, expected_fingerprint);
    if (!receipt_path.empty()) {
      write_receipt(receipt_path, receipt_json(receipt));
      std::printf("verified receipt: %s\n", receipt_path.c_str());
    }
    std::printf("verified headless provisioning bundle: %s\n",
                receipt.version.c_str());
    return 0;
  } catch (const Failure &error) {
    std::fprintf(stderr, "provisioning verification failed: %s\n", error.what());
    return 1;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "provisioning verification failed: %s\n", error.what());
    return 1;
  } catch (...) {
    std::fprintf(stderr, "provisioning verification failed\n");
    return 1;
  }
}
