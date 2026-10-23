#include "feed_file.h"

#include <array>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace amnezia::awgMigration {
namespace {
[[noreturn]] void reject() { throw std::runtime_error("feed_rejected"); }

class Descriptor final {
public:
    explicit Descriptor(int value) : value_(value) { if (value < 0) reject(); }
    ~Descriptor() { if (value_ >= 0) ::close(value_); }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }
private:
    int value_;
};

int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool componentCharacter(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '+';
}

std::vector<std::string> components(std::string_view request, bool routing) {
    if (request.empty() || request.front() != '/' || request.substr(0, 2) == "//") reject();
    request = request.substr(0, request.find_first_of("?#"));
    std::string path;
    for (std::size_t i = 0; i < request.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(request[i]);
        if (c == '%') {
            if (i + 2 >= request.size()) reject();
            const int high = hex(request[i + 1]), low = hex(request[i + 2]);
            if (high < 0 || low < 0) reject();
            c = static_cast<unsigned char>(16 * high + low);
            i += 2;
        }
        if (c != '/' && !componentCharacter(c)) reject();
        path.push_back(static_cast<char>(c));
    }
    std::vector<std::string> parts;
    std::size_t start = 1;
    while (start <= path.size()) {
        const auto end = path.find('/', start);
        auto part = path.substr(start, end == std::string::npos ? end : end - start);
        if (part.empty() || part == "." || part == "..") reject();
        parts.push_back(std::move(part));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    bool allowed = path == (routing ? "/rules.json" : "/manifest.json");
    if (!routing && parts.size() >= 2 && parts.front() == "files") {
        constexpr std::array<std::string_view, 12> suffixes{
            ".exe", ".msi", ".apk", ".zip", ".tar.gz", ".tgz",
            ".deb", ".rpm", ".run", ".AppImage", ".sig", ".sha256"};
        const auto &last = parts.back();
        for (const auto suffix : suffixes) {
            if (last.size() >= suffix.size()
                && last.compare(last.size() - suffix.size(), suffix.size(), suffix) == 0) allowed = true;
        }
    }
    if (!allowed) reject();
    return parts;
}
} // namespace

FeedFile::FeedFile(int descriptor, std::uint64_t size, bool json) noexcept
    : descriptor_(descriptor), size_(size), json_(json) {}
FeedFile::~FeedFile() { if (descriptor_ >= 0) ::close(descriptor_); }
FeedFile::FeedFile(FeedFile &&other) noexcept
    : descriptor_(std::exchange(other.descriptor_, -1)), size_(other.size_), json_(other.json_) {}
FeedFile &FeedFile::operator=(FeedFile &&other) noexcept {
    if (this != &other) {
        if (descriptor_ >= 0) ::close(descriptor_);
        descriptor_ = std::exchange(other.descriptor_, -1);
        size_ = other.size_;
        json_ = other.json_;
    }
    return *this;
}

FeedFile openFeed(const std::string &root, std::string_view request, bool routing) {
    const auto parts = components(request, routing);
    // The root must be supplied as a directory path, not an embedded NUL or a
    // trailing slash that would let the kernel follow a final root symlink.
    if (root.empty() || root.find('\0') != std::string::npos || root.back() == '/') reject();
    Descriptor initial(::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    FeedFile directory(initial.release(), 0);
    for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
        Descriptor child(::openat(directory.descriptor(), parts[i].c_str(),
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        directory = FeedFile(child.release(), 0);
    }
    // Nonblocking open prevents attacker-controlled FIFOs hanging the worker
    // before fstat rejects the inode. It does not alter regular-file reads.
    Descriptor file(::openat(directory.descriptor(), parts.back().c_str(),
                             O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    struct stat info {};
    if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1
        || info.st_size < 0 || static_cast<std::uint64_t>(info.st_size) > (std::uint64_t{2} << 30)) reject();
    const auto &last = parts.back();
    const bool json = last.size() >= 5 && last.compare(last.size() - 5, 5, ".json") == 0;
    return FeedFile(file.release(), static_cast<std::uint64_t>(info.st_size), json);
}
} // namespace amnezia::awgMigration
