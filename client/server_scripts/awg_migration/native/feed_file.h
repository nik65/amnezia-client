#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace amnezia::awgMigration {

// No socket, HTTP, Docker, configuration, or deployment side effects. The
// descriptor pins the opened inode; callers must still handle concurrent writes.
class FeedFile final {
public:
    FeedFile(int descriptor, std::uint64_t size, bool json = false) noexcept;
    ~FeedFile();
    FeedFile(const FeedFile &) = delete;
    FeedFile &operator=(const FeedFile &) = delete;
    FeedFile(FeedFile &&other) noexcept;
    FeedFile &operator=(FeedFile &&other) noexcept;
    int descriptor() const noexcept { return descriptor_; }
    std::uint64_t size() const noexcept { return size_; }
    bool isJson() const noexcept { return json_; }

private:
    int descriptor_;
    std::uint64_t size_;
    bool json_;
};

// Throws std::runtime_error on rejected paths or filesystem errors. Only
// origin-form HTTP targets are accepted; query and fragment are not filenames.
FeedFile openFeed(const std::string &root, std::string_view request, bool routing);

} // namespace amnezia::awgMigration
