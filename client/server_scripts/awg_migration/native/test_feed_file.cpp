#include "feed_file.h"
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using amnezia::awgMigration::openFeed;
static void check(bool result, const char *message) {
    if (!result) throw std::runtime_error(message);
}
template<class Function> void denied(Function function) {
    bool rejected = false;
    try { function(); } catch (const std::runtime_error &) { rejected = true; }
    check(rejected, "unsafe feed accepted");
}
static std::size_t descriptors() {
    std::size_t count = 0;
    for (const auto &entry : fs::directory_iterator("/proc/self/fd")) {
        (void)entry; ++count;
    }
    return count;
}
int main() {
    char pattern[] = "/tmp/amnezia-native-feed-test-XXXXXX";
    const char *created = ::mkdtemp(pattern);
    if (!created) return 2;
    const fs::path temporary(created);
    struct Cleanup { fs::path root; ~Cleanup() { std::error_code e; fs::remove_all(root, e); } } cleanup{temporary};
    try {
        const auto root = temporary / "public";
        fs::create_directories(root / "files" / "nested");
        std::ofstream(root / "manifest.json") << "manifest";
        std::ofstream(root / "rules.json") << "rules";
        std::ofstream(root / "files" / "nested" / "client.apk") << "package";
        std::ofstream(root / "files" / "nested" / "AmneziaVPN_test_android9+_arm64-v8a.apk") << "android fixture";
        std::ofstream(temporary / "private.apk") << "PRIVATE";
        {
            auto manifest = openFeed(root.string(), "/manifest.json?cache=1", false);
            char data[32]{};
            check(manifest.size() == 8 && ::read(manifest.descriptor(), data, sizeof(data)) == 8
                  && std::string(data, 8) == "manifest", "manifest bytes differ");
            const int fd = manifest.descriptor();
            auto moved = std::move(manifest);
            check(manifest.descriptor() == -1 && moved.descriptor() == fd, "move duplicated ownership");
            check((::fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0, "descriptor inherited by subprocess");
        }
        check(openFeed(root.string(), "/files/nested/client.apk", false).size() == 7, "nested file rejected");
        check(openFeed(root.string(), "/rules.json", true).size() == 5, "routing feed rejected");
        for (const auto request : {"/files/nested/AmneziaVPN_test_android9+_arm64-v8a.apk",
                                   "/files/nested/AmneziaVPN_test_android9%2B_arm64-v8a.apk"}) {
            auto android = openFeed(root.string(), request, false);
            char payload[32]{};
            check(android.size() == 15 && ::read(android.descriptor(), payload, sizeof(payload)) == 15
                  && std::string(payload, 15) == "android fixture", "Android plus filename rejected");
        }
        denied([&] { openFeed(root.string(), "/files/nested/AmneziaVPN_test_android9%252B_arm64-v8a.apk", false); });
        denied([&] { openFeed(root.string(), "/files/nested/AmneziaVPN_test_android9%2B_arm64-v8a.apk.bak", false); });
        check(openFeed(root.string(), "/%6danifest.json", false).size() == 8, "single decoding differs");
        for (const auto request : {"/", "/files/", "/rules.json", "/signing.pem", "/files/../private.apk",
                                   "/files/%2e%2e/private.apk", "/files/%252e%252e/private.apk",
                                   "/files/%00client.apk", "/files/%ff.apk", "/files/a\\b.apk",
                                   "/files/a%.apk", "/files/a%2.apk", "/files//client.apk",
                                   "/files/nested/client.APK", "https://elsewhere/manifest.json", "//host/manifest.json"}) {
            denied([&] { openFeed(root.string(), request, false); });
        }
        denied([&] { openFeed(root.string(), "/manifest.json", true); });
        denied([&] { openFeed(root.string(), "/files/nested/client.apk", true); });
        fs::create_symlink(temporary / "private.apk", root / "files" / "leak.apk");
        fs::create_directory_symlink(temporary, root / "files" / "alias");
        fs::create_hard_link(temporary / "private.apk", root / "files" / "hard.apk");
        fs::create_directory_symlink(root, temporary / "alias-root");
        for (const auto request : {"/files/leak.apk", "/files/alias/private.apk", "/files/hard.apk"})
            denied([&] { openFeed(root.string(), request, false); });
        denied([&] { openFeed((temporary / "alias-root").string(), "/manifest.json", false); });
        fs::create_directory(root / "files" / "directory.apk");
        denied([&] { openFeed(root.string(), "/files/directory.apk", false); });
        check(::mkfifo((root / "files" / "pipe.apk").c_str(), 0600) == 0, "FIFO fixture failed");
        denied([&] { openFeed(root.string(), "/files/pipe.apk", false); });
        const auto huge = root / "files" / "huge.apk";
        const int fd = ::open(huge.c_str(), O_CREAT | O_WRONLY | O_EXCL, 0600);
        check(fd >= 0, "sparse fixture failed");
        const auto maximum = static_cast<off_t>(std::uint64_t{2} << 30);
        check(::ftruncate(fd, maximum + 1) == 0, "sparse size failed");
        denied([&] { openFeed(root.string(), "/files/huge.apk", false); });
        check(::ftruncate(fd, maximum) == 0, "sparse boundary failed");
        check(openFeed(root.string(), "/files/huge.apk", false).size() == static_cast<std::uint64_t>(maximum),
              "2 GiB boundary differs");
        ::close(fd);
        const auto before = descriptors();
        for (int i = 0; i < 1000; ++i) {
            denied([&] { openFeed(root.string(), "/files/leak.apk", false); });
            denied([&] { openFeed(root.string(), "/files/missing.apk", false); });
        }
        check(descriptors() == before, "rejected requests leaked descriptors");
        // A pathname replacement after open must not redirect an existing handle.
        auto pinned = openFeed(root.string(), "/files/nested/client.apk", false);
        fs::rename(root / "files" / "nested" / "client.apk", root / "files" / "nested" / "moved.apk");
        fs::create_symlink(temporary / "private.apk", root / "files" / "nested" / "client.apk");
        char data[16]{};
        check(::read(pinned.descriptor(), data, sizeof(data)) == 7 && std::string(data, 7) == "package",
              "opened descriptor followed replacement");
        std::cout << "feed access security tests passed\n";
    } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
