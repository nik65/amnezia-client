#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

int main(int argc, char *argv[])
{
    if (argc < 3 || std::strcmp(argv[1], "-device") != 0) {
        return 2;
    }
    if (std::strcmp(argv[2], "tun://wait") == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 0;
    }
    if (std::strcmp(argv[2], "tun://output") != 0) {
        return 3;
    }

    constexpr size_t chunkSize = 64 * 1024;
    constexpr int chunkCount = 5 * 1024 * 1024 / chunkSize;
    char standardOutput[chunkSize];
    char standardError[chunkSize];
    std::memset(standardOutput, 'O', sizeof(standardOutput));
    std::memset(standardError, 'E', sizeof(standardError));
    for (int index = 0; index < chunkCount; ++index) {
        if (std::fwrite(standardOutput, 1, sizeof(standardOutput), stdout)
            != sizeof(standardOutput)) {
            return 4;
        }
    }
    std::fflush(stdout);
    for (int index = 0; index < chunkCount; ++index) {
        if (std::fwrite(standardError, 1, sizeof(standardError), stderr)
            != sizeof(standardError)) {
            return 5;
        }
    }
    std::fflush(stderr);
    return 0;
}
