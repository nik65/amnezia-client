#include "../../platforms/linux/daemon/uapiresultlinux.h"
#include <cstdio>

int main()
{
    struct Case { const char* reply; int expected; };
    const Case cases[] = {
        {"errno=0", 0}, {"public_key=abc\nerrno=0\n\n", 0},
        {"errno=22", 22}, {"errno=5\n", 5},
        {"", EINVAL}, {"public_key=abc", EINVAL},
        {"errno=garbage", EINVAL}, {"errno=", EINVAL},
        {"errno=0garbage", EINVAL}, {"errno= 0", EINVAL},
        {"errno=-1", EINVAL}, {"errno=+0", EINVAL},
        {"errno=99999999999999999999", EINVAL},
        {"errno=0\nerrno=5", EINVAL}, {"errno=0\nerrno=0", EINVAL}
    };
    for (const auto& test : cases) {
        if (LinuxUapi::resultErrno(QString::fromLatin1(test.reply)) != test.expected) {
            std::fprintf(stderr, "Unexpected result for UAPI fixture: %s\n", test.reply);
            return 1;
        }
    }
    return 0;
}
