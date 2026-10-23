#include "core/models/protocols/awgProtocolConfig.h"
#include "core/models/protocols/wireGuardProtocolConfig.h"
#include "core/utils/constants/configKeys.h"
#include <QCoreApplication>
#include <QDebug>
#include <array>
#include <climits>
#include <cstring>
#include <new>

static int failures = 0;
static void check(bool okay, const char *message)
{
    if (!okay) { ++failures; qCritical() << message; }
}

template<class T> void defaults()
{
    alignas(T) unsigned char storage[sizeof(T)];
    std::memset(storage, 0x55, sizeof(storage));
    T *value = new (storage) T;
    const int zero = 0;
    // Compare object representation without evaluating an indeterminate int.
    const bool initialized = std::memcmp(&value->port, &zero, sizeof(zero)) == 0;
    check(initialized, "default-constructed port must be initialized to zero");
    if (initialized) {
        const auto serialized = value->toJson();
        check(!serialized.contains(amnezia::configKey::port), "empty model must not invent endpoint port");
        check(T::fromJson(serialized).port == 0, "empty model roundtrip port is zero");
    }
    value->~T();
    T explicitPort{};
    explicitPort.port = 51820;
    check(T::fromJson(explicitPort.toJson()).port == 51820, "explicit endpoint port survives roundtrip");
    check(T::fromJson(QJsonObject{}).port == 0, "missing JSON port defaults to zero");
}

static void sizes()
{
    const std::array<int, 10> values = {INT_MIN, INT_MIN + 148, -148, -92, -64, -32, 0, 56, INT_MAX - 148, INT_MAX};
    for (int a : values) for (int b : values) for (int c : values) for (int d : values) {
        const std::array<qint64, 4> sums = {qint64(148) + a, qint64(92) + b, qint64(64) + c, qint64(32) + d};
        bool collision = false;
        for (unsigned i = 0; i < sums.size(); ++i)
            for (unsigned j = i + 1; j < sums.size(); ++j) collision |= sums[i] == sums[j];
        check(amnezia::AwgProtocolConfig::isPacketSizeEqual(a,b,c,d) == collision, "packet-size equality must use mathematical sums");
    }
    check(amnezia::AwgProtocolConfig::isPacketSizeEqual(0,56,0,0), "148 equals 92 plus 56");
    check(!amnezia::AwgProtocolConfig::isPacketSizeEqual(0,0,0,0), "ordinary packet sizes remain distinct");
    // Exercise overflow boundary on all four independent sums.
    check(!amnezia::AwgProtocolConfig::isPacketSizeEqual(INT_MAX,INT_MAX,INT_MAX,INT_MAX), "all maximum additions remain distinct");
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2) return 2;
    const QString mode = QString::fromLocal8Bit(argv[1]);
    if (mode == "defaults") { defaults<amnezia::AwgClientConfig>(); defaults<amnezia::WireGuardClientConfig>(); }
    else if (mode == "sizes") sizes();
    else return 2;
    return failures ? 1 : 0;
}
