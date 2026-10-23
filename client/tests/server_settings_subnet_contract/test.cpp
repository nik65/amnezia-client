#include <QCoreApplication>
#include <QDebug>
#include "core/models/protocols/wireGuardProtocolConfig.h"
#include "core/models/protocols/awgProtocolConfig.h"
#include "core/models/protocols/openVpnProtocolConfig.h"

// The compared object drives InstallController reinstall/update decisions.
// These tests prove model contract only; they do not execute deployment.
static int failures = 0;
static void check(bool condition, const char *message)
{
    if (!condition) { qCritical() << message; ++failures; }
}

template<class T> void prefixChange(const char *label)
{
    T old;
    old.port = QStringLiteral("51820");
    old.subnetAddress = QStringLiteral("10.8.0.0");
    old.subnetCidr = QStringLiteral("24");
    check(old.hasEqualServerSettings(old), "unchanged identity remains equal");
    const T roundtrip = T::fromJson(old.toJson());
    check(old.hasEqualServerSettings(roundtrip), "serialization preserves deployment identity");
    T changed = old;
    changed.subnetCidr = QStringLiteral("25");
    check(!old.hasEqualServerSettings(changed), label);
    check(!changed.hasEqualServerSettings(old), "network change comparison is symmetric");
    const T changedRoundtrip = T::fromJson(changed.toJson());
    check(!old.hasEqualServerSettings(changedRoundtrip), "saved changed prefix still requires deployment");
    changed = old;
    changed.port = QStringLiteral("51821");
    check(!old.hasEqualServerSettings(changed), "existing port-change behavior preserved");
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    prefixChange<amnezia::WireGuardServerConfig>("WG /24 -> /25 must require deployment");
    prefixChange<amnezia::AwgServerConfig>("AWG /24 -> /25 must require deployment");
    prefixChange<amnezia::OpenVpnServerConfig>("OpenVPN /24 -> /25 must require deployment");
    amnezia::OpenVpnServerConfig old;
    old.subnetMask = QStringLiteral("255.255.255.0");
    auto changed = old;
    changed.subnetMask = QStringLiteral("255.255.255.128");
    check(!old.hasEqualServerSettings(changed), "OpenVPN changed netmask requires deployment");
    check(!changed.hasEqualServerSettings(old), "netmask comparison is symmetric");
    amnezia::WireGuardServerConfig wg;
    auto wgMetadata = wg;
    wgMetadata.subnetMask = QStringLiteral("255.255.255.128");
    check(wg.hasEqualServerSettings(wgMetadata), "WG unused mask metadata must preserve no-op");
    qInfo() << "Subnet contract failures:" << failures;
    return failures ? 1 : 0;
}
