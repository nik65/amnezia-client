#include "actual_profile_json.h"
#include <QCoreApplication>
#include <cstdio>

namespace {
int checks = 0;
int failures = 0;
void check(bool ok, const char *message)
{
    ++checks;
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL %s\n", message); }
}
QJsonObject descriptor()
{
    return {
        { "enabled", true }, { "domain", "D27.Example.com." },
        { "publicKey", QString(64, QLatin1Char('A')) },
        { "vlessId", "12345678-1234-4321-ABCD-123456789ABC" }
    };
}
template<class Model> void roundtrip(const QJsonObject &valid)
{
    const QJsonObject profile { { "hostName", "server.example.com" }, { "dnsFallback", valid } };
    const auto model = Model::fromJson(profile);
    check(model.toJson().value("dnsFallback").toObject() == valid, "profile model lost DNS credentials");
    const auto malformed = Model::fromJson(QJsonObject { { "dnsFallback", QJsonObject{{"enabled", true}} } });
    check(!malformed.toJson().contains("dnsFallback"), "profile model retained malformed descriptor");
    const auto absent = Model::fromJson(QJsonObject { { "hostName", "another.example.com" } });
    check(!absent.toJson().contains("dnsFallback"), "profile without enrollment gained credentials");
    const auto disabled = Model::fromJson(QJsonObject { { "dnsFallback", QJsonObject{{"enabled", false}} } });
    check(disabled.toJson().value("dnsFallback").toObject() == QJsonObject{{"enabled", false}}, "explicit disable lost");
}
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    using namespace amnezia::dnsFallbackConfig;
    const auto valid = normalized(descriptor());
    check(valid.size() == 6, "valid enrollment rejected");
    check(valid.value("domain") == "d27.example.com", "domain not canonical");
    check(valid.value("publicKey") == QString(64, QLatin1Char('a')), "key not canonical");
    check(valid.value("vlessId") == "12345678-1234-4321-abcd-123456789abc", "UUID not canonical");
    check(valid.value("probeUrl") == "https://example.com/" && valid.value("failureThreshold") == 3, "safe defaults lost");
    check(normalized(QJsonValue()).isEmpty() && normalized(true).isEmpty(), "non-object accepted");
    for (const auto &field : { "enabled", "domain", "publicKey", "vlessId" }) {
        auto o = descriptor(); o.remove(QLatin1String(field));
        check(normalized(o).isEmpty(), "missing required field accepted");
    }
    for (const auto &domain : { "localhost", "127.0.0.1", "-bad.example.com", "bad..example.com", "a.local", "a.localhost", "a;b.example.com", "a/example.com" }) {
        auto o = descriptor(); o["domain"] = domain;
        check(normalized(o).isEmpty(), "unsafe DNS endpoint accepted");
    }
    auto o = descriptor(); o["domain"] = QString(64, QLatin1Char('a'))+".example.com";
    check(normalized(o).isEmpty(), "oversize label accepted");
    o = descriptor(); o["publicKey"] = QString(64, QLatin1Char('0'));
    check(normalized(o).isEmpty(), "zero key accepted");
    o = descriptor(); o["publicKey"] = QString(64, QLatin1Char('z'));
    check(normalized(o).isEmpty(), "non-hex key accepted");
    o = descriptor(); o["vlessId"] = "00000000-0000-0000-0000-000000000000";
    check(normalized(o).isEmpty(), "zero UUID accepted");
    for (const QJsonValue &threshold : { QJsonValue(1), QJsonValue(9), QJsonValue(3.5), QJsonValue("3"), QJsonValue(true) }) {
        o = descriptor(); o["failureThreshold"] = threshold;
        check(normalized(o).isEmpty(), "invalid failure threshold accepted");
    }
    for (const auto &url : { "http://example.com/", "https://127.0.0.1/", "https://user:pass@example.com/", "https://example.com/#fragment", "https://example.com:444/", "file:///tmp/probe", "https://a.local/" }) {
        o = descriptor(); o["probeUrl"] = url;
        check(normalized(o).isEmpty(), "unsafe probe accepted");
    }
    o = descriptor(); o["shellCommand"] = "untrusted payload";
    check(!normalized(o).contains("shellCommand"), "unrecognized launch parameter forwarded");
    o = descriptor(); o["junk"] = QString(2100, QLatin1Char('x'));
    check(normalized(o).isEmpty(), "oversize descriptor accepted");
    o = descriptor(); o["enabled"] = false;
    check(normalized(o) == QJsonObject{{"enabled", false}}, "disabled config retained secret fields");

    QJsonObject connection { { "protocol", "awg" }, { "dnsFallback", valid } };
    copyToConnection({}, connection);
    check(!connection.contains("dnsFallback") && connection.value("protocol") == "awg", "reused context leaked previous credentials");
    copyToConnection(QJsonObject{{"dnsFallback", descriptor()}}, connection);
    check(connection.value("dnsFallback").toObject() == valid, "connection descriptor not copied");
    copyToConnection(QJsonObject{{"dnsFallback", descriptor()}}, connection, true);
    check(!connection.contains("dnsFallback"), "API subscription enabled an unenrolled fallback");
    copyToConnection(QJsonObject{{"dnsFallback", descriptor()}}, connection);
    copyToConnection(QJsonObject{{"dnsFallback", QJsonObject{{"enabled", true}}}}, connection);
    check(!connection.contains("dnsFallback"), "invalid profile inherited previous credentials");

    QJsonArray apps { "org.telegram.messenger" };
    connection["dnsFallback"] = valid;
    applyOwnerApplicationPolicy(connection, amnezia::AppsRouteMode::VpnOnlyForwardApps, apps);
    check(apps == QJsonArray({"org.telegram.messenger", "org.amnezia.vpn"}), "DNS health owner missing from allowed applications");
    applyOwnerApplicationPolicy(connection, amnezia::AppsRouteMode::VpnOnlyForwardApps, apps);
    check(apps.size() == 2, "owner application duplicated");
    apps = QJsonArray { "org.amnezia.vpn", "org.telegram.messenger" };
    applyOwnerApplicationPolicy(connection, amnezia::AppsRouteMode::VpnAllExceptApps, apps);
    check(!connection.contains("dnsFallback") && connection.value("dnsFallbackUnavailableReason") == "owner_excluded_by_app_split",
          "explicit owner exclusion did not disable fallback with a reason");
    check(apps == QJsonArray({"org.amnezia.vpn", "org.telegram.messenger"}), "explicit exclusion changed");
    copyToConnection(QJsonObject{{"dnsFallback", valid}}, connection);
    check(!connection.contains("dnsFallbackUnavailableReason"), "new profile inherited previous unavailability reason");
    connection = QJsonObject{{"dnsFallback", valid}}; apps = QJsonArray { "org.telegram.messenger" };
    applyOwnerApplicationPolicy(connection, amnezia::AppsRouteMode::VpnAllExceptApps, apps);
    check(connection.value("dnsFallback").toObject() == valid && apps == QJsonArray({"org.telegram.messenger"}), "unrelated exclusion changed");
    applyOwnerApplicationPolicy(connection, amnezia::AppsRouteMode::VpnAllApps, apps);
    check(apps == QJsonArray({"org.telegram.messenger"}), "all-app mode was modified");
    connection = QJsonObject{}; apps = QJsonArray { "org.telegram.messenger" };
    applyOwnerApplicationPolicy(connection, amnezia::AppsRouteMode::VpnOnlyForwardApps, apps);
    check(apps == QJsonArray({"org.telegram.messenger"}), "unenrolled profile acquired owner route");
    connection = QJsonObject{{"dnsFallback", QJsonObject{{"enabled", false}}}};
    applyOwnerApplicationPolicy(connection, amnezia::AppsRouteMode::VpnOnlyForwardApps, apps);
    check(apps == QJsonArray({"org.telegram.messenger"}), "disabled fallback acquired owner route");

    roundtrip<amnezia::SelfHostedAdminServerConfig>(valid);
    roundtrip<amnezia::SelfHostedUserServerConfig>(valid);
    roundtrip<amnezia::NativeServerConfig>(valid);
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
