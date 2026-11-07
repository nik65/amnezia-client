#include "actual_stream_settings.h"
#include <QCoreApplication>
#include <QDebug>
#include <cstdio>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    XrayConfigurator builder;
    int failures = 0, checks = 0;
    auto check = [&](bool ok, const char *message) {
        ++checks;
        if (!ok) { ++failures; std::fprintf(stderr, "%s\n", message); }
    };
    const QList<QPair<QString, QString>> modes {
        { "", "auto" }, { "Auto", "auto" }, { "  AUTO ", "auto" },
        { "Packet-up", "packet-up" }, { "packet-up", "packet-up" },
        { "Stream-up", "stream-up" }, { "Stream-one", "stream-one" }
    };
    for (const auto &mode : modes) {
        amnezia::XrayServerConfig config;
        config.transport = "xhttp";
        config.security = "tls";
        config.sni = "tunnel.example.org";
        config.xhttp.host = "tunnel.example.org";
        config.xhttp.path = "/private-test";
        config.xhttp.mode = mode.first;
        const auto stream = builder.buildStreamSettings(config, "test-client");
        const auto xhttp = stream["xhttpSettings"].toObject();
        check(xhttp["mode"].toString() == mode.second, "Explicit/default XHTTP mode must survive generation");
        check(xhttp["path"] == "/private-test" && xhttp["host"] == "tunnel.example.org", "XHTTP host/path lost");
        check(stream["tlsSettings"].toObject()["serverName"] == "tunnel.example.org", "TLS SNI lost");
    }
    for (const auto &placement : { "Header", "Cookie" }) {
        amnezia::XrayServerConfig config;
        config.transport = "xhttp";
        config.xhttp.mode = "Packet-up";
        config.xhttp.uplinkDataPlacement = placement;
        const auto xhttp = builder.buildStreamSettings(config, "")["xhttpSettings"].toObject();
        check(xhttp["uplinkDataPlacement"] == QString::fromLatin1(placement).toLower(), "Packet-up payload placement dropped");
        config.xhttp.mode = "Stream-one";
        check(!builder.buildStreamSettings(config, "")["xhttpSettings"].toObject().contains("uplinkDataPlacement"),
              "Stream-one must keep filtering packet-only payload placement");
    }
    amnezia::XrayServerConfig raw;
    raw.transport = "raw";
    check(!builder.buildStreamSettings(raw, "").contains("xhttpSettings"), "Raw transport unexpectedly changed");
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
