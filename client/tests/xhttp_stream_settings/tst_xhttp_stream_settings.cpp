#include "core/models/protocols/xrayProtocolConfig.h"

#include <QJsonArray>
#include <cstdio>

int main()
{
    int failures = 0;
    int checks = 0;
    auto check = [&](bool ok, const char *message) {
        ++checks;
        if (!ok) {
            ++failures;
            std::fprintf(stderr, "%s\n", message);
        }
    };

    const QList<QPair<QString, QString>> modes {
        { "", "auto" }, { "Auto", "auto" }, { "  AUTO ", "auto" },
        { "Packet-up", "packet-up" }, { "packet-up", "packet-up" },
        { "Stream-up", "stream-up" }, { "Stream-one", "stream-one" }
    };
    for (const auto &mode : modes) {
        amnezia::XrayProtocolConfig config;
        auto &server = config.serverConfig;
        server.transport = "xhttp";
        server.security = "tls";
        server.sni = "tunnel.example.org";
        server.xhttp.host = "tunnel.example.org";
        server.xhttp.path = "/private-test";
        server.xhttp.mode = mode.first;

        amnezia::XrayClientOutboundInputs inputs;
        inputs.serverAddress = "192.0.2.7";
        inputs.clientId = "fixture";
        inputs.tlsPinnedPeerCertSha256 = QString(64, 'a');
        const auto native = config.toClientOutboundJson(inputs);
        const auto outbound = native["outbounds"].toArray().first().toObject();
        const auto stream = outbound["streamSettings"].toObject();
        const auto xhttp = stream["xhttpSettings"].toObject();

        check(xhttp["mode"].toString() == mode.second,
              "Selected XHTTP mode must survive actual client native generation");
        check(xhttp["path"] == "/private-test" && xhttp["host"] == "tunnel.example.org",
              "XHTTP host/path lost");
        const auto tls = stream["tlsSettings"].toObject();
        check(tls["serverName"] == "tunnel.example.org", "TLS SNI lost");
        check(tls["pinnedPeerCertSha256"] == QString(64, 'a'), "TLS certificate pin lost");
    }

    amnezia::XrayServerConfig raw;
    raw.transport = "raw";
    check(!raw.clientStreamSettings().contains("xhttpSettings"), "Raw transport unexpectedly changed");

    for (const auto &placement : { "Header", "Cookie" }) {
        amnezia::XrayServerConfig config;
        config.transport = "xhttp";
        config.xhttp.mode = "Packet-up";
        config.xhttp.uplinkDataPlacement = placement;
        const auto packetSettings = config.clientStreamSettings()["xhttpSettings"].toObject();
        check(packetSettings["uplinkDataPlacement"] == QString::fromLatin1(placement).toLower(),
              "Packet-up payload placement dropped");

        config.xhttp.mode = "Stream-one";
        check(!config.clientStreamSettings()["xhttpSettings"].toObject().contains("uplinkDataPlacement"),
              "Stream-one must filter packet-only payload placement");
    }

    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
