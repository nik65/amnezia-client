#include "core/controllers/connectionHealthController.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>

#include <functional>

namespace
{
class LocalHeadServer final : public QObject
{
public:
    explicit LocalHeadServer(bool respond, int statusCode = 204, int delayMs = 0)
        : m_respond(respond), m_statusCode(statusCode), m_delayMs(delayMs)
    {
        QObject::connect(&m_server, &QTcpServer::newConnection, this, [this]() {
            while (QTcpSocket *socket = m_server.nextPendingConnection()) {
                QObject::connect(socket, &QTcpSocket::readyRead, socket,
                                 [this, guardedSocket = QPointer<QTcpSocket>(socket)]() {
                    if (!guardedSocket) {
                        return;
                    }
                    m_request.append(guardedSocket->readAll());
                    if (!m_respond || !m_request.contains("\r\n\r\n")) {
                        return;
                    }
                    QObject::disconnect(guardedSocket, &QTcpSocket::readyRead, nullptr, nullptr);
                    QTimer::singleShot(m_delayMs, guardedSocket, [this, guardedSocket]() {
                        if (!guardedSocket) {
                            return;
                        }
                        const QByteArray response = QByteArrayLiteral("HTTP/1.1 ")
                                + QByteArray::number(m_statusCode)
                                + QByteArrayLiteral(" Guardian\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        guardedSocket->write(response);
                        guardedSocket->disconnectFromHost();
                    });
                });
            }
        });
    }

    bool listen()
    {
        return m_server.listen(QHostAddress::LocalHost, 0);
    }

    QUrl url(const QString &authorityPrefix = QString()) const
    {
        return QUrl(QStringLiteral("http://%1%2:%3/guardian?secret=query")
                            .arg(authorityPrefix, m_server.serverAddress().toString())
                            .arg(m_server.serverPort()));
    }

    QByteArray request() const { return m_request; }

private:
    QTcpServer m_server;
    bool m_respond;
    int m_statusCode;
    int m_delayMs;
    QByteArray m_request;
};

bool waitUntil(const std::function<bool()> &condition, int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        QThread::msleep(1);
    }
    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    return condition();
}

bool require(bool condition, const char *message)
{
    if (!condition) {
        qCritical("FAILED: %s", message);
    }
    return condition;
}
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QNetworkAccessManager manager;
    manager.setProxy(QNetworkProxy::NoProxy);
    ConnectionHealthController health;

    health.recordProbeResult(true, true, true, 10.0, -1.0, QString(), true, false);
    const QVariantMap unverifiedPathSnapshot = health.healthSnapshot();
    const QVariantMap unverifiedPathEvent = health.flightRecorder().last().toMap();
    const QVariantMap unverifiedPathDetails = unverifiedPathEvent.value(QStringLiteral("details")).toMap();
    if (!require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                 "authenticated origin without a tunnel path proof is degraded")
        || !require(health.lastReason() == QStringLiteral("tunnel_path_unverified"),
                    "unverified tunnel path reason retained")
        || !require(unverifiedPathSnapshot.value(QStringLiteral("origin_authenticated")).toBool(),
                    "health snapshot retains authenticated origin")
        || !require(!unverifiedPathSnapshot.value(QStringLiteral("tunnel_path_verified")).toBool(),
                    "health snapshot keeps tunnel path unverified")
        || !require(unverifiedPathDetails.value(QStringLiteral("origin_authenticated")).toBool(),
                    "probe event retains authenticated origin")
        || !require(!unverifiedPathDetails.value(QStringLiteral("tunnel_path_verified")).toBool(),
                    "probe event retains unverified tunnel path")) {
        return 1;
    }

    health.recordProbeResult(true, true, true, 10.0, -1.0, QString(), true, true);
    if (!require(health.healthState() == ConnectionHealthController::HealthState::Healthy,
                  "authenticated origin on a verified tunnel path may be healthy")
        || !require(health.originAuthenticated(), "origin authentication property is true")
        || !require(health.tunnelPathVerified(), "tunnel path property is true")) {
        return 1;
    }

    health.recordHealthState(ConnectionHealthController::HealthState::Unknown,
                             QStringLiteral("awaiting_probe"));
    const QVariantMap newEpochSnapshot = health.healthSnapshot();
    const QJsonObject newEpochDoctor = health.doctorObject();
    const QJsonArray newEpochChecks = newEpochDoctor.value(QStringLiteral("checks")).toArray();
    bool freshnessIsStale = false;
    bool qualityIsUnknown = false;
    for (const QJsonValue &checkValue : newEpochChecks) {
        const QJsonObject check = checkValue.toObject();
        if (check.value(QStringLiteral("id")).toString() == QStringLiteral("health_freshness")) {
            freshnessIsStale = check.value(QStringLiteral("reason")).toString()
                    == QStringLiteral("probe_stale");
        } else if (check.value(QStringLiteral("id")).toString() == QStringLiteral("network_quality")) {
            qualityIsUnknown = check.value(QStringLiteral("reason")).toString()
                    == QStringLiteral("metrics_not_supplied");
        }
    }
    if (!require(newEpochSnapshot.value(QStringLiteral("last_probe_at")).toString().isEmpty(),
                 "state-only epoch clears the prior probe timestamp")
        || !require(!newEpochSnapshot.value(QStringLiteral("has_latency")).toBool(),
                    "state-only epoch clears prior latency")
        || !require(!newEpochSnapshot.value(QStringLiteral("has_packet_loss")).toBool(),
                    "state-only epoch clears prior packet loss")
        || !require(freshnessIsStale, "doctor does not call the prior epoch probe current")
        || !require(qualityIsUnknown, "doctor does not classify prior epoch quality")) {
        return 1;
    }

    ConnectionHealthController reachabilityPrivacy;
    reachabilityPrivacy.recordHealthState(ConnectionHealthController::HealthState::Unknown,
                                          QStringLiteral("reachability_hint_offline"));
    reachabilityPrivacy.recordEvent(
            QStringLiteral("reachability"), QStringLiteral("hint_offline"),
            { { QStringLiteral("authoritative"), false },
              { QStringLiteral("endpoint"), QStringLiteral("https://private.example/secret") },
              { QStringLiteral("reason_code"), QStringLiteral("free form secret") } });
    const QVariantMap reachabilityEvent = reachabilityPrivacy.flightRecorder().last().toMap();
    const QVariantMap reachabilityDetails = reachabilityEvent.value(QStringLiteral("details")).toMap();
    if (!require(reachabilityPrivacy.lastReason() == QStringLiteral("reachability_hint_offline"),
                 "fixed reachability reason remains symbolic")
        || !require(reachabilityEvent.value(QStringLiteral("category")).toString()
                            == QStringLiteral("reachability"),
                    "fixed reachability category remains symbolic")
        || !require(reachabilityEvent.value(QStringLiteral("outcome")).toString()
                            == QStringLiteral("hint_offline"),
                    "fixed reachability outcome remains symbolic")
        || !require(reachabilityDetails.contains(QStringLiteral("authoritative"))
                            && !reachabilityDetails.value(QStringLiteral("authoritative")).toBool(),
                    "non-authoritative reachability marker is retained")
        || !require(!reachabilityDetails.contains(QStringLiteral("endpoint")),
                    "free-form endpoint detail is discarded")
        || !require(!reachabilityPrivacy.statusJson().contains(QStringLiteral("private.example"))
                            && !reachabilityPrivacy.statusJson().contains(QStringLiteral("free form secret")),
                    "free-form reachability data is not exposed")) {
        return 1;
    }

    health.recordProbeResult(true, true, true, 10.0, -1.0, QString(), false, true);
    if (!require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                 "unverified egress cannot be healthy")
        || !require(health.lastReason() == QStringLiteral("egress_unverified"),
                    "unverified egress reason retained")) {
        return 1;
    }

    health.recordHealthState(ConnectionHealthController::HealthState::Healthy,
                             QStringLiteral("connectivity_probe_ok"), true, false);
    if (!require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                 "direct healthy observations also require a tunnel path proof")
        || !require(health.lastReason() == QStringLiteral("tunnel_path_unverified"),
                    "direct healthy observation is downgraded explicitly")) {
        return 1;
    }

    ConnectionHealthController observedRecovery;
    observedRecovery.recordHealthState(ConnectionHealthController::HealthState::Unhealthy,
                                       QStringLiteral("tunnel_error"));
    observedRecovery.evaluateRecovery(QStringLiteral("tunnel_error"));
    observedRecovery.recordHealthState(ConnectionHealthController::HealthState::Degraded,
                                       QStringLiteral("tunnel_path_unverified"), true, false);
    if (!require(!observedRecovery.recoveryPending(),
                 "a new health observation expires a stale recommendation")) {
        return 1;
    }

    LocalHeadServer healthyServer(true);
    if (!require(healthyServer.listen(), "healthy server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&manager, healthyServer.url(QStringLiteral("user:password@")), true, 1000);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 2000), "healthy probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                    "plain HTTP reachability cannot be healthy")
        || !require(health.lastReason() == QStringLiteral("egress_unverified"),
                    "plain HTTP reason")
        || !require(health.hasLatency(), "successful egress has latency")
        || !require(!health.hasPacketLoss(), "single request does not invent packet loss")
        || !require(!healthyServer.request().contains("secret"), "query secret stripped")
        || !require(!healthyServer.request().contains("guardian"), "opaque path stripped")
        || !require(healthyServer.request().startsWith("HEAD / HTTP/1.1"), "origin root probed")
        || !require(!healthyServer.request().contains("password"), "userinfo secret stripped")) {
        return 1;
    }

    LocalHeadServer errorResponseServer(true, 503);
    if (!require(errorResponseServer.listen(), "error response server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&manager, errorResponseServer.url(), true, 1000);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 2000), "HTTP 503 probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                    "HTTP status is reachability-only, never authenticated")) {
        return 1;
    }

    LocalHeadServer hangingServer(false);
    if (!require(hangingServer.listen(), "hanging server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&manager, hangingServer.url(), true, 300);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 1500), "timeout probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Unhealthy,
                    "timeout classified unhealthy")
        || !require(health.lastReason() == QStringLiteral("probe_timeout"), "timeout reason retained")
        || !require(health.recoveryPending(), "timeout only creates a recovery recommendation")) {
        return 1;
    }

    LocalHeadServer recoveredServer(true);
    if (!require(recoveredServer.listen(), "recovered server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&manager, recoveredServer.url(), true, 1000);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 2000), "recovery probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                    "plain HTTP recovery remains degraded")
        || !require(!health.recoveryPending(),
                    "a completed degraded probe expires the stale recommendation")) {
        return 1;
    }

    health.resetRecoveryPolicy();
    LocalHeadServer staleServer(false);
    LocalHeadServer replacementServer(true);
    if (!require(staleServer.listen(), "stale server listen")
        || !require(replacementServer.listen(), "replacement server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&manager, staleServer.url(), true, 300);
    health.startConnectivityProbe(&manager, replacementServer.url(), true, 1000);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 2000), "replacement probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                    "new generation wins")) {
        return 1;
    }
    waitUntil([]() { return false; }, 400);
    if (!require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                 "stale timeout cannot overwrite newer result")) {
        return 1;
    }

    health.startConnectivityProbe(&manager, QUrl(QStringLiteral("file:///tmp/not-network")), true, 1000);
    if (!require(!health.probeRunning(), "invalid scheme never starts network work")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Unknown,
                    "unobservable endpoint remains unknown")) {
        return 1;
    }

    qInfo("connection_health_probe_tests: all checks passed");
    return 0;
}
