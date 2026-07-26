#include "core/controllers/connectionHealthController.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkProxyFactory>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <QStringList>

#include <functional>
#include <cstdio>

namespace
{
QStringList *g_capturedMessages = nullptr;

void captureQtMessage(QtMsgType, const QMessageLogContext &, const QString &message)
{
    if (g_capturedMessages) {
        g_capturedMessages->append(message);
    }
}

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

class RejectingApplicationProxyFactory final : public QNetworkProxyFactory
{
public:
    static void resetQueryCount() { s_queryCount = 0; }
    static int queryCount() { return s_queryCount; }

    QList<QNetworkProxy> queryProxy(const QNetworkProxyQuery &) override
    {
        ++s_queryCount;
        return { QNetworkProxy(QNetworkProxy::HttpProxy,
                               QStringLiteral("127.0.0.1"), 1) };
    }

private:
    inline static int s_queryCount = 0;
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
        std::fprintf(stderr, "FAILED: %s\n", message);
        std::fflush(stderr);
        qCritical("FAILED: %s", message);
    }
    return condition;
}
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QNetworkAccessManager guardianManager;
    guardianManager.setProxy(QNetworkProxy::NoProxy);
    ConnectionHealthController health;

    ConnectionHealthController manualRecovery;
    bool recoveryRequestObserved = false;
    quint64 requestedRecoveryEpoch = 0;
    QObject::connect(
            &manualRecovery,
            &ConnectionHealthController::recoveryActionRequested,
            &manualRecovery,
            [&](ConnectionHealthController::RecoveryAction,
                const QString &, int, quint64 recoveryEpoch) {
                recoveryRequestObserved = true;
                requestedRecoveryEpoch = recoveryEpoch;
            });
    manualRecovery.recordHealthState(
            ConnectionHealthController::HealthState::Unhealthy,
            QStringLiteral("tunnel_error"));
    manualRecovery.evaluateRecovery(QStringLiteral("tunnel_error"));
    const quint64 pendingRecoveryEpoch =
            manualRecovery.pendingRecoveryEpoch();
    if (!require(pendingRecoveryEpoch != 0,
                 "accepted recovery has a nonzero epoch")
        || !require(manualRecovery.requestPendingRecovery(),
                    "explicit user request dispatches pending recovery")
        || !require(recoveryRequestObserved
                            && requestedRecoveryEpoch == pendingRecoveryEpoch,
                    "recovery request preserves its epoch")
        || !require(manualRecovery.recoveryRequestDispatched(),
                    "recovery request is single-dispatch")
        || !require(!manualRecovery.requestPendingRecovery(),
                    "duplicate explicit request is rejected")) {
        return 1;
    }
    manualRecovery.acknowledgeRecoveryResult(
            false, QStringLiteral("recovery_stale_epoch"),
            pendingRecoveryEpoch + 1);
    if (!require(manualRecovery.recoveryPending(),
                 "stale acknowledgement cannot consume a newer recovery")
        || !require(manualRecovery.recoveryRequestDispatched(),
                    "stale acknowledgement preserves in-flight state")) {
        return 1;
    }
    manualRecovery.acknowledgeRecoveryResult(
            true, QStringLiteral("recovery_succeeded"),
            pendingRecoveryEpoch);
    if (!require(!manualRecovery.recoveryPending(),
                 "matching acknowledgement consumes pending recovery")
        || !require(!manualRecovery.recoveryRequestDispatched(),
                    "matching acknowledgement clears dispatch state")) {
        return 1;
    }

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

    QStringList guardianLogMessages;
    g_capturedMessages = &guardianLogMessages;
    const QtMessageHandler previousMessageHandler = qInstallMessageHandler(captureQtMessage);
    {
        ConnectionHealthController loggedGuardian;
        loggedGuardian.recordHealthState(
                ConnectionHealthController::HealthState::Unknown,
                QStringLiteral("guardian-secret-reason C:\\Users\\Secret\\profile.json"));
        loggedGuardian.recordEvent(
                QStringLiteral("guardian"), QStringLiteral("observed"),
                { { QStringLiteral("endpoint"),
                    QStringLiteral("https://private.guardian.invalid/sensitive-path?token=secret") },
                  { QStringLiteral("reason_code"),
                    QStringLiteral("guardian-secret-reason C:\\Users\\Secret\\profile.json") } });
        loggedGuardian.recordProbeResult(
                false, false, false, -1.0, -1.0,
                QStringLiteral("https://private.guardian.invalid/sensitive-path?token=secret"));
    }
    qInstallMessageHandler(previousMessageHandler);
    g_capturedMessages = nullptr;

    int structuredGuardianEvents = 0;
    bool guardianEventsAreStructured = true;
    for (const QString &message : guardianLogMessages) {
        if (!message.startsWith(QStringLiteral("GuardianEvent "))) {
            continue;
        }
        ++structuredGuardianEvents;
        const int jsonStart = message.indexOf(QLatin1Char('{'));
        const QJsonDocument document = QJsonDocument::fromJson(message.mid(jsonStart).toUtf8());
        guardianEventsAreStructured = guardianEventsAreStructured
                && jsonStart > 0 && document.isObject()
                && document.object().contains(QStringLiteral("sequence"))
                && document.object().contains(QStringLiteral("category"));
    }
    const QString combinedGuardianLog = guardianLogMessages.join(QLatin1Char('\n'));
    if (!require(structuredGuardianEvents >= 4,
                 "each flight-recorder append is persisted as a GuardianEvent")
        || !require(guardianEventsAreStructured,
                    "GuardianEvent payloads are compact structured JSON")
        || !require(!combinedGuardianLog.contains(QStringLiteral("guardian-secret-reason")),
                    "arbitrary reasons never leak to the Qt log")
        || !require(!combinedGuardianLog.contains(QStringLiteral("private.guardian.invalid")),
                    "URLs never leak to the Qt log")
        || !require(!combinedGuardianLog.contains(QStringLiteral("sensitive-path"))
                            && !combinedGuardianLog.contains(QStringLiteral("Users\\Secret")),
                    "paths never leak to the Qt log")) {
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

    ConnectionHealthController hysteresis;
    hysteresis.recordProbeResult(false, false, false, -1.0, -1.0,
                                 QStringLiteral("handshake_probe_failed"));
    QVariantMap hysteresisSnapshot = hysteresis.healthSnapshot();
    QVariantMap hysteresisEventDetails =
            hysteresis.flightRecorder().last().toMap().value(QStringLiteral("details")).toMap();
    if (!require(hysteresis.healthState() == ConnectionHealthController::HealthState::Degraded,
                 "one raw unhealthy probe is not enough to enter unhealthy")
        || !require(hysteresis.lastReason() == QStringLiteral("probe_failure_unconfirmed"),
                    "first failure is explicitly unconfirmed")
        || !require(hysteresisSnapshot.value(QStringLiteral("observed_probe_state")).toString()
                            == QStringLiteral("unhealthy"),
                    "snapshot preserves the raw unhealthy observation")
        || !require(hysteresisSnapshot.value(QStringLiteral("observed_probe_reason")).toString()
                            == QStringLiteral("handshake_probe_failed"),
                    "snapshot preserves the sanitized root cause")
        || !require(hysteresisSnapshot.value(QStringLiteral("probe_failure_streak")).toInt() == 1,
                    "snapshot exposes the first bounded failure streak")
        || !require(hysteresisEventDetails.value(QStringLiteral("observed_reason_code")).toString()
                            == QStringLiteral("handshake_probe_failed"),
                    "event preserves the sanitized root cause")
        || !require(hysteresisEventDetails.value(QStringLiteral("probe_failure_streak")).toInt() == 1,
                    "event exposes the bounded failure streak")) {
        return 1;
    }

    hysteresis.recordProbeResult(false, false, false, -1.0, -1.0,
                                 QStringLiteral("handshake_probe_failed"));
    const QVariantMap firstRecoveryDecision =
            hysteresis.evaluateRecovery(QStringLiteral("handshake_probe_failed"));
    const QString pendingAction = hysteresis.pendingRecoveryAction();
    if (!require(hysteresis.healthState() == ConnectionHealthController::HealthState::Unhealthy,
                 "two consecutive raw unhealthy probes enter unhealthy")
        || !require(hysteresis.healthSnapshot().value(QStringLiteral("probe_failure_streak")).toInt() == 2,
                    "failure streak is bounded at the confirmation threshold")
        || !require(firstRecoveryDecision.value(QStringLiteral("accepted")).toBool(),
                    "confirmed unhealthy can create one recovery recommendation")
        || !require(hysteresis.recoveryAttempts() == 1 && hysteresis.recoveryPending(),
                    "one recovery attempt is pending")) {
        return 1;
    }

    hysteresis.recordProbeResult(false, false, false, -1.0, -1.0,
                                 QStringLiteral("egress_probe_failed"));
    const QVariantMap repeatedFailureDecision =
            hysteresis.evaluateRecovery(QStringLiteral("egress_probe_failed"));
    if (!require(hysteresis.recoveryPending()
                            && hysteresis.pendingRecoveryAction() == pendingAction,
                    "another unhealthy probe preserves the pending action")
        || !require(hysteresis.recoveryAttempts() == 1,
                    "another unhealthy probe does not spend recovery budget")
        || !require(!repeatedFailureDecision.value(QStringLiteral("accepted")).toBool()
                            && repeatedFailureDecision.value(QStringLiteral("reason")).toString()
                                    == QStringLiteral("recovery_result_pending"),
                    "another unhealthy probe cannot loop the first recovery action")) {
        return 1;
    }

    hysteresis.recordProbeResult(true, true, true, 10.0, -1.0, QString(), true, true);
    hysteresisSnapshot = hysteresis.healthSnapshot();
    const QVariantMap firstRecoveryConfirmation = hysteresis.evaluateRecovery();
    if (!require(hysteresis.healthState() == ConnectionHealthController::HealthState::Unhealthy,
                 "one raw recovery observation is not enough to leave unhealthy")
        || !require(hysteresis.lastReason() == QStringLiteral("probe_recovery_unconfirmed"),
                    "first recovery is explicitly unconfirmed")
        || !require(hysteresisSnapshot.value(QStringLiteral("observed_probe_state")).toString()
                            == QStringLiteral("healthy"),
                    "snapshot preserves the raw recovery observation")
        || !require(hysteresisSnapshot.value(QStringLiteral("probe_recovery_streak")).toInt() == 1,
                    "snapshot exposes the first bounded recovery streak")
        || !require(hysteresis.recoveryPending() && hysteresis.recoveryAttempts() == 1,
                    "unconfirmed recovery preserves the pending action and budget")
        || !require(!firstRecoveryConfirmation.value(QStringLiteral("accepted")).toBool(),
                    "unconfirmed recovery cannot create another action")) {
        return 1;
    }

    hysteresis.recordProbeResult(true, true, true, 10.0, -1.0, QString(), true, true);
    hysteresisSnapshot = hysteresis.healthSnapshot();
    if (!require(hysteresis.healthState() == ConnectionHealthController::HealthState::Healthy,
                 "two consecutive raw recovery observations leave unhealthy")
        || !require(!hysteresis.recoveryPending(),
                    "confirmed recovery supersedes the stale recommendation")
        || !require(hysteresisSnapshot.value(QStringLiteral("probe_recovery_streak")).toInt() == 2,
                    "recovery streak is bounded at the confirmation threshold")) {
        return 1;
    }

    hysteresis.recordHealthState(ConnectionHealthController::HealthState::Unknown,
                                 QStringLiteral("awaiting_probe"));
    hysteresisSnapshot = hysteresis.healthSnapshot();
    if (!require(hysteresisSnapshot.value(QStringLiteral("probe_failure_streak")).toInt() == 0
                            && hysteresisSnapshot.value(QStringLiteral("probe_recovery_streak")).toInt() == 0,
                    "state-only epoch resets both probe streaks")
        || !require(hysteresisSnapshot.value(QStringLiteral("observed_probe_state")).toString()
                            == QStringLiteral("unknown"),
                    "state-only epoch clears prior raw probe evidence")) {
        return 1;
    }
    hysteresis.recordProbeResult(false, false, false, -1.0, -1.0,
                                 QStringLiteral("handshake_probe_failed"));
    if (!require(hysteresis.healthState() == ConnectionHealthController::HealthState::Degraded
                            && hysteresis.healthSnapshot()
                                       .value(QStringLiteral("probe_failure_streak")).toInt() == 1,
                    "failure confirmation restarts after a state-only epoch")) {
        return 1;
    }

    ConnectionHealthController epochSupersession;
    epochSupersession.recordHealthState(ConnectionHealthController::HealthState::Unhealthy,
                                        QStringLiteral("tunnel_error"));
    epochSupersession.evaluateRecovery(QStringLiteral("tunnel_error"));
    epochSupersession.recordHealthState(ConnectionHealthController::HealthState::Unhealthy,
                                        QStringLiteral("tunnel_error"));
    if (!require(!epochSupersession.recoveryPending(),
                 "a state-only epoch supersedes a pending recommendation even at the same state")) {
        return 1;
    }

    LocalHeadServer healthyServer(true);
    if (!require(healthyServer.listen(), "healthy server listen")) {
        return 1;
    }
    RejectingApplicationProxyFactory::resetQueryCount();
    QNetworkProxyFactory::setApplicationProxyFactory(
            new RejectingApplicationProxyFactory);
    const bool guardianPolicyRemainsDirect = guardianManager.proxyFactory() == nullptr
            && guardianManager.proxy().type() == QNetworkProxy::NoProxy;
    health.startConnectivityProbe(&guardianManager,
                                  healthyServer.url(QStringLiteral("user:password@")),
                                  true, 1000);
    const bool healthyProbeCompleted =
            waitUntil([&health]() { return !health.probeRunning(); }, 2000);
    const int applicationProxyFactoryQueries =
            RejectingApplicationProxyFactory::queryCount();
    QNetworkProxyFactory::setApplicationProxyFactory(nullptr);
    if (!require(guardianPolicyRemainsDirect,
                 "Guardian manager keeps its explicit NoProxy policy")
        || !require(healthyProbeCompleted, "healthy probe completed")
        || !require(applicationProxyFactoryQueries == 0,
                    "Guardian request bypasses the dynamic application proxy factory")
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

    LocalHeadServer reentrantProxyServer(true);
    if (!require(reentrantProxyServer.listen(), "reentrant proxy server listen")) {
        return 1;
    }
    QNetworkAccessManager reentrantManager;
    reentrantManager.setProxy(QNetworkProxy::NoProxy);
    ConnectionHealthController reentrantProxyHealth;
    bool reentrantMutationApplied = false;
    QObject::connect(
            &reentrantProxyHealth,
            &ConnectionHealthController::probeRunningChanged,
            &reentrantProxyHealth,
            [&]() {
                if (reentrantProxyHealth.probeRunning()
                    && !reentrantMutationApplied) {
                    reentrantMutationApplied = true;
                    reentrantManager.setProxy(QNetworkProxy(
                            QNetworkProxy::HttpProxy,
                            QStringLiteral("127.0.0.1"), 1));
                }
            },
            Qt::DirectConnection);
    reentrantProxyHealth.startConnectivityProbe(
            &reentrantManager, reentrantProxyServer.url(), true, 1000, true);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    if (!require(reentrantMutationApplied,
                 "hostile same-thread slot changed the manager policy")
        || !require(!reentrantProxyHealth.probeRunning(),
                    "reentrant proxy mutation fails closed before dispatch")
        || !require(reentrantProxyHealth.healthState()
                            == ConnectionHealthController::HealthState::Unknown,
                    "reentrant proxy mutation remains unknown")
        || !require(reentrantProxyHealth.lastReason()
                            == QStringLiteral("probe_proxy_path_unverified"),
                    "reentrant proxy mutation has a stable reason")
        || !require(reentrantProxyServer.request().isEmpty(),
                    "reentrant proxy mutation sends no HTTP request")) {
        return 1;
    }

    LocalHeadServer errorResponseServer(true, 503);
    if (!require(errorResponseServer.listen(), "error response server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&guardianManager, errorResponseServer.url(), true, 1000);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 2000), "HTTP 503 probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                    "HTTP status is reachability-only, never authenticated")) {
        return 1;
    }

    LocalHeadServer hangingServer(false);
    if (!require(hangingServer.listen(), "hanging server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&guardianManager, hangingServer.url(), true, 300);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 1500), "first timeout probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                    "one timeout remains an unconfirmed failure")
        || !require(health.lastReason() == QStringLiteral("probe_failure_unconfirmed"),
                    "first timeout is explicitly unconfirmed")
        || !require(!health.recoveryPending(),
                    "one timeout does not create a recovery recommendation")) {
        return 1;
    }
    health.startConnectivityProbe(&guardianManager, hangingServer.url(), true, 300);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 1500), "second timeout probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Unhealthy,
                    "two timeouts confirm unhealthy")
        || !require(health.lastReason() == QStringLiteral("probe_timeout"), "timeout root cause retained")
        || !require(health.recoveryPending(), "confirmed timeout creates one recovery recommendation")) {
        return 1;
    }

    LocalHeadServer recoveredServer(true);
    if (!require(recoveredServer.listen(), "recovered server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&guardianManager, recoveredServer.url(), true, 1000);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 2000), "first recovery probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Unhealthy,
                    "one degraded recovery observation keeps unhealthy")
        || !require(health.recoveryPending(),
                    "one degraded recovery observation preserves the recommendation")) {
        return 1;
    }
    health.startConnectivityProbe(&guardianManager, recoveredServer.url(), true, 1000);
    if (!require(waitUntil([&health]() { return !health.probeRunning(); }, 2000), "second recovery probe completed")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Degraded,
                    "two degraded recovery observations leave unhealthy")
        || !require(!health.recoveryPending(),
                    "confirmed degraded recovery expires the stale recommendation")) {
        return 1;
    }

    health.resetRecoveryPolicy();
    LocalHeadServer staleServer(false);
    LocalHeadServer replacementServer(true);
    if (!require(staleServer.listen(), "stale server listen")
        || !require(replacementServer.listen(), "replacement server listen")) {
        return 1;
    }
    health.startConnectivityProbe(&guardianManager, staleServer.url(), true, 300);
    health.startConnectivityProbe(&guardianManager, replacementServer.url(), true, 1000);
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

    health.startConnectivityProbe(&guardianManager,
                                  QUrl(QStringLiteral("file:///tmp/not-network")),
                                  true, 1000);
    if (!require(!health.probeRunning(), "invalid scheme never starts network work")
        || !require(health.healthState() == ConnectionHealthController::HealthState::Unknown,
                    "unobservable endpoint remains unknown")) {
        return 1;
    }

    qInfo("connection_health_probe_tests: all checks passed");
    return 0;
}
