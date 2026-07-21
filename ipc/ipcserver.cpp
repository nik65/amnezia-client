#include "ipcserver.h"

#include <QDateTime>
#include <QDebug>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QRemoteObjectHost>
#include <QRemoteObjectNode>
#include <QString>
#include <QStringList>
#include <QTimer>

#include "logger.h"
#include "localpeerauthentication.h"
#include "router.h"
#include "killswitch.h"
#include "xray.h"
#include "core/utils/managedRoutePolicy.h"

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#endif

namespace {
constexpr int maximumGlobalProcessCapabilities = 32;
constexpr int maximumUnclaimedProcessCapabilities = 8;
constexpr int maximumProcessCapabilitiesPerUser = 8;
constexpr int maximumProcessCapabilitiesPerPid = 4;
constexpr int maximumRejectedCapabilityPeers = 8;
constexpr int capabilityClaimTimeoutMilliseconds = 10000;
constexpr int processStartTimeoutMilliseconds = 30000;
constexpr int processFinishedGraceMilliseconds = 5000;
constexpr int processTerminationRetryMilliseconds = 5000;
}


IpcServer::IpcServer(QObject *parent) : IpcInterfaceSource(parent)
{
    connect(&m_pingHelper, &PingHelper::connectionLose, this, &IpcServer::connectionLose);
}

int IpcServer::protocolVersion()
{
    return amnezia::PrivilegedIpcProtocolVersion;
}

QString IpcServer::createPrivilegedProcess()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createPrivilegedProcess";
#endif

    if (m_processes.size() >= maximumGlobalProcessCapabilities) {
        qWarning() << "IpcServer: global privileged process capability limit reached";
        return {};
    }
    int unclaimed = 0;
    for (const auto &descriptor : std::as_const(m_processes)) {
        if (descriptor && descriptor->phase == ProcessPhase::AwaitingClaim) {
            ++unclaimed;
        }
    }
    if (unclaimed >= maximumUnclaimedProcessCapabilities) {
        qWarning() << "IpcServer: unclaimed privileged process capability limit reached";
        return {};
    }

    const auto pd = QSharedPointer<ProcessDescriptor>::create();
#ifndef Q_OS_WIN
    pd->localServer.setSocketOptions(QLocalServer::WorldAccessOption);
#else
    pd->localServer.setAutoRearm(false);
#endif
    pd->localServer.setMaxPendingConnections(1);
    pd->localServer.setListenBacklogSize(1);

    QString capability;
    for (int attempt = 0; attempt < 8; ++attempt) {
        capability = amnezia::generateIpcCapability();
        if (!m_processes.contains(capability)
            && pd->localServer.listen(amnezia::getIpcProcessUrl(capability))) {
            break;
        }
        capability.clear();
    }
    if (capability.isEmpty()) {
        qWarning() << QString("Unable to start the process capability: %1.")
                              .arg(pd->localServer.errorString());
        return {};
    }

    m_processes.insert(capability, pd);

    QObject::connect(&pd->localServer,
                     &amnezia::ipc::PrivilegedLocalServer::newConnection, this,
                     [this, capability] { handleProcessConnection(capability); });
    QObject::connect(&pd->lifecycleTimer, &QTimer::timeout, this,
                     [this, capability] { handleProcessTimeout(capability); });
    QObject::connect(&pd->serverNode, &QRemoteObjectHost::error, this,
                     [this, capability](QRemoteObjectNode::ErrorCode errorCode) {
                         qWarning() << "Privileged process QtRO error" << errorCode;
                         beginProcessTermination(capability);
                     });
    QObject::connect(&pd->ipcProcess, &IpcServerProcess::stateChanged, this,
                     [this, capability](QProcess::ProcessState state) {
                         const auto descriptor = m_processes.value(capability);
                         if (descriptor) {
                             descriptor->processState = state;
                         }
                     });
    QObject::connect(&pd->ipcProcess, &IpcServerProcess::started, this,
                     [this, capability] {
                         const auto descriptor = m_processes.value(capability);
                         if (!descriptor) {
                             return;
                         }
                         descriptor->processState = QProcess::Running;
                         if (descriptor->phase == ProcessPhase::Terminating
                             || !descriptor->connection
                             || descriptor->connection->state()
                                     != QLocalSocket::ConnectedState) {
                             beginProcessTermination(capability);
                             return;
                         }
                         descriptor->phase = ProcessPhase::Running;
                         descriptor->lifecycleTimer.stop();
                     });
    QObject::connect(&pd->ipcProcess, &IpcServerProcess::finished, this,
                     [this, capability](int, QProcess::ExitStatus) {
                         const auto descriptor = m_processes.value(capability);
                         if (!descriptor) {
                             return;
                         }
                         descriptor->processState = QProcess::NotRunning;
                         descriptor->phase = ProcessPhase::Finished;
                         descriptor->lifecycleTimer.start(
                                 processFinishedGraceMilliseconds);
                     });
    QObject::connect(&pd->ipcProcess, &IpcServerProcess::errorOccurred, this,
                     [this, capability](QProcess::ProcessError error) {
                         const auto descriptor = m_processes.value(capability);
                         if (!descriptor) {
                             return;
                         }
                         if (error == QProcess::FailedToStart
                             && descriptor->processState == QProcess::NotRunning) {
                             descriptor->phase = ProcessPhase::Finished;
                             descriptor->lifecycleTimer.start(
                                     processFinishedGraceMilliseconds);
                         }
                     });

    pd->lifecycleTimer.setSingleShot(true);
    pd->lifecycleTimer.start(capabilityClaimTimeoutMilliseconds);

    return capability;
}

void IpcServer::handleProcessConnection(const QString &capability)
{
    const auto pd = m_processes.value(capability);
    if (!pd) {
        return;
    }

    QLocalSocket *connection = pd->localServer.nextPendingConnection();
    if (!connection) {
        return;
    }
    if (pd->phase != ProcessPhase::AwaitingClaim) {
        connection->abort();
        connection->deleteLater();
        return;
    }

    QString authorizationError;
    amnezia::ipc::LocalPeerIdentity peerIdentity;
    if (!amnezia::ipc::authorizePrivilegedClient(
                connection, amnezia::ipc::installedClientExecutablePath(), &peerIdentity,
                &authorizationError)) {
        ++pd->rejectedPeers;
        qWarning() << "Rejected unauthorized process IPC connection:"
                   << authorizationError << "attempt" << pd->rejectedPeers;
        connection->abort();
        connection->deleteLater();
        if (pd->rejectedPeers >= maximumRejectedCapabilityPeers) {
            finalizeProcessCapability(capability);
            return;
        }
#ifdef Q_OS_WIN
        if (!pd->localServer.resumeAccepting()) {
            qWarning() << "Unable to re-arm rejected process capability:"
                       << pd->localServer.errorString();
            finalizeProcessCapability(capability);
        }
#endif
        return;
    }

    if (!peerIdentity.isValid() || !processQuotaAvailable(peerIdentity)
        || connection->state() != QLocalSocket::ConnectedState) {
        qWarning() << "Rejected process capability due to identity/quota/state";
        connection->abort();
        connection->deleteLater();
        finalizeProcessCapability(capability);
        return;
    }

    pd->localServer.close();
    while (pd->localServer.hasPendingConnections()) {
        if (QLocalSocket *extra = pd->localServer.nextPendingConnection()) {
            extra->abort();
            extra->deleteLater();
        }
    }

    pd->connection = connection;
    pd->peerIdentity = peerIdentity;
    pd->phase = ProcessPhase::AwaitingStart;
    pd->lifecycleTimer.start(processStartTimeoutMilliseconds);

    QObject::connect(connection, &QLocalSocket::disconnected, this,
                     [this, capability] {
                         QTimer::singleShot(0, this,
                                            [this, capability] {
                                                handleProcessSocketGone(capability);
                                            });
                     });
    QObject::connect(connection, &QObject::destroyed, this,
                     [this, capability] {
                         QTimer::singleShot(0, this,
                                            [this, capability] {
                                                handleProcessSocketGone(capability);
                                            });
                     });

    pd->serverNode.addHostSideConnection(connection);
    if (!pd->serverNode.enableRemoting(&pd->ipcProcess)) {
        qWarning() << "Unable to enable privileged process remoting";
        beginProcessTermination(capability);
        return;
    }
    qDebug() << "Accepted process IPC capability for" << peerIdentity.userIdentifier
             << "PID" << peerIdentity.processId << "session" << peerIdentity.sessionId;
}

bool IpcServer::processQuotaAvailable(
        const amnezia::ipc::LocalPeerIdentity &identity) const
{
    int forUser = 0;
    int forProcess = 0;
    for (const auto &descriptor : m_processes) {
        if (!descriptor || descriptor->phase == ProcessPhase::AwaitingClaim
            || !descriptor->peerIdentity.isValid()) {
            continue;
        }
        if (descriptor->peerIdentity.userIdentifier.compare(
                    identity.userIdentifier, Qt::CaseInsensitive) == 0) {
            ++forUser;
            if (descriptor->peerIdentity.processId == identity.processId
                && descriptor->peerIdentity.sessionId == identity.sessionId
                && descriptor->peerIdentity.logonIdentifier == identity.logonIdentifier) {
                ++forProcess;
            }
        }
    }
    return forUser < maximumProcessCapabilitiesPerUser
            && forProcess < maximumProcessCapabilitiesPerPid;
}

void IpcServer::handleProcessSocketGone(const QString &capability)
{
    const auto pd = m_processes.value(capability);
    if (!pd) {
        return;
    }
    pd->connection.clear();
    if (pd->phase == ProcessPhase::Running
        || pd->phase == ProcessPhase::Terminating
        || pd->processState != QProcess::NotRunning) {
        beginProcessTermination(capability);
    } else {
        finalizeProcessCapability(capability);
    }
}

void IpcServer::handleProcessTimeout(const QString &capability)
{
    const auto pd = m_processes.value(capability);
    if (!pd) {
        return;
    }
    switch (pd->phase) {
    case ProcessPhase::AwaitingClaim:
    case ProcessPhase::Finished:
        finalizeProcessCapability(capability);
        return;
    case ProcessPhase::AwaitingStart:
    case ProcessPhase::Running:
        beginProcessTermination(capability);
        return;
    case ProcessPhase::Terminating:
        if (pd->processState == QProcess::NotRunning) {
            finalizeProcessCapability(capability);
            return;
        }
        ++pd->terminationAttempts;
        pd->ipcProcess.kill();
        pd->lifecycleTimer.start(processTerminationRetryMilliseconds);
        return;
    }
}

void IpcServer::beginProcessTermination(const QString &capability)
{
    const auto pd = m_processes.value(capability);
    if (!pd) {
        return;
    }
    pd->localServer.close();
    if (pd->connection) {
        QLocalSocket *connection = pd->connection.data();
        pd->connection.clear();
        connection->abort();
    }
    if (pd->processState == QProcess::NotRunning) {
        finalizeProcessCapability(capability);
        return;
    }
    pd->phase = ProcessPhase::Terminating;
    ++pd->terminationAttempts;
    pd->ipcProcess.kill();
    pd->lifecycleTimer.start(processTerminationRetryMilliseconds);
}

void IpcServer::finalizeProcessCapability(const QString &capability)
{
    const auto pd = m_processes.take(capability);
    if (!pd) {
        return;
    }
    pd->lifecycleTimer.stop();
    pd->localServer.close();
    pd->serverNode.disableRemoting(&pd->ipcProcess);
    if (pd->connection) {
        QLocalSocket *connection = pd->connection.data();
        pd->connection.clear();
        connection->abort();
    }
}

int IpcServer::routeAddList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeAddList";
#endif

    return Router::routeAddList(gw, ips);
}

int IpcServer::routeAddTrustedList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeAddTrustedList";
#endif

    bool valid = false;
    const QStringList managedRoutes =
            amnezia::managedRoutePolicy::validatedManagedRoutes(ips, &valid);
    if (!valid) {
        qWarning() << "IpcServer: rejected an unsafe or oversized trusted route batch";
        return 0;
    }

    QSet<QString> candidateRoutes = m_trustedManagedRoutes;
    for (const QString &route : managedRoutes) {
        candidateRoutes.insert(route);
    }
    if (candidateRoutes.size() > amnezia::managedRoutePolicy::maximumTotalRouteCount) {
        qWarning() << "IpcServer: cumulative managed route budget exceeded";
        return 0;
    }

    // Reserve the entire validated request even when the platform reports a
    // partial add. This is deliberately conservative: the service cannot know
    // which subset reached the OS, so later batches must not exceed the cap.
    m_trustedManagedRoutes = candidateRoutes;
    return Router::routeAddTrustedList(gw, managedRoutes);
}

bool IpcServer::clearSavedRoutes()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearSavedRoutes";
#endif

    const bool cleared = Router::clearSavedRoutes();
    if (cleared) {
        m_trustedManagedRoutes.clear();
    }
    return cleared;
}

bool IpcServer::routeDeleteList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeDeleteList";
#endif

    return Router::routeDeleteList(gw, ips);
}

bool IpcServer::flushDns()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::flushDns";
#endif

    return Router::flushDns();
}

void IpcServer::resetIpStack()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetIpStack";
#endif

    Router::resetIpStack();
}

bool IpcServer::checkAndInstallDriver()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::checkAndInstallDriver";
#endif

#ifdef Q_OS_WIN
    return TapController::checkAndSetup();
#else
    return true;
#endif
}

QStringList IpcServer::getTapList()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::getTapList";
#endif

#ifdef Q_OS_WIN
    return TapController::getTapList();
#else
    return QStringList();
#endif
}

void IpcServer::cleanUp()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::cleanUp";
#endif

    Logger::init(true);
}

void IpcServer::clearLogs()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearLogs";
#endif

    Logger::init(true);
}

bool IpcServer::createTun(const QString &dev, const QString &subnet)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createTun";
#endif

    return Router::createTun(dev, subnet);
}

bool IpcServer::deleteTun(const QString &dev)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::deleteTun";
#endif

    return Router::deleteTun(dev);
}

bool IpcServer::updateResolvers(const QString &ifname, const QList<QHostAddress> &resolvers)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::updateResolvers";
#endif

    return Router::updateResolvers(ifname, resolvers);
}

bool IpcServer::restoreResolvers()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::restoreResolvers";
#endif

    return Router::restoreResolvers();
}

bool IpcServer::StartRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StartRoutingIpv6";
#endif

    return Router::StartRoutingIpv6();
}

bool IpcServer::StopRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StopRoutingIpv6";
#endif

    return Router::StopRoutingIpv6();
}

void IpcServer::setLogsEnabled(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::setLogsEnabled";
#endif

    Q_UNUSED(enabled);
    Logger::init(true);
}

bool IpcServer::startNetworkCheck(const QString& serverIpv4Gateway, const QString& deviceIpv4Address)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::startNetworkCheck";
#endif

    m_pingHelper.start(serverIpv4Gateway, deviceIpv4Address);
    return true;
}

bool IpcServer::stopNetworkCheck()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::stopNetworkCheck";
#endif

    m_pingHelper.stop();
    return true;
}

bool IpcServer::resetKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetKillSwitchAllowedRange";
#endif

    return KillSwitch::instance()->resetAllowedRange(ranges);
}

bool IpcServer::addKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::addKillSwitchAllowedRange";
#endif

    return KillSwitch::instance()->addAllowedRange(ranges);
}

bool IpcServer::disableAllTraffic()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableAllTraffic";
#endif

    return KillSwitch::instance()->disableAllTraffic();
}

bool IpcServer::enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enableKillSwitch";
#endif

    return KillSwitch::instance()->enableKillSwitch(configStr, vpnAdapterIndex);
}

bool IpcServer::disableKillSwitch()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableKillSwitch";
#endif

    return KillSwitch::instance()->disableKillSwitch();
}

bool IpcServer::enablePeerTraffic(const QJsonObject &configStr)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enablePeerTraffic";
#endif

    return KillSwitch::instance()->enablePeerTraffic(configStr);
}

bool IpcServer::refreshKillSwitch(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::refreshKillSwitch";
#endif

    return KillSwitch::instance()->refresh(enabled);
}

bool IpcServer::xrayStart(const QString& cfg)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStart";
#endif

    return Xray::getInstance().startXray(cfg);
}

bool IpcServer::xrayStop()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStop";
#endif

    return Xray::getInstance().stopXray();
}
