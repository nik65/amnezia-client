#ifndef IPCSERVER_H
#define IPCSERVER_H

#include <QMap>
#include <QObject>
#include <QPointer>
#include <QProcess>
#include <QRemoteObjectNode>
#include <QJsonObject>
#include <QSet>
#include <QSharedPointer>
#include <QTimer>
#include "../client/daemon/interfaceconfig.h"
#include "../client/mozilla/pinghelper.h"

#include "ipc.h"
#include "ipcserverprocess.h"
#include "localpeerauthentication.h"
#include "windowsprivilegedpipe.h"

#include "rep_ipc_interface_source.h"

class IpcServer : public IpcInterfaceSource
{
public:
    explicit IpcServer(QObject *parent = nullptr);
    int protocolVersion() override;
    QString createPrivilegedProcess() override;

    virtual int routeAddList(const QString &gw, const QStringList &ips) override;
    virtual int routeAddTrustedList(const QString &gw, const QStringList &ips) override;
    virtual bool clearSavedRoutes() override;
    virtual bool routeDeleteList(const QString &gw, const QStringList &ips) override;
    virtual bool flushDns() override;
    virtual void resetIpStack() override;
    virtual bool checkAndInstallDriver() override;
    virtual QStringList getTapList() override;
    virtual void cleanUp() override;
    virtual void clearLogs() override;
    virtual void setLogsEnabled(bool enabled) override;
    virtual bool createTun(const QString &dev, const QString &subnet) override;
    virtual bool deleteTun(const QString &dev) override;
    virtual bool StartRoutingIpv6() override;
    virtual bool StopRoutingIpv6() override;
    virtual bool disableAllTraffic() override;
    virtual bool addKillSwitchAllowedRange(QStringList ranges) override;
    virtual bool resetKillSwitchAllowedRange(QStringList ranges) override;
    virtual bool enablePeerTraffic(const QJsonObject &configStr) override;
    virtual bool enableKillSwitch(const QJsonObject &excludeAddr, int vpnAdapterIndex) override;
    virtual bool disableKillSwitch() override;
    virtual bool refreshKillSwitch( bool enabled ) override;
    virtual bool updateResolvers(const QString& ifname, const QList<QHostAddress>& resolvers) override;
    virtual bool restoreResolvers() override;
    virtual bool xrayStart(const QString& cfg) override;
    virtual bool xrayStop() override;
    virtual bool startNetworkCheck(const QString& serverIpv4Gateway, const QString& deviceIpv4Address) override;
    virtual bool stopNetworkCheck() override;

private:
    enum class ProcessPhase {
        AwaitingClaim,
        AwaitingStart,
        Running,
        Finished,
        Terminating,
    };

    struct ProcessDescriptor {
        // Destruction is reverse declaration order. Keep the acceptor first so
        // QtRO wrappers/process state are gone before its child QLocalSocket.
        amnezia::ipc::PrivilegedLocalServer localServer;
        QRemoteObjectHost serverNode;
        IpcServerProcess ipcProcess;
        QTimer lifecycleTimer;
        QPointer<QLocalSocket> connection;
        amnezia::ipc::LocalPeerIdentity peerIdentity;
        ProcessPhase phase = ProcessPhase::AwaitingClaim;
        QProcess::ProcessState processState = QProcess::NotRunning;
        int rejectedPeers = 0;
        int terminationAttempts = 0;
    };

    void handleProcessConnection(const QString &capability);
    void handleProcessSocketGone(const QString &capability);
    void handleProcessTimeout(const QString &capability);
    void beginProcessTermination(const QString &capability);
    void finalizeProcessCapability(const QString &capability);
    [[nodiscard]] bool processQuotaAvailable(
            const amnezia::ipc::LocalPeerIdentity &identity) const;

    QMap<QString, QSharedPointer<ProcessDescriptor>> m_processes;
    QSet<QString> m_trustedManagedRoutes;
    PingHelper m_pingHelper;
};

#endif // IPCSERVER_H
