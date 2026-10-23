#pragma once
#include "core/utils/nativeSessionRestore.h"
#include <QObject>
#include <QSharedPointer>
#include <QTimer>
#include <QDebug>
#include <QCoreApplication>
#include "core/utils/errorCodes.h"
#include <functional>
// Explicit inert seams: container classifier, protocol object and final Android
// wrapper/UI adoption. No networking, repositories, JNI or real VPN object.
enum class DockerContainer { None, Awg, WireGuard };
namespace ContainerUtils { inline bool isAwgContainer(DockerContainer c) { return c==DockerContainer::Awg; } }
namespace Vpn { enum class ConnectionState { Connected, Disconnected, Unknown, Disconnecting, Connecting, Reconnecting, Preparing, Error }; }
using ErrorCode=amnezia::ErrorCode;
class VpnConnection : public QObject {
public:
    NativeSessionRestore::Pending m_pendingNativeRestore;
    QString m_nativeRestoreProbe;
    QSharedPointer<QObject> m_vpnProtocol;
    QObject *m_migrationTeardownContext = nullptr;
    bool m_migrationTeardownRecoveryRequired = false, m_unboundNativeSessionObserved = false;
    quint64 m_connectionEpoch = 12;
    QJsonObject m_restoredNativeIdentity, adopted;
    QStringList events;
    Vpn::ConnectionState m_connectionState=Vpn::ConnectionState::Unknown;
    std::function<void(Vpn::ConnectionState)> refusalSink;
    void registerNativeRestore(const QString &,const QString &);
    void invalidateNativeRestore();
    bool rejectNativeRestoreConnect();
    void observeUnboundNativeSession(quint64);
    void observeEmptyNativeServiceState(Vpn::ConnectionState);
    void adoptNativeRestore(const QJsonObject &,const QString &,int,DockerContainer,const QJsonObject &);
    void nativeRestoreRegistered(const QString &,const QString &,bool accepted) { events << (accepted?"ack":"reject"); }
    void nativeRestoreAccepted(const QString &,const QString &) { events << "accepted"; }
    void vpnProtocolError(ErrorCode) { events << "704"; }
    void nativeRestoreConnectRefused(Vpn::ConnectionState state) { if (refusalSink) refusalSink(state); }
    void setConnectionState(Vpn::ConnectionState) { events << "UI"; }
    void restoreConnection(const QString &,int,DockerContainer,const QJsonObject &config,Vpn::ConnectionState) {
        adopted=config; ++m_connectionEpoch; events << "wrapper";
    }
};
class ConnectionController : public QObject {
public:
    ErrorCode m_cachedLastConnectionError{};
    Vpn::ConnectionState m_cachedConnectionState=Vpn::ConnectionState::Unknown;
    std::function<void(Vpn::ConnectionState)> uiSink;
    void handleNativeRestoreConnectRefused(Vpn::ConnectionState);
    void connectionStateChanged(Vpn::ConnectionState state) { if(uiSink)uiSink(state); }
};
struct FakeNetworkManager { int clears=0;void clearConnectionCache(){++clears;} };
struct FakeApplication { FakeNetworkManager manager;FakeNetworkManager *networkManager(){return &manager;} };
inline FakeApplication fakeApplication;
inline FakeApplication *amnApp=&fakeApplication;
class ConnectionUiController {
public:
    std::function<void()> m_pendingConnectionStep;
    Vpn::ConnectionState m_state=Vpn::ConnectionState::Unknown;
    bool m_isConnected=false,m_isConnectionInProgress=false;
    QString m_connectionStateText;
    ErrorCode lastError{};
    void onConnectionStateChanged(Vpn::ConnectionState);
    ErrorCode getLastConnectionError(){return lastError;}
    void connectionErrorOccurred(ErrorCode) {}
    void connectionStateChanged() {}
};
class AndroidController : public QObject {
public:
    int genericStops=0,boundStops=0;
    QJsonObject lastIdentity;
    QString m_restoreServiceGeneration,m_restoreReadyDeliveredGeneration;
    quint64 m_nativeObservationDeliveredTicket=0;
    bool m_restoreRoutesReady=false;
    QStringList restoreEvents;
    void flushRestoreServiceReady();
    void nativeSessionObserved(quint64) { restoreEvents << "observation"; }
    void restoreServiceReady(const QString &) { restoreEvents << "ready"; }
    static AndroidController *instance() { static AndroidController instance;return &instance; }
    void stop() { ++genericStops; }
    void stopBound(const QJsonObject &identity) { ++boundStops;lastIdentity=identity; }
};
class AndroidVpnProtocol {
public:
    QJsonObject m_rawConfig;
    void setConnectionState(Vpn::ConnectionState) {}
    void stop();
};
