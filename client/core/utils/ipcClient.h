#ifndef IPCCLIENT_H
#define IPCCLIENT_H

#include <QLocalSocket>
#include <QObject>
#include <QPointer>

#include "rep_ipc_interface_replica.h"
#include "rep_ipc_process_interface_replica.h"

class IpcClient : public QObject
{
    Q_OBJECT
public:
    explicit IpcClient(QObject *parent = nullptr);

    static IpcClient& Instance();

    static QSharedPointer<IpcInterfaceReplica> Interface();
    static QSharedPointer<IpcProcessInterfaceReplica> CreatePrivilegedProcess();

    template <typename Func>
    static auto withInterface(Func func)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().readyInterface();
        using ReturnType = decltype(func(std::declval<QSharedPointer<IpcInterfaceReplica>>()));

        if (iface.isNull()) {
            qWarning() << "IpcClient::withInterface(): Service is not running";

            if constexpr (std::is_void_v<ReturnType>)
                return;
            else
                return ReturnType{};
        }

        return func(iface);
    }

    template <typename OnSuccess, typename OnFailure>
    static auto withInterface(OnSuccess onSuccess, OnFailure onFailure)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().readyInterface();
        if (iface.isNull()) {
            return onFailure();
        }

        return onSuccess(iface);
    }
signals:

private:
    QSharedPointer<IpcInterfaceReplica> readyInterface();
    void resetServiceConnection();

    QRemoteObjectNode m_node;
    QSharedPointer<IpcInterfaceReplica> m_interface;
    QPointer<QLocalSocket> m_socket;
    bool m_protocolValidated = false;
};

#endif // IPCCLIENT_H
