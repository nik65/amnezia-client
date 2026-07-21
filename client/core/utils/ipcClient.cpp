#include "ipcClient.h"
#include "ipc.h"
#include "localpeerauthentication.h"
#include "windowsprivilegedpipe.h"
#include "version.h"
#include <QMetaObject>
#include <QRemoteObjectNode>
#include <QThread>
#include <QTimer>
#include <QtNetwork/qlocalsocket.h>

#include <atomic>
#include <memory>

namespace {

constexpr int PrivilegedProcessReleaseTimeoutMs = 30'000;

struct PrivilegedProcessReplicaLifetime
{
    QPointer<IpcProcessInterfaceReplica> replica;
    QPointer<QRemoteObjectNode> node;
    QPointer<QLocalSocket> socket;
    std::atomic_bool finished = false;
    std::atomic_bool released = false;
    std::atomic_bool cleanupScheduled = false;
};

using PrivilegedProcessReplicaLifetimePtr =
    std::shared_ptr<PrivilegedProcessReplicaLifetime>;

QObject *cleanupContext(const PrivilegedProcessReplicaLifetimePtr &lifetime)
{
    if (lifetime->node)
        return lifetime->node.data();
    if (lifetime->replica)
        return lifetime->replica.data();
    return lifetime->socket.data();
}

void cleanupPrivilegedProcessReplica(
    const PrivilegedProcessReplicaLifetimePtr &lifetime)
{
    if (!lifetime || lifetime->cleanupScheduled.exchange(true))
        return;

    const auto cleanup = [lifetime]() {
        if (lifetime->socket)
            lifetime->socket->abort();
        if (lifetime->replica)
            lifetime->replica->deleteLater();
        if (lifetime->node)
            lifetime->node->deleteLater();
        else if (lifetime->socket)
            lifetime->socket->deleteLater();
    };

    QObject *context = cleanupContext(lifetime);
    if (!context || context->thread() == QThread::currentThread()) {
        cleanup();
        return;
    }

    QMetaObject::invokeMethod(context, cleanup, Qt::QueuedConnection);
}

void releasePrivilegedProcessReplica(
    const PrivilegedProcessReplicaLifetimePtr &lifetime)
{
    lifetime->released.store(true);
    if (lifetime->cleanupScheduled.load())
        return;
    if (lifetime->finished.load()) {
        cleanupPrivilegedProcessReplica(lifetime);
        return;
    }

    QObject *context = cleanupContext(lifetime);
    if (!context) {
        cleanupPrivilegedProcessReplica(lifetime);
        return;
    }

    const auto armTimeout = [lifetime]() {
        if (lifetime->cleanupScheduled.load())
            return;
        if (lifetime->finished.load()) {
            cleanupPrivilegedProcessReplica(lifetime);
            return;
        }

        QObject *timerContext = cleanupContext(lifetime);
        if (!timerContext) {
            cleanupPrivilegedProcessReplica(lifetime);
            return;
        }
        QTimer::singleShot(PrivilegedProcessReleaseTimeoutMs, timerContext,
                           [lifetime]() {
                               cleanupPrivilegedProcessReplica(lifetime);
                           });
    };

    if (context->thread() == QThread::currentThread())
        armTimeout();
    else
        QMetaObject::invokeMethod(context, armTimeout, Qt::QueuedConnection);
}

void abortAndDeleteProcessNode(QLocalSocket *socket, QRemoteObjectNode *node)
{
    if (socket)
        socket->abort();
    if (node)
        node->deleteLater();
}

} // namespace

IpcClient::IpcClient(QObject *parent) : QObject(parent)
{
}

IpcClient& IpcClient::Instance()
{
    thread_local IpcClient ipcClient;
    return ipcClient;
}

QSharedPointer<IpcInterfaceReplica> IpcClient::Interface()
{
    QSharedPointer<IpcInterfaceReplica> rep = Instance().readyInterface();
    if (rep.isNull()) {
        qCritical() << "IpcClient::Interface(): Failed to acquire replica";
        return nullptr;
    }
    return rep;
}

void IpcClient::resetServiceConnection()
{
    if (m_socket) {
        QLocalSocket *socket = m_socket.data();
        m_socket = nullptr;
        socket->abort();
        socket->deleteLater();
    }
    m_protocolValidated = false;
}

QSharedPointer<IpcInterfaceReplica> IpcClient::readyInterface()
{
    if (!m_socket || m_socket->state() != QLocalSocket::ConnectedState) {
        resetServiceConnection();

        auto *socket = new QLocalSocket(&m_node);
#ifdef Q_OS_WIN
        QString connectionError;
        if (!amnezia::ipc::connectWindowsPrivilegedPipe(
                    socket, amnezia::getIpcServiceUrl(), 1000, &connectionError)) {
            qWarning() << "IpcClient: Failed to connect to privileged service:"
                       << connectionError;
            socket->abort();
            socket->deleteLater();
            return {};
        }
#else
        socket->connectToServer(amnezia::getIpcServiceUrl(), QIODevice::ReadWrite);
        if (!socket->waitForConnected(1000)) {
            qWarning() << "IpcClient: Failed to connect to privileged service";
            socket->abort();
            socket->deleteLater();
            return {};
        }
#endif

        QString authorizationError;
        if (!amnezia::ipc::authorizePrivilegedServer(
                socket, amnezia::ipc::installedServiceExecutablePath(),
                QStringLiteral(SERVICE_NAME), nullptr, &authorizationError)) {
            qCritical() << "IpcClient: Rejected untrusted privileged service:"
                        << authorizationError;
            socket->abort();
            socket->deleteLater();
            return {};
        }

        m_node.addClientSideConnection(socket);
        m_socket = socket;
        m_protocolValidated = false;
        if (m_interface.isNull()) {
            m_interface.reset(m_node.acquire<IpcInterfaceReplica>());
        }
    }

    if (m_interface.isNull() || !m_interface->waitForSource(1000)
        || !m_interface->isReplicaValid()) {
        resetServiceConnection();
        return {};
    }
    if (!m_protocolValidated) {
        auto versionReply = m_interface->protocolVersion();
        if (!versionReply.waitForFinished(1000)
            || versionReply.returnValue() != amnezia::PrivilegedIpcProtocolVersion) {
            qCritical() << "IpcClient: Privileged IPC protocol version mismatch";
            resetServiceConnection();
            return {};
        }
        m_protocolValidated = true;
    }
    return m_interface;
}

QSharedPointer<IpcProcessInterfaceReplica> IpcClient::CreatePrivilegedProcess()
{
    return withInterface([](QSharedPointer<IpcInterfaceReplica> &iface) -> QSharedPointer<IpcProcessInterfaceReplica> {
        auto createPrivilegedProcess = iface->createPrivilegedProcess();
        if (!createPrivilegedProcess.waitForFinished(1000)) {
            qCritical() << "Failed to create privileged process";
            Instance().resetServiceConnection();
            return nullptr;
        }

        const QString capability = createPrivilegedProcess.returnValue();
        if (capability.isEmpty()) {
            qCritical() << "Failed to allocate privileged process capability";
            Instance().resetServiceConnection();
            return nullptr;
        }

        auto* node = new QRemoteObjectNode();
        auto *socket = new QLocalSocket(node);
#ifdef Q_OS_WIN
        QString connectionError;
        if (!amnezia::ipc::connectWindowsPrivilegedPipe(
                    socket, amnezia::getIpcProcessUrl(capability), 1000,
                    &connectionError)) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Failed to connect:"
                        << connectionError;
            abortAndDeleteProcessNode(socket, node);
            return nullptr;
        }
#else
        socket->connectToServer(amnezia::getIpcProcessUrl(capability), QIODevice::ReadWrite);
        if (!socket->waitForConnected(1000)) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Failed to connect";
            abortAndDeleteProcessNode(socket, node);
            return nullptr;
        }
#endif
        QString authorizationError;
        if (!amnezia::ipc::authorizePrivilegedServer(
                socket, amnezia::ipc::installedServiceExecutablePath(),
                QStringLiteral(SERVICE_NAME), nullptr, &authorizationError)) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Rejected service:"
                        << authorizationError;
            abortAndDeleteProcessNode(socket, node);
            return nullptr;
        }
        node->addClientSideConnection(socket);

        IpcProcessInterfaceReplica *replica =
            node->acquire<IpcProcessInterfaceReplica>();
        if (!replica) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Failed to acquire replica";
            abortAndDeleteProcessNode(socket, node);
            return nullptr;
        }

        const auto lifetime = std::make_shared<PrivilegedProcessReplicaLifetime>();
        lifetime->replica = replica;
        lifetime->node = node;
        lifetime->socket = socket;

        QObject::connect(replica, &IpcProcessInterfaceReplica::finished, node,
                         [lifetime](int, QProcess::ExitStatus) {
                             lifetime->finished.store(true);
                             if (lifetime->released.load())
                                 cleanupPrivilegedProcessReplica(lifetime);
                         });

        QSharedPointer<IpcProcessInterfaceReplica> rep(
            replica,
            [lifetime](IpcProcessInterfaceReplica *) {
                releasePrivilegedProcessReplica(lifetime);
            });
        if (!rep->waitForSource(1000)) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Failed to initialize replica";
            cleanupPrivilegedProcessReplica(lifetime);
            return nullptr;
        }
        if (!rep->isReplicaValid()) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Replica is invalid";
            cleanupPrivilegedProcessReplica(lifetime);
            return nullptr;
        }

        return rep;
    },
    []() -> QSharedPointer<IpcProcessInterfaceReplica> {
        return nullptr;
    });
}
