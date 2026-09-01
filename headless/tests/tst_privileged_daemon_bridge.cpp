#include <QtTest>

#include <atomic>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QTemporaryDir>

#include "privilegedDaemonBridge.h"

using namespace amnezia::headless;

namespace
{

class AllowPeer final : public PrivilegedPeerVerifier
{
public:
    bool verify(QLocalSocket *, QString *) const override
    {
        return true;
    }
};

class FakePrivilegedDaemon final
{
public:
    explicit FakePrivilegedDaemon(QString socketPath)
        : m_socketPath(std::move(socketPath))
    {
    }

    ~FakePrivilegedDaemon()
    {
        stop();
    }

    bool start()
    {
        const auto ready = std::make_shared<std::promise<bool>>();
        auto result = ready->get_future();
        m_stop.store(false);
        m_thread = std::thread([this, ready]() { serve(ready); });
        return result.get();
    }

    void stop()
    {
        m_stop.store(true);
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    QString commandType() const
    {
        const std::lock_guard lock(m_mutex);
        return m_lastCommandType;
    }

    QJsonObject command() const
    {
        const std::lock_guard lock(m_mutex);
        return m_lastCommand;
    }

private:
    void serve(const std::shared_ptr<std::promise<bool>> &ready)
    {
        QLocalServer server;
        QLocalServer::removeServer(m_socketPath);
        if (!server.listen(m_socketPath)) {
            ready->set_value(false);
            return;
        }
        ready->set_value(true);

        while (!m_stop.load()) {
            if (!server.waitForNewConnection(100)) {
                continue;
            }
            std::unique_ptr<QLocalSocket> socket(server.nextPendingConnection());
            if (!socket) {
                continue;
            }
            while (!m_stop.load() && socket->waitForReadyRead(1000)) {
                readCommand(socket.get());
            }
        }

        server.close();
        QLocalServer::removeServer(m_socketPath);
    }

    void readCommand(QLocalSocket *socket)
    {
        while (socket->canReadLine()) {
            const QJsonDocument document = QJsonDocument::fromJson(socket->readLine().trimmed());
            if (!document.isObject()) {
                continue;
            }
            const QJsonObject command = document.object();
            const QString type = command.value(QStringLiteral("type")).toString();
            {
                const std::lock_guard lock(m_mutex);
                m_lastCommand = command;
                m_lastCommandType = type;
            }
            const int protocol = command.value(QStringLiteral("protocolVersion")).toInt(-1);
            if (protocol != 2) {
                socket->disconnectFromServer();
                return;
            }

            if (type == QStringLiteral("activate")) {
                socket->write(QByteArrayLiteral("{\"protocolVersion\":2,\"type\":\"connected\",\"pubkey\":\"test\"}\n"));
            } else if (type == QStringLiteral("deactivate")) {
                socket->write(QByteArrayLiteral("{\"protocolVersion\":2,\"type\":\"disconnected\"}\n"));
            } else if (type == QStringLiteral("status")) {
                socket->write(QByteArrayLiteral("{\"protocolVersion\":2,\"type\":\"status\",\"connected\":true}\n"));
            } else if (type == QStringLiteral("logs")) {
                socket->write(QByteArrayLiteral("{\"protocolVersion\":2,\"type\":\"logs\",\"logs\":\"safe\"}\n"));
            }
            socket->flush();
        }
    }

    QString m_socketPath;
    std::atomic_bool m_stop = false;
    std::thread m_thread;
    mutable std::mutex m_mutex;
    QString m_lastCommandType;
    QJsonObject m_lastCommand;
};

} // namespace

class PrivilegedDaemonBridgeTest : public QObject
{
    Q_OBJECT

private slots:
    void sendsVersionedActivateAndWaitsForHandshake()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString socketPath = temporaryDirectory.filePath(QStringLiteral("daemon.sock"));
        FakePrivilegedDaemon server(socketPath);
        QVERIFY(server.start());

        PrivilegedDaemonBridge bridge(socketPath, std::make_shared<AllowPeer>(), 1000);
        const BridgeResult result = bridge.activate(QJsonObject {
            { QStringLiteral("protocol"), QStringLiteral("wireguard") },
            { QStringLiteral("wireguard_config_data"), QJsonObject {
                { QStringLiteral("client_priv_key"), QStringLiteral("[REDACTED]") },
            } },
        });

        QVERIFY2(result.ok, qPrintable(result.message));
        QCOMPARE(server.commandType(), QStringLiteral("activate"));
        QCOMPARE(server.command().value(QStringLiteral("protocolVersion")).toInt(), 2);
        QVERIFY(!server.command().contains(QStringLiteral("protocol"))
                || server.command().value(QStringLiteral("protocol")).isString());
    }

    void statusAndLogsUseExistingV2Replies()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString socketPath = temporaryDirectory.filePath(QStringLiteral("daemon.sock"));
        FakePrivilegedDaemon server(socketPath);
        QVERIFY(server.start());
        PrivilegedDaemonBridge bridge(socketPath, std::make_shared<AllowPeer>(), 1000);

        QJsonObject status;
        QVERIFY2(bridge.status(status).ok, qPrintable(bridge.lastError().message));
        QCOMPARE(status.value(QStringLiteral("connected")).toBool(), true);
        QCOMPARE(server.commandType(), QStringLiteral("status"));

        QString logs;
        QVERIFY2(bridge.logs(logs).ok, qPrintable(bridge.lastError().message));
        QCOMPARE(logs, QStringLiteral("safe"));
        QCOMPARE(server.commandType(), QStringLiteral("logs"));
    }

    void deactivationWaitsForDisconnectedEvent()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString socketPath = temporaryDirectory.filePath(QStringLiteral("daemon.sock"));
        FakePrivilegedDaemon server(socketPath);
        QVERIFY(server.start());
        PrivilegedDaemonBridge bridge(socketPath, std::make_shared<AllowPeer>(), 1000);

        QVERIFY2(bridge.deactivate().ok, qPrintable(bridge.lastError().message));
        QCOMPARE(server.commandType(), QStringLiteral("deactivate"));
    }
};

QTEST_MAIN(PrivilegedDaemonBridgeTest)
#include "tst_privileged_daemon_bridge.moc"
