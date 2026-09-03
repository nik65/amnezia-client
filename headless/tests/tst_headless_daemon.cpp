#include <QtTest>

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QTemporaryDir>

#include "daemon.h"
#include "headlessProtocol.h"
#include "vpnBackend.h"

using namespace amnezia::headless;

namespace
{

class FakeCommandRunner final : public CommandRunner
{
public:
    explicit FakeCommandRunner(bool wireGuardAvailable = false)
        : m_wireGuardAvailable(wireGuardAvailable)
    {
    }

    bool isAvailable(const QString &program) const override
    {
        return (m_wireGuardAvailable && program == QStringLiteral("wg-quick"))
            || (m_wireGuardAvailable && program == QStringLiteral("wg"))
            || program == QStringLiteral("ip")
            || program == QStringLiteral("resolvectl");
    }

    QString resolveExecutable(const QStringList &candidates) const override
    {
        for (const QString &candidate : candidates) {
            if (isAvailable(candidate)) {
                return candidate;
            }
        }
        return {};
    }

    CommandResult run(const QString &program, const QStringList &arguments) override
    {
        calls.append({ QStringLiteral("run"), {}, program, arguments });
        if (program == QStringLiteral("wg-quick")
            && arguments.contains(QStringLiteral("up"))) {
            m_interfacePresent = true;
        } else if (program == QStringLiteral("wg-quick")
                   && arguments.contains(QStringLiteral("down"))) {
            m_interfacePresent = false;
        }
        return { true, 0, {} };
    }

    CommandResult runCaptured(const QString &program,
                              const QStringList &arguments) override
    {
        if (program == QStringLiteral("ip")
            && arguments.contains(QStringLiteral("link"))) {
            return m_interfacePresent
                ? CommandResult { true, 0, {}, QStringLiteral("7: %1: <POINTOPOINT>\n")
                                      .arg(arguments.constLast()) }
                : CommandResult { false, 1, QStringLiteral("interface absent"), {} };
        }
        if (program == QStringLiteral("ip")
            && arguments.contains(QStringLiteral("addr"))) {
            return m_interfacePresent
                ? CommandResult { true, 0, {}, QStringLiteral("7: %1    inet 10.8.1.2/32\n")
                                      .arg(arguments.constLast()) }
                : CommandResult { false, 1, QStringLiteral("interface absent"), {} };
        }
        if (program == QStringLiteral("resolvectl")
            && arguments == QStringList { QStringLiteral("status") }) {
            return { true, 0, {}, resolverStatusOutput };
        }
        if (program == QStringLiteral("wg")
            && arguments.contains(QStringLiteral("showconf"))) {
            return { true, 0, {}, {} };
        }
        return { true, 0, {}, {} };
    }

    CommandResult start(const QString &id, const QString &program,
                        const QStringList &arguments) override
    {
        calls.append({ QStringLiteral("start"), id, program, arguments });
        return { true, 0, {} };
    }

    CommandResult stop(const QString &id) override
    {
        calls.append({ QStringLiteral("stop"), id, {}, {} });
        return { true, 0, {} };
    }

    struct Call
    {
        QString operation;
        QString id;
        QString program;
        QStringList arguments;
    };
    QList<Call> calls;
    bool m_wireGuardAvailable = false;
    bool m_interfacePresent = false;
    QString resolverStatusOutput;
};

QJsonDocument readResponse(QLocalSocket &client)
{
    QByteArray buffer;
    for (int attempt = 0; attempt < 100; ++attempt) {
        buffer.append(client.readAll());
        const qsizetype newline = buffer.indexOf('\n');
        if (newline >= 0) {
            return QJsonDocument::fromJson(buffer.left(newline).trimmed());
        }
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        if (!client.waitForReadyRead(10)) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        }
    }
    return {};
}

void sendRequest(QLocalSocket &client, const Request &request)
{
    QVERIFY(client.write(encodeRequest(request)) > 0);
}

} // namespace

class HeadlessDaemonTest : public QObject
{
    Q_OBJECT

private slots:
    void statusRequestIsServedOverLocalSocket()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString socketPath = temporaryDirectory.filePath(QStringLiteral("amneziad.sock"));

        auto runner = std::make_shared<FakeCommandRunner>();
        Daemon daemon(socketPath, {}, runner);
        QString startError;
        QVERIFY2(daemon.start(&startError), qPrintable(startError));
        QVERIFY(daemon.isRunning());

        QLocalSocket client;
        client.connectToServer(socketPath, QIODevice::ReadWrite);
        QVERIFY2(client.waitForConnected(1000), qPrintable(client.errorString()));
        QTRY_COMPARE_WITH_TIMEOUT(daemon.connectedClientCount(), 1, 1000);

        const Request request { Command::Status, QStringLiteral("status-1"), {} };
        sendRequest(client, request);
        QTRY_COMPARE_WITH_TIMEOUT(daemon.processedRequestCount(), 1, 1000);

        const QJsonDocument response = readResponse(client);
        QVERIFY(response.isObject());
        QCOMPARE(response.object().value(QStringLiteral("protocol")).toInt(),
                 WireProtocolVersion);
        QCOMPARE(response.object().value(QStringLiteral("ok")).toBool(), true);
        QCOMPARE(response.object().value(QStringLiteral("id")).toString(),
                 QStringLiteral("status-1"));
        QCOMPARE(response.object().value(QStringLiteral("result")).toObject()
                         .value(QStringLiteral("state")).toString(),
                 QStringLiteral("disconnected"));

        client.disconnectFromServer();
        daemon.stop();
        QVERIFY(!daemon.isRunning());
    }

    void malformedRequestGetsBoundedError()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        Daemon daemon(temporaryDirectory.filePath(QStringLiteral("amneziad.sock")),
                      temporaryDirectory.filePath(QStringLiteral("profiles.json")), runner);
        QVERIFY(daemon.start());

        QLocalSocket client;
        client.connectToServer(daemon.socketPath(), QIODevice::ReadWrite);
        QVERIFY(client.waitForConnected(1000));
        QTRY_COMPARE_WITH_TIMEOUT(daemon.connectedClientCount(), 1, 1000);
        QVERIFY(client.write(QByteArrayLiteral("not-json\n")) > 0);
        QTRY_COMPARE_WITH_TIMEOUT(daemon.processedRequestCount(), 0, 50);

        const QJsonDocument response = readResponse(client);
        QVERIFY(response.isObject());
        QCOMPARE(response.object().value(QStringLiteral("ok")).toBool(), false);
        QVERIFY(response.object().value(QStringLiteral("error")).toObject()
                        .value(QStringLiteral("code")).isString());
        QVERIFY(response.object().value(QStringLiteral("error")).toObject()
                        .value(QStringLiteral("message")).toString().size() <= 1024);
    }

    void oversizedCompleteFrameIsRejected()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        Daemon daemon(temporaryDirectory.filePath(QStringLiteral("amneziad.sock")),
                      temporaryDirectory.filePath(QStringLiteral("profiles.json")), runner);
        QVERIFY(daemon.start());

        QLocalSocket client;
        client.connectToServer(daemon.socketPath(), QIODevice::ReadWrite);
        QVERIFY(client.waitForConnected(1000));
        QTRY_COMPARE_WITH_TIMEOUT(daemon.connectedClientCount(), 1, 1000);

        QByteArray oversized(MaximumFrameSize, 'x');
        oversized.append('\n');
        QVERIFY(oversized.size() > MaximumFrameSize);
        QVERIFY(client.write(oversized) > 0);

        const QJsonDocument response = readResponse(client);
        QVERIFY(response.isObject());
        QCOMPARE(response.object().value(QStringLiteral("ok")).toBool(), false);
        QCOMPARE(response.object().value(QStringLiteral("error")).toObject()
                         .value(QStringLiteral("code")).toString(),
                 QStringLiteral("frame_too_large"));
        QVERIFY(client.waitForDisconnected(1000) || client.state() == QLocalSocket::UnconnectedState);
    }

    void partialTailAfterCompleteFrameIsTimedOut()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        Daemon daemon(temporaryDirectory.filePath(QStringLiteral("amneziad.sock")),
                      temporaryDirectory.filePath(QStringLiteral("profiles.json")), runner);
        QVERIFY(daemon.start());
        QLocalSocket client;
        client.connectToServer(daemon.socketPath(), QIODevice::ReadWrite);
        QVERIFY(client.waitForConnected(1000));
        const QByteArray complete = encodeRequest(
                Request { Command::Status, QStringLiteral("tail-1"), {} });
        QVERIFY(client.write(complete + QByteArrayLiteral("{\"protocol\":")) > 0);
        QVERIFY(client.waitForReadyRead(1000));
        QTest::qWait(10'200);
        QVERIFY(client.state() == QLocalSocket::UnconnectedState
                || client.waitForDisconnected(1000));
        daemon.stop();
    }

    void staleSocketIsReplacedWhenNoDaemonOwnsIt()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString socketPath = temporaryDirectory.filePath(QStringLiteral("amneziad.sock"));
        QFile staleSocket(socketPath);
        QVERIFY(staleSocket.open(QIODevice::WriteOnly));
        staleSocket.write("stale");
        staleSocket.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        Daemon daemon(socketPath, temporaryDirectory.filePath(QStringLiteral("profiles.json")), runner);
        QString error;
        QVERIFY2(daemon.start(&error), qPrintable(error));
        QVERIFY(daemon.isRunning());
        daemon.stop();
    }

    void doctorReportsUnavailableVpnBackend()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        Daemon daemon(temporaryDirectory.filePath(QStringLiteral("amneziad.sock")),
                      temporaryDirectory.filePath(QStringLiteral("profiles.json")),
                      std::make_shared<FakeCommandRunner>());
        QVERIFY(daemon.start());

        QLocalSocket client;
        client.connectToServer(daemon.socketPath(), QIODevice::ReadWrite);
        QVERIFY(client.waitForConnected(1000));
        const Request request { Command::Doctor, QStringLiteral("doctor-1"), {} };
        sendRequest(client, request);
        QTRY_COMPARE_WITH_TIMEOUT(daemon.processedRequestCount(), 1, 1000);

        const QJsonDocument response = readResponse(client);
        QVERIFY(response.isObject());
        QCOMPARE(response.object().value(QStringLiteral("ok")).toBool(), true);
        const QJsonObject result = response.object().value(QStringLiteral("result")).toObject();
        QCOMPARE(result.value(QStringLiteral("ready")).toBool(), false);
        const QJsonArray backends = result.value(QStringLiteral("backends")).toArray();
        QCOMPARE(backends.size(), 4);
        for (const QJsonValue &backend : backends) {
            QCOMPARE(backend.toObject().value(QStringLiteral("available")).toBool(), false);
        }
    }

    void startupDetectsOrphanDnsOnConfiguredCustomInterface()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("work.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\n");
        config.close();
        const QString storePath = temporaryDirectory.filePath(QStringLiteral("profiles.json"));
        QFile store(storePath);
        QVERIFY(store.open(QIODevice::WriteOnly));
        const QJsonObject storedProfile {
            { QStringLiteral("id"), QStringLiteral("work") },
            { QStringLiteral("name"), QStringLiteral("Work VPN") },
            { QStringLiteral("protocol"), QStringLiteral("wireguard") },
            { QStringLiteral("configPath"), configPath },
            { QStringLiteral("interfaceName"), QStringLiteral("custom0") },
            { QStringLiteral("dnsServers"), QJsonArray { QStringLiteral("10.0.0.53") } },
            { QStringLiteral("dnsDomains"), QJsonArray { QStringLiteral("~.") } },
        };
        QVERIFY(store.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 1 },
            { QStringLiteral("profiles"), QJsonArray { storedProfile } },
        }).toJson(QJsonDocument::Compact)) > 0);
        store.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->resolverStatusOutput = QStringLiteral(
                "Global\nLink 77 (custom0)\n    DNS Servers: 10.0.0.53\n"
                "    DNS Domain: ~.\n");
        Daemon daemon(temporaryDirectory.filePath(QStringLiteral("amneziad.sock")),
                      storePath, runner);
        QString error;
        QVERIFY(!daemon.start(&error));
        QCOMPARE(daemon.isRunning(), false);
        QVERIFY(error.contains(QStringLiteral("orphaned")));
        QVERIFY(runner->calls.isEmpty());
    }

    void profileCanConnectAndDisconnectThroughDaemon()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString socketPath = temporaryDirectory.filePath(QStringLiteral("amneziad.sock"));
        const QString storePath = temporaryDirectory.filePath(QStringLiteral("profiles.json"));
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("work.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>(true);
        Daemon daemon(socketPath, storePath, runner);
        QVERIFY(daemon.start());

        QLocalSocket client;
        client.connectToServer(socketPath, QIODevice::ReadWrite);
        QVERIFY(client.waitForConnected(1000));

        const QJsonObject profile {
            { QStringLiteral("id"), QStringLiteral("work") },
            { QStringLiteral("name"), QStringLiteral("Work VPN") },
            { QStringLiteral("protocol"), QStringLiteral("wireguard") },
            { QStringLiteral("configPath"), configPath },
        };
        sendRequest(client, Request {
            Command::Import, QStringLiteral("import-1"),
            QJsonObject { { QStringLiteral("profile"), profile } },
        });
        QCOMPARE(readResponse(client).object().value(QStringLiteral("ok")).toBool(), true);

        sendRequest(client, Request {
            Command::Connect, QStringLiteral("connect-1"),
            QJsonObject { { QStringLiteral("profile"), QStringLiteral("work") } },
        });
        const QJsonDocument connectResponse = readResponse(client);
        QVERIFY(connectResponse.object().value(QStringLiteral("ok")).toBool());

        sendRequest(client, Request { Command::Status, QStringLiteral("status-2"), {} });
        const QJsonObject connectedStatus = readResponse(client).object()
                                                 .value(QStringLiteral("result")).toObject();
        QCOMPARE(connectedStatus.value(QStringLiteral("state")).toString(),
                 QStringLiteral("connected"));
        QCOMPARE(connectedStatus.value(QStringLiteral("activeProfile")).toString(),
                 QStringLiteral("work"));

        sendRequest(client, Request { Command::Disconnect, QStringLiteral("disconnect-1"), {} });
        const QJsonObject disconnectedStatus = readResponse(client).object()
                                                    .value(QStringLiteral("result")).toObject();
        QCOMPARE(disconnectedStatus.value(QStringLiteral("state")).toString(),
                 QStringLiteral("disconnected"));
        QCOMPARE(runner->calls.size(), 2);
        const QStringList expectedUpArguments { QStringLiteral("up"), configPath };
        const QStringList expectedDownArguments { QStringLiteral("down"), configPath };
        QCOMPARE(runner->calls.constFirst().arguments, expectedUpArguments);
        QCOMPARE(runner->calls.constLast().arguments, expectedDownArguments);
    }
};

QTEST_MAIN(HeadlessDaemonTest)
#include "tst_headless_daemon.moc"
