#include <QtTest>

#include <QElapsedTimer>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QTemporaryDir>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include "headlessProtocol.h"
#include "cliResponse.h"

using namespace amnezia::headless;

namespace {
class ResponsePeer
{
public:
    ResponsePeer(QString path, QList<QByteArray> chunks, int delayMs, int intervalMs = 0)
        : m_path(std::move(path))
    {
        auto ready = m_ready.get_future();
        m_thread = std::thread([this, chunks, delayMs, intervalMs] {
            QLocalServer server;
            const bool listening = server.listen(m_path);
            m_ready.set_value(listening);
            if (!listening || !server.waitForNewConnection(5000)) return;
            auto peer = std::unique_ptr<QLocalSocket>(server.nextPendingConnection());
            if (!peer) return;
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            for (const auto &chunk : chunks) {
                if (peer->write(chunk) < 0) break;
                if (peer->bytesToWrite()) peer->waitForBytesWritten(1000);
                std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            }
            peer->disconnectFromServer();
        });
        m_listening = ready.get();
    }
    ~ResponsePeer() { if (m_thread.joinable()) m_thread.join(); }
    bool listening() const { return m_listening; }
    const QString &path() const { return m_path; }
private:
    QString m_path;
    std::promise<bool> m_ready;
    std::thread m_thread;
    bool m_listening = false;
};
}

class HeadlessProtocolTest : public QObject
{
    Q_OBJECT

private slots:
    void cliWaitsForDelayedMutationJson_data()
    {
        QTest::addColumn<QString>("command");
        QTest::addColumn<bool>("success");
        QTest::newRow("connect-success") << QStringLiteral("connect") << true;
        QTest::newRow("connect-error") << QStringLiteral("connect") << false;
        QTest::newRow("disconnect-success") << QStringLiteral("disconnect") << true;
        QTest::newRow("disconnect-error") << QStringLiteral("disconnect") << false;
    }
    void cliWaitsForDelayedMutationJson()
    {
        QFETCH(QString, command);
        QFETCH(bool, success);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QByteArray frame = success
                ? QByteArrayLiteral("{\"protocol\":1,\"id\":\"test\",\"ok\":true,\"result\":{\"state\":\"connected\"}}\n")
                : QByteArrayLiteral("{\"protocol\":1,\"id\":\"test\",\"ok\":false,\"error\":{\"code\":\"trial_rejected\",\"message\":\"legacy restored\"}}\n");
        ResponsePeer peer(directory.filePath(QStringLiteral("ipc.sock")), { frame }, 2300);
        QVERIFY(peer.listening());
        QProcess cli;
        QStringList arguments { QStringLiteral("--socket"), peer.path(), QStringLiteral("--json"), command };
        if (command == QStringLiteral("connect")) arguments.append(QStringLiteral("test-profile"));
        cli.start(QStringLiteral(HEADLESS_CLI_BINARY), arguments);
        QVERIFY(cli.waitForStarted(1000));
        QVERIFY(cli.waitForFinished(7000));
        QCOMPARE(cli.exitStatus(), QProcess::NormalExit);
        QCOMPARE(cli.exitCode(), success ? 0 : 1);
        const auto response = QJsonDocument::fromJson(cli.readAllStandardOutput());
        QVERIFY(response.isObject());
        QCOMPARE(response.object().value(QStringLiteral("ok")).toBool(), success);
        if (!success) QCOMPARE(response.object().value(QStringLiteral("error")).toObject()
                                       .value(QStringLiteral("code")).toString(), QStringLiteral("trial_rejected"));
    }
    void responseDeadlineCannotBeExtendedByTrickle()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        ResponsePeer peer(directory.filePath(QStringLiteral("ipc.sock")), { "{", "x", "x", "x", "x" }, 10, 25);
        QVERIFY(peer.listening());
        QLocalSocket client;
        client.connectToServer(peer.path());
        QVERIFY(client.waitForConnected(1000));
        QString error;
        QElapsedTimer elapsed; elapsed.start();
        QVERIFY(readCliResponseFrame(client, error, 65).isEmpty());
        QVERIFY(elapsed.elapsed() < 120);
        QCOMPARE(error, QStringLiteral("daemon response deadline exceeded"));
    }
    void responsePeerCloseFailsFast()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        ResponsePeer peer(directory.filePath(QStringLiteral("ipc.sock")), {}, 10);
        QVERIFY(peer.listening());
        QLocalSocket client;
        client.connectToServer(peer.path());
        QVERIFY(client.waitForConnected(1000));
        QString error;
        QElapsedTimer elapsed; elapsed.start();
        QVERIFY(readCliResponseFrame(client, error, 120000).isEmpty());
        QVERIFY(elapsed.elapsed() < 1000);
        QVERIFY(!error.isEmpty());
    }
    void responseOversizedFrameRejected()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        ResponsePeer peer(directory.filePath(QStringLiteral("ipc.sock")), { QByteArray(MaximumFrameSize + 1, 'x') }, 0);
        QVERIFY(peer.listening());
        QLocalSocket client;
        client.connectToServer(peer.path());
        QVERIFY(client.waitForConnected(1000));
        QString error;
        QVERIFY(readCliResponseFrame(client, error, 2000).isEmpty());
        QCOMPARE(error, QStringLiteral("daemon response frame is too large"));
    }

    void statusRequestRoundTrips()
    {
        const Request original { Command::Status, QStringLiteral("request-1"), {} };
        const QByteArray frame = encodeRequest(original);

        Request parsed;
        QString error;
        QVERIFY(parseRequest(frame, parsed, &error));
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QCOMPARE(parsed.command, Command::Status);
        QCOMPARE(parsed.requestId, QStringLiteral("request-1"));
        QVERIFY(parsed.parameters.isEmpty());
    }

    void commandsWithParametersRoundTrip()
    {
        const Request original {
            Command::Connect,
            QStringLiteral("request-2"),
            QJsonObject { { QStringLiteral("profile"), QStringLiteral("work") } }
        };

        Request parsed;
        QVERIFY(parseRequest(encodeRequest(original), parsed));
        QCOMPARE(parsed.command, Command::Connect);
        QCOMPARE(parsed.parameters.value(QStringLiteral("profile")).toString(),
                 QStringLiteral("work"));
    }

    void unknownCommandIsRejected()
    {
        Request parsed;
        QString error;
        QVERIFY(!parseRequest(
            QByteArrayLiteral("{\"protocol\":1,\"id\":\"x\",\"command\":\"reboot\",\"params\":{}}\n"),
            parsed, &error));
        QVERIFY(error.contains(QStringLiteral("command")));
    }

    void malformedAndOversizedFramesAreRejected()
    {
        Request parsed;
        QString error;
        QVERIFY(!parseRequest(QByteArrayLiteral("not-json\n"), parsed, &error));
        QVERIFY(!error.isEmpty());

        QByteArray oversized(MaximumFrameSize + 1, 'x');
        oversized.append('\n');
        QVERIFY(!parseRequest(oversized, parsed, &error));
        QVERIFY(error.contains(QStringLiteral("large")));
    }

    void responseIsSingleLineAndVersioned()
    {
        const QByteArray frame = encodeResponse(
            QStringLiteral("request-3"), QJsonObject { { QStringLiteral("connected"), false } });
        QVERIFY(frame.endsWith('\n'));
        QCOMPARE(frame.count('\n'), 1);

        const QJsonDocument document = QJsonDocument::fromJson(frame.trimmed());
        QVERIFY(document.isObject());
        QCOMPARE(document.object().value(QStringLiteral("protocol")).toInt(),
                 WireProtocolVersion);
        QCOMPARE(document.object().value(QStringLiteral("ok")).toBool(), true);
        QCOMPARE(document.object().value(QStringLiteral("id")).toString(),
                 QStringLiteral("request-3"));
    }
};

QTEST_MAIN(HeadlessProtocolTest)
#include "tst_headless_protocol.moc"
