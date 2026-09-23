#include "../remoteLogUploader.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QRegularExpression>
#include <QTemporaryDir>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtTest>

#include "../../client/core/utils/constants/configKeys.h"
#include "../../client/core/utils/selfhosted/clientLogsTarget.h"

using amnezia::headless::HeadlessRemoteLogUploader;

namespace
{
class MockCollector final : public QTcpServer
{
public:
    explicit MockCollector(QObject *parent = nullptr) : QTcpServer(parent)
    {
        connect(this, &QTcpServer::newConnection, this, [this] {
            while (hasPendingConnections()) {
                auto *socket = nextPendingConnection();
                m_buffers.insert(socket, {});
                connect(socket, &QTcpSocket::readyRead, this, [this, socket] {
                    readRequest(socket);
                });
                connect(socket, &QTcpSocket::disconnected, this, [this, socket] {
                    m_buffers.remove(socket);
                    socket->deleteLater();
                });
            }
        });
    }

    bool badReceipt = false;
    QList<QByteArray> payloads;
    QList<QByteArray> batchIds;

private:
    void readRequest(QTcpSocket *socket)
    {
        QByteArray &buffer = m_buffers[socket];
        buffer += socket->readAll();
        const qsizetype headerEnd = buffer.indexOf("\r\n\r\n");
        if (headerEnd < 0) return;
        const QByteArray header = buffer.left(headerEnd);
        const QRegularExpression lengthExpression(QStringLiteral(
                "(?im)^content-length:\\s*(\\d+)\\s*$"));
        const auto lengthMatch = lengthExpression.match(QString::fromLatin1(header));
        if (!lengthMatch.hasMatch()) return;
        const qsizetype bodyLength = lengthMatch.captured(1).toLongLong();
        const qsizetype bodyStart = headerEnd + 4;
        if (buffer.size() < bodyStart + bodyLength) return;
        payloads.append(buffer.mid(bodyStart, bodyLength));
        const QRegularExpression idExpression(QStringLiteral(
                "(?im)^x-amnezia-batch-id:\\s*([^\\r\\n]+)"));
        const auto idMatch = idExpression.match(QString::fromLatin1(header));
        batchIds.append(idMatch.hasMatch() ? idMatch.captured(1).toLatin1() : QByteArray());
        QByteArray response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n";
        if (!badReceipt) {
            response += "X-Amnezia-Batch-Accepted: 1\r\nX-Amnezia-Batch-Id: ";
            response += batchIds.back();
            response += "\r\n";
        }
        response += "Content-Length: 0\r\n\r\n";
        socket->write(response);
        socket->disconnectFromHost();
    }

    QHash<QTcpSocket *, QByteArray> m_buffers;
};

class RedirectingNetworkAccessManager final : public QNetworkAccessManager
{
public:
    RedirectingNetworkAccessManager(quint16 port, QObject *parent = nullptr)
        : QNetworkAccessManager(parent), m_port(port)
    {
    }

protected:
    QNetworkReply *createRequest(Operation operation, const QNetworkRequest &request,
                                 QIODevice *outgoingData = nullptr) override
    {
        QNetworkRequest redirected(request);
        QUrl url = redirected.url();
        url.setHost(QStringLiteral("127.0.0.1"));
        url.setPort(m_port);
        redirected.setUrl(url);
        return QNetworkAccessManager::createRequest(operation, redirected, outgoingData);
    }

private:
    quint16 m_port;
};

QJsonObject target(const QByteArray &token = QByteArray(64, 'b'))
{
    return {
        { QStringLiteral("endpoint"), amnezia::clientLogsTarget::endpoint() },
        { QStringLiteral("clientId"), QString(64, QLatin1Char('a')) },
        { QStringLiteral("token"), QString::fromLatin1(token) },
    };
}

bool writeConfig(const QString &path, const QString &sourcePath,
                 const QByteArray &token = QByteArray(64, 'b'))
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) return false;
    const QJsonObject config {
        { QStringLiteral("version"), 1 },
        { QStringLiteral("enabled"), true },
        { QStringLiteral("sourcePath"), sourcePath },
        { QStringLiteral("installationId"), QString(32, QLatin1Char('i')) },
        { QStringLiteral("clientLogs"), target(token) },
    };
    if (file.write(QJsonDocument(config).toJson(QJsonDocument::Compact)) < 0) return false;
    file.close();
    return QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
}

bool appendBytes(const QString &path, const QByteArray &bytes)
{
    QFile file(path);
    return file.open(QIODevice::Append) && file.write(bytes) == bytes.size();
}
} // namespace

class RemoteLogUploaderTest final : public QObject
{
    Q_OBJECT

private slots:
    void receiptDoesNotAdvanceWhenStateCommitFails();
    void streamStateSurvivesRestartAndRedactsSecretSplitAcrossBatches();
    void replacementWithSamePrefixIsQuarantined();
    void targetChangeQuarantinesOldReceipt();
    void unsafeParentChainIsRejected();
    void executableConfigModeIsRejected();
    void symlinkSourceIsRejected();
    void executableStateModeIsRejected();
};

void RemoteLogUploaderTest::receiptDoesNotAdvanceWhenStateCommitFails()
{
    QTemporaryDir directory(QDir::home().filePath(QStringLiteral("amnezia-uploader-test-XXXXXX")));
    QVERIFY(directory.isValid());
    const QString sourcePath = directory.filePath(QStringLiteral("client.log"));
    const QString configPath = directory.filePath(QStringLiteral("client-logs.json"));
    QFile source(sourcePath);
    QVERIFY(source.open(QIODevice::WriteOnly));
    QVERIFY(source.write(QByteArray(1024 * 1024 + 128, 'x')) > 0);
    source.close();
    QVERIFY(writeConfig(configPath, sourcePath));
    MockCollector collector;
    QVERIFY(collector.listen(QHostAddress::LocalHost));
    RedirectingNetworkAccessManager network(collector.serverPort());
    HeadlessRemoteLogUploader uploader(configPath, &network);
    QString error;
    QVERIFY(uploader.load(&error));
    QVERIFY(QDir().mkdir(configPath + QStringLiteral(".state")));
    uploader.poll();
    QCOMPARE(collector.payloads.size(), 1);
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Error);
    uploader.poll();
    QCOMPARE(collector.payloads.size(), 1);
}

void RemoteLogUploaderTest::streamStateSurvivesRestartAndRedactsSecretSplitAcrossBatches()
{
    QTemporaryDir directory(QDir::home().filePath(QStringLiteral("amnezia-uploader-test-XXXXXX")));
    QVERIFY(directory.isValid());
    const QString sourcePath = directory.filePath(QStringLiteral("client.log"));
    const QString configPath = directory.filePath(QStringLiteral("client-logs.json"));
    QFile source(sourcePath);
    QVERIFY(source.open(QIODevice::WriteOnly));
    QVERIFY(source.write(QByteArray(1024 * 1024 + 128, 'x')) > 0);
    source.close();
    QVERIFY(writeConfig(configPath, sourcePath));
    MockCollector collector;
    QVERIFY(collector.listen(QHostAddress::LocalHost));
    RedirectingNetworkAccessManager network(collector.serverPort());
    HeadlessRemoteLogUploader uploader(configPath, &network);
    QVERIFY(uploader.load());
    uploader.poll();
    uploader.poll();
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Healthy);
    const QByteArray first = QByteArray(15 * 1024 * 1024 - 9, 'x') + QByteArrayLiteral("password=");
    QVERIFY(appendBytes(sourcePath, first));
    uploader.poll();
    QCOMPARE(collector.payloads.size(), 2);
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Pending);
    uploader.poll();
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Healthy);
    const int batchesBeforeRestart = collector.payloads.size();
    QVERIFY(batchesBeforeRestart >= 2);
    HeadlessRemoteLogUploader restarted(configPath, &network);
    QVERIFY(restarted.load());
    QVERIFY(appendBytes(sourcePath, QByteArrayLiteral("TOPSECRET\n")));
    restarted.poll();
    QVERIFY(collector.payloads.size() > batchesBeforeRestart);
    for (const QByteArray &payload : collector.payloads)
        QVERIFY2(!payload.contains("TOPSECRET"), payload.constData());
}

void RemoteLogUploaderTest::replacementWithSamePrefixIsQuarantined()
{
    QTemporaryDir directory(QDir::home().filePath(QStringLiteral("amnezia-uploader-test-XXXXXX")));
    QVERIFY(directory.isValid());
    const QString sourcePath = directory.filePath(QStringLiteral("client.log"));
    const QString backupPath = directory.filePath(QStringLiteral("client.old"));
    const QString configPath = directory.filePath(QStringLiteral("client-logs.json"));
    const QByteArray contents = QByteArray(1024 * 1024 + 128, 'x');
    QVERIFY(appendBytes(sourcePath, contents));
    QVERIFY(writeConfig(configPath, sourcePath));
    MockCollector collector;
    QVERIFY(collector.listen(QHostAddress::LocalHost));
    RedirectingNetworkAccessManager network(collector.serverPort());
    HeadlessRemoteLogUploader uploader(configPath, &network);
    QVERIFY(uploader.load());
    uploader.poll();
    uploader.poll();
    QVERIFY(QFile::rename(sourcePath, backupPath));
    QVERIFY(appendBytes(sourcePath, contents));
    const int batches = collector.payloads.size();
    uploader.poll();
    QCOMPARE(collector.payloads.size(), batches);
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Error);
}

void RemoteLogUploaderTest::targetChangeQuarantinesOldReceipt()
{
    QTemporaryDir directory(QDir::home().filePath(QStringLiteral("amnezia-uploader-test-XXXXXX")));
    QVERIFY(directory.isValid());
    const QString sourcePath = directory.filePath(QStringLiteral("client.log"));
    const QString configPath = directory.filePath(QStringLiteral("client-logs.json"));
    QVERIFY(appendBytes(sourcePath, QByteArray(1024 * 1024 + 128, 'x')));
    QVERIFY(writeConfig(configPath, sourcePath));
    MockCollector collector;
    QVERIFY(collector.listen(QHostAddress::LocalHost));
    RedirectingNetworkAccessManager network(collector.serverPort());
    HeadlessRemoteLogUploader uploader(configPath, &network);
    QVERIFY(uploader.load());
    uploader.poll();
    uploader.poll();
    QVERIFY(writeConfig(configPath, sourcePath, QByteArray(64, 'c')));
    HeadlessRemoteLogUploader rebound(configPath, &network);
    QVERIFY(rebound.load());
    const QStringList quarantined = QDir(directory.path()).entryList(
            { QStringLiteral("client-logs.json.state.quarantine.*") }, QDir::Files);
    QVERIFY(!quarantined.isEmpty());
}

void RemoteLogUploaderTest::unsafeParentChainIsRejected()
{
#ifndef Q_OS_UNIX
    QSKIP("parent ownership checks are Unix-only");
#else
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const QString sourcePath = directory.filePath(QStringLiteral("client.log"));
    const QString configPath = directory.filePath(QStringLiteral("client-logs.json"));
    QVERIFY(appendBytes(sourcePath, QByteArrayLiteral("safe\n")));
    QVERIFY(writeConfig(configPath, sourcePath));
    HeadlessRemoteLogUploader uploader(configPath);
    QString error;
    QVERIFY(!uploader.load(&error));
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Error);
    QCOMPARE(error, QStringLiteral("config_permissions_or_size"));
#endif
}

void RemoteLogUploaderTest::executableConfigModeIsRejected()
{
    QTemporaryDir directory(QDir::home().filePath(QStringLiteral("amnezia-uploader-test-XXXXXX")));
    QVERIFY(directory.isValid());
    const QString sourcePath = directory.filePath(QStringLiteral("client.log"));
    const QString configPath = directory.filePath(QStringLiteral("client-logs.json"));
    QVERIFY(appendBytes(sourcePath, QByteArrayLiteral("safe\n")));
    QVERIFY(writeConfig(configPath, sourcePath));
    QVERIFY(QFile::setPermissions(configPath, QFileDevice::ReadOwner
                                  | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    HeadlessRemoteLogUploader uploader(configPath);
    QString error;
    QVERIFY(!uploader.load(&error));
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Error);
}

void RemoteLogUploaderTest::symlinkSourceIsRejected()
{
    QTemporaryDir directory(QDir::home().filePath(QStringLiteral("amnezia-uploader-test-XXXXXX")));
    QVERIFY(directory.isValid());
    const QString realPath = directory.filePath(QStringLiteral("real.log"));
    const QString linkPath = directory.filePath(QStringLiteral("link.log"));
    const QString configPath = directory.filePath(QStringLiteral("client-logs.json"));
    QVERIFY(appendBytes(realPath, QByteArrayLiteral("safe\n")));
    if (!QFile::link(realPath, linkPath) || !QFileInfo(linkPath).isSymLink())
        QSKIP("symlink creation is unavailable");
    QVERIFY(writeConfig(configPath, linkPath));
    HeadlessRemoteLogUploader uploader(configPath);
    QString error;
    QVERIFY(!uploader.load(&error));
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Error);
}

void RemoteLogUploaderTest::executableStateModeIsRejected()
{
    QTemporaryDir directory(QDir::home().filePath(QStringLiteral("amnezia-uploader-test-XXXXXX")));
    QVERIFY(directory.isValid());
    const QString sourcePath = directory.filePath(QStringLiteral("client.log"));
    const QString configPath = directory.filePath(QStringLiteral("client-logs.json"));
    QVERIFY(appendBytes(sourcePath, QByteArrayLiteral("safe\n")));
    QVERIFY(writeConfig(configPath, sourcePath));
    const QString statePath = configPath + QStringLiteral(".state");
    QFile state(statePath);
    QVERIFY(state.open(QIODevice::WriteOnly));
    QVERIFY(state.write("{}") == 2);
    state.close();
    QVERIFY(QFile::setPermissions(statePath, QFileDevice::ReadOwner
                                  | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    HeadlessRemoteLogUploader uploader(configPath);
    QString error;
    QVERIFY(!uploader.load(&error));
    QCOMPARE(uploader.state(), HeadlessRemoteLogUploader::State::Error);
}

QTEST_MAIN(RemoteLogUploaderTest)
#include "tst_remote_log_uploader.moc"
