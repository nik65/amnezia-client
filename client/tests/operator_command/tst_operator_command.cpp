#include <QByteArray>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QString>
#include <QTextStream>
#include <QUuid>
#include <QVector>

#include <initializer_list>

#include "core/utils/operatorCommand.h"
#include "ipc/localpeerauthentication.h"
#include "ipc/windowsprivilegedpipe.h"

using namespace amnezia::operatorMode;

namespace
{
class TestRunner
{
public:
    void check(bool condition, const char *expression, int line)
    {
        ++m_assertions;
        if (condition) {
            return;
        }
        ++m_failures;
        QTextStream(stderr) << "FAIL line " << line << ": " << expression << Qt::endl;
    }

    int finish() const
    {
        QTextStream stream(m_failures == 0 ? stdout : stderr);
        stream << (m_failures == 0 ? "PASS" : "FAIL")
               << ": " << m_assertions << " assertions, " << m_failures << " failures"
               << Qt::endl;
        return m_failures == 0 ? 0 : 1;
    }

private:
    int m_assertions = 0;
    int m_failures = 0;
};

CommandParseResult parse(std::initializer_list<QByteArray> arguments)
{
    QVector<QByteArray> storage;
    storage.reserve(static_cast<qsizetype>(arguments.size()) + 1);
    storage.append(QByteArrayLiteral("operator-command-tests"));
    for (const QByteArray &argument : arguments) {
        storage.append(argument);
    }

    QVector<char *> argv;
    argv.reserve(storage.size());
    for (QByteArray &argument : storage) {
        argv.append(argument.data());
    }
    return parseArguments(static_cast<int>(argv.size()), argv.data());
}

bool sameRequest(const CommandRequest &left, const CommandRequest &right)
{
    return left.type == right.type && left.json == right.json && left.argument == right.argument;
}
}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    TestRunner runner;

    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--status") });
        CHECK(parsed.hasOperatorArguments);
        CHECK(parsed.valid);
        CHECK(parsed.error.isEmpty());
        CHECK(parsed.request.type == CommandType::Status);
        CHECK(!parsed.request.json);
        CHECK(parsed.request.argument.isEmpty());
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--status"), QByteArrayLiteral("--json") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::Status);
        CHECK(parsed.request.json);
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--json"), QByteArrayLiteral("--doctor") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::Doctor);
        CHECK(parsed.request.json);
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--doctor") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::Doctor);
        CHECK(!parsed.request.json);
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--disconnect") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::Disconnect);
        CHECK(!parsed.request.json);
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--routes-explain"), QByteArrayLiteral("example.com") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::RoutesExplain);
        CHECK(!parsed.request.json);
        CHECK(parsed.request.argument == QStringLiteral("example.com"));
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--routes-explain=2001:db8::1") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::RoutesExplain);
        CHECK(parsed.request.argument == QStringLiteral("2001:db8::1"));
    }

    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--status"), QByteArrayLiteral("--doctor") });
        CHECK(parsed.hasOperatorArguments);
        CHECK(!parsed.valid);
        CHECK(parsed.error == QStringLiteral("Only one operator command may be used at a time."));
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--json") });
        CHECK(parsed.hasOperatorArguments);
        CHECK(!parsed.valid);
        CHECK(!parsed.error.isEmpty());
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--disconnect"), QByteArrayLiteral("--json") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::Disconnect);
        CHECK(parsed.request.json);
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--routes-explain"), QByteArrayLiteral("example.com"),
                  QByteArrayLiteral("--json") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::RoutesExplain);
        CHECK(parsed.request.argument == QStringLiteral("example.com"));
        CHECK(parsed.request.json);
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--watch") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::Watch);
        CHECK(!parsed.request.json);
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--watch"), QByteArrayLiteral("--json") });
        CHECK(parsed.valid);
        CHECK(parsed.request.type == CommandType::Watch);
        CHECK(parsed.request.json);
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--routes-explain") });
        CHECK(!parsed.valid);
        CHECK(parsed.error.contains(QStringLiteral("requires")));
    }

    const QString secretSentinel = QStringLiteral("SENSITIVE_SENTINEL_8d9b8607");
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--status"), QByteArrayLiteral("--import"), secretSentinel.toUtf8() });
        CHECK(!parsed.valid);
        CHECK(parsed.error.contains(QStringLiteral("--import")));
        CHECK(!parsed.error.contains(secretSentinel));
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--doctor"),
                  QByteArrayLiteral("--unknown=SENSITIVE_SENTINEL_8d9b8607") });
        CHECK(!parsed.valid);
        CHECK(!parsed.error.contains(secretSentinel));
        CHECK(parsed.error == QStringLiteral("Operator commands cannot be combined with other startup arguments."));
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--status"),
                  QByteArrayLiteral("--import=SENSITIVE_SENTINEL_8d9b8607") });
        CHECK(!parsed.valid);
        CHECK(parsed.error.contains(QStringLiteral("--import")));
        CHECK(!parsed.error.contains(secretSentinel));
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--status"), QByteArrayLiteral("--import"),
                  QByteArrayLiteral("--SENSITIVE_SENTINEL_8d9b8607") });
        CHECK(!parsed.valid);
        CHECK(!parsed.error.contains(secretSentinel));
        CHECK(parsed.error.contains(QStringLiteral("--import")));
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--import"), QByteArrayLiteral("SENSITIVE_SENTINEL_8d9b8607") });
        CHECK(!parsed.hasOperatorArguments);
        CHECK(!parsed.valid);
        CHECK(parsed.error.isEmpty());
    }
    {
        // QApplication may consume the second token as a Qt option value. The
        // immutable pre-QApplication classifier must still reject the mixed
        // invocation instead of later reclassifying it as an unlocked UI.
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("-stylesheet"), QByteArrayLiteral("--status") });
        CHECK(parsed.hasOperatorArguments);
        CHECK(!parsed.valid);
        CHECK(parsed.error == QStringLiteral(
                "Operator commands cannot be combined with other startup arguments."));
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("-platform"), QByteArrayLiteral("offscreen"),
                  QByteArrayLiteral("--doctor") });
        CHECK(parsed.hasOperatorArguments);
        CHECK(!parsed.valid);
        CHECK(parsed.error == QStringLiteral(
                "Operator commands cannot be combined with other startup arguments."));
    }
    {
        const CommandParseResult parsed = parse(
                { QByteArrayLiteral("--"), QByteArrayLiteral("--status") });
        CHECK(parsed.hasOperatorArguments);
        CHECK(!parsed.valid);
        CHECK(parsed.error == QStringLiteral(
                "Operator commands cannot be combined with other startup arguments."));
    }
    {
        const CommandParseResult parsed = parse({ QByteArrayLiteral("--raise") });
        CHECK(!parsed.hasOperatorArguments);
        CHECK(!parsed.valid);
        CHECK(parsed.request.type == CommandType::None);
        CHECK(parsed.error.isEmpty());
    }

    const QVector<CommandRequest> requests {
        { CommandType::Status, false, QString() },
        { CommandType::Status, true, QString() },
        { CommandType::Doctor, false, QString() },
        { CommandType::Doctor, true, QString() },
        { CommandType::Disconnect, false, QString() },
        { CommandType::Disconnect, true, QString() },
        { CommandType::RoutesExplain, false, QStringLiteral("vpn.example") },
        { CommandType::RoutesExplain, true, QStringLiteral("vpn.example") },
        { CommandType::Watch, false, QString() },
        { CommandType::Watch, true, QString() },
        { CommandType::Raise, false, QString() },
    };
    for (const CommandRequest &request : requests) {
        QString validationError;
        CHECK(request.isValid(&validationError));
        CHECK(validationError.isEmpty());

        CommandRequest decoded;
        QString decodeError;
        CHECK(CommandRequest::fromJson(request.toJson(), &decoded, &decodeError));
        CHECK(decodeError.isEmpty());
        CHECK(sameRequest(request, decoded));
        CHECK(decoded.toJson() == request.toJson());
    }

    {
        QJsonObject wrongProtocol = requests.first().toJson();
        wrongProtocol.insert(QStringLiteral("protocol"), WireProtocolVersion + 1);
        QString error;
        CHECK(!CommandRequest::fromJson(wrongProtocol, nullptr, &error));
        CHECK(!error.isEmpty());
    }
    {
        QJsonObject missingField = requests.first().toJson();
        QString error;
        missingField.remove(QStringLiteral("protocol"));
        CHECK(!CommandRequest::fromJson(missingField, nullptr, &error));
        CHECK(!error.isEmpty());

        missingField = requests.first().toJson();
        missingField.remove(QStringLiteral("command"));
        CHECK(!CommandRequest::fromJson(missingField, nullptr, &error));
        CHECK(!error.isEmpty());
    }
    {
        QJsonObject unknownCommand = requests.first().toJson();
        unknownCommand.insert(QStringLiteral("command"), QStringLiteral("unknown"));
        QString error;
        CHECK(!CommandRequest::fromJson(unknownCommand, nullptr, &error));
        CHECK(!error.isEmpty());
    }

    {
        CommandRequest maximumRouteRequest {
            CommandType::RoutesExplain,
            false,
            QString(MaximumRouteArgumentLength, QLatin1Char('a')),
        };
        QString error;
        CHECK(maximumRouteRequest.isValid(&error));
        CHECK(error.isEmpty());

        CommandRequest decoded;
        CHECK(CommandRequest::fromJson(maximumRouteRequest.toJson(), &decoded, &error));
        CHECK(decoded.argument.size() == MaximumRouteArgumentLength);

        maximumRouteRequest.argument.append(QLatin1Char('b'));
        CHECK(!maximumRouteRequest.isValid(&error));
        CHECK(!error.contains(maximumRouteRequest.argument));
        CHECK(!CommandRequest::fromJson(maximumRouteRequest.toJson(), nullptr, &error));
    }
    {
        const QByteArray maximumArgument(MaximumRouteArgumentLength, 'a');
        const CommandParseResult maximumParsed = parse(
                { QByteArrayLiteral("--routes-explain=") + maximumArgument });
        CHECK(maximumParsed.valid);
        CHECK(maximumParsed.request.argument.size() == MaximumRouteArgumentLength);

        const CommandParseResult oversizedParsed = parse(
                { QByteArrayLiteral("--routes-explain=") + maximumArgument + QByteArrayLiteral("b") });
        CHECK(!oversizedParsed.valid);
        CHECK(oversizedParsed.error.contains(QStringLiteral("too long")));
        CHECK(!oversizedParsed.error.contains(QString(maximumArgument)));
    }
    {
        CHECK(wireFrameState(QByteArray()) == WireFrameState::Incomplete);
        CHECK(wireFrameState(QByteArrayLiteral("{}\n")) == WireFrameState::Complete);

        QByteArray incompleteAtLimitMinusOne(MaximumWireFrameSize - 1, 'x');
        CHECK(wireFrameState(incompleteAtLimitMinusOne) == WireFrameState::Incomplete);

        QByteArray exactLimitFrame(MaximumWireFrameSize, 'x');
        exactLimitFrame[exactLimitFrame.size() - 1] = '\n';
        CHECK(wireFrameState(exactLimitFrame) == WireFrameState::Complete);

        QByteArray unterminatedAtLimit(MaximumWireFrameSize, 'x');
        CHECK(wireFrameState(unterminatedAtLimit) == WireFrameState::TooLarge);

        QByteArray limitPlusOneFrame(MaximumWireFrameSize + 1, 'x');
        limitPlusOneFrame[limitPlusOneFrame.size() - 1] = '\n';
        CHECK(wireFrameState(limitPlusOneFrame) == WireFrameState::TooLarge);
    }
    {
        CHECK(canProcessWireFrame(false, false));
        CHECK(!canProcessWireFrame(true, false));
        CHECK(!canProcessWireFrame(false, true));
        CHECK(!canProcessWireFrame(true, true));
    }
    {
        const RouteRuntimeDecision noSnapshot = assessRouteRuntime(
                QStringLiteral("vpn"), false, false, true, false, false, false, true);
        CHECK(!noSnapshot.runtimeApplied);
        CHECK(noSnapshot.inspectionBasis == QStringLiteral("policyPreview"));
        CHECK(noSnapshot.route == QStringLiteral("unknown"));
        CHECK(noSnapshot.warning == QStringLiteral("runtime_snapshot_unavailable"));

        const RouteRuntimeDecision disconnected = assessRouteRuntime(
                QStringLiteral("direct"), true, false, true, false, true, false, true);
        CHECK(!disconnected.runtimeApplied);
        CHECK(disconnected.inspectionBasis == QStringLiteral("policyPreview"));
        CHECK(disconnected.route == QStringLiteral("unknown"));
        CHECK(disconnected.warning == QStringLiteral("vpn_not_connected"));

        const RouteRuntimeDecision hostname = assessRouteRuntime(
                QStringLiteral("vpn"), true, true, false, false, false, false, true);
        CHECK(hostname.runtimeApplied);
        CHECK(hostname.inspectionBasis == QStringLiteral("effectivePolicyWhileConnected"));
        CHECK(hostname.route == QStringLiteral("unknown"));
        CHECK(hostname.warning == QStringLiteral("hostname_resolution_required"));

        const RouteRuntimeDecision ipv6Split = assessRouteRuntime(
                QStringLiteral("direct"), true, true, true, true, true, false, true);
        CHECK(ipv6Split.runtimeApplied);
        CHECK(ipv6Split.route == QStringLiteral("unknown"));
        CHECK(ipv6Split.warning == QStringLiteral("ipv6_route_not_runtime_verified"));

        const RouteRuntimeDecision protectedRoute = assessRouteRuntime(
                QStringLiteral("direct"), true, true, true, false, true, true, true);
        CHECK(protectedRoute.runtimeApplied);
        CHECK(protectedRoute.route == QStringLiteral("unknown"));
        CHECK(protectedRoute.warning == QStringLiteral("protected_route_requires_runtime_verification"));

        const RouteRuntimeDecision diverged = assessRouteRuntime(
                QStringLiteral("vpn"), true, true, true, false, true, false, false);
        CHECK(diverged.runtimeApplied);
        CHECK(diverged.route == QStringLiteral("unknown"));
        CHECK(diverged.warning == QStringLiteral("runtime_policy_mode_diverged"));

        const RouteRuntimeDecision connectedIpv4 = assessRouteRuntime(
                QStringLiteral("direct"), true, true, true, false, true, false, true);
        CHECK(connectedIpv4.runtimeApplied);
        CHECK(connectedIpv4.inspectionBasis == QStringLiteral("effectivePolicyWhileConnected"));
        CHECK(connectedIpv4.route == QStringLiteral("unknown"));
        CHECK(connectedIpv4.warning == QStringLiteral("split_route_not_runtime_verified"));

        const RouteRuntimeDecision fullTunnelIpv6 = assessRouteRuntime(
                QStringLiteral("vpn"), true, true, true, true, false, false, true);
        CHECK(fullTunnelIpv6.runtimeApplied);
        CHECK(fullTunnelIpv6.route == QStringLiteral("unknown"));
        CHECK(fullTunnelIpv6.warning == QStringLiteral("ipv6_route_not_runtime_verified"));
    }
    {
        // Real local-socket roundtrip: peer identities come from the kernel,
        // and fragmented frames are not processed before their newline.
        const QString serverName = QStringLiteral("amnezia-operator-test-%1")
                .arg(QUuid::createUuid().toString(QUuid::Id128));
#ifdef Q_OS_WIN
        amnezia::ipc::WindowsPrivilegedPipeServer server;
        CHECK(server.listen(serverName));

        QLocalSocket client;
        QString connectionError;
        CHECK(amnezia::ipc::connectWindowsPrivilegedPipe(
                &client, serverName, 2000, &connectionError));
        QElapsedTimer connectionTimer;
        connectionTimer.start();
        while (!server.hasPendingConnections() && connectionTimer.elapsed() < 2000) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        }
        CHECK(server.hasPendingConnections());
#else
        QLocalServer server;
        server.setSocketOptions(QLocalServer::UserAccessOption);
        CHECK(server.listen(serverName));

        QLocalSocket client;
        client.connectToServer(serverName, QIODevice::ReadWrite);
        CHECK(client.waitForConnected(2000));
        CHECK(server.waitForNewConnection(2000));
#endif
        QLocalSocket *accepted = server.nextPendingConnection();
        CHECK(accepted != nullptr);
        if (accepted) {
            amnezia::ipc::LocalPeerIdentity clientIdentity;
            amnezia::ipc::LocalPeerIdentity serverIdentity;
            QString identityError;
            CHECK(amnezia::ipc::queryLocalPeerIdentity(
                    accepted, clientIdentity, &identityError));
            CHECK(identityError.isEmpty());
            CHECK(amnezia::ipc::queryLocalServerIdentity(
                    &client, serverIdentity, &identityError));
            CHECK(identityError.isEmpty());
            const QString currentUser = amnezia::ipc::currentProcessUserIdentifier(&identityError);
            const QString currentExecutable = amnezia::ipc::canonicalExecutablePath(
                    QCoreApplication::applicationFilePath());
            CHECK(!currentUser.isEmpty());
            CHECK(clientIdentity.processId == QCoreApplication::applicationPid());
            CHECK(serverIdentity.processId == QCoreApplication::applicationPid());
            CHECK(clientIdentity.userIdentifier == currentUser);
            CHECK(serverIdentity.userIdentifier == currentUser);
            CHECK(amnezia::ipc::executablePathsMatch(
                    clientIdentity.executablePath, currentExecutable));
            CHECK(amnezia::ipc::executablePathsMatch(
                    serverIdentity.executablePath, currentExecutable));
            CHECK(!amnezia::ipc::executablePathsMatch(
                    currentExecutable, currentExecutable + QStringLiteral(".other")));

            const CommandRequest request { CommandType::Status, true, QString() };
            QByteArray requestFrame = QJsonDocument(request.toJson()).toJson(QJsonDocument::Compact);
            requestFrame.append('\n');
            const qsizetype split = requestFrame.size() / 2;
            CHECK(client.write(requestFrame.left(split)) == split);
            CHECK(client.waitForBytesWritten(2000));
            CHECK(accepted->waitForReadyRead(2000));
            QByteArray received = accepted->readAll();
            CHECK(wireFrameState(received) == WireFrameState::Incomplete);
            CHECK(client.write(requestFrame.mid(split)) == requestFrame.size() - split);
            CHECK(client.waitForBytesWritten(2000));
            CHECK(accepted->waitForReadyRead(2000));
            received.append(accepted->readAll());
            CHECK(wireFrameState(received) == WireFrameState::Complete);
            CommandRequest decoded;
            QString decodeError;
            CHECK(CommandRequest::fromJson(
                    QJsonDocument::fromJson(received.left(received.indexOf('\n'))).object(),
                    &decoded, &decodeError));
            CHECK(decodeError.isEmpty());
            CHECK(sameRequest(decoded, request));

            accepted->disconnectFromServer();
            accepted->deleteLater();
        }
        client.abort();
        server.close();
#ifndef Q_OS_WIN
        QLocalServer::removeServer(serverName);
#endif
    }
    {
        const QString user = QStringLiteral("user-1000");
        const QString executable = QStringLiteral("C:/Program Files/Amnezia/AmneziaVPN.exe");
        const QString scopedName = scopedLocalServerName(
                QStringLiteral("AmneziaVPNInstance"), user, executable);
        CHECK(scopedName.startsWith(QStringLiteral("AmneziaVPNInstance-")));
        CHECK(scopedName.size() == QStringLiteral("AmneziaVPNInstance-").size() + 32);
        CHECK(scopedName == scopedLocalServerName(
                                    QStringLiteral("AmneziaVPNInstance"), user, executable));
        CHECK(scopedName != scopedLocalServerName(
                                    QStringLiteral("AmneziaVPNInstance"), QStringLiteral("user-1001"), executable));
        CHECK(scopedName != scopedLocalServerName(
                                    QStringLiteral("AmneziaVPNInstance"), user,
                                    QStringLiteral("C:/Other/AmneziaVPN.exe")));
        CHECK(scopedLocalServerName(QString(), user, executable).isEmpty());
        CHECK(scopedLocalServerName(QStringLiteral("AmneziaVPNInstance"), QString(), executable).isEmpty());
        CHECK(peerIdentityMatches(user, executable, user,
                                  QStringLiteral("C:\\Program Files\\Amnezia\\AmneziaVPN.exe")));
        CHECK(!peerIdentityMatches(user, executable, QStringLiteral("user-1001"), executable));
        CHECK(!peerIdentityMatches(user, executable, user,
                                   QStringLiteral("C:/Other/AmneziaVPN.exe")));
    }
    {
        const QJsonObject status {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.status.v1") },
            { QStringLiteral("ok"), true },
            { QStringLiteral("state"), QStringLiteral("connected") },
        };
        const QByteArray frame = watchSnapshotFrame(
                status, 0, 42, QStringLiteral("2026-07-21T12:34:56.789Z"), 12345);
        CHECK(!frame.isEmpty());
        CHECK(wireFrameState(frame) == WireFrameState::Complete);

        QJsonParseError error;
        const QJsonObject snapshot = QJsonDocument::fromJson(frame, &error).object();
        CHECK(error.error == QJsonParseError::NoError);
        CHECK(snapshot.value(QStringLiteral("schema")).toString()
              == QStringLiteral("amnezia.operator.watch.v1"));
        CHECK(snapshot.value(QStringLiteral("event")).toString() == QStringLiteral("snapshot"));
        CHECK(snapshot.value(QStringLiteral("sequence")).toString() == QStringLiteral("42"));
        CHECK(snapshot.value(QStringLiteral("primaryPid")).toInteger(-1) == 12345);
        CHECK(snapshot.value(QStringLiteral("statusExitCode")).toInt(-1) == 0);
        CHECK(snapshot.value(QStringLiteral("status")).toObject() == status);

        QJsonObject wrongStatus = status;
        wrongStatus.insert(QStringLiteral("schema"), QStringLiteral("amnezia.operator.other.v1"));
        CHECK(watchSnapshotFrame(wrongStatus, 0, 1, QStringLiteral("now"), 12345).isEmpty());
        CHECK(watchSnapshotFrame(status, 0, 0, QStringLiteral("now"), 12345).isEmpty());
        CHECK(watchSnapshotFrame(status, 0, 1, QStringLiteral("now"), 0).isEmpty());
        CHECK(watchSnapshotFrame(status, MaximumProcessExitCode + 1, 1,
                                 QStringLiteral("now"), 12345).isEmpty());

        QJsonObject oversizedStatus = status;
        oversizedStatus.insert(QStringLiteral("padding"),
                               QString(MaximumWireFrameSize, QLatin1Char('x')));
        CHECK(watchSnapshotFrame(oversizedStatus, 0, 1,
                                 QStringLiteral("now"), 12345).isEmpty());

        const QByteArray initialTerminal = watchTerminalFrame(
                QStringLiteral("primary_unavailable"),
                QStringLiteral("No primary instance."), 4, 0,
                QStringLiteral("2026-07-21T12:35:00.000Z"));
        CHECK(!initialTerminal.isEmpty());
        CHECK(wireFrameState(initialTerminal) == WireFrameState::Complete);
        const QJsonObject initialTerminalObject =
                QJsonDocument::fromJson(initialTerminal, &error).object();
        CHECK(error.error == QJsonParseError::NoError);
        CHECK(initialTerminalObject.value(QStringLiteral("schema")).toString()
              == QStringLiteral("amnezia.operator.watch.v1"));
        CHECK(initialTerminalObject.value(QStringLiteral("event")).toString()
              == QStringLiteral("terminal"));
        CHECK(initialTerminalObject.value(QStringLiteral("reason")).toString()
              == QStringLiteral("primary_unavailable"));
        CHECK(initialTerminalObject.value(QStringLiteral("lastSequence")).toString()
              == QStringLiteral("0"));
        CHECK(initialTerminalObject.value(QStringLiteral("exitCode")).toInt(-1) == 4);
        CHECK(!initialTerminalObject.contains(QStringLiteral("primaryPid")));

        const QByteArray lossTerminal = watchTerminalFrame(
                QStringLiteral("primary_lost"), QStringLiteral("Primary lost."),
                5, 42, QStringLiteral("2026-07-21T12:36:00.000Z"), 12345);
        CHECK(!lossTerminal.isEmpty());
        const QJsonObject lossTerminalObject = QJsonDocument::fromJson(lossTerminal, &error).object();
        CHECK(error.error == QJsonParseError::NoError);
        CHECK(lossTerminalObject.value(QStringLiteral("event")).toString()
              == QStringLiteral("terminal"));
        CHECK(lossTerminalObject.value(QStringLiteral("lastSequence")).toString()
              == QStringLiteral("42"));
        CHECK(lossTerminalObject.value(QStringLiteral("primaryPid")).toInteger(-1) == 12345);
        CHECK(lossTerminalObject.value(QStringLiteral("exitCode")).toInt(-1) == 5);

        CHECK(watchTerminalFrame(QStringLiteral("Invalid reason"), QStringLiteral("message"),
                                 4, 0, QStringLiteral("now")).isEmpty());
        CHECK(watchTerminalFrame(QStringLiteral("primary_lost"), QStringLiteral("message"),
                                 3, 0, QStringLiteral("now")).isEmpty());
        CHECK(watchTerminalFrame(QStringLiteral("primary_lost"),
                                 QString(MaximumWatchTerminalMessageLength + 1,
                                         QLatin1Char('x')),
                                 5, 1, QStringLiteral("now"), 12345).isEmpty());
    }

    {
        CommandResponse response;
        response.exitCode = 4;
        response.humanOutput = QStringLiteral("Primary application is unavailable.");
        response.result = {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.status.v1") },
            { QStringLiteral("ok"), false },
            { QStringLiteral("details"), QJsonObject { { QStringLiteral("state"), QStringLiteral("unknown") } } },
            { QStringLiteral("checks"), QJsonArray { QStringLiteral("ipc"), QStringLiteral("settings") } },
        };

        CommandResponse decoded;
        QString error;
        CHECK(CommandResponse::fromJson(response.toJson(), &decoded, &error));
        CHECK(error.isEmpty());
        CHECK(decoded.exitCode == response.exitCode);
        CHECK(decoded.humanOutput == response.humanOutput);
        CHECK(decoded.result == response.result);
        CHECK(decoded.toJson() == response.toJson());
    }
    {
        CommandResponse response;
        response.result = { { QStringLiteral("ok"), true } };
        QJsonObject wrongProtocol = response.toJson();
        wrongProtocol.insert(QStringLiteral("protocol"), WireProtocolVersion + 1);
        QString error;
        CHECK(!CommandResponse::fromJson(wrongProtocol, nullptr, &error));
        CHECK(!error.isEmpty());

        QJsonObject malformedResult = response.toJson();
        malformedResult.insert(QStringLiteral("result"), QStringLiteral("not-an-object"));
        CHECK(!CommandResponse::fromJson(malformedResult, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResult = response.toJson();
        malformedResult.remove(QStringLiteral("result"));
        CHECK(!CommandResponse::fromJson(malformedResult, nullptr, &error));
        CHECK(!error.isEmpty());
    }
    {
        QJsonObject malformedRequest = requests.first().toJson();
        malformedRequest.insert(QStringLiteral("json"), QStringLiteral("true"));
        QString error;
        CHECK(!CommandRequest::fromJson(malformedRequest, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedRequest = requests.first().toJson();
        malformedRequest.insert(QStringLiteral("argument"), 7);
        CHECK(!CommandRequest::fromJson(malformedRequest, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedRequest = requests.first().toJson();
        malformedRequest.remove(QStringLiteral("json"));
        CHECK(!CommandRequest::fromJson(malformedRequest, nullptr, &error));
        CHECK(!error.isEmpty());
    }
    {
        CommandResponse response;
        response.result = { { QStringLiteral("ok"), true } };
        QJsonObject malformedResponse = response.toJson();
        QString error;

        malformedResponse.insert(QStringLiteral("exitCode"), QStringLiteral("0"));
        CHECK(!CommandResponse::fromJson(malformedResponse, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResponse = response.toJson();
        malformedResponse.insert(QStringLiteral("exitCode"), 1.5);
        CHECK(!CommandResponse::fromJson(malformedResponse, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResponse = response.toJson();
        malformedResponse.insert(QStringLiteral("exitCode"), MinimumProcessExitCode - 1);
        CHECK(!CommandResponse::fromJson(malformedResponse, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResponse = response.toJson();
        malformedResponse.insert(QStringLiteral("exitCode"), MaximumProcessExitCode + 1);
        CHECK(!CommandResponse::fromJson(malformedResponse, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResponse = response.toJson();
        malformedResponse.remove(QStringLiteral("exitCode"));
        CHECK(!CommandResponse::fromJson(malformedResponse, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResponse = response.toJson();
        malformedResponse.insert(QStringLiteral("human"), QJsonArray());
        CHECK(!CommandResponse::fromJson(malformedResponse, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResponse = response.toJson();
        malformedResponse.remove(QStringLiteral("human"));
        CHECK(!CommandResponse::fromJson(malformedResponse, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResponse = response.toJson();
        malformedResponse.remove(QStringLiteral("protocol"));
        CHECK(!CommandResponse::fromJson(malformedResponse, nullptr, &error));
        CHECK(!error.isEmpty());

        malformedResponse = response.toJson();
        malformedResponse.insert(QStringLiteral("exitCode"), MaximumProcessExitCode);
        CommandResponse decoded;
        CHECK(CommandResponse::fromJson(malformedResponse, &decoded, &error));
        CHECK(error.isEmpty());
        CHECK(decoded.exitCode == MaximumProcessExitCode);
    }

    return runner.finish();
}
