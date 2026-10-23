#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLocalSocket>
#include <QSaveFile>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTextStream>
#include <QUuid>
#include <cstring>

#include "headlessProtocol.h"
#include "cliResponse.h"
#include "headless_fs_dispatch.h"
#include "rollbackCoordinator.h"
#include "rollbackCliResponse.h"

#if defined(Q_OS_LINUX)
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace
{

QString defaultSocketPath()
{
#ifdef Q_OS_UNIX
    QString runtimeDirectory = qEnvironmentVariable("XDG_RUNTIME_DIR").trimmed();
    if (runtimeDirectory.isEmpty()) {
        runtimeDirectory = QDir::tempPath();
    }
    return QDir(runtimeDirectory).filePath(QStringLiteral("amneziad.sock"));
#else
    return QStringLiteral("amneziad");
#endif
}

int printResponse(const QByteArray &frame, bool jsonOutput, const QString &outputPath)
{
    const QJsonDocument response = QJsonDocument::fromJson(frame.trimmed());
    if (!response.isObject()) {
        QTextStream(stderr) << "amnezia-cli: daemon returned malformed response" << Qt::endl;
        return 1;
    }

    const QJsonObject object = response.object();
    const bool ok = object.value(QStringLiteral("ok")).toBool(false);
    if (!outputPath.isEmpty()) {
        if (!ok) {
            QTextStream(stderr) << "amnezia-cli: cannot write output for failed request" << Qt::endl;
            return 1;
        }
        const QJsonObject profile = object.value(QStringLiteral("result")).toObject()
                                        .value(QStringLiteral("profile")).toObject();
        if (profile.isEmpty()) {
            QTextStream(stderr) << "amnezia-cli: response has no profile to export" << Qt::endl;
            return 1;
        }
        QSaveFile file(outputPath);
        if (!file.open(QIODevice::WriteOnly)
            || file.write(QJsonDocument(profile).toJson(QJsonDocument::Indented)) < 0
            || !file.commit()) {
            QTextStream(stderr) << "amnezia-cli: cannot write " << outputPath << Qt::endl;
            return 1;
        }
        return 0;
    }

    if (jsonOutput) {
        QTextStream(stdout) << response.toJson(QJsonDocument::Indented);
    } else if (ok) {
        const QJsonObject result = object.value(QStringLiteral("result")).toObject();
        if (result.contains(QStringLiteral("state"))) {
            QTextStream(stdout) << result.value(QStringLiteral("state")).toString()
                                << Qt::endl;
        } else {
            QTextStream(stdout) << QJsonDocument(result).toJson(QJsonDocument::Indented);
        }
    } else {
        const QJsonObject error = object.value(QStringLiteral("error")).toObject();
        QTextStream(stderr) << error.value(QStringLiteral("code")).toString()
                            << ": " << error.value(QStringLiteral("message")).toString()
                            << Qt::endl;
    }
    return ok ? 0 : 1;
}

bool readJsonObject(const QString &path, QJsonObject &object, QString &error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        error = QStringLiteral("cannot read profile file");
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        error = QStringLiteral("profile file is not a JSON object");
        return false;
    }
    object = document.object();
    return true;
}

bool fixedRootDaemonPeer(QLocalSocket &socket, const QString &path)
{
#if defined(Q_OS_LINUX)
    if (::geteuid() != 0 || path != QStringLiteral("/run/amnezia/amneziad.sock")
        || socket.socketDescriptor() < 0) return false;
    struct ucred peer {};
    socklen_t size = sizeof(peer);
    if (::getsockopt(static_cast<int>(socket.socketDescriptor()), SOL_SOCKET,
                     SO_PEERCRED, &peer, &size) != 0 || peer.uid != 0 || peer.pid <= 0) return false;
    QProcess process;
    QProcessEnvironment environment;
    environment.insert(QStringLiteral("PATH"), QStringLiteral("/usr/bin:/bin"));
    environment.insert(QStringLiteral("LC_ALL"), QStringLiteral("C"));
    process.setProcessEnvironment(environment);
    process.start(QStringLiteral("/usr/bin/systemctl"),
                  {QStringLiteral("show"), QStringLiteral("--property=MainPID"),
                   QStringLiteral("--value"), QStringLiteral("amneziad.service")});
    if (!process.waitForFinished(2000)) {
        process.kill();
        process.waitForFinished(1000);
        return false;
    }
    bool ok = false;
    const qlonglong pid = QString::fromLatin1(process.readAllStandardOutput()).trimmed().toLongLong(&ok);
    return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0
        && ok && pid == peer.pid;
#else
    Q_UNUSED(socket);
    Q_UNUSED(path);
    return false;
#endif
}

} // namespace

int main(int argc, char *argv[])
{
    // Provisioning uses only the already-authenticated CLI executable. Dispatch
    // before Qt can consume argv or the normal client can create an IPC socket.
    if (argc >= 2 && std::strcmp(argv[1], "--provisioning-fs") == 0) {
        return headless_fs::dispatch(argc - 1, argv + 1);
    }
    if (argc >= 2 && std::strcmp(argv[1], "--rollback-coordinator") == 0) {
        QStringList commands;
        for (int index = 2; index < argc; ++index) commands.append(QString::fromLocal8Bit(argv[index]));
        QCoreApplication application(argc, argv);
        return amnezia::headless::RollbackCoordinator::dispatch(commands);
    }
    QCoreApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("amnezia-cli"));
    QCoreApplication::setApplicationVersion(QStringLiteral(AMNEZIA_HEADLESS_VERSION));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Headless AmneziaVPN CLI"));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption(QCommandLineOption(
        { QStringLiteral("s"), QStringLiteral("socket") },
        QStringLiteral("Unix socket path"), QStringLiteral("path")));
    parser.addOption(QCommandLineOption(
        { QStringLiteral("j"), QStringLiteral("json") },
        QStringLiteral("Print the complete JSON response")));
    parser.addOption(QCommandLineOption(
        { QStringLiteral("o"), QStringLiteral("output") },
        QStringLiteral("Write an exported profile to this file"), QStringLiteral("path")));
    parser.addOption(QCommandLineOption(
        QStringLiteral("source-path"),
        QStringLiteral("Absolute headless log source path for remote log provisioning"), QStringLiteral("path")));
    parser.addOption(QCommandLineOption(
        QStringLiteral("installation-id"),
        QStringLiteral("Stable non-secret installation identity for remote logs"), QStringLiteral("id")));
    parser.addPositionalArgument(QStringLiteral("command"),
                                 QStringLiteral("status, list-profiles, doctor, connect, disconnect, import, export, import-remote-logs or update-rollback"));
    parser.addPositionalArgument(QStringLiteral("argument"),
                                 QStringLiteral("profile name, profile JSON file or profile id"));
    parser.process(application);

    const QStringList positional = parser.positionalArguments();
    if (positional.isEmpty()) {
        parser.showHelp(2);
    }

    amnezia::headless::Command command;
    if (!amnezia::headless::commandFromName(positional.at(0), command)) {
        QTextStream(stderr) << "amnezia-cli: unsupported command" << Qt::endl;
        return 2;
    }

    const bool takesArgument = command == amnezia::headless::Command::Connect
        || command == amnezia::headless::Command::Import
        || command == amnezia::headless::Command::ImportRemoteLogs
        || command == amnezia::headless::Command::Export;
    if ((takesArgument && positional.size() != 2)
        || (!takesArgument && positional.size() != 1)) {
        QTextStream(stderr) << "amnezia-cli: unexpected or missing positional argument" << Qt::endl;
        return 2;
    }
    if (command == amnezia::headless::Command::Export
        && parser.value(QStringLiteral("output")).trimmed().isEmpty()) {
        QTextStream(stderr) << "amnezia-cli: export requires --output" << Qt::endl;
        return 2;
    }

    QJsonObject parameters;
    if (command == amnezia::headless::Command::Connect) {
        parameters.insert(QStringLiteral("profile"), positional.at(1));
    } else if (command == amnezia::headless::Command::Export) {
        parameters.insert(QStringLiteral("id"), positional.at(1));
    } else if (command == amnezia::headless::Command::Import) {
        QJsonObject profile;
        QString error;
        if (!readJsonObject(positional.at(1), profile, error)) {
            QTextStream(stderr) << "amnezia-cli: " << error << Qt::endl;
            return 2;
        }
        parameters.insert(QStringLiteral("profile"), profile);
    } else if (command == amnezia::headless::Command::ImportRemoteLogs) {
        QJsonObject desktopExport;
        QString error;
        if (!readJsonObject(positional.at(1), desktopExport, error)) {
            QTextStream(stderr) << "amnezia-cli: " << error << Qt::endl;
            return 2;
        }
        const QString sourcePath = parser.value(QStringLiteral("source-path")).trimmed();
        const QString installationId = parser.value(QStringLiteral("installation-id")).trimmed();
        if (sourcePath.isEmpty() || installationId.isEmpty()) {
            QTextStream(stderr) << "amnezia-cli: import-remote-logs requires --source-path and --installation-id" << Qt::endl;
            return 2;
        }
        parameters.insert(QStringLiteral("clientLogs"), desktopExport);
        parameters.insert(QStringLiteral("sourcePath"), sourcePath);
        parameters.insert(QStringLiteral("installationId"), installationId);
    }

    const amnezia::headless::Request request {
        command,
        QUuid::createUuid().toString(QUuid::WithoutBraces),
        parameters,
    };

    QLocalSocket socket;
    const QString socketPath = parser.value(QStringLiteral("socket")).trimmed().isEmpty()
        ? defaultSocketPath() : parser.value(QStringLiteral("socket"));
    socket.connectToServer(socketPath, QIODevice::ReadWrite);
    if (!socket.waitForConnected(1000)) {
        QTextStream(stderr) << "amnezia-cli: cannot connect to " << socketPath
                            << ": " << socket.errorString() << Qt::endl;
        return 1;
    }
    const bool coordinatedRollback = command == amnezia::headless::Command::UpdateRollback;
    if (coordinatedRollback) {
        if (!fixedRootDaemonPeer(socket, socketPath)) {
            QTextStream(stderr) << "amnezia-cli: coordinated rollback requires the fixed root system service" << Qt::endl;
            return 1;
        }
        // Preparation may exceed the daemon's request-frame timeout. Drop this
        // authenticated preflight socket, then authenticate a fresh connection.
        socket.abort();
        const auto prepared = amnezia::headless::RollbackCoordinator().prepare();
        if (!prepared.ok) {
            QTextStream(stderr) << prepared.code << ": " << prepared.message << Qt::endl;
            return 1;
        }
        socket.connectToServer(socketPath, QIODevice::ReadWrite);
        if (!socket.waitForConnected(1000) || !fixedRootDaemonPeer(socket, socketPath)) {
            QTextStream(stderr) << "amnezia-cli: root service identity changed after rollback preparation" << Qt::endl;
            return 1;
        }
    }
    if (socket.write(amnezia::headless::encodeRequest(request)) < 0) {
        QTextStream(stderr) << "amnezia-cli: daemon request failed: "
                            << socket.errorString() << Qt::endl;
        return 1;
    }

    QString responseError;
    const int responseBudget = command == amnezia::headless::Command::Connect
            || command == amnezia::headless::Command::Disconnect ? 120000
            : coordinatedRollback ? 60000 : 2000;
    const QByteArray responseFrame = amnezia::headless::readCliResponseFrame(socket, responseError, responseBudget);
    if (responseFrame.isEmpty()) {
        // A scheduled restart may close the daemon connection. The installed
        // CLI process still runs14 and can non-blockingly wake its retained
        // worker, but only a genuine pending product journal authorizes it.
        if (coordinatedRollback) {
            const auto scheduled = amnezia::headless::RollbackCoordinator().rollbackRequested();
            const auto pending = amnezia::headless::acceptedPendingRollbackResponse(
                    request.requestId, responseError, scheduled);
            if (!pending.isEmpty()) {
                return printResponse(pending, parser.isSet(QStringLiteral("json")),
                                     parser.value(QStringLiteral("output")));
            }
        }
        QTextStream(stderr) << "amnezia-cli: daemon response failed: "
                            << responseError << Qt::endl;
        return 1;
    }
    if (coordinatedRollback && QJsonDocument::fromJson(responseFrame).object()
            .value(QStringLiteral("ok")).toBool(false)
            && !amnezia::headless::daemonScheduledRollback(responseFrame)) {
        const auto requested = amnezia::headless::RollbackCoordinator().rollbackRequested();
        if (!requested.ok) {
            QTextStream(stderr) << requested.code << ": " << requested.message << Qt::endl;
            return 1;
        }
    }
    return printResponse(responseFrame, parser.isSet(QStringLiteral("json")),
                         parser.value(QStringLiteral("output")));
}
