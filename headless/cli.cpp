#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLocalSocket>
#include <QSaveFile>
#include <QTextStream>
#include <QUuid>

#include "daemon.h"

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

QByteArray readResponseFrame(QLocalSocket &socket, QString &error)
{
    QByteArray buffer;
    while (buffer.size() <= amnezia::headless::MaximumFrameSize) {
        buffer.append(socket.readAll());
        const qsizetype newline = buffer.indexOf('\n');
        if (newline >= 0) {
            if (newline + 1 > amnezia::headless::MaximumFrameSize) {
                error = QStringLiteral("daemon response frame is too large");
                return {};
            }
            return buffer.left(newline + 1);
        }
        if (!socket.waitForReadyRead(2000)) {
            error = socket.errorString();
            return {};
        }
    }
    error = QStringLiteral("daemon response frame is too large");
    return {};
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

} // namespace

int main(int argc, char *argv[])
{
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
    parser.addPositionalArgument(QStringLiteral("command"),
                                 QStringLiteral("status, list-profiles, doctor, connect, disconnect, import, export or update-rollback"));
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
    if (socket.write(amnezia::headless::encodeRequest(request)) < 0) {
        QTextStream(stderr) << "amnezia-cli: daemon request failed: "
                            << socket.errorString() << Qt::endl;
        return 1;
    }

    QString responseError;
    const QByteArray responseFrame = readResponseFrame(socket, responseError);
    if (responseFrame.isEmpty()) {
        QTextStream(stderr) << "amnezia-cli: daemon response failed: "
                            << responseError << Qt::endl;
        return 1;
    }
    return printResponse(responseFrame, parser.isSet(QStringLiteral("json")),
                         parser.value(QStringLiteral("output")));
}
