#include "headlessProtocol.h"

#include <QJsonValue>

namespace amnezia::headless
{
namespace
{

void setError(QString *error, const QString &message)
{
    if (error) {
        *error = message;
    }
}

bool isValidRequestId(const QString &requestId)
{
    return !requestId.isEmpty() && requestId.size() <= MaximumRequestIdSize;
}

QByteArray compactJsonLine(const QJsonObject &object)
{
    QByteArray frame = QJsonDocument(object).toJson(QJsonDocument::Compact);
    frame.append('\n');
    return frame;
}

} // namespace

QString commandName(Command command)
{
    switch (command) {
    case Command::Status:
        return QStringLiteral("status");
    case Command::ListProfiles:
        return QStringLiteral("list-profiles");
    case Command::Connect:
        return QStringLiteral("connect");
    case Command::Disconnect:
        return QStringLiteral("disconnect");
    case Command::Doctor:
        return QStringLiteral("doctor");
    case Command::Import:
        return QStringLiteral("import");
    case Command::Export:
        return QStringLiteral("export");
    case Command::UpdateRollback:
        return QStringLiteral("update-rollback");
    }
    return {};
}

bool commandFromName(const QString &name, Command &command)
{
    static const Command commands[] = {
        Command::Status,
        Command::ListProfiles,
        Command::Connect,
        Command::Disconnect,
        Command::Doctor,
        Command::Import,
        Command::Export,
        Command::UpdateRollback,
    };

    for (const Command candidate : commands) {
        if (commandName(candidate) == name) {
            command = candidate;
            return true;
        }
    }
    return false;
}

QByteArray encodeRequest(const Request &request)
{
    QJsonObject object {
        { QStringLiteral("protocol"), WireProtocolVersion },
        { QStringLiteral("id"), request.requestId },
        { QStringLiteral("command"), commandName(request.command) },
        { QStringLiteral("params"), request.parameters },
    };
    return compactJsonLine(object);
}

QByteArray encodeResponse(const QString &requestId, const QJsonObject &result)
{
    const QByteArray frame = compactJsonLine(QJsonObject {
        { QStringLiteral("protocol"), WireProtocolVersion },
        { QStringLiteral("id"), requestId },
        { QStringLiteral("ok"), true },
        { QStringLiteral("result"), result },
    });
    if (frame.size() <= MaximumFrameSize) return frame;
    return encodeError(requestId, QStringLiteral("response_too_large"),
                       QStringLiteral("response exceeds the IPC frame limit"));
}

QByteArray encodeError(const QString &requestId, const QString &code, const QString &message)
{
    return compactJsonLine(QJsonObject {
        { QStringLiteral("protocol"), WireProtocolVersion },
        { QStringLiteral("id"), requestId },
        { QStringLiteral("ok"), false },
        { QStringLiteral("error"), QJsonObject {
            { QStringLiteral("code"), code },
            { QStringLiteral("message"), message },
        } },
    });
}

bool parseRequest(const QByteArray &frame, Request &request, QString *error)
{
    setError(error, {});
    if (frame.size() > MaximumFrameSize) {
        setError(error, QStringLiteral("request frame is too large"));
        return false;
    }
    if (frame.isEmpty() || !frame.endsWith('\n')) {
        setError(error, QStringLiteral("request frame must end with a newline"));
        return false;
    }

    const QByteArray payload = frame.left(frame.size() - 1);
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        setError(error, QStringLiteral("request frame is not a JSON object"));
        return false;
    }

    const QJsonObject object = document.object();
    const QJsonValue protocol = object.value(QStringLiteral("protocol"));
    const QJsonValue id = object.value(QStringLiteral("id"));
    const QJsonValue commandValue = object.value(QStringLiteral("command"));
    const QJsonValue params = object.value(QStringLiteral("params"));
    if (!protocol.isDouble() || protocol.toInt(-1) != WireProtocolVersion) {
        setError(error, QStringLiteral("unsupported protocol version"));
        return false;
    }
    if (!id.isString() || !isValidRequestId(id.toString())) {
        setError(error, QStringLiteral("request id is missing or invalid"));
        return false;
    }
    if (!commandValue.isString() || !params.isObject()) {
        setError(error, QStringLiteral("command or params is malformed"));
        return false;
    }

    Command command;
    if (!commandFromName(commandValue.toString(), command)) {
        setError(error, QStringLiteral("unknown command"));
        return false;
    }

    request.command = command;
    request.requestId = id.toString();
    request.parameters = params.toObject();
    return true;
}

} // namespace amnezia::headless
