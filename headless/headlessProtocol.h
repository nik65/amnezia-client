#ifndef AMNEZIA_HEADLESS_PROTOCOL_H
#define AMNEZIA_HEADLESS_PROTOCOL_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

namespace amnezia::headless
{

constexpr int WireProtocolVersion = 1;
constexpr qsizetype MaximumFrameSize = 64 * 1024;
constexpr qsizetype MaximumRequestIdSize = 128;

// JSON-lines is deliberately small and transport-neutral. The daemon owns
// state; the CLI and future HTTPS adapter only serialize these messages.
enum class Command {
    Status,
    ListProfiles,
    Connect,
    Disconnect,
    Doctor,
    Import,
    Export,
    UpdateRollback,
};

struct Request
{
    Command command = Command::Status;
    QString requestId;
    QJsonObject parameters;
};

QString commandName(Command command);
bool commandFromName(const QString &name, Command &command);

QByteArray encodeRequest(const Request &request);
QByteArray encodeResponse(const QString &requestId, const QJsonObject &result);
QByteArray encodeError(const QString &requestId, const QString &code, const QString &message);

bool parseRequest(const QByteArray &frame, Request &request, QString *error = nullptr);

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_PROTOCOL_H
