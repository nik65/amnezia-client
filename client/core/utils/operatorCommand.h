#ifndef OPERATORCOMMAND_H
#define OPERATORCOMMAND_H

#include <QByteArray>
#include <QCryptographicHash>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QtGlobal>

#include <cmath>

namespace amnezia::operatorMode
{
constexpr int WireProtocolVersion = 1;
constexpr qsizetype MaximumRouteArgumentLength = 2048;
constexpr qsizetype MaximumWireFrameSize = 64 * 1024;
constexpr qsizetype MaximumWatchTerminalReasonLength = 64;
constexpr qsizetype MaximumWatchTerminalMessageLength = 1024;
constexpr int MinimumProcessExitCode = 0;
constexpr int MaximumProcessExitCode = 255;

inline QString normalizedExecutableIdentity(QString path)
{
    path.replace(QLatin1Char('\\'), QLatin1Char('/'));
    path = QDir::cleanPath(path.trimmed());
#ifdef Q_OS_WIN
    path = path.toCaseFolded();
#endif
    return path;
}

inline bool peerIdentityMatches(const QString &expectedUserIdentity,
                                const QString &expectedExecutablePath,
                                const QString &peerUserIdentity,
                                const QString &peerExecutablePath)
{
    return !expectedUserIdentity.isEmpty()
            && expectedUserIdentity == peerUserIdentity
            && !normalizedExecutableIdentity(expectedExecutablePath).isEmpty()
            && normalizedExecutableIdentity(expectedExecutablePath)
                    == normalizedExecutableIdentity(peerExecutablePath);
}

inline QString scopedLocalServerName(const QString &baseName,
                                     const QString &userIdentity,
                                     const QString &canonicalExecutablePath)
{
    if (baseName.isEmpty() || userIdentity.isEmpty() || canonicalExecutablePath.isEmpty()) {
        return {};
    }
    const QByteArray namespaceMaterial = userIdentity.toUtf8() + '\0'
            + normalizedExecutableIdentity(canonicalExecutablePath).toUtf8();
    const QByteArray digest = QCryptographicHash::hash(namespaceMaterial, QCryptographicHash::Sha256).toHex();
    return QStringLiteral("%1-%2").arg(baseName, QString::fromLatin1(digest.left(32)));
}

enum class WireFrameState {
    Incomplete,
    Complete,
    TooLarge,
};

inline bool canProcessWireFrame(bool handled, bool processing)
{
    return !handled && !processing;
}

inline WireFrameState wireFrameState(const QByteArray &buffer)
{
    if (buffer.size() > MaximumWireFrameSize) {
        return WireFrameState::TooLarge;
    }
    const qsizetype newline = buffer.indexOf('\n');
    if (newline >= 0) {
        return WireFrameState::Complete;
    }
    return buffer.size() == MaximumWireFrameSize
            ? WireFrameState::TooLarge : WireFrameState::Incomplete;
}

enum class CommandType {
    None,
    Status,
    Disconnect,
    Doctor,
    RoutesExplain,
    Watch,
    // Internal authenticated handshake used by an ordinary secondary launch.
    // It is intentionally not exposed by parseArguments().
    Raise,
};

inline QString commandName(CommandType type)
{
    switch (type) {
    case CommandType::Status:
        return QStringLiteral("status");
    case CommandType::Disconnect:
        return QStringLiteral("disconnect");
    case CommandType::Doctor:
        return QStringLiteral("doctor");
    case CommandType::RoutesExplain:
        return QStringLiteral("routes-explain");
    case CommandType::Watch:
        return QStringLiteral("watch");
    case CommandType::Raise:
        return QStringLiteral("raise");
    case CommandType::None:
        break;
    }
    return QStringLiteral("none");
}

inline CommandType commandType(const QString &name)
{
    if (name == QStringLiteral("status")) {
        return CommandType::Status;
    }
    if (name == QStringLiteral("disconnect")) {
        return CommandType::Disconnect;
    }
    if (name == QStringLiteral("doctor")) {
        return CommandType::Doctor;
    }
    if (name == QStringLiteral("routes-explain")) {
        return CommandType::RoutesExplain;
    }
    if (name == QStringLiteral("watch")) {
        return CommandType::Watch;
    }
    if (name == QStringLiteral("raise")) {
        return CommandType::Raise;
    }
    return CommandType::None;
}

struct CommandRequest {
    CommandType type = CommandType::None;
    bool json = false;
    QString argument;

    bool isValid(QString *error = nullptr) const
    {
        QString message;
        if (type == CommandType::None) {
            message = QStringLiteral("No operator command was specified.");
        } else if (type == CommandType::RoutesExplain && argument.trimmed().isEmpty()) {
            message = QStringLiteral("--routes-explain requires a host name or IP address.");
        } else if (type == CommandType::RoutesExplain && argument.size() > MaximumRouteArgumentLength) {
            message = QStringLiteral("--routes-explain argument is too long.");
        } else if (type != CommandType::RoutesExplain && !argument.isEmpty()) {
            message = QStringLiteral("The selected operator command does not accept an argument.");
        }

        if (error) {
            *error = message;
        }
        return message.isEmpty();
    }

    QJsonObject toJson() const
    {
        QJsonObject object {
            { QStringLiteral("protocol"), WireProtocolVersion },
            { QStringLiteral("command"), commandName(type) },
            { QStringLiteral("json"), json },
        };
        if (!argument.isEmpty()) {
            object.insert(QStringLiteral("argument"), argument);
        }
        return object;
    }

    static bool fromJson(const QJsonObject &object, CommandRequest *request, QString *error = nullptr)
    {
        QString message;
        CommandRequest parsed;
        const QJsonValue protocol = object.value(QStringLiteral("protocol"));
        const QJsonValue command = object.value(QStringLiteral("command"));
        const QJsonValue json = object.value(QStringLiteral("json"));
        const QJsonValue argument = object.value(QStringLiteral("argument"));
        if (!protocol.isDouble() || protocol.toDouble() != static_cast<double>(WireProtocolVersion)) {
            message = QStringLiteral("Unsupported operator command protocol version.");
        } else if (!command.isString() || !json.isBool()
                   || (!argument.isUndefined() && !argument.isString())) {
            message = QStringLiteral("Malformed operator command.");
        } else {
            parsed.type = commandType(command.toString());
            parsed.json = json.toBool();
            parsed.argument = argument.toString();
            parsed.isValid(&message);
        }

        if (error) {
            *error = message;
        }
        if (!message.isEmpty()) {
            return false;
        }
        if (request) {
            *request = parsed;
        }
        return true;
    }
};

struct CommandParseResult {
    bool hasOperatorArguments = false;
    bool valid = false;
    CommandRequest request;
    QString error;
};

struct RouteRuntimeDecision {
    bool runtimeApplied = false;
    QString inspectionBasis = QStringLiteral("policyPreview");
    QString route = QStringLiteral("unknown");
    QString warning;
};

// The operator CLI has access to the effective policy and a bounded snapshot
// of the VPN worker, but it does not inspect the OS routing table. Keep policy
// prediction separate from the runtime answer and fail closed whenever the
// available snapshot cannot support a definitive statement.
inline RouteRuntimeDecision assessRouteRuntime(const QString &policyRoute,
                                               bool snapshotAvailable,
                                               bool connected,
                                               bool literalTarget,
                                               bool ipv6Target,
                                               bool splitMode,
                                               bool protectedTarget,
                                               bool appliedModeMatchesPolicy)
{
    RouteRuntimeDecision decision;
    if (!snapshotAvailable) {
        decision.warning = QStringLiteral("runtime_snapshot_unavailable");
        return decision;
    }
    if (!connected) {
        decision.warning = QStringLiteral("vpn_not_connected");
        return decision;
    }

    decision.runtimeApplied = true;
    decision.inspectionBasis = QStringLiteral("effectivePolicyWhileConnected");
    if (!appliedModeMatchesPolicy) {
        decision.warning = QStringLiteral("runtime_policy_mode_diverged");
        return decision;
    }
    if (!literalTarget) {
        decision.warning = QStringLiteral("hostname_resolution_required");
        return decision;
    }
    if (protectedTarget) {
        decision.warning = QStringLiteral("protected_route_requires_runtime_verification");
        return decision;
    }
    if (ipv6Target) {
        decision.warning = QStringLiteral("ipv6_route_not_runtime_verified");
        return decision;
    }
    if (splitMode) {
        decision.warning = QStringLiteral("split_route_not_runtime_verified");
        return decision;
    }
    if (policyRoute != QStringLiteral("vpn") && policyRoute != QStringLiteral("direct")) {
        decision.warning = QStringLiteral("invalid_policy_route");
        return decision;
    }

    decision.route = policyRoute;
    decision.warning = QStringLiteral("os_route_not_verified");
    return decision;
}

inline QByteArray watchSnapshotFrame(const QJsonObject &status,
                                     int statusExitCode,
                                     quint64 sequence,
                                     const QString &observedAt,
                                     qint64 primaryPid)
{
    if (sequence == 0 || observedAt.isEmpty() || primaryPid <= 0
        || status.value(QStringLiteral("schema")).toString()
                != QStringLiteral("amnezia.operator.status.v1")
        || statusExitCode < MinimumProcessExitCode
        || statusExitCode > MaximumProcessExitCode) {
        return {};
    }

    const QJsonObject snapshot {
        { QStringLiteral("schema"), QStringLiteral("amnezia.operator.watch.v1") },
        { QStringLiteral("event"), QStringLiteral("snapshot") },
        // JSON numbers lose integer precision above 2^53. A decimal string is
        // stable for long-running monitors and straightforward to parse.
        { QStringLiteral("sequence"), QString::number(sequence) },
        { QStringLiteral("observedAt"), observedAt },
        { QStringLiteral("primaryPid"), primaryPid },
        { QStringLiteral("statusExitCode"), statusExitCode },
        { QStringLiteral("status"), status },
    };
    QByteArray frame = QJsonDocument(snapshot).toJson(QJsonDocument::Compact);
    frame.append('\n');
    return wireFrameState(frame) == WireFrameState::Complete ? frame : QByteArray();
}

inline QByteArray watchTerminalFrame(const QString &reason,
                                     const QString &message,
                                     int exitCode,
                                     quint64 lastSequence,
                                     const QString &observedAt,
                                     qint64 primaryPid = -1)
{
    if (reason.isEmpty() || reason.size() > MaximumWatchTerminalReasonLength
        || message.size() > MaximumWatchTerminalMessageLength
        || observedAt.isEmpty() || (exitCode != 4 && exitCode != 5)
        || primaryPid == 0) {
        return {};
    }
    for (const QChar character : reason) {
        if (!((character >= QLatin1Char('a') && character <= QLatin1Char('z'))
              || (character >= QLatin1Char('0') && character <= QLatin1Char('9'))
              || character == QLatin1Char('_'))) {
            return {};
        }
    }

    QJsonObject terminal {
        { QStringLiteral("schema"), QStringLiteral("amnezia.operator.watch.v1") },
        { QStringLiteral("event"), QStringLiteral("terminal") },
        { QStringLiteral("reason"), reason },
        { QStringLiteral("message"), message },
        { QStringLiteral("lastSequence"), QString::number(lastSequence) },
        { QStringLiteral("observedAt"), observedAt },
        { QStringLiteral("exitCode"), exitCode },
    };
    if (primaryPid > 0) {
        terminal.insert(QStringLiteral("primaryPid"), primaryPid);
    }
    QByteArray frame = QJsonDocument(terminal).toJson(QJsonDocument::Compact);
    frame.append('\n');
    return wireFrameState(frame) == WireFrameState::Complete ? frame : QByteArray();
}

inline CommandParseResult parseArguments(int argc, char *argv[])
{
    CommandParseResult result;
    QStringList conflictingOptions;
    bool hasForeignArguments = false;

    const auto setCommand = [&result](CommandType type) {
        result.hasOperatorArguments = true;
        if (result.request.type != CommandType::None) {
            result.error = QStringLiteral("Only one operator command may be used at a time.");
            return;
        }
        result.request.type = type;
    };

    for (int i = 1; i < argc; ++i) {
        const QString argument = QString::fromLocal8Bit(argv[i]);
        if (argument == QStringLiteral("--json")) {
            result.hasOperatorArguments = true;
            result.request.json = true;
        } else if (argument == QStringLiteral("--status")) {
            setCommand(CommandType::Status);
        } else if (argument == QStringLiteral("--disconnect")) {
            setCommand(CommandType::Disconnect);
        } else if (argument == QStringLiteral("--doctor")) {
            setCommand(CommandType::Doctor);
        } else if (argument == QStringLiteral("--watch")) {
            setCommand(CommandType::Watch);
        } else if (argument == QStringLiteral("--routes-explain")) {
            setCommand(CommandType::RoutesExplain);
            if (i + 1 >= argc) {
                result.error = QStringLiteral("--routes-explain requires a host name or IP address.");
            } else {
                result.request.argument = QString::fromLocal8Bit(argv[++i]).trimmed();
                if (result.request.argument.startsWith(QLatin1Char('-'))) {
                    result.error = QStringLiteral("--routes-explain requires a host name or IP address.");
                }
            }
        } else if (argument.startsWith(QStringLiteral("--routes-explain="))) {
            setCommand(CommandType::RoutesExplain);
            result.request.argument = argument.mid(QStringLiteral("--routes-explain=").size()).trimmed();
        } else {
            hasForeignArguments = true;
            // Command lines can contain imported configuration data, tokens or
            // other secrets. Report only option names and never echo values.
            if (argument.startsWith(QLatin1Char('-'))) {
                const QString optionName = argument.section(QLatin1Char('='), 0, 0);
                static const QStringList knownStartupOptions {
                    QStringLiteral("-a"),
                    QStringLiteral("--autostart"),
                    QStringLiteral("-c"),
                    QStringLiteral("--cleanup"),
                    QStringLiteral("--connect"),
                    QStringLiteral("--import"),
                    QStringLiteral("--publish-bundled-updates-once"),
                    QStringLiteral("--help"),
                    QStringLiteral("--version"),
                };
                if (knownStartupOptions.contains(optionName) && !conflictingOptions.contains(optionName)) {
                    conflictingOptions.append(optionName);
                }
            }
        }
    }

    if (!result.hasOperatorArguments) {
        return result;
    }
    if (hasForeignArguments && result.error.isEmpty()) {
        result.error = conflictingOptions.isEmpty()
                ? QStringLiteral("Operator commands cannot be combined with other startup arguments.")
                : QStringLiteral("Operator commands cannot be combined with: %1")
                          .arg(conflictingOptions.join(QStringLiteral(", ")));
    }
    if (result.error.isEmpty()) {
        result.request.isValid(&result.error);
    }
    result.valid = result.error.isEmpty();
    return result;
}

struct CommandResponse {
    int exitCode = 0;
    QString humanOutput;
    QJsonObject result;

    QJsonObject toJson() const
    {
        return {
            { QStringLiteral("protocol"), WireProtocolVersion },
            { QStringLiteral("exitCode"), exitCode },
            { QStringLiteral("human"), humanOutput },
            { QStringLiteral("result"), result },
        };
    }

    static bool fromJson(const QJsonObject &object, CommandResponse *response, QString *error = nullptr)
    {
        QString message;
        const QJsonValue protocol = object.value(QStringLiteral("protocol"));
        const QJsonValue exitCode = object.value(QStringLiteral("exitCode"));
        const QJsonValue human = object.value(QStringLiteral("human"));
        const QJsonValue result = object.value(QStringLiteral("result"));
        const double numericExitCode = exitCode.toDouble(-1.0);
        const bool validExitCode = exitCode.isDouble() && std::isfinite(numericExitCode)
                && std::floor(numericExitCode) == numericExitCode
                && numericExitCode >= static_cast<double>(MinimumProcessExitCode)
                && numericExitCode <= static_cast<double>(MaximumProcessExitCode);
        if (!protocol.isDouble() || protocol.toDouble() != static_cast<double>(WireProtocolVersion)) {
            message = QStringLiteral("Unsupported operator response protocol version.");
        } else if (!validExitCode || !human.isString() || !result.isObject()) {
            message = QStringLiteral("Malformed operator response.");
        }

        if (error) {
            *error = message;
        }
        if (!message.isEmpty()) {
            return false;
        }
        if (response) {
            response->exitCode = static_cast<int>(numericExitCode);
            response->humanOutput = human.toString();
            response->result = result.toObject();
        }
        return true;
    }
};
}

#endif // OPERATORCOMMAND_H
