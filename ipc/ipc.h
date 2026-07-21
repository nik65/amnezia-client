#ifndef IPC_H
#define IPC_H

#include <QDir>
#include <QFileInfo>
#include <QHostAddress>
#include <QObject>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QUrl>

#include "../client/core/utils/utilities.h"

#define IPC_SERVICE_URL "local:AmneziaVpnIpcInterface.v2"

namespace amnezia {

inline constexpr int PrivilegedIpcProtocolVersion = 2;
inline constexpr qsizetype MaximumDaemonFrameSize = 1024 * 1024;
inline constexpr qint64 MaximumProcessOutputChunk = 1024 * 1024;
inline constexpr QLatin1StringView DaemonProtocolVersionKey("protocolVersion");

enum PermittedProcess {
    Invalid,
    OpenVPN,
    Wireguard,
    Tun2Socks,
    CertUtil,
    PermittedProcessCount
};

struct ProcessArgumentsValidation
{
    bool valid = false;
    QStringList arguments;
    QString error;
};

enum class DaemonFrameState {
    NeedMoreData,
    FrameReady,
    TooLarge
};

inline QString permittedProcessPath(PermittedProcess pid)
{
    switch (pid) {
    case PermittedProcess::OpenVPN:
        return Utils::openVpnExecPath();
    case PermittedProcess::Wireguard:
        return Utils::wireguardExecPath();
    case PermittedProcess::CertUtil:
        return Utils::certUtilPath();
    case PermittedProcess::Tun2Socks:
        return Utils::tun2socksPath();
    default:
        return {};
    }
}

inline QString privilegedIpcRuntimeDirectory()
{
#ifdef Q_OS_WIN
    return {};
#else
    return QStringLiteral("/var/run/amneziavpn");
#endif
}

inline QString getIpcServiceUrl()
{
#ifdef Q_OS_WIN
    return QStringLiteral(IPC_SERVICE_URL);
#else
    return privilegedIpcRuntimeDirectory() + QStringLiteral("/control-v2.sock");
#endif
}

inline QString getIpcProcessUrl(const QString &capability)
{
#ifdef Q_OS_WIN
    return QStringLiteral(IPC_SERVICE_URL "-") + capability;
#else
    return privilegedIpcRuntimeDirectory() + QStringLiteral("/process-v2-") + capability
        + QStringLiteral(".sock");
#endif
}

inline QString getDaemonServiceUrl()
{
#ifdef Q_OS_WIN
    return QStringLiteral("\\\\.\\pipe\\amneziavpn-v2");
#else
    return privilegedIpcRuntimeDirectory() + QStringLiteral("/daemon-v2.sock");
#endif
}

inline QString generateIpcCapability()
{
    QString capability;
    capability.reserve(32);
    for (int i = 0; i < 4; ++i) {
        capability += QStringLiteral("%1").arg(QRandomGenerator::system()->generate(), 8, 16,
                                               QLatin1Char('0'));
    }
    return capability;
}

inline bool hasUnsafeArgumentCharacters(const QString &argument)
{
    for (const QChar character : argument) {
        if (character.unicode() < 0x20 || character.unicode() == 0x7f) {
            return true;
        }
    }
    return false;
}

inline bool isBoundedRegularFile(const QString &path, qint64 maximumSize)
{
    const QFileInfo file(path);
    return file.isAbsolute() && file.exists() && file.isFile() && !file.isSymLink()
        && file.size() >= 0 && file.size() <= maximumSize;
}

inline QByteArray openVpnConfigSecurityPolicyPrefix()
{
    // Keep the exact setenv-with-space rule first for ordinary pushed options,
    // then preserve the safe namespaced form and reject remaining raw-token
    // spacing variants before any filter supplied by an imported configuration.
    // The bundled OpenVPN semantic guard rejects plain setenv after tokenization.
    return QByteArrayLiteral("pull-filter reject \"setenv \"\n"
                             "pull-filter accept \"setenv-safe\"\n"
                             "pull-filter reject \"setenv\"\n");
}

inline QByteArray hardenOpenVpnConfigContent(const QByteArray &content)
{
    const QByteArray policy = openVpnConfigSecurityPolicyPrefix();
    if (content.startsWith(policy)) {
        return content;
    }

    QByteArray hardened;
    hardened.reserve(policy.size() + content.size());
    hardened.append(policy);
    hardened.append(content);
    return hardened;
}

inline bool validateOpenVpnConfigContent(const QByteArray &content,
                                         const QString &trustedResolverScript = {},
                                         QString *errorMessage = nullptr)
{
    if (content.isEmpty() || content.size() > 4 * 1024 * 1024 || content.contains('\0')) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("OpenVPN configuration has an invalid size or encoding");
        }
        return false;
    }

    static const QSet<QString> dataBlocks {
        QStringLiteral("auth-user-pass"), QStringLiteral("ca"), QStringLiteral("cert"),
        QStringLiteral("dh"), QStringLiteral("extra-certs"), QStringLiteral("key"),
        QStringLiteral("pkcs12"), QStringLiteral("secret"), QStringLiteral("tls-auth"),
        QStringLiteral("tls-crypt"), QStringLiteral("tls-crypt-v2")
    };
    static const QSet<QString> forbiddenDirectives {
        QStringLiteral("askpass"), QStringLiteral("auth-gen-token-secret"),
        QStringLiteral("auth-gen-token"), QStringLiteral("auth-user-pass-optional"),
        QStringLiteral("auth-user-pass-verify"), QStringLiteral("cd"),
        QStringLiteral("bcast-buffers"), QStringLiteral("capath"),
        QStringLiteral("ccd-exclusive"),
        QStringLiteral("chroot"), QStringLiteral("client-connect"),
        QStringLiteral("client-cert-not-required"),
        QStringLiteral("client-crresponse"), QStringLiteral("client-disconnect"),
        QStringLiteral("client-config-dir"), QStringLiteral("client-to-client"),
        QStringLiteral("connect-freq"), QStringLiteral("connect-freq-initial"),
        QStringLiteral("config"), QStringLiteral("cryptoapicert"),
        QStringLiteral("daemon"), QStringLiteral("dns-updown"), QStringLiteral("down"),
        QStringLiteral("duplicate-cn"),
        QStringLiteral("engine"), QStringLiteral("group"),
        QStringLiteral("genkey"), QStringLiteral("hash-size"),
        QStringLiteral("http-proxy"), QStringLiteral("http-proxy-user-pass"),
        QStringLiteral("ipchange"),
        QStringLiteral("ifconfig-ipv6-pool"), QStringLiteral("ifconfig-ipv6-push"),
        QStringLiteral("ifconfig-pool"), QStringLiteral("ifconfig-pool-persist"),
        QStringLiteral("ifconfig-push"), QStringLiteral("ifconfig-push-constraint"),
        QStringLiteral("iproute"), QStringLiteral("learn-address"),
        QStringLiteral("log"), QStringLiteral("log-append"),
        QStringLiteral("management"), QStringLiteral("management-client-auth"),
        QStringLiteral("management-external-cert"), QStringLiteral("management-external-key"),
        QStringLiteral("max-clients"), QStringLiteral("max-routes-per-client"),
        QStringLiteral("mode"), QStringLiteral("nice"), QStringLiteral("opt-verify"),
        QStringLiteral("override-username"), QStringLiteral("plugin"),
        QStringLiteral("pkcs11-providers"), QStringLiteral("providers"),
        QStringLiteral("port-share"), QStringLiteral("push"),
        QStringLiteral("push-continuation"), QStringLiteral("push-remove"),
        QStringLiteral("push-reset"),
        QStringLiteral("replay-persist"), QStringLiteral("route-pre-down"),
        QStringLiteral("route-up"), QStringLiteral("script-security"),
        QStringLiteral("server"), QStringLiteral("server-bridge"),
        QStringLiteral("server-ipv6"), QStringLiteral("setcon"),
        QStringLiteral("setenv"),
        QStringLiteral("socks-proxy"),
        QStringLiteral("status"), QStringLiteral("tls-crypt-v2-verify"),
        QStringLiteral("tls-export-cert"), QStringLiteral("tls-server"),
        QStringLiteral("tls-verify"), QStringLiteral("tmp-dir"),
        QStringLiteral("up"), QStringLiteral("user"),
        QStringLiteral("username-as-common-name"), QStringLiteral("verify-client-cert"),
        QStringLiteral("writepid")
    };
    static const QSet<QString> externalFileDirectives {
        QStringLiteral("auth-user-pass"), QStringLiteral("ca"), QStringLiteral("cert"),
        QStringLiteral("crl-verify"), QStringLiteral("dh"), QStringLiteral("extra-certs"),
        QStringLiteral("key"), QStringLiteral("pkcs12"), QStringLiteral("secret"),
        QStringLiteral("tls-auth"), QStringLiteral("tls-crypt"),
        QStringLiteral("tls-crypt-v2")
    };
    static const QRegularExpression directivePattern(
        QStringLiteral(R"(^\s*(?:--)?([A-Za-z0-9_-]+)(?:\s+(.*))?$)"));
    static const QRegularExpression openTagPattern(
        QStringLiteral(R"(^\s*<([A-Za-z0-9_-]+)>\s*$)"));
    static const QRegularExpression closeTagPattern(
        QStringLiteral(R"(^\s*</([A-Za-z0-9_-]+)>\s*$)"));

    const QString text = QString::fromUtf8(content);
    if (text.contains(QChar::ReplacementCharacter)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("OpenVPN configuration is not valid UTF-8");
        }
        return false;
    }

    QString activeDataBlock;
    QString logicalLine;
    bool hasClientSemantics = false;
    const QStringList physicalLines = text.split(QLatin1Char('\n'));
    for (QString physicalLine : physicalLines) {
        if (physicalLine.endsWith(QLatin1Char('\r'))) {
            physicalLine.chop(1);
        }
        logicalLine += physicalLine;
        qsizetype trailingBackslashes = 0;
        for (qsizetype index = logicalLine.size(); index > 0
             && logicalLine.at(index - 1) == QLatin1Char('\\'); --index) {
            ++trailingBackslashes;
        }
        if ((trailingBackslashes % 2) != 0) {
            logicalLine.chop(1);
            continue;
        }

        const QString trimmed = logicalLine.trimmed();
        logicalLine.clear();
        if (trimmed.isEmpty() || trimmed.startsWith(QLatin1Char('#'))
            || trimmed.startsWith(QLatin1Char(';'))) {
            continue;
        }

        if (!activeDataBlock.isEmpty()) {
            const QRegularExpressionMatch closing = closeTagPattern.match(trimmed);
            if (closing.hasMatch()
                && closing.captured(1).compare(activeDataBlock, Qt::CaseInsensitive) == 0) {
                activeDataBlock.clear();
            }
            continue;
        }

        const QRegularExpressionMatch opening = openTagPattern.match(trimmed);
        if (opening.hasMatch()) {
            const QString block = opening.captured(1).toLower();
            if (dataBlocks.contains(block)) {
                activeDataBlock = block;
            }
            continue;
        }
        const QRegularExpressionMatch closing = closeTagPattern.match(trimmed);
        if (closing.hasMatch()
            && closing.captured(1).compare(QStringLiteral("connection"),
                                           Qt::CaseInsensitive) == 0) {
            continue;
        }

        const QRegularExpressionMatch directiveMatch = directivePattern.match(trimmed);
        if (!directiveMatch.hasMatch()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("OpenVPN configuration contains an invalid directive");
            }
            return false;
        }

        const QString directive = directiveMatch.captured(1).toLower();
        const QString value = directiveMatch.captured(2).trimmed();
        if ((directive == QStringLiteral("client")
             || directive == QStringLiteral("tls-client"))
            && value.isEmpty()) {
            hasClientSemantics = true;
        }
        if (directive == QStringLiteral("script-security") && value == QStringLiteral("2")
            && !trustedResolverScript.isEmpty()) {
            continue;
        }
        if ((directive == QStringLiteral("up") || directive == QStringLiteral("down"))
            && !trustedResolverScript.isEmpty()) {
            QString configuredScript = value;
            if (configuredScript.size() >= 2
                && ((configuredScript.startsWith(QLatin1Char('"'))
                     && configuredScript.endsWith(QLatin1Char('"')))
                    || (configuredScript.startsWith(QLatin1Char('\''))
                        && configuredScript.endsWith(QLatin1Char('\''))))) {
                configuredScript = configuredScript.mid(1, configuredScript.size() - 2);
            }
            const QString actual = QDir::cleanPath(QFileInfo(configuredScript).absoluteFilePath());
            const QString expected = QDir::cleanPath(QFileInfo(trustedResolverScript).absoluteFilePath());
#ifdef Q_OS_WIN
            const bool scriptMatches = actual.compare(expected, Qt::CaseInsensitive) == 0;
#else
            const bool scriptMatches = actual == expected;
#endif
            if (scriptMatches) {
                continue;
            }
        }
        if (forbiddenDirectives.contains(directive)
            || (externalFileDirectives.contains(directive)
                && value.compare(QStringLiteral("[inline]"), Qt::CaseInsensitive) != 0)) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("OpenVPN configuration contains a privileged directive: %1")
                                    .arg(directive);
            }
            return false;
        }
    }

    if (!logicalLine.isEmpty() || !activeDataBlock.isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("OpenVPN configuration contains an incomplete block");
        }
        return false;
    }
    if (!hasClientSemantics) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("OpenVPN configuration must explicitly use client mode");
        }
        return false;
    }
    return true;
}

inline ProcessArgumentsValidation validateProcessArguments(PermittedProcess process,
                                                            const QStringList &arguments)
{
    ProcessArgumentsValidation result;
    if (arguments.size() > 8) {
        result.error = QStringLiteral("Too many privileged process arguments");
        return result;
    }

    qsizetype totalLength = 0;
    for (const QString &argument : arguments) {
        totalLength += argument.size();
        if (argument.size() > 8192 || totalLength > 32768 || hasUnsafeArgumentCharacters(argument)) {
            result.error = QStringLiteral("Unsafe privileged process argument");
            return result;
        }
    }

    switch (process) {
    case PermittedProcess::OpenVPN: {
        if (arguments.size() != 6 || arguments.at(0) != QStringLiteral("--config")
            || arguments.at(2) != QStringLiteral("--management")
            || arguments.at(3) != QStringLiteral("127.0.0.1")
            || arguments.at(5) != QStringLiteral("--management-client")
            || !isBoundedRegularFile(arguments.at(1), 4 * 1024 * 1024)) {
            result.error = QStringLiteral("Invalid OpenVPN launch specification");
            return result;
        }
        bool portValid = false;
        const int port = arguments.at(4).toInt(&portValid);
        if (!portValid || port < 1 || port > 65535 || arguments.at(4) != QString::number(port)) {
            result.error = QStringLiteral("Invalid OpenVPN management port");
            return result;
        }
        break;
    }
    case PermittedProcess::Tun2Socks: {
        if (arguments.size() != 4 || arguments.at(0) != QStringLiteral("-device")
            || arguments.at(2) != QStringLiteral("-proxy")) {
            result.error = QStringLiteral("Invalid tun2socks launch specification");
            return result;
        }
        static const QRegularExpression devicePattern(
            QStringLiteral(R"(^tun://[A-Za-z0-9_.:-]{1,64}$)"));
        if (!devicePattern.match(arguments.at(1)).hasMatch()) {
            result.error = QStringLiteral("Invalid tun2socks device");
            return result;
        }
        const QString proxy = arguments.at(3);
        const qsizetype separator = proxy.lastIndexOf(QLatin1Char('@'));
        if (!proxy.startsWith(QStringLiteral("socks5://"), Qt::CaseInsensitive)
            || separator <= qsizetype(QStringLiteral("socks5://").size())) {
            result.error = QStringLiteral("Invalid tun2socks proxy");
            return result;
        }
        const QUrl endpoint(QStringLiteral("socks5://") + proxy.mid(separator + 1), QUrl::StrictMode);
        const QString host = endpoint.host();
        const int port = endpoint.port(-1);
        if (!endpoint.isValid() || (host != QStringLiteral("127.0.0.1") && host != QStringLiteral("::1"))
            || port < 1 || port > 65535 || !endpoint.path().isEmpty() || endpoint.hasQuery()
            || endpoint.hasFragment()) {
            result.error = QStringLiteral("Tun2socks proxy must use a loopback endpoint");
            return result;
        }
        break;
    }
    case PermittedProcess::CertUtil:
        if (arguments.size() != 6 || arguments.at(0) != QStringLiteral("-f")
            || arguments.at(1) != QStringLiteral("-importpfx")
            || arguments.at(2) != QStringLiteral("-p")
            || arguments.at(5) != QStringLiteral("NoExport")
            || !isBoundedRegularFile(arguments.at(4), 16 * 1024 * 1024)) {
            result.error = QStringLiteral("Invalid certificate import specification");
            return result;
        }
        break;
    case PermittedProcess::Invalid:
    case PermittedProcess::Wireguard:
    case PermittedProcess::PermittedProcessCount:
    default:
        result.error = QStringLiteral("Privileged process is not supported");
        return result;
    }

    result.valid = true;
    result.arguments = arguments;
    return result;
}

// Compatibility wrapper for the existing process implementation. An invalid
// specification returns an empty list and must be paired with the explicit
// validation result before start().
inline QStringList sanitizeArguments(PermittedProcess process, const QStringList &arguments)
{
    const ProcessArgumentsValidation validation = validateProcessArguments(process, arguments);
    return validation.valid ? validation.arguments : QStringList {};
}

inline DaemonFrameState takeDaemonFrame(QByteArray &buffer, QByteArray &frame)
{
    const qsizetype delimiter = buffer.indexOf('\n');
    if (delimiter < 0) {
        return buffer.size() > MaximumDaemonFrameSize ? DaemonFrameState::TooLarge
                                                       : DaemonFrameState::NeedMoreData;
    }
    if (delimiter > MaximumDaemonFrameSize) {
        return DaemonFrameState::TooLarge;
    }
    frame = buffer.left(delimiter);
    buffer.remove(0, delimiter + 1);
    return DaemonFrameState::FrameReady;
}

} // namespace amnezia

#endif // IPC_H
