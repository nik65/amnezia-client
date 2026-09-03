#include "vpnBackend.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QProcess>
#include <QRegularExpression>
#include <QTemporaryDir>
#include <QStandardPaths>
#include <QElapsedTimer>
#include <QThread>
#include <QEventLoop>
#include <QTimer>
#include <QDateTime>

#include <utility>

namespace amnezia::headless
{

namespace
{
constexpr qint64 WireGuardHandshakeMaxAgeSeconds = 180;

bool waitForProcessFinished(QProcess &process, int timeoutMs)
{
    if (process.state() == QProcess::NotRunning) return true;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&process, &QProcess::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(timeoutMs);
    loop.exec();
    return process.state() == QProcess::NotRunning;
}
}

struct RealCommandRunner::RunningProcess
{
    QHash<QString, QProcess *> processes;
};

RealCommandRunner::RealCommandRunner()
    : m_processes(std::make_unique<RunningProcess>())
{
}

RealCommandRunner::~RealCommandRunner()
{
    if (!m_processes) {
        return;
    }
    for (QProcess *process : std::as_const(m_processes->processes)) {
        if (!process) {
            continue;
        }
        if (process->state() != QProcess::NotRunning) {
            process->terminate();
            if (!waitForProcessFinished(*process, 2000)) {
                process->kill();
                waitForProcessFinished(*process, 2000);
            }
        }
        delete process;
    }
    m_processes->processes.clear();
}

bool RealCommandRunner::isAvailable(const QString &program) const
{
    return !resolveExecutable({ program }).isEmpty();
}

QString RealCommandRunner::resolveExecutable(const QStringList &candidates) const
{
    for (const QString &candidate : candidates) {
        if (QFileInfo(candidate).isAbsolute()) {
            const QFileInfo info(candidate);
            if (info.isFile() && info.isExecutable() && !info.isSymLink()) {
                return info.absoluteFilePath();
            }
            continue;
        }
        // Never resolve privileged VPN helpers from the ambient service PATH.
        // Only the distro-owned absolute locations below are accepted.
        const QStringList trustedDirectories {
            QStringLiteral("/usr/bin"), QStringLiteral("/usr/sbin"),
            QStringLiteral("/bin"), QStringLiteral("/sbin"),
            QStringLiteral("/usr/local/bin"), QStringLiteral("/usr/local/sbin")
        };
        for (const QString &directory : trustedDirectories) {
            const QFileInfo info(QDir(directory).filePath(candidate));
            if (info.isFile() && info.isExecutable() && !info.isSymLink()) {
                return info.absoluteFilePath();
            }
        }
    }
    return {};
}

CommandResult RealCommandRunner::run(const QString &program, const QStringList &arguments)
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    // Some Linux VPN adapters daemonize a userspace tunnel process.  Do not
    // leave their inherited stdout/stderr pipe attached to QProcess: that can
    // make waitForFinished() wait for the daemon rather than the adapter
    // command.  Adapter output is intentionally not part of the control
    // protocol or the privacy-safe daemon log.
    process.setStandardOutputFile(QProcess::nullDevice());
    process.setStandardErrorFile(QProcess::nullDevice());
    process.start();
    if (!process.waitForStarted(3000)) {
        return { false, -1, QStringLiteral("unable to start backend executable") };
    }
    if (!waitForProcessFinished(process, 30'000)) {
        process.kill();
        waitForProcessFinished(process, 2000);
        return { false, -1, QStringLiteral("backend executable timed out") };
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return { false, process.exitCode(),
                 QStringLiteral("backend executable failed") };
    }
    return { true, process.exitCode(), {} };
}

CommandResult RealCommandRunner::runCaptured(const QString &program,
                                             const QStringList &arguments)
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    process.start();
    if (!process.waitForStarted(3000)) {
        return { false, -1, QStringLiteral("unable to start backend executable"), {} };
    }
    if (!waitForProcessFinished(process, 30'000)) {
        process.kill();
        waitForProcessFinished(process, 2000);
        return { false, -1, QStringLiteral("backend executable timed out"), {} };
    }
    const QString output = QString::fromUtf8(process.readAllStandardOutput());
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return { false, process.exitCode(),
                 QStringLiteral("backend executable failed"), output };
    }
    return { true, process.exitCode(), {}, output };
}

CommandResult RealCommandRunner::startDetached(const QString &program,
                                               const QStringList &arguments)
{
    if (!QProcess::startDetached(program, arguments)) {
        return { false, -1, QStringLiteral("unable to start detached helper") };
    }
    return { true, 0, {} };
}

CommandResult RealCommandRunner::start(const QString &id, const QString &program,
                                       const QStringList &arguments)
{
    if (!m_processes) {
        m_processes = std::make_unique<RunningProcess>();
    }
    if (m_processes->processes.contains(id)) {
        return { false, -1, QStringLiteral("backend session already exists") };
    }

    auto *process = new QProcess;
    process->setProgram(program);
    process->setArguments(arguments);
    process->setStandardOutputFile(QProcess::nullDevice());
    process->setStandardErrorFile(QProcess::nullDevice());
    process->start();
    if (!process->waitForStarted(3000)) {
        delete process;
        return { false, -1, QStringLiteral("unable to start backend executable") };
    }

    m_processes->processes.insert(id, process);
    return { true, 0, {} };
}

CommandResult RealCommandRunner::stop(const QString &id)
{
    if (!m_processes || !m_processes->processes.contains(id)) {
        return { false, -1, QStringLiteral("backend session does not exist") };
    }

    QProcess *process = m_processes->processes.take(id);
    if (!process) {
        return { false, -1, QStringLiteral("backend session is invalid") };
    }

    bool stopped = true;
    if (process->state() != QProcess::NotRunning) {
        process->terminate();
        if (!waitForProcessFinished(*process, 2000)) {
            process->kill();
            stopped = waitForProcessFinished(*process, 2000);
        }
    }
    delete process;
    return stopped ? CommandResult { true, 0, {} }
                    : CommandResult { false, -1, QStringLiteral("unable to stop backend executable") };
}

bool RealCommandRunner::isSessionAlive(const QString &id) const
{
    return m_processes && m_processes->processes.contains(id)
        && m_processes->processes.value(id)
        && m_processes->processes.value(id)->state() != QProcess::NotRunning;
}

VpnBackend::VpnBackend(std::shared_ptr<CommandRunner> runner,
                       QString configRoot,
                       bool requireRootOwnedConfig,
                       QString stagingRoot)
    : m_runner(runner ? std::move(runner) : std::make_shared<RealCommandRunner>()),
      m_configRoot(std::move(configRoot)),
      m_requireRootOwnedConfig(requireRootOwnedConfig),
      m_stagingRoot(std::move(stagingRoot))
{
}

BackendResult VpnBackend::connect(const Profile &profile)
{
    m_lastError = {};
    if (m_session) {
        return failure(QStringLiteral("already_connected"),
                       QStringLiteral("a VPN profile is already active"));
    }

    const QString protocol = normalizeProtocol(profile.protocol);
    if (protocol.isEmpty()) {
        return failure(QStringLiteral("invalid_profile"),
                       QStringLiteral("profile protocol is empty"));
    }
    if (!isSupportedProtocol(protocol)) {
        return failure(QStringLiteral("unsupported_protocol"),
                       QStringLiteral("profile protocol is not supported on Ubuntu"));
    }
    if (profile.routingMode == QStringLiteral("all-except")
        && (protocol == QStringLiteral("xray") || protocol == QStringLiteral("ssxray"))) {
        return failure(QStringLiteral("routing_mode_unsupported"),
                       QStringLiteral("all-except requires a native VPN interface; XRay proxy mode is not a full tunnel"));
    }

    BackendResult configResult;
    if (!configIsUsable(profile, configResult)) {
        m_lastError = configResult;
        return configResult;
    }

    const QString executable = m_runner->resolveExecutable(candidatesForProtocol(protocol));
    if (executable.isEmpty()) {
        return failure(QStringLiteral("backend_unavailable"),
                       QStringLiteral("required Linux VPN executable is not installed"));
    }

    QString effectiveConfigPath = profile.configPath;
    QString temporaryConfigDirectory;
    QString preparationError;
    if (profile.routingMode == QStringLiteral("all-except")
        && (protocol == QStringLiteral("wireguard") || protocol == QStringLiteral("amneziawg"))
        && !prepareFullTunnelConfig(profile, protocol, effectiveConfigPath,
                                    temporaryConfigDirectory, &preparationError)) {
        return failure(QStringLiteral("config_invalid"), preparationError);
    }

    const QStringList arguments = argumentsForProtocol(protocol, effectiveConfigPath);
    CommandResult commandResult;
    const bool longRunning = isLongRunningProtocol(protocol);
    if (longRunning) {
        commandResult = m_runner->start(profile.id, executable, arguments);
    } else {
        commandResult = m_runner->run(executable, arguments);
    }
    if (!commandResult.ok) {
        if (!temporaryConfigDirectory.isEmpty()) {
            QDir(temporaryConfigDirectory).removeRecursively();
        }
        const QString message = commandResult.message.isEmpty()
            ? QStringLiteral("Linux VPN backend failed to connect")
            : commandResult.message;
        return failure(QStringLiteral("backend_failed"), message);
    }

    const QString interfaceName = profile.interfaceName.isEmpty()
            ? (protocol == QStringLiteral("wireguard") ? QStringLiteral("wg0")
               : protocol == QStringLiteral("amneziawg") ? QStringLiteral("amn0")
               : protocol == QStringLiteral("openvpn") ? QStringLiteral("tun0") : QString())
            : profile.interfaceName;
    m_session = std::make_unique<Session>(Session {
        profile.id,
        protocol,
        effectiveConfigPath,
        temporaryConfigDirectory,
        executable,
        interfaceName,
        longRunning ? SessionKind::LongRunning : SessionKind::OneShot,
    });
    // Process start is not tunnel readiness.  All native backends must expose
    // their kernel interface before the routing controller is allowed to
    // mutate policy routes or the daemon reports connected.
    const bool nativeInterfaceBackend = protocol == QStringLiteral("wireguard")
        || protocol == QStringLiteral("amneziawg")
        || protocol == QStringLiteral("openvpn");
    if (nativeInterfaceBackend) {
        const QString ip = m_runner->resolveExecutable({ QStringLiteral("ip"),
                                                          QStringLiteral("/usr/sbin/ip"),
                                                          QStringLiteral("/sbin/ip") });
        QElapsedTimer timer;
        timer.start();
        bool ready = false;
        while (!ip.isEmpty() && timer.elapsed() < 5000) {
            // This is a bounded post-process readiness grace period.  It only
            // observes kernel interface/address/configuration state; a
            // WireGuard handshake depends on the policy routes being installed
            // below and must not be a pre-route prerequisite.
            ready = interfaceHealthy(interfaceName);
            if (ready && protocol == QStringLiteral("openvpn")) {
                ready = m_runner->isSessionAlive(profile.id);
            }
            if (ready) break;
            QThread::msleep(100);
        }
        if (!ready) {
            if (longRunning) {
                m_runner->stop(profile.id);
            } else {
                m_runner->run(executable, { QStringLiteral("down"), effectiveConfigPath });
            }
            if (!temporaryConfigDirectory.isEmpty()) QDir(temporaryConfigDirectory).removeRecursively();
            m_session.reset();
            return failure(QStringLiteral("backend_not_ready"),
                           QStringLiteral("VPN backend did not create its native interface in time"));
        }
    }
    return { true, {}, {} };
}

BackendResult VpnBackend::disconnect()
{
    m_lastError = {};
    if (!m_session) {
        return { true, {}, {} };
    }

    CommandResult commandResult { true, 0, {} };
    if (m_session->kind == SessionKind::LongRunning) {
        commandResult = m_runner->stop(m_session->profileId);
    } else {
        QStringList arguments;
        if (m_session->protocol == QStringLiteral("wireguard")
            || m_session->protocol == QStringLiteral("amneziawg")) {
            arguments = { QStringLiteral("down"), m_session->configPath };
        }
        commandResult = m_runner->run(m_session->program, arguments);
    }
    if (!commandResult.ok) {
        return failure(QStringLiteral("disconnect_failed"),
                       commandResult.message.isEmpty()
                           ? QStringLiteral("Linux VPN backend failed to disconnect")
                           : commandResult.message);
    }

    const QString temporaryConfigDirectory = m_session->temporaryConfigDirectory;
    m_session.reset();
    if (!temporaryConfigDirectory.isEmpty()
        && !QDir(temporaryConfigDirectory).removeRecursively()) {
        return failure(QStringLiteral("config_cleanup_failed"),
                       QStringLiteral("temporary full-tunnel configuration could not be removed"));
    }
    return { true, {}, {} };
}

bool VpnBackend::prepareFullTunnelConfig(const Profile &profile,
                                         const QString &protocol,
                                         QString &configPath,
                                         QString &temporaryDirectory,
                                         QString *error) const
{
    if (protocol != QStringLiteral("wireguard") && protocol != QStringLiteral("amneziawg")) {
        return true;
    }

    QFile source(profile.configPath);
    if (!source.open(QIODevice::ReadOnly) || source.size() > 1024 * 1024) {
        if (error) *error = QStringLiteral("VPN configuration cannot be staged for full tunnel");
        return false;
    }
    const QString content = QString::fromUtf8(source.readAll());
    const QRegularExpression allowedIpsLine(
            QStringLiteral(R"(^\s*AllowedIPs\s*=\s*[^\r\n]*$)"),
            QRegularExpression::MultilineOption);
    if (!allowedIpsLine.match(content).hasMatch()) {
        if (error) *error = QStringLiteral("WireGuard configuration has no AllowedIPs entry");
        return false;
    }

    QString rewritten = content;
    rewritten.replace(allowedIpsLine,
                      QStringLiteral("AllowedIPs = 0.0.0.0/0, ::/0"));

    // The native wg-quick policy-rules generator is not the transaction owner
    // for headless full-tunnel mode.  Disable it explicitly and let the
    // reconciler stage table 51821 plus its bounded rules atomically.
    const QRegularExpression tableLine(
            QStringLiteral(R"(^\s*Table\s*=\s*[^\r\n]*$)"),
            QRegularExpression::MultilineOption | QRegularExpression::CaseInsensitiveOption);
    if (tableLine.match(rewritten).hasMatch()) {
        rewritten.replace(tableLine, QStringLiteral("Table = off"));
    } else {
        const qsizetype interfaceEnd = rewritten.indexOf(QRegularExpression(
                QStringLiteral(R"(^\s*\[Peer\]\s*$)")), 0);
        const QString line = QStringLiteral("Table = off\n");
        if (interfaceEnd >= 0) {
            rewritten.insert(interfaceEnd, line);
        } else {
            rewritten.append(QStringLiteral("\n") + line);
        }
    }

    QString interfaceName = profile.interfaceName.trimmed();
    if (interfaceName.isEmpty()) {
        interfaceName = protocol == QStringLiteral("amneziawg")
                ? QStringLiteral("amn0") : QStringLiteral("wg0");
    }
    const QString stagingRoot = m_stagingRoot.trimmed().isEmpty()
            ? QDir::tempPath() : m_stagingRoot.trimmed();
    QTemporaryDir temporary(QDir(stagingRoot).filePath(
            QStringLiteral("amnezia-headless-full-tunnel-XXXXXX")));
    if (!temporary.isValid()) {
        if (error) *error = QStringLiteral("full-tunnel staging root is not writable");
        return false;
    }
    temporary.setAutoRemove(false);
    const QString stagedPath = QDir(temporary.path()).filePath(interfaceName + QStringLiteral(".conf"));
    QFile staged(stagedPath);
    if (!staged.open(QIODevice::WriteOnly | QIODevice::Truncate)
        || staged.write(rewritten.toUtf8()) != rewritten.toUtf8().size()
        || !staged.flush()) {
        if (error) *error = QStringLiteral("temporary full-tunnel configuration cannot be written");
        QDir(temporary.path()).removeRecursively();
        return false;
    }
    staged.close();
#ifndef Q_OS_WIN
    QFile::setPermissions(stagedPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    configPath = stagedPath;
    temporaryDirectory = temporary.path();
    return true;
}

QJsonObject VpnBackend::doctor() const
{
    QJsonArray backends;
    bool anyBackendAvailable = false;
    const QStringList protocols {
        QStringLiteral("wireguard"),
        QStringLiteral("amneziawg"),
        QStringLiteral("openvpn"),
        QStringLiteral("xray"),
    };
    for (const QString &protocol : protocols) {
        const QString executable = m_runner->resolveExecutable(candidatesForProtocol(protocol));
        anyBackendAvailable = anyBackendAvailable || !executable.isEmpty();
        backends.append(QJsonObject {
            { QStringLiteral("protocol"), protocol },
            { QStringLiteral("available"), !executable.isEmpty() },
            { QStringLiteral("executable"), executable.isEmpty()
                                                   ? QJsonValue {}
                                                   : QJsonValue(executable) },
        });
    }
    return QJsonObject {
        { QStringLiteral("ready"), anyBackendAvailable },
        { QStringLiteral("activeProfile"), activeProfile() },
        { QStringLiteral("backends"), backends },
    };
}

QString VpnBackend::activeProfile() const
{
    return m_session ? m_session->profileId : QString();
}

QString VpnBackend::activeInterface() const
{
    return m_session ? m_session->interfaceName : QString();
}

bool VpnBackend::sessionAlive() const
{
    if (!m_session) return false;
    if (m_session->kind == SessionKind::LongRunning) {
        return m_runner->isSessionAlive(m_session->profileId)
            && interfaceHealthy(m_session->interfaceName);
    }
    // One-shot WireGuard/AmneziaWG commands return after configuring the
    // interface; process liveness is therefore not a health signal.  Probe
    // the actual interface on every health tick instead.
    return interfaceHealthy(m_session->interfaceName);
}

bool VpnBackend::interfaceHealthy(const QString &interfaceName) const
{
    return interfaceHealthy(interfaceName, false);
}

bool VpnBackend::sessionHealthyAfterRouting() const
{
    if (!m_session) return false;
    return interfaceHealthy(m_session->interfaceName, true);
}

bool VpnBackend::interfaceHealthy(const QString &interfaceName,
                                  bool requireRecentHandshake) const
{
    if (!m_session) return false;
    const QString requestedInterface = interfaceName.trimmed();
    const QString targetInterface = m_session->interfaceName;
    if (!requestedInterface.isEmpty() && requestedInterface != targetInterface) return false;
    if (targetInterface.isEmpty()) return true;
    const QString ip = m_runner->resolveExecutable(
            { QStringLiteral("ip"), QStringLiteral("/usr/sbin/ip"), QStringLiteral("/sbin/ip") });
    if (ip.isEmpty()) return false;
    const CommandResult result = m_runner->runCaptured(
            ip, { QStringLiteral("link"), QStringLiteral("show"),
                  QStringLiteral("dev"), targetInterface });
    const QRegularExpression linkPattern(QStringLiteral(
            "(?m)^\\s*\\d+:\\s*%1(?:[@:]|\\s)")
            .arg(QRegularExpression::escape(targetInterface)));
    if (!result.ok || !linkPattern.match(result.output).hasMatch()) return false;

    const CommandResult addresses = m_runner->runCaptured(
            ip, { QStringLiteral("-o"), QStringLiteral("addr"), QStringLiteral("show"),
                  QStringLiteral("dev"), targetInterface });
    // Native routing is safe only after the interface has an assigned,
    // non-loopback address.  This applies to OpenVPN and WireGuard alike.
    if (!addresses.ok || !QRegularExpression(QStringLiteral(
            "\\b(?:inet|inet6)\\s+(?!127\\.)(?!::1(?:/|\\b))\\S+/\\d+\\b"))
            .match(addresses.output).hasMatch()) {
        return false;
    }

    if (m_session->protocol == QStringLiteral("wireguard")
        || m_session->protocol == QStringLiteral("amneziawg")) {
        const QString tool = m_runner->resolveExecutable(
                m_session->protocol == QStringLiteral("amneziawg")
                    ? QStringList { QStringLiteral("awg"), QStringLiteral("/usr/bin/awg"),
                                     QStringLiteral("/usr/sbin/awg") }
                    : QStringList { QStringLiteral("wg"), QStringLiteral("/usr/bin/wg"),
                                     QStringLiteral("/usr/sbin/wg") });
        // showconf proves that the kernel interface has the expected native
        // configuration without imposing a traffic-dependent handshake gate.
        if (tool.isEmpty()
            || !m_runner->runCaptured(tool,
                                      { QStringLiteral("showconf"), targetInterface }).ok) {
            return false;
        }
        if (!requireRecentHandshake) {
            return true;
        }
        const CommandResult handshakes = m_runner->runCaptured(
                tool, { QStringLiteral("show"), targetInterface,
                        QStringLiteral("latest-handshakes") });
        if (!handshakes.ok) return false;
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        const QStringList lines = handshakes.output.split(
                QRegularExpression(QStringLiteral("[\\r\\n]")), Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            const QStringList fields = line.trimmed().split(
                    QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
            if (fields.size() < 2) return false;
            bool timestampOk = false;
            const qint64 timestamp = fields.constLast().toLongLong(&timestampOk);
            if (!timestampOk || timestamp <= 0 || timestamp > now + 5
                || now - timestamp > WireGuardHandshakeMaxAgeSeconds) {
                return false;
            }
        }
        // An empty latest-handshakes result means the interface has no peers;
        // that is not a stale-peer failure.
        return true;
    }
    return true;
}

bool VpnBackend::configuredInterfacePresent(const Profile &profile) const
{
    const QString protocol = normalizeProtocol(profile.protocol);
    QString interfaceName = profile.interfaceName.trimmed();
    if (interfaceName.isEmpty()) {
        if (protocol == QStringLiteral("wireguard")) interfaceName = QStringLiteral("wg0");
        else if (protocol == QStringLiteral("amneziawg")) interfaceName = QStringLiteral("amn0");
        else if (protocol == QStringLiteral("openvpn")) interfaceName = QStringLiteral("tun0");
    }
    if (interfaceName.isEmpty() || (protocol != QStringLiteral("wireguard")
                                    && protocol != QStringLiteral("amneziawg")
                                    && protocol != QStringLiteral("openvpn"))) {
        return false;
    }
    const QString ip = m_runner->resolveExecutable(
            { QStringLiteral("ip"), QStringLiteral("/usr/sbin/ip"), QStringLiteral("/sbin/ip") });
    if (ip.isEmpty()) return true;
    const CommandResult result = m_runner->runCaptured(
            ip, { QStringLiteral("link"), QStringLiteral("show"), QStringLiteral("dev"), interfaceName });
    if (!result.ok) return true;
    return QRegularExpression(QStringLiteral(
            "(?m)^\\s*\\d+:\\s*%1(?:[@:]|\\s)")
            .arg(QRegularExpression::escape(interfaceName))).match(result.output).hasMatch();
}

bool VpnBackend::configuredDnsBindingPresent(const Profile &profile) const
{
    if (profile.dnsServers.isEmpty() && profile.dnsDomains.isEmpty()) return false;

    const QString protocol = normalizeProtocol(profile.protocol);
    QString interfaceName = profile.interfaceName.trimmed();
    if (interfaceName.isEmpty()) {
        if (protocol == QStringLiteral("wireguard")) interfaceName = QStringLiteral("wg0");
        else if (protocol == QStringLiteral("amneziawg")) interfaceName = QStringLiteral("amn0");
        else if (protocol == QStringLiteral("openvpn")) interfaceName = QStringLiteral("tun0");
    }
    if (interfaceName.isEmpty()) return false;

    const QString resolver = m_runner->resolveExecutable(
            { QStringLiteral("resolvectl"), QStringLiteral("/usr/bin/resolvectl"),
              QStringLiteral("/bin/resolvectl") });
    if (resolver.isEmpty()) return true;
    const CommandResult result = m_runner->runCaptured(
            resolver, { QStringLiteral("status") });
    if (!result.ok) return true;

    const QRegularExpression linkPattern(QStringLiteral(
            R"(^\s*Link\s+(?:\d+\s+)?\(([^)]+)\)\s*:?.*$)"));
    bool targetLink = false;
    for (const QString &line : result.output.split(
            QRegularExpression(QStringLiteral("[\\r\\n]")), Qt::SkipEmptyParts)) {
        const QRegularExpressionMatch link = linkPattern.match(line);
        if (link.hasMatch()) {
            targetLink = link.captured(1) == interfaceName;
            continue;
        }
        if (!targetLink) continue;
        const QString trimmed = line.trimmed();
        if (trimmed.startsWith(QStringLiteral("DNS Servers:"))
            || trimmed.startsWith(QStringLiteral("Current DNS Server:"))
            || trimmed.startsWith(QStringLiteral("DNS Domain:"))) {
            return true;
        }
    }
    return false;
}

BackendResult VpnBackend::lastError() const
{
    return m_lastError;
}

BackendResult VpnBackend::failure(const QString &code, const QString &message)
{
    m_lastError = { false, code, message };
    return m_lastError;
}

QString VpnBackend::normalizeProtocol(const QString &protocol)
{
    const QString value = protocol.trimmed().toLower();
    if (value == QStringLiteral("awg") || value == QStringLiteral("awg2")
        || value == QStringLiteral("amnezia-wg") || value == QStringLiteral("amneziawg")) {
        return QStringLiteral("amneziawg");
    }
    if (value == QStringLiteral("ss-xray")) {
        return QStringLiteral("ssxray");
    }
    return value;
}

QStringList VpnBackend::candidatesForProtocol(const QString &protocol)
{
    if (protocol == QStringLiteral("wireguard")) {
        return { QStringLiteral("wg-quick") };
    }
    if (protocol == QStringLiteral("amneziawg")) {
        return { QStringLiteral("awg-quick"), QStringLiteral("amneziawg-quick") };
    }
    if (protocol == QStringLiteral("openvpn")) {
        return { QStringLiteral("openvpn") };
    }
    if (protocol == QStringLiteral("xray") || protocol == QStringLiteral("ssxray")) {
        return { QStringLiteral("xray") };
    }
    return {};
}

bool VpnBackend::isLongRunningProtocol(const QString &protocol)
{
    return protocol == QStringLiteral("openvpn")
        || protocol == QStringLiteral("xray")
        || protocol == QStringLiteral("ssxray");
}

bool VpnBackend::isSupportedProtocol(const QString &protocol)
{
    const QString normalized = normalizeProtocol(protocol);
    return normalized == QStringLiteral("wireguard")
        || normalized == QStringLiteral("amneziawg")
        || normalized == QStringLiteral("openvpn")
        || normalized == QStringLiteral("xray")
        || normalized == QStringLiteral("ssxray");
}

QStringList VpnBackend::argumentsForProtocol(const QString &protocol,
                                              const QString &configPath)
{
    if (protocol == QStringLiteral("wireguard")
        || protocol == QStringLiteral("amneziawg")) {
        return { QStringLiteral("up"), configPath };
    }
    if (protocol == QStringLiteral("openvpn")) {
        return { QStringLiteral("--config"), configPath };
    }
    return { QStringLiteral("run"), QStringLiteral("-c"), configPath };
}

bool VpnBackend::configIsUsable(const Profile &profile, BackendResult &result) const
{
    const QFileInfo configInfo(profile.configPath);
    if (profile.id.trimmed().isEmpty()) {
        result = { false, QStringLiteral("invalid_profile"),
                   QStringLiteral("profile id is empty") };
        return false;
    }
    if (!configInfo.isAbsolute() || !configInfo.isFile() || !configInfo.isReadable()) {
        result = { false, QStringLiteral("config_unavailable"),
                   QStringLiteral("profile configuration file is not readable") };
        return false;
    }

    if (!m_configRoot.isEmpty()) {
        const QString rootPath = QFileInfo(m_configRoot).canonicalFilePath();
        const QString configPath = configInfo.canonicalFilePath();
        const QString rootPrefix = rootPath + QDir::separator();
        if (rootPath.isEmpty() || configPath.isEmpty()
            || !configPath.startsWith(rootPrefix)) {
            result = { false, QStringLiteral("config_not_allowed"),
                       QStringLiteral("profile configuration is outside the trusted directory") };
            return false;
        }

#ifdef Q_OS_UNIX
        if (m_requireRootOwnedConfig
            && (configInfo.ownerId() != 0
                || configInfo.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) {
            result = { false, QStringLiteral("config_not_allowed"),
                       QStringLiteral("profile configuration must be root-owned and not group/world writable") };
            return false;
        }
#endif
    }
    return true;
}

} // namespace amnezia::headless
