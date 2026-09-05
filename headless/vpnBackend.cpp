#include "vpnBackend.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include <QStandardPaths>
#include <QElapsedTimer>
#include <QThread>
#include <QEventLoop>
#include <QTimer>
#include <QDateTime>

#if defined(Q_OS_UNIX)
#include <unistd.h>
#include <sys/stat.h>
#endif

#include <utility>

namespace amnezia::headless
{

namespace
{
constexpr qint64 WireGuardHandshakeMaxAgeSeconds = 180;
constexpr int LongRunningStartupGraceMs = 500;
// Kernel probes can contain one line per managed policy destination plus the
// host's ordinary rules/routes.  Keep this allowance separate from the small
// control/diagnostic limits used by run(), runBatch(), and stderr capture.
constexpr qsizetype MaxCapturedProbeStdout = 1024 * 1024;
constexpr qsizetype MaxCapturedProbeStderr = 4096;
constexpr qsizetype ProbeReadChunkSize = 64 * 1024;

struct WireGuardConfigDetails
{
    bool hasInterface = false;
    int peerCount = 0;
    int allowedIpsCount = 0;
    int allowedIpsLine = -1;
    QSet<QString> peerPublicKeys;
};

struct BatchRoot
{
    QString path;
    QString category;
};

bool isSecureWritableDirectory(const QString &path)
{
    const QFileInfo info(path);
    if (!info.exists() || !info.isDir() || info.isSymLink()) return false;
    const QFileDevice::Permissions permissions = info.permissions();
    if (!(permissions & QFileDevice::WriteOwner)
        || (permissions & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) {
        return false;
    }
#if defined(Q_OS_UNIX)
    const uint effectiveUid = static_cast<uint>(::geteuid());
    if (info.ownerId() != 0 && info.ownerId() != effectiveUid) return false;
#endif
    return info.isWritable();
}

bool safeDirectoryAncestors(const QString &path)
{
    QDir current(QFileInfo(path).absoluteFilePath());
    while (true) {
        const QFileInfo info(current.absolutePath());
        if (!info.exists() || !info.isDir() || info.isSymLink()) return false;
#if defined(Q_OS_UNIX)
        struct stat st {};
        if (::stat(info.absoluteFilePath().toLocal8Bit().constData(), &st) != 0) return false;
        const mode_t writableByOther = S_IWGRP | S_IWOTH;
        if ((st.st_mode & writableByOther) != 0
            && !((st.st_mode & S_IWOTH) != 0 && (st.st_mode & S_ISVTX) != 0)) {
            return false;
        }
#endif
        const QString parent = info.absolutePath();
        if (parent == info.filePath() || parent == current.absolutePath()) break;
        current.setPath(parent);
        if (current.absolutePath() == QDir::rootPath()) {
            const QFileInfo root(current.absolutePath());
#if defined(Q_OS_UNIX)
            struct stat rootStat {};
            if (::stat(root.absoluteFilePath().toLocal8Bit().constData(), &rootStat) != 0
                || (rootStat.st_mode & (S_IWGRP | S_IWOTH)) != 0) return false;
#endif
            break;
        }
    }
    return true;
}

bool isUsableTemporaryDirectory(const QString &path)
{
    const QFileInfo info(path);
    if (!info.exists() || !info.isDir() || info.isSymLink() || !info.isWritable()
        || !safeDirectoryAncestors(path)) return false;
#if defined(Q_OS_UNIX)
    struct stat st {};
    if (::stat(info.absoluteFilePath().toLocal8Bit().constData(), &st) != 0) return false;
    const uint effectiveUid = static_cast<uint>(::geteuid());
    if (st.st_uid != 0 && st.st_uid != effectiveUid) return false;
    // A world-writable temporary root is acceptable only with sticky-bit
    // semantics.  The conventional private temporary root is 1777: its
    // group-write bit is inseparable from world-write, and the sticky bit
    // provides the ownership isolation.  Reject group-writable roots that do
    // not have those sticky world-temporary semantics.
    if ((st.st_mode & S_IWGRP) != 0
        && !((st.st_mode & S_IWOTH) != 0 && (st.st_mode & S_ISVTX) != 0)) {
        return false;
    }
    if ((st.st_mode & S_IWOTH) != 0 && (st.st_mode & S_ISVTX) == 0) return false;
#endif
    return true;
}

BatchRoot selectBatchRoot(const QString &configuredRoot)
{
    const QString configured = configuredRoot.trimmed();
    if (!configured.isEmpty()) {
        if (QDir::isAbsolutePath(configured) && isSecureWritableDirectory(configured)
            && safeDirectoryAncestors(configured)) {
            return { configured, QStringLiteral("configured-runtime") };
        }
        // An explicit service root is a security contract.  Never silently
        // bypass it with an ambient temporary directory.
        return {};
    }
#if defined(Q_OS_LINUX)
    const QString systemRuntime = QStringLiteral("/run/amnezia");
    if (isSecureWritableDirectory(systemRuntime)) {
        return { systemRuntime, QStringLiteral("system-runtime") };
    }
#endif
    const QString temporaryRoot = QDir::tempPath();
    // The fallback is intentionally limited to Qt's ordinary temporary
    // directory.  QTemporaryFile provides the owner-only, unpredictable file
    // name protection needed here; this path is never used when the service
    // supplies an explicit runtime root.
    if (isUsableTemporaryDirectory(temporaryRoot)) {
        return { temporaryRoot, QStringLiteral("temporary") };
    }
    return {};
}

WireGuardConfigDetails parseWireGuardConfig(const QString &content)
{
    WireGuardConfigDetails details;
    const QRegularExpression sectionHeader(
            QStringLiteral(R"(^\s*\[([^\]]+)\]\s*$)"));
    const QRegularExpression allowedIps(
            QStringLiteral(R"(^\s*AllowedIPs\s*=\s*[^\r\n]*$)"),
            QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression publicKey(
            QStringLiteral(R"(^\s*PublicKey\s*=\s*([^\s#]+).*$)"),
            QRegularExpression::CaseInsensitiveOption);
    bool inPeer = false;
    const QStringList lines = content.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    for (int index = 0; index < lines.size(); ++index) {
        const QString line = lines.at(index).trimmed();
        const QRegularExpressionMatch section = sectionHeader.match(line);
        if (section.hasMatch()) {
            const QString sectionName = section.captured(1).trimmed();
            inPeer = sectionName.compare(QStringLiteral("Peer"), Qt::CaseInsensitive) == 0;
            if (sectionName.compare(QStringLiteral("Interface"), Qt::CaseInsensitive) == 0) {
                details.hasInterface = true;
            }
            if (inPeer) ++details.peerCount;
            continue;
        }
        if (!inPeer) continue;
        if (allowedIps.match(line).hasMatch()) {
            ++details.allowedIpsCount;
            details.allowedIpsLine = index;
        }
        const QRegularExpressionMatch key = publicKey.match(line);
        if (key.hasMatch()) details.peerPublicKeys.insert(key.captured(1));
    }
    return details;
}

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

RealCommandRunner::RealCommandRunner(QString stagingRoot)
    : m_processes(std::make_unique<RunningProcess>()),
      m_stagingRoot(std::move(stagingRoot))
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

CommandResult RealCommandRunner::runBatch(const QString &program,
                                          const QList<QStringList> &commands)
{
    if (commands.isEmpty()) return { true, 0, {} };
    // `ip -batch` consumes one argv-style command per line.  The reconciler
    // supplies only validated canonical route tokens and interface names;
    // reject whitespace/control characters here as a second boundary so a
    // future caller cannot turn the batch file into an ambiguous command.
    const BatchRoot batchRoot = selectBatchRoot(m_stagingRoot);
    if (batchRoot.path.isEmpty()) {
        return { false, -1,
                 m_stagingRoot.trimmed().isEmpty()
                     ? QStringLiteral("unable to select secure ip batch root (temporary root unavailable)")
                     : QStringLiteral("unable to select secure ip batch root (configured runtime rejected)") };
    }
    QTemporaryFile batchFile(QDir(batchRoot.path).filePath(
            QStringLiteral("amnezia-ip-batch-XXXXXX")));
    batchFile.setAutoRemove(true);
    if (!batchFile.open()) {
        return { false, -1, QStringLiteral(
                         "unable to create a private ip batch file (batch root category: %1)")
                         .arg(batchRoot.category) };
    }
    if (!batchFile.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        return { false, -1, QStringLiteral(
                         "unable to secure private ip batch file (batch root category: %1)")
                         .arg(batchRoot.category) };
    }
    for (const QStringList &command : commands) {
        if (command.isEmpty()) {
            return { false, -1, QStringLiteral("empty ip batch command") };
        }
        for (const QString &argument : command) {
            for (const QChar ch : argument) {
                if (ch.isSpace() || ch.unicode() < 0x20 || ch == QLatin1Char(0x7f)) {
                    return { false, -1, QStringLiteral("unsafe ip batch argument") };
                }
            }
        }
        const QByteArray line = command.join(QLatin1Char(' ')).toUtf8() + QByteArrayLiteral("\n");
        if (batchFile.write(line) != line.size()) {
            return { false, -1, QStringLiteral(
                             "unable to write private ip batch file (batch root category: %1)")
                             .arg(batchRoot.category) };
        }
    }
    if (!batchFile.flush()) {
        return { false, -1, QStringLiteral(
                         "unable to flush private ip batch file (batch root category: %1)")
                         .arg(batchRoot.category) };
    }
    batchFile.close();

    QProcess process;
    process.setProgram(program);
    process.setArguments({ QStringLiteral("-batch"), batchFile.fileName() });
    process.setStandardOutputFile(QProcess::nullDevice());
    // Keep stderr connected: ip reports the exact failing batch command and
    // errno there.  It is consumed below with a strict bound, while stdout
    // remains suppressed because it is never part of the control protocol.
    QByteArray stderrBuffer;
    QObject::connect(&process, &QProcess::readyReadStandardError, [&process, &stderrBuffer]() {
        constexpr qsizetype MaxCapturedStderr = 4096;
        const QByteArray chunk = process.readAllStandardError();
        if (stderrBuffer.size() < MaxCapturedStderr) {
            stderrBuffer.append(chunk.left(MaxCapturedStderr - stderrBuffer.size()));
        }
    });
    process.start();
    if (!process.waitForStarted(3000)) {
        return { false, -1, QStringLiteral(
                         "unable to start ip batch helper (batch root category: %1)")
                         .arg(batchRoot.category) };
    }
    // Keep each kernel batch bounded independently of the ordinary backend
    // watchdog.  iproute2 may spend several seconds in RTNL while the host is
    // busy; five seconds was short enough to abort a healthy allow-list
    // expansion.  The reconciler also applies an aggregate deadline across
    // all batches, so this larger per-batch allowance cannot hang forever.
    if (!waitForProcessFinished(process, 15'000)) {
        process.kill();
        waitForProcessFinished(process, 2000);
        return { false, -1, QStringLiteral(
                         "ip batch helper timed out (batch root category: %1)")
                         .arg(batchRoot.category) };
    }
    // Keep diagnostics bounded and local to the result.  Do not expose the
    // batch file or stdout (which could contain caller-controlled data) in
    // the daemon protocol; ip's stderr is useful for a concise operator
    // failure reason.
    // Drain the final signal-delivery window as well; the buffer itself never
    // grows beyond the hard cap above.
    const QByteArray tail = process.readAllStandardError();
    if (stderrBuffer.size() < 4096) {
        stderrBuffer.append(tail.left(4096 - stderrBuffer.size()));
    }
    const QString diagnostic = QString::fromLocal8Bit(stderrBuffer).trimmed().left(2048);
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return { false, process.exitCode(), diagnostic.isEmpty()
                     ? QStringLiteral("ip batch helper failed (batch root category: %1)")
                           .arg(batchRoot.category)
                     : QStringLiteral("ip batch helper failed: %1 (batch root category: %2)")
                           .arg(diagnostic, batchRoot.category) };
    }
    return { true, process.exitCode(), {} };
}

CommandResult RealCommandRunner::runCaptured(const QString &program,
                                             const QStringList &arguments)
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);

    QByteArray output;
    QByteArray error;
    bool outputExceeded = false;

    // Drain both channels while the process is running.  Waiting first and
    // then calling readAll() can leave a large (but valid) kernel snapshot in
    // QProcess's unbounded internal buffer, while an output-producing helper
    // can otherwise block on a full pipe.  Once the explicit probe limit is
    // crossed, discard the partial snapshot and stop the helper; callers must
    // never receive a truncated kernel state as if it were complete.
    const auto drainOutput = [&]() {
        process.setReadChannel(QProcess::StandardOutput);
        while (process.bytesAvailable() > 0) {
            const QByteArray chunk = process.read(ProbeReadChunkSize);
            if (chunk.isEmpty()) {
                break;
            }
            if (outputExceeded) {
                continue;
            }
            const qsizetype remaining = MaxCapturedProbeStdout - output.size();
            if (chunk.size() > remaining) {
                output.clear();
                outputExceeded = true;
                process.kill();
                continue;
            }
            output.append(chunk);
        }
    };
    const auto drainError = [&]() {
        process.setReadChannel(QProcess::StandardError);
        while (process.bytesAvailable() > 0) {
            const QByteArray chunk = process.read(ProbeReadChunkSize);
            if (chunk.isEmpty()) {
                break;
            }
            if (error.size() < MaxCapturedProbeStderr) {
                error.append(chunk.left(MaxCapturedProbeStderr - error.size()));
            }
        }
    };
    QObject::connect(&process, &QProcess::readyReadStandardOutput,
                     &process, drainOutput);
    QObject::connect(&process, &QProcess::readyReadStandardError,
                     &process, drainError);
    process.start();
    if (!process.waitForStarted(3000)) {
        return { false, -1, QStringLiteral("unable to start backend executable"), {} };
    }
    if (!waitForProcessFinished(process, 30'000)) {
        process.kill();
        waitForProcessFinished(process, 2000);
        return { false, -1, QStringLiteral("backend executable timed out"), {} };
    }
    drainOutput();
    drainError();
    if (outputExceeded) {
        return { false, process.exitCode(),
                 QStringLiteral("probe output exceeded safe limit"), {} };
    }
    // Probes are read-only, but their output is still bounded before it can
    // enter a result or diagnostic.  Preserve a small stderr tail so callers
    // can distinguish a vanished link from resolver/backend failure.
    const QString outputText = QString::fromUtf8(output);
    const QString errorText = QString::fromLocal8Bit(error).trimmed();
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return { false, process.exitCode(),
                 errorText.isEmpty() ? QStringLiteral("backend executable failed")
                                     : QStringLiteral("backend executable failed: %1")
                                           .arg(errorText.left(2048)),
                 outputText };
    }
    return { true, process.exitCode(), {}, outputText };
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
    : m_runner(runner ? std::move(runner) : std::make_shared<RealCommandRunner>(stagingRoot)),
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
    if (protocol == QStringLiteral("wireguard") || protocol == QStringLiteral("amneziawg")) {
        QFile config(profile.configPath);
        if (!config.open(QIODevice::ReadOnly) || config.size() > 1024 * 1024
            || !parseWireGuardConfig(QString::fromUtf8(config.readAll())).hasInterface) {
            return failure(QStringLiteral("config_invalid"),
                           QStringLiteral("WireGuard configuration requires an [Interface] section"));
        }
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
    if (longRunning && (protocol == QStringLiteral("xray")
                        || protocol == QStringLiteral("ssxray"))) {
        // A successful fork/start is not proof that XRay accepted its config.
        // Keep this bounded: an immediate exit must not be reported as a live
        // proxy session, while a normal long-running process gets no traffic
        // or network readiness requirement here.
        QElapsedTimer startupTimer;
        startupTimer.start();
        bool alive = false;
        while (startupTimer.elapsed() < LongRunningStartupGraceMs) {
            alive = m_runner->isSessionAlive(profile.id);
            if (!alive) break;
            QThread::msleep(50);
        }
        if (!alive) {
            m_runner->stop(profile.id);
            m_session.reset();
            return failure(QStringLiteral("backend_not_ready"),
                           QStringLiteral("XRay backend exited during startup"));
        }
    }
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
    const WireGuardConfigDetails details = parseWireGuardConfig(content);
    if (!details.hasInterface || details.peerCount != 1 || details.allowedIpsCount != 1
        || details.allowedIpsLine < 0) {
        if (error) *error = QStringLiteral(
                "all-except requires exactly one peer with one AllowedIPs entry");
        return false;
    }

    QStringList lines = content.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    lines[details.allowedIpsLine] = QStringLiteral("AllowedIPs = 0.0.0.0/0, ::/0");
    QString rewritten = lines.join(QLatin1Char('\n'));

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
    const BatchRoot trustedRoot = selectBatchRoot(m_stagingRoot);
    if (trustedRoot.path.isEmpty()) {
        if (error) *error = QStringLiteral("full-tunnel staging root is not trusted");
        return false;
    }
    QTemporaryDir temporary(QDir(trustedRoot.path).filePath(
            QStringLiteral("amnezia-headless-full-tunnel-XXXXXX")));
    if (!temporary.isValid()) {
        if (error) *error = QStringLiteral("full-tunnel staging root is not writable");
        return false;
    }
    temporary.setAutoRemove(false);
    const QFileInfo temporaryInfo(temporary.path());
    if (!temporaryInfo.exists() || !temporaryInfo.isDir() || temporaryInfo.isSymLink()
        || !safeDirectoryAncestors(temporary.path())
        || !QFile::setPermissions(temporary.path(), QFileDevice::ReadOwner
                                   | QFileDevice::WriteOwner | QFileDevice::ExeOwner)) {
        if (error) *error = QStringLiteral("temporary full-tunnel directory is not secure");
        QDir(temporary.path()).removeRecursively();
        return false;
    }
    const QString stagedPath = QDir(temporary.path()).filePath(interfaceName + QStringLiteral(".conf"));
    if (QFileInfo::exists(stagedPath) && QFileInfo(stagedPath).isSymLink()) {
        if (error) *error = QStringLiteral("temporary full-tunnel configuration path is a symlink");
        QDir(temporary.path()).removeRecursively();
        return false;
    }
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
    if (!QFile::setPermissions(stagedPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        if (error) *error = QStringLiteral("temporary full-tunnel configuration permissions failed");
        QDir(temporary.path()).removeRecursively();
        return false;
    }
#endif
    const QFileInfo stagedInfo(stagedPath);
    if (!stagedInfo.exists() || !stagedInfo.isFile() || stagedInfo.isSymLink()
        || (stagedInfo.permissions() & (QFileDevice::ReadGroup | QFileDevice::WriteGroup
                                         | QFileDevice::ExeGroup | QFileDevice::ReadOther
                                         | QFileDevice::WriteOther | QFileDevice::ExeOther))) {
        if (error) *error = QStringLiteral("temporary full-tunnel configuration is not secure");
        QDir(temporary.path()).removeRecursively();
        return false;
    }
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
        QFile config(m_session->configPath);
        if (!config.open(QIODevice::ReadOnly) || config.size() > 1024 * 1024) {
            return false;
        }
        const WireGuardConfigDetails details = parseWireGuardConfig(
                QString::fromUtf8(config.readAll()));
        if (!details.hasInterface || details.peerCount == 0
            || details.peerPublicKeys.size() != details.peerCount) return false;
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        const QStringList lines = handshakes.output.split(
                QRegularExpression(QStringLiteral("[\\r\\n]")), Qt::SkipEmptyParts);
        bool configuredPeerHandshake = false;
        for (const QString &line : lines) {
            const QStringList fields = line.trimmed().split(
                    QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
            if (fields.size() < 2 || !details.peerPublicKeys.contains(fields.constFirst())) {
                continue;
            }
            bool timestampOk = false;
            const qint64 timestamp = fields.constLast().toLongLong(&timestampOk);
            if (timestampOk && timestamp > 0 && timestamp <= now + 5
                && now - timestamp <= WireGuardHandshakeMaxAgeSeconds) {
                configuredPeerHandshake = true;
                break;
            }
        }
        if (configuredPeerHandshake) m_session->handshakeObserved = true;
        // A peer only needs to prove that the configured tunnel has exchanged
        // traffic once.  An otherwise healthy idle tunnel must not be torn
        // down merely because its last handshake has aged out.
        return m_session->handshakeObserved;
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
    // A normal ENODEV-style failed probe proves absence.  Only an unavailable
    // probe tool above is treated as unknown/potential orphan state.
    if (!result.ok) return false;
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
