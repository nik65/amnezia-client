#include "ipcserverprocess.h"
#include "ipc.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QScopeGuard>
#include <QTemporaryFile>

#include <algorithm>
#include <limits>

#ifdef Q_OS_WIN
#include <qt_windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef Q_OS_IOS

namespace {
constexpr qsizetype MaximumBufferedProcessOutput = 4 * 1024 * 1024;
constexpr qsizetype ProcessOutputDrainChunk = 64 * 1024;
constexpr int MaximumRemoteProcessWaitMs = 1000;

void appendBounded(QByteArray &buffer, const QByteArray &data)
{
    if (data.isEmpty()) {
        return;
    }
    if (data.size() >= MaximumBufferedProcessOutput) {
        buffer = data.right(MaximumBufferedProcessOutput);
        return;
    }

    const qsizetype overflow = buffer.size() + data.size() - MaximumBufferedProcessOutput;
    if (overflow > 0) {
        buffer.remove(0, overflow);
    }
    buffer.append(data);
}

QProcessEnvironment trustedProcessEnvironment()
{
    QProcessEnvironment environment;
#ifdef Q_OS_WIN
    wchar_t windowsDirectory[MAX_PATH + 1] = {};
    wchar_t systemDirectory[MAX_PATH + 1] = {};
    wchar_t temporaryDirectory[MAX_PATH + 1] = {};
    const UINT windowsLength = GetWindowsDirectoryW(windowsDirectory, MAX_PATH + 1);
    const UINT systemLength = GetSystemDirectoryW(systemDirectory, MAX_PATH + 1);
    const DWORD temporaryLength = GetTempPathW(MAX_PATH + 1, temporaryDirectory);
    if (windowsLength > 0 && windowsLength <= MAX_PATH) {
        const QString root = QString::fromWCharArray(windowsDirectory,
                                                     static_cast<qsizetype>(windowsLength));
        environment.insert(QStringLiteral("SystemRoot"), root);
        environment.insert(QStringLiteral("WINDIR"), root);
        if (root.size() >= 2 && root.at(1) == QLatin1Char(':')) {
            environment.insert(QStringLiteral("SystemDrive"), root.left(2));
        }
    }
    if (systemLength > 0 && systemLength <= MAX_PATH) {
        QString path = QString::fromWCharArray(systemDirectory,
                                               static_cast<qsizetype>(systemLength));
        environment.insert(QStringLiteral("COMSPEC"),
                           QDir(path).filePath(QStringLiteral("cmd.exe")));
        if (windowsLength > 0 && windowsLength <= MAX_PATH) {
            path += QLatin1Char(';');
            path += QString::fromWCharArray(windowsDirectory,
                                            static_cast<qsizetype>(windowsLength));
        }
        environment.insert(QStringLiteral("PATH"), path);
    }
    if (temporaryLength > 0 && temporaryLength <= MAX_PATH) {
        const QString temporary = QString::fromWCharArray(
            temporaryDirectory, static_cast<qsizetype>(temporaryLength));
        environment.insert(QStringLiteral("TEMP"), temporary);
        environment.insert(QStringLiteral("TMP"), temporary);
    }
    environment.insert(QStringLiteral("PATHEXT"), QStringLiteral(".COM;.EXE;.BAT;.CMD"));
#else
    environment.insert(QStringLiteral("PATH"),
                       QStringLiteral("/usr/sbin:/usr/bin:/sbin:/bin"));
    environment.insert(QStringLiteral("HOME"), QStringLiteral("/"));
    environment.insert(QStringLiteral("TMPDIR"), QStringLiteral("/tmp"));
    environment.insert(QStringLiteral("LANG"), QStringLiteral("C"));
    environment.insert(QStringLiteral("LC_ALL"), QStringLiteral("C"));
#endif
    return environment;
}

bool readValidatedRegularFile(const QString &sourcePath, qint64 maximumSize,
                              QByteArray &content, QString &errorMessage)
{
    content.clear();
    if (sourcePath.isEmpty() || !QDir::isAbsolutePath(sourcePath)
        || sourcePath.contains(QChar::Null) || maximumSize < 0
        || maximumSize >= std::numeric_limits<int>::max()) {
        errorMessage = QStringLiteral("Invalid privileged process input path or size limit");
        return false;
    }

#ifdef Q_OS_WIN
    HANDLE handle = CreateFileW(reinterpret_cast<LPCWSTR>(sourcePath.utf16()), GENERIC_READ,
                                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
                                    | FILE_FLAG_SEQUENTIAL_SCAN,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        errorMessage = QStringLiteral("Unable to open privileged process input safely");
        return false;
    }

    const auto closeHandle = qScopeGuard([handle]() { CloseHandle(handle); });
    FILE_ATTRIBUTE_TAG_INFO attributes = {};
    LARGE_INTEGER fileSize = {};
    if (GetFileType(handle) != FILE_TYPE_DISK
        || !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes,
                                         sizeof(attributes))
        || (attributes.FileAttributes
            & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        || !GetFileSizeEx(handle, &fileSize) || fileSize.QuadPart < 0
        || fileSize.QuadPart > maximumSize) {
        errorMessage = QStringLiteral("Privileged process input is not a bounded regular file");
        return false;
    }

    content.reserve(static_cast<qsizetype>(fileSize.QuadPart));
    while (content.size() <= maximumSize) {
        const qint64 remaining = maximumSize + 1 - content.size();
        const DWORD requested = static_cast<DWORD>(std::min<qint64>(remaining, 64 * 1024));
        char chunk[64 * 1024];
        DWORD bytesRead = 0;
        if (!ReadFile(handle, chunk, requested, &bytesRead, nullptr)) {
            errorMessage = QStringLiteral("Unable to read privileged process input safely");
            return false;
        }
        if (bytesRead == 0) {
            break;
        }
        content.append(chunk, static_cast<qsizetype>(bytesRead));
    }
#else
    const QByteArray nativePath = QFile::encodeName(sourcePath);
    if (nativePath.contains('\0')) {
        errorMessage = QStringLiteral("Invalid privileged process input path");
        return false;
    }

    const int descriptor = ::open(nativePath.constData(),
                                  O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (descriptor < 0) {
        errorMessage = QStringLiteral("Unable to open privileged process input safely");
        return false;
    }

    const auto closeDescriptor = qScopeGuard([descriptor]() { ::close(descriptor); });
    struct stat fileStatus = {};
    if (::fstat(descriptor, &fileStatus) != 0 || !S_ISREG(fileStatus.st_mode)
        || fileStatus.st_size < 0 || fileStatus.st_size > maximumSize) {
        errorMessage = QStringLiteral("Privileged process input is not a bounded regular file");
        return false;
    }

    content.reserve(static_cast<qsizetype>(fileStatus.st_size));
    while (content.size() <= maximumSize) {
        const qint64 remaining = maximumSize + 1 - content.size();
        const size_t requested = static_cast<size_t>(std::min<qint64>(remaining, 64 * 1024));
        char chunk[64 * 1024];
        const ssize_t bytesRead = ::read(descriptor, chunk, requested);
        if (bytesRead < 0) {
            if (errno == EINTR) {
                continue;
            }
            errorMessage = QStringLiteral("Unable to read privileged process input safely");
            return false;
        }
        if (bytesRead == 0) {
            break;
        }
        content.append(chunk, static_cast<qsizetype>(bytesRead));
    }
#endif

    if (content.size() > maximumSize) {
        content.clear();
        errorMessage = QStringLiteral("Privileged process input exceeds the size limit");
        return false;
    }
    return true;
}
}

IpcServerProcess::IpcServerProcess(QObject *parent) :
    IpcProcessInterfaceSource(parent),
    m_process(QSharedPointer<QProcess>(new QProcess()))
{
    m_process->setProcessEnvironment(trustedProcessEnvironment());
    connect(m_process.data(), &QProcess::errorOccurred, this, &IpcServerProcess::errorOccurred);
    connect(m_process.data(), QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this](int exitCode, QProcess::ExitStatus exitStatus) {
                drainProcessChannel(QProcess::StandardOutput);
                drainProcessChannel(QProcess::StandardError);
                emit finished(exitCode, exitStatus);
            });
    connect(m_process.data(), &QProcess::readyReadStandardError, this, [this]() {
        drainProcessChannel(QProcess::StandardError);
    });
    connect(m_process.data(), &QProcess::readyReadStandardOutput, this, [this]() {
        drainProcessChannel(QProcess::StandardOutput);
    });
    connect(m_process.data(), &QProcess::started, this, &IpcServerProcess::started);
    connect(m_process.data(), &QProcess::stateChanged, this, &IpcServerProcess::stateChanged);

    connect(m_process.data(), &QProcess::errorOccurred, [&](QProcess::ProcessError error){
        qDebug() << "IpcServerProcess errorOccurred " << error;
    });

}

IpcServerProcess::~IpcServerProcess()
{
    qDebug() << "IpcServerProcess::~IpcServerProcess";
}

void IpcServerProcess::start()
{
    if (!m_programConfigured || !m_argumentsConfigured || m_configurationRejected
        || m_process->program().isEmpty()) {
        qWarning() << "IpcServerProcess refused an incomplete or rejected launch specification";
        emit errorOccurred(QProcess::FailedToStart);
        return;
    }

    m_process->start();
    qDebug() << "IpcServerProcess started" << static_cast<int>(m_program);
}

void IpcServerProcess::terminate() {
    m_process->terminate();
}

void IpcServerProcess::kill() {
    m_process->kill();
}

void IpcServerProcess::close()
{
    drainProcessChannel(QProcess::StandardOutput);
    drainProcessChannel(QProcess::StandardError);
    m_process->close();
}

void IpcServerProcess::setArguments(const QStringList &arguments)
{
    m_argumentsConfigured = false;
    m_process->setArguments({});
    if (!m_programConfigured || m_configurationRejected) {
        rejectLaunchSpecification(QStringLiteral("Program must be selected before arguments"));
        return;
    }

    const amnezia::ProcessArgumentsValidation validation =
        amnezia::validateProcessArguments(m_program, arguments);
    if (!validation.valid) {
        rejectLaunchSpecification(validation.error);
        return;
    }
    QStringList stagedArguments = validation.arguments;
    m_stagedInput.reset();
    if (m_program == amnezia::PermittedProcess::OpenVPN
        || m_program == amnezia::PermittedProcess::CertUtil) {
        const int pathIndex = m_program == amnezia::PermittedProcess::OpenVPN ? 1 : 4;
        QString stagedPath;
        QString stagingError;
        const qint64 maximumSize = m_program == amnezia::PermittedProcess::OpenVPN
            ? 4 * 1024 * 1024
            : 16 * 1024 * 1024;
        if (!stageInputFile(stagedArguments.at(pathIndex), maximumSize,
                            m_program == amnezia::PermittedProcess::OpenVPN,
                            stagedPath, stagingError)) {
            rejectLaunchSpecification(stagingError);
            return;
        }
        stagedArguments[pathIndex] = stagedPath;
    }

    m_process->setArguments(stagedArguments);
    m_argumentsConfigured = true;
}

void IpcServerProcess::setInputChannelMode(QProcess::InputChannelMode mode)
{
    if (mode != QProcess::ManagedInputChannel && mode != QProcess::ForwardedInputChannel) {
        rejectLaunchSpecification(QStringLiteral("Invalid process input channel mode"));
        return;
    }
    m_process->setInputChannelMode(mode);
}

void IpcServerProcess::setNativeArguments(const QString &arguments)
{
#ifdef Q_OS_WIN
    if (!arguments.isEmpty()) {
        rejectLaunchSpecification(QStringLiteral("Native process arguments are disabled"));
    }
#else
    Q_UNUSED(arguments)
#endif
}

void IpcServerProcess::setProcessChannelMode(QProcess::ProcessChannelMode mode)
{
    if (mode < QProcess::SeparateChannels || mode > QProcess::ForwardedErrorChannel) {
        rejectLaunchSpecification(QStringLiteral("Invalid process channel mode"));
        return;
    }
    m_process->setProcessChannelMode(mode);
}

void IpcServerProcess::setProgram(int programId)
{
    m_program = amnezia::PermittedProcess::Invalid;
    m_programConfigured = false;
    m_argumentsConfigured = false;
    m_configurationRejected = false;
    m_process->setProgram({});
    m_process->setArguments({});
    m_stagedInput.reset();
    m_standardOutput.clear();
    m_standardError.clear();

    if (programId <= static_cast<int>(amnezia::PermittedProcess::Invalid)
        || programId >= static_cast<int>(amnezia::PermittedProcess::PermittedProcessCount)) {
        rejectLaunchSpecification(QStringLiteral("Invalid privileged process identifier"));
        return;
    }

    const auto program = static_cast<amnezia::PermittedProcess>(programId);
    if (program == amnezia::PermittedProcess::Wireguard) {
        rejectLaunchSpecification(QStringLiteral("WireGuard root launcher is not supported"));
        return;
    }
    const QString path = amnezia::permittedProcessPath(program);
    const QFileInfo executable(path);
    if (path.isEmpty() || !executable.isAbsolute() || !executable.isFile()) {
        rejectLaunchSpecification(QStringLiteral("Privileged process executable is unavailable"));
        return;
    }

    m_program = program;
    m_process->setProgram(executable.absoluteFilePath());
    m_process->setWorkingDirectory(executable.absolutePath());
    m_programConfigured = true;
}

void IpcServerProcess::setWorkingDirectory(const QString &dir)
{
    if (!dir.isEmpty()) {
        rejectLaunchSpecification(QStringLiteral("Caller-controlled working directories are disabled"));
    }
}

QByteArray IpcServerProcess::readAll()
{
    return takeBufferedOutput(m_standardOutput);
}

QByteArray IpcServerProcess::readAllStandardError()
{
    return takeBufferedOutput(m_standardError);
}

QByteArray IpcServerProcess::readAllStandardOutput()
{
    return takeBufferedOutput(m_standardOutput);
}

bool IpcServerProcess::waitForStarted() {
    return m_process->waitForStarted(MaximumRemoteProcessWaitMs);
}

bool IpcServerProcess::waitForStarted(int msecs) {
    return m_process->waitForStarted(std::clamp(msecs, 0, MaximumRemoteProcessWaitMs));
}

bool IpcServerProcess::waitForFinished() {
    const bool finished = m_process->waitForFinished(MaximumRemoteProcessWaitMs);
    drainProcessChannel(QProcess::StandardOutput);
    drainProcessChannel(QProcess::StandardError);
    return finished;
}

bool IpcServerProcess::waitForFinished(int msecs) {
    const bool finished = m_process->waitForFinished(
        std::clamp(msecs, 0, MaximumRemoteProcessWaitMs));
    drainProcessChannel(QProcess::StandardOutput);
    drainProcessChannel(QProcess::StandardError);
    return finished;
}

void IpcServerProcess::rejectLaunchSpecification(const QString &reason)
{
    m_configurationRejected = true;
    m_argumentsConfigured = false;
    m_process->setArguments({});
    qWarning() << "IpcServerProcess rejected launch specification:" << reason;
}

bool IpcServerProcess::stageInputFile(const QString &sourcePath, qint64 maximumSize,
                                      bool openVpnConfig, QString &stagedPath,
                                      QString &errorMessage)
{
    QByteArray content;
    if (!readValidatedRegularFile(sourcePath, maximumSize, content, errorMessage)) {
        return false;
    }
    if (openVpnConfig) {
        const QString trustedResolverScript = QDir(QCoreApplication::applicationDirPath())
                                                  .filePath(QStringLiteral("update-resolv-conf.sh"));
        if (!amnezia::validateOpenVpnConfigContent(content, trustedResolverScript,
                                                   &errorMessage)) {
            return false;
        }
        content = amnezia::hardenOpenVpnConfigContent(content);
        if (content.size() > maximumSize) {
            errorMessage = QStringLiteral("Hardened OpenVPN configuration exceeds the size limit");
            return false;
        }
    }

    auto staged = std::make_unique<QTemporaryFile>(
        QDir::temp().filePath(QStringLiteral("AmneziaVPN-service-XXXXXX")));
    staged->setAutoRemove(true);
    if (!staged->open()
        || !staged->setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)
        || staged->write(content) != content.size() || !staged->flush()) {
        errorMessage = QStringLiteral("Unable to stage privileged process input safely");
        return false;
    }
    staged->close();
    stagedPath = staged->fileName();
    m_stagedInput = std::move(staged);
    return true;
}

void IpcServerProcess::drainProcessChannel(QProcess::ProcessChannel channel)
{
    QByteArray &buffer = channel == QProcess::StandardError ? m_standardError : m_standardOutput;
    const QProcess::ProcessChannel previous = m_process->readChannel();
    m_process->setReadChannel(channel);
    bool receivedData = false;
    for (;;) {
        const QByteArray chunk = m_process->read(ProcessOutputDrainChunk);
        if (chunk.isEmpty()) {
            break;
        }
        receivedData = true;
        appendBounded(buffer, chunk);
    }
    m_process->setReadChannel(previous);

    if (!receivedData) {
        return;
    }
    if (channel == QProcess::StandardError) {
        emit readyReadStandardError();
    } else {
        emit readyReadStandardOutput();
    }
    if (channel == previous) {
        emit readyRead();
    }
}

QByteArray IpcServerProcess::takeBufferedOutput(QByteArray &buffer)
{
    const qsizetype size = std::min<qsizetype>(buffer.size(),
                                               amnezia::MaximumProcessOutputChunk);
    const QByteArray result = buffer.left(size);
    buffer.remove(0, size);
    return result;
}

#endif
