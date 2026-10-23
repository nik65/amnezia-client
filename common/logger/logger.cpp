#include "logger.h"

#include <QDateTime>
#include <QDebug>
#include <QDesktopServices>
#include <QDir>
#include <QJsonDocument>
#include <QMetaEnum>
#include <QStandardPaths>
#include <QUrl>

#include "version.h"

#ifdef AMNEZIA_DESKTOP
    #include <core/utils/ipcClient.h>
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include <AmneziaVPN-Swift.h>
#endif

QRecursiveMutex Logger::m_fileMutex;
QFile Logger::m_file;
QTextStream Logger::m_textStream;
QString Logger::m_logFileName = QString("%1.log").arg(APPLICATION_NAME);
QString Logger::m_serviceLogFileName = QString("%1.log").arg(SERVICE_NAME);

void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    if (msg.simplified().isEmpty()) {
        return;
    }

    // Do not silently discard actionable QML/UI failures. These formerly
    // suppressed families may contain private user paths or values, so persist
    // only a stable category and severity rather than the original text.
    const bool actionable = type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg;
    QString safeMessage = msg;
    if (actionable && msg.startsWith("Unknown property")) {
        safeMessage = QStringLiteral("AmneziaDiagnostics schema=1 source_kind=application event=QmlUnknownProperty severity=%1").arg(type == QtWarningMsg ? "warning" : type == QtCriticalMsg ? "error" : "fatal");
    } else if (actionable && msg.startsWith("Could not create pixmap")) {
        safeMessage = QStringLiteral("AmneziaDiagnostics schema=1 source_kind=application event=QmlPixmapLoad severity=%1").arg(type == QtWarningMsg ? "warning" : type == QtCriticalMsg ? "error" : "fatal");
    } else if (!actionable && (msg.contains("OpenType support missing for")
               || msg.startsWith("Unknown property") || msg.startsWith("Could not create pixmap")
               || msg.startsWith("Populating font") || msg.startsWith("stale focus object"))) {
        return;
    }

    switch (type) {
    case QtDebugMsg: Logger::Instance().debug() << safeMessage; break;
    case QtInfoMsg: Logger::Instance().info() << safeMessage; break;
    case QtWarningMsg: Logger::Instance().warning() << safeMessage; break;
    case QtCriticalMsg: Logger::Instance().error() << safeMessage; break;
    case QtFatalMsg: {
        Logger::Instance().error() << safeMessage;
    } // Brackets are needed to ensure the destructor of LogStreamer is called before abort()
        abort();
    }
}

Logger &Logger::Instance()
{
    static Logger s;
    return s;
}

bool Logger::init(bool isServiceLogger)
{
    const QMutexLocker lock(&m_fileMutex);
    if (m_file.isOpen()) {
        return true;
    }

    QString path = isServiceLogger ? systemLogDir() : userLogsDir();
    QString logFileName = isServiceLogger ? m_serviceLogFileName : m_logFileName;
    QDir appDir(path);
    if (!appDir.mkpath(path)) {
        qWarning() << "AmneziaDiagnostics schema=1 source_kind=application event=LogSourceDirectoryFailed severity=warning writable=false";
        return false;
    }

    m_file.setFileName(appDir.filePath(logFileName));
    if (!m_file.open(QIODevice::Append)) {
        qWarning() << "AmneziaDiagnostics schema=1 source_kind=application event=LogSourceOpenFailed severity=warning writable=false";
        return false;
    }

    m_file.setTextModeEnabled(true);
    m_textStream.setDevice(&m_file);

    qInstallMessageHandler(messageHandler);
    qInfo().noquote() << QStringLiteral("AmneziaDiagnostics schema=1 source_kind=%1 event=LogSourceReady severity=info writable=true")
            .arg(isServiceLogger ? QStringLiteral("service") : QStringLiteral("application"));

    return true;
}

void Logger::deInit()
{
    const QMutexLocker lock(&m_fileMutex);
    m_textStream.setDevice(nullptr);
    m_file.close();
}

bool Logger::isInitialized()
{
    const QMutexLocker lock(&m_fileMutex);
    return m_file.isOpen();
}

void Logger::configurationDiagnostic(ConfigurationEvent event, int protocol,
                                     int splitMode, qint64 ruleCount, bool snapshotGuardEnabled)
{
    const char *eventName = "ConfigurationUnknown";
    switch (event) {
    case ConfigurationEvent::Applied: eventName = "ConfigurationApplied"; break;
    case ConfigurationEvent::Deferred: eventName = "ConfigurationDeferred"; break;
    case ConfigurationEvent::Rejected: eventName = "ConfigurationRejected"; break;
    }
    // -1 is explicitly unknown, never wrap/truncate an out-of-range value.
    const int safeProtocol = protocol >= 0 && protocol <= 255 ? protocol : -1;
    const int safeMode = splitMode >= 0 && splitMode <= 2 ? splitMode : -1;
    const qint64 safeCount = ruleCount >= 0 && ruleCount <= 1000000 ? ruleCount : -1;
    qInfo().noquote() << QStringLiteral("AmneziaDiagnostics schema=1 source_kind=configuration event=%1 severity=info protocolCode=%2 splitMode=%3 ruleCount=%4 snapshotGuardEnabled=%5")
            .arg(eventName).arg(safeProtocol).arg(safeMode).arg(safeCount)
            .arg(snapshotGuardEnabled ? QStringLiteral("true") : QStringLiteral("false"));
}

bool Logger::setServiceLogsEnabled(bool enabled)
{
#ifdef AMNEZIA_DESKTOP
    return IpcClient::withInterface([enabled](QSharedPointer<IpcInterfaceReplica> iface) {
        iface->setLogsEnabled(enabled);
        qDebug() << "Logger::setServiceLogsEnabled(): Logs transitioned to be " << (enabled ? "enabled" : "disabled");
        return true;
    },[](){
        qWarning() << "Logger::setServiceLogsEnabled(): Service is not running";
        return false;
    });
#endif

    return true;
}

QString Logger::userLogsDir()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/log";
}

QString Logger::systemLogDir()
{
#ifdef Q_OS_WIN
    QStringList locationList = QStandardPaths::standardLocations(QStandardPaths::GenericDataLocation);
    QString primaryLocation = "ProgramData";
    foreach (const QString &location, locationList) {
        if (location.contains(primaryLocation)) {
            return QString("%1/%2/log").arg(location).arg(APPLICATION_NAME);
        }
    }
    return QString();
#else
    return QString("/var/log/%1").arg(APPLICATION_NAME);
#endif
}

QString Logger::userLogsFilePath()
{
    return userLogsDir() + QDir::separator() + m_logFileName;
}

QString Logger::serviceLogsFilePath()
{
    return systemLogDir() + QDir::separator() + m_serviceLogFileName;
}

QString Logger::getLogFile()
{
    QString qtLog;
    {
        const QMutexLocker lock(&m_fileMutex);
        if (m_file.isOpen()) {
            m_file.flush();
        }
        QFile file(userLogsFilePath());
        file.open(QIODevice::ReadOnly);
        qtLog = file.readAll();
    }

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    return QString().fromStdString(AmneziaVPN::swiftUpdateLogData(qtLog.toStdString()));
#else
    return qtLog;
#endif
}

QString Logger::getServiceLogFile()
{
    QString qtLog;
    {
        const QMutexLocker lock(&m_fileMutex);
        if (m_file.isOpen()) {
            m_file.flush();
        }
        QFile file(serviceLogsFilePath());
        file.open(QIODevice::ReadOnly);
        qtLog = file.readAll();
    }

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    return QString().fromStdString(AmneziaVPN::swiftUpdateLogData(qtLog.toStdString()));
#else
    return qtLog;
#endif
}

bool Logger::openLogsFolder(bool isServiceLogger)
{
    QString path = isServiceLogger ? systemLogDir() : userLogsDir();
    if (!QDesktopServices::openUrl(QUrl::fromLocalFile(path))) {
        qWarning() << "Can't open url:" << path;
        return false;
    }
    return true;
}

void Logger::clearLogs(bool isServiceLogger)
{
    const QMutexLocker lock(&m_fileMutex);
    bool isLogActive = m_file.isOpen();
    m_file.close();

    QFile file(isServiceLogger ? serviceLogsFilePath() : userLogsFilePath());

    file.open(QIODevice::WriteOnly | QIODevice::Truncate);
    file.resize(0);
    file.close();

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    AmneziaVPN::swiftDeleteLog();
#endif

    if (isLogActive) {
        init(isServiceLogger);
    }
}

void Logger::clearServiceLogs()
{
#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
        iface->clearLogs();
        qDebug() << "Logger::clearServiceLogs(): Logs cleared";
    }, []() {
        qWarning() << "Logger::clearServiceLogs(): Service is not running";
    });
#endif
}

void Logger::cleanUp()
{
    const QMutexLocker lock(&m_fileMutex);
    clearLogs(false);
    QDir dir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation));
    dir.removeRecursively();

    clearLogs(true);
}

Logger::LogStreamer::LogStreamer(Logger *logger, LogLevel logLevel)
    : m_logger(logger), m_logLevel(logLevel), m_data(new Data())
{
}

Logger::LogStreamer::~LogStreamer()
{
    QString logLevelString;
    switch (m_logLevel) {
    case LogLevel::Trace: logLevelString = "[TRACE]"; break;
    case LogLevel::Debug: logLevelString = "[DEBUG]"; break;
    case LogLevel::Info: logLevelString = "[INFO]"; break;
    case LogLevel::Warning: logLevelString = "[WARNING]"; break;
    case LogLevel::Error: logLevelString = "[ERROR]"; break;
    }

    const QString message = QString("%1 %2 Amnezia %3 : %4")
                                    .arg(QDateTime::currentDateTimeUtc().toString("[yyyy-MM-dd hh:mm:ss.zzzZ]"),
                                         logLevelString, m_logger->className(), m_data->m_buffer.trimmed());

    // Qt may invoke the message handler concurrently from any worker thread.
    // Serialize complete file records against lifecycle operations. Recursive
    // init diagnostics can return through the same handler on this thread.
    {
        const QMutexLocker lock(&m_fileMutex);
        if (m_file.isOpen()) {
            QTextStream logToFile(&m_file);
            logToFile << message << Qt::endl << Qt::flush;
        }
    }
    // A blocked console must not retain the shared log-file lock.

    QTextStream logToOutput((m_logLevel == LogLevel::Error) ? stderr : stdout);
    logToOutput << message << Qt::endl << Qt::flush;

    delete m_data;
}

Logger::LogStreamer Logger::error()
{
    return { this, LogLevel::Error };
}

Logger::LogStreamer Logger::warning()
{
    return { this, LogLevel::Warning };
}

Logger::LogStreamer Logger::info()
{
    return { this, LogLevel::Info };
}

Logger::LogStreamer Logger::debug()
{
    return { this, LogLevel::Debug };
}

QString Logger::sensitive(const QString &input)
{
#ifdef Q_DEBUG
    return input;
#else
    Q_UNUSED(input);
    return { 8, 'X' };
#endif
}

#define CREATE_LOGSTREAMER_OP_REF(x)                                                                                   \
    Logger::LogStreamer &Logger::LogStreamer::operator<<(x t)                                                          \
    {                                                                                                                  \
        m_data->m_ts << t << ' ';                                                                                      \
        return *this;                                                                                                  \
    }

CREATE_LOGSTREAMER_OP_REF(uint64_t);
CREATE_LOGSTREAMER_OP_REF(const char *);
CREATE_LOGSTREAMER_OP_REF(const QString &);
CREATE_LOGSTREAMER_OP_REF(const QByteArray &);
CREATE_LOGSTREAMER_OP_REF(const void *);

#undef CREATE_LOGSTREAMER_OP_REF

Logger::LogStreamer &Logger::LogStreamer::operator<<(const QStringList &t)
{
    m_data->m_ts << '[' << t.join(",") << ']' << ' ';
    return *this;
}

Logger::LogStreamer &Logger::LogStreamer::operator<<(const QJsonObject &t)
{
    m_data->m_ts << QJsonDocument(t).toJson(QJsonDocument::Indented) << ' ';
    return *this;
}

Logger::LogStreamer &Logger::LogStreamer::operator<<(QTextStreamFunction t)
{
    m_data->m_ts << t;
    return *this;
}

void Logger::LogStreamer::addMetaEnum(quint64 value, const QMetaObject *meta, const char *name)
{
    QMetaEnum me = meta->enumerator(meta->indexOfEnumerator(name));

    QString out;
    QTextStream ts(&out);

    if (const char *scope = me.scope()) {
        ts << scope << "::";
    }

    const char *key = me.valueToKey(static_cast<int>(value));
    const bool scoped = me.isScoped();
    if (scoped || !key) {
        ts << me.enumName() << (!key ? "(" : "::");
    }

    if (key) {
        ts << key;
    } else {
        ts << value << ")";
    }

    m_data->m_ts << out;
}
