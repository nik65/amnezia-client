#include "logger.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QStandardPaths>
#include <QProcess>
#include <cassert>
int main(int argc, char **argv) {
    QTemporaryDir temp; assert(temp.isValid());
    qputenv("XDG_DATA_HOME", temp.path().toUtf8());
    QCoreApplication app(argc, argv);
    app.setApplicationName("LoggingCoverageTest"); app.setOrganizationName("AmneziaTest");
    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("directory-failure")) {
        QFile blocker(temp.path() + "/blocked"); assert(blocker.open(QIODevice::WriteOnly)); blocker.close();
        qputenv("XDG_DATA_HOME", blocker.fileName().toUtf8());
        assert(!Logger::init(false)); return 0;
    }
    assert(Logger::init(false));
    if (argc > 1) { qFatal("Unknown property SYNTHETIC_FATAL_SECRET"); }
    qDebug("coverage-debug"); qInfo("coverage-info");
    qWarning("Unknown property token=SYNTHETIC_PRIVATE_TOKEN address=192.0.2.123");
    qCritical("Could not create pixmap /private/SYNTHETIC_PRIVATE_PATH");
    qWarning("coverage-warning"); qCritical("coverage-error");
    qDebug("Unknown property benign-debug-noise");
    Logger::configurationDiagnostic(Logger::ConfigurationEvent::Applied, 1, 2, 42, true);
    Logger::configurationDiagnostic(Logger::ConfigurationEvent::Rejected, -2, 9, 1000001, false);
    Logger::configurationDiagnostic(static_cast<Logger::ConfigurationEvent>(999), 300, -1, -1, false);
    QProcess fatalChild;
    fatalChild.start(QCoreApplication::applicationFilePath(), {QStringLiteral("fatal-child")});
    assert(fatalChild.waitForFinished());
    assert(fatalChild.exitStatus() == QProcess::CrashExit || fatalChild.exitCode() != 0);
    const QByteArray fatalOutput = fatalChild.readAllStandardOutput() + fatalChild.readAllStandardError();
    assert(fatalOutput.contains("event=QmlUnknownProperty severity=fatal"));
    assert(!fatalOutput.contains("SYNTHETIC_FATAL_SECRET"));
    QProcess failingChild;
    failingChild.start(QCoreApplication::applicationFilePath(), {QStringLiteral("directory-failure")});
    assert(failingChild.waitForFinished() && failingChild.exitCode() == 0);
    const QByteArray failureOutput = failingChild.readAllStandardError();
    assert(failureOutput.contains("event=LogSourceDirectoryFailed severity=warning writable=false"));
    const QString output = Logger::getLogFile();
    assert(output.contains("event=LogSourceReady severity=info writable=true"));
    assert(output.contains("coverage-debug") && output.contains("coverage-info"));
    assert(output.contains("[WARNING]") && output.contains("[ERROR]"));
    assert(output.contains("event=QmlUnknownProperty"));
    assert(output.contains("event=QmlPixmapLoad"));
    assert(!output.contains("SYNTHETIC_PRIVATE") && !output.contains("192.0.2.123"));
    assert(!output.contains("benign-debug-noise"));
    assert(output.contains("coverage-warning") && output.contains("coverage-error"));
    assert(output.contains("event=ConfigurationApplied severity=info protocolCode=1 splitMode=2 ruleCount=42 snapshotGuardEnabled=true"));
    assert(output.contains("event=ConfigurationRejected severity=info protocolCode=-1 splitMode=-1 ruleCount=-1 snapshotGuardEnabled=false"));
    assert(output.contains("event=ConfigurationUnknown"));
    QFile file(Logger::userLogsFilePath()); assert(file.exists());
    Logger::deInit();
}
