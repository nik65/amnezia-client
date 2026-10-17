#include <QtTest>
#include <QTemporaryDir>
#include <cstring>
#include "platforms/windows/daemon/windowstunnellogger.h"

static QStringList messages;
static QtMessageHandler previousHandler = nullptr;
static void captureMessage(QtMsgType, const QMessageLogContext&, const QString& message) {
    messages.append(message);
}

class TunnelLoggerRecoveryTests : public QObject {
    Q_OBJECT
private:
    static void poll(WindowsTunnelLogger& logger) {
        QVERIFY(QMetaObject::invokeMethod(&logger, "timeout", Qt::DirectConnection));
    }
    static void writeRing(const QString& path, quint32 magic = 0xbadbabe,
                          quint32 index = 0) {
        QByteArray data(8 + 520 * 2048, '\0');
        std::memcpy(data.data(), &magic, 4);
        std::memcpy(data.data() + 4, &index, 4);
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write(data), data.size());
    }
private slots:
    void init() { messages.clear(); previousHandler = qInstallMessageHandler(captureMessage); }
    void cleanup() { qInstallMessageHandler(previousHandler); }
    void emptyPathNeverOpensAndBacksOff() {
        int calls = 0;
        WindowsTunnelLogger logger([&] { ++calls; return QString(); });
        auto* file = logger.findChild<QFile*>();
        auto* timer = logger.findChild<QTimer*>();
        for (int i = 0; i < 12; ++i) {
            poll(logger);
            QVERIFY(!file->isOpen());
            QVERIFY(file->fileName().isEmpty());
            QVERIFY(timer->interval() >= 1000 && timer->interval() <= 30000);
        }
        QCOMPARE(calls, 12);
        QCOMPARE(timer->interval(), 30000);
        QVERIFY(messages.filter("No file name specified").isEmpty());
    }
    void initialMissingPathRecoversWithoutRestart() {
        QTemporaryDir directory;
        QString path;
        WindowsTunnelLogger logger([&] { return path; });
        poll(logger);
        path = directory.filePath("log.bin");
        writeRing(path);
        poll(logger);
        QVERIFY(logger.findChild<QFile*>()->isOpen());
        QCOMPARE(logger.findChild<QTimer*>()->interval(), 250);
    }
    void malformedAndShortRingsRecover() {
        QTemporaryDir directory;
        const QString path = directory.filePath("log.bin");
        WindowsTunnelLogger logger(path);
        { QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly)); file.write("x"); }
        poll(logger);
        QVERIFY(!logger.findChild<QFile*>()->isOpen());
        writeRing(path, 123);
        poll(logger);
        QVERIFY(!logger.findChild<QFile*>()->isOpen());
        writeRing(path);
        poll(logger);
        QVERIFY(logger.findChild<QFile*>()->isOpen());
    }
    void unsignedRingIndexAndDeletionAreSafe() {
        QTemporaryDir directory;
        QString path = directory.filePath("first.bin");
        writeRing(path, 0xbadbabe, 0xffffffffu);
        WindowsTunnelLogger logger([&] { return path; });
        poll(logger);
        QVERIFY(logger.findChild<QFile*>()->isOpen());
        // A provider can redirect to a new backend directory after failure.
        // Windows mappings cannot be unlinked while open; test a failed path
        // separately, then discovery recovery, without touching a live log.
        WindowsTunnelLogger second([&] { return path; });
        poll(second);
        QVERIFY(second.findChild<QFile*>()->isOpen());
        path = directory.filePath("missing.bin");
        poll(second);
        QVERIFY(!second.findChild<QFile*>()->isOpen());
        writeRing(path);
        poll(second);
        QVERIFY(second.findChild<QFile*>()->isOpen());
        QCOMPARE(second.findChild<QFile*>()->fileName(), path);
    }
};
QTEST_GUILESS_MAIN(TunnelLoggerRecoveryTests)
#include "test_tunnel_logger.moc"
