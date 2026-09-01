#include <QtTest>

#include <QTemporaryDir>

#include "headlessUpdateManager.h"

using namespace amnezia::headless;

class HeadlessUpdateTest : public QObject
{
    Q_OBJECT

private slots:
    void disabledUpdatesDoNotTouchNetworkOrStateUnexpectedly()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        HeadlessUpdateManager manager({},
                                      temporaryDirectory.filePath(QStringLiteral("updates.json")),
                                      temporaryDirectory.path());
        Profile profile;
        profile.autoUpdate = false;

        const HeadlessUpdateResult result = manager.checkAndApply(
                profile, QStringLiteral("5.0.1.6"));
        QVERIFY(result.ok);
        QCOMPARE(result.code, QStringLiteral("disabled"));
        QCOMPARE(manager.status().value(QStringLiteral("state")).toString(),
                 QStringLiteral("disabled"));
        QVERIFY(!manager.status().value(QStringLiteral("rollbackAvailable")).toBool());
    }
};

QTEST_MAIN(HeadlessUpdateTest)
#include "tst_headless_updates.moc"
