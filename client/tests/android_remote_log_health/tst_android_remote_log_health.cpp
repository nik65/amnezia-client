#include <QtTest>
#include <limits>
#include "ui/controllers/remoteLogHealthUiController.h"
const QMetaObject Vpn::staticMetaObject = QObject::staticMetaObject;
RemoteLogUploader::RemoteLogUploader(SecureServersRepository *, SecureAppSettingsRepository *, VpnConnection *, QObject *parent) : QObject(parent) {}
// The desktop uploader is deliberately absent: exercise the actual service-health consumer.
RemoteLogUploader::State RemoteLogUploader::state() const { return State::WaitingForVpn; }
QDateTime RemoteLogUploader::lastSuccess() const { return {}; }
qint64 RemoteLogUploader::pendingBytes() const { return 0; }
RemoteLogUploader::ErrorCategory RemoteLogUploader::lastErrorCategory() const { return ErrorCategory::None; }
QDateTime RemoteLogUploader::nextRetryAt() const { return {}; }
void RemoteLogUploader::retryNow() {}
void RemoteLogUploader::start() {}
class HealthTests : public QObject {
    Q_OBJECT
    QJsonObject snapshot() {
        return {{"schema",1},{"state",5},{"lastSuccessMs",0},{"pendingBytes",512},
                {"errorCategory",2},{"httpStatus",404},{"nextRetryMs",0}};
    }
private slots:
    void enrollmentThenRealDelivery() {
        RemoteLogHealthUiController controller(nullptr);
        QSignalSpy changed(&controller, &RemoteLogHealthUiController::healthChanged);
        controller.observeServiceHealth(snapshot());
        QCOMPARE(controller.state(), RemoteLogHealthUiController::State::Error);
        QCOMPARE(controller.lastErrorCategory(), RemoteLogHealthUiController::ErrorCategory::Bootstrap);
        QCOMPARE(controller.lastHttpStatus(),404);
        QCOMPARE(controller.pendingBytes(),512);
        QVERIFY(!controller.lastSuccess().isValid());
        QVERIFY(!controller.retryAvailable()); // Read-only bridge never offers a service-changing Retry.
        auto success=snapshot(); const auto now=QDateTime::currentMSecsSinceEpoch();
        success["state"]=3;success["errorCategory"]=0;success["httpStatus"]=204;
        success["pendingBytes"]=0;success["lastSuccessMs"]=double(now);
        controller.observeServiceHealth(success);
        QVERIFY(controller.healthy());QCOMPARE(controller.lastSuccess().toMSecsSinceEpoch(),now);
        QCOMPARE(changed.count(),2);
    }
    void desktopUploaderRetainsAuthority() {
        RemoteLogUploader uploader(nullptr,nullptr,nullptr);
        RemoteLogHealthUiController controller(&uploader);
        controller.observeServiceHealth(snapshot());
        QCOMPARE(controller.state(),RemoteLogHealthUiController::State::WaitingForVpn);
        QCOMPARE(controller.lastHttpStatus(),0);
        QCOMPARE(controller.pendingBytes(),0);
    }
    void rejectsPrivateFieldsAndMalformedMetadata() {
        RemoteLogHealthUiController controller(nullptr);controller.observeServiceHealth(snapshot());
        QSignalSpy changed(&controller, &RemoteLogHealthUiController::healthChanged);
        for (const auto &name : {"token","clientId","endpoint","domain","body","config","installationId"}) {
            auto bad=snapshot();bad[name]="private-material";controller.observeServiceHealth(bad);
            QCOMPARE(controller.lastHttpStatus(),404);
        }
        for (const auto &name : {"state","errorCategory","httpStatus","pendingBytes","lastSuccessMs","nextRetryMs"}) {
            auto bad=snapshot();bad[name]="secret";controller.observeServiceHealth(bad);
            QCOMPARE(controller.lastHttpStatus(),404);
        }
        for (const auto &value : {-1.0,6.0,6.5,100.0,std::numeric_limits<double>::infinity()}) {
            auto bad=snapshot();bad["state"]=value;controller.observeServiceHealth(bad);
            QCOMPARE(controller.state(),RemoteLogHealthUiController::State::Error);
        }
        auto missing=snapshot();missing.remove("schema");controller.observeServiceHealth(missing);
        auto future=snapshot();future["lastSuccessMs"]=double(QDateTime::currentMSecsSinceEpoch()+600000);
        controller.observeServiceHealth(future);QVERIFY(!controller.lastSuccess().isValid());
        auto fakeHealthy=snapshot();fakeHealthy["state"]=3;fakeHealthy["errorCategory"]=0;
        controller.observeServiceHealth(fakeHealthy);
        QCOMPARE(changed.count(),0);
    }
};
QTEST_GUILESS_MAIN(HealthTests)
#include "tst_android_remote_log_health.moc"
