#ifndef UPDATEUICONTROLLER_H
#define UPDATEUICONTROLLER_H

#include <QObject>
#include <QVariantMap>

#include "core/controllers/updateController.h"

class UpdateUiController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QString changelogText READ getChangelogText NOTIFY updateFound)
    Q_PROPERTY(QString headerText READ getHeaderText NOTIFY updateFound)
    Q_PROPERTY(bool checking READ isChecking NOTIFY checkingChanged)
    Q_PROPERTY(QString releaseChannel READ releaseChannel NOTIFY releasePolicyChanged)
    Q_PROPERTY(qint64 releasePolicyGeneration READ releasePolicyGeneration NOTIFY releasePolicyChanged)
    Q_PROPERTY(QString releasePolicyDisposition READ releasePolicyDisposition NOTIFY releasePolicyChanged)
    Q_PROPERTY(bool healthConfirmationPending READ healthConfirmationPending NOTIFY updateHealthReceiptChanged)
    Q_PROPERTY(QVariantMap pendingHealthReceipt READ pendingHealthReceipt NOTIFY updateHealthReceiptChanged)
    Q_PROPERTY(QVariantMap lastHealthReceipt READ lastHealthReceipt NOTIFY updateHealthReceiptChanged)
    Q_PROPERTY(bool rollbackAvailable READ rollbackAvailable NOTIFY rollbackAvailabilityChanged)
    Q_PROPERTY(QVariantMap rollbackActionMetadata READ rollbackActionMetadata NOTIFY rollbackAvailabilityChanged)

public:
    explicit UpdateUiController(UpdateController* updateController, QObject *parent = nullptr);

    QString getHeaderText() const;
    QString getChangelogText() const;
    QString getVersion() const;
    bool isChecking() const;
    QString releaseChannel() const;
    qint64 releasePolicyGeneration() const;
    QString releasePolicyDisposition() const;
    bool healthConfirmationPending() const;
    QVariantMap pendingHealthReceipt() const;
    QVariantMap lastHealthReceipt() const;
    bool rollbackAvailable() const;
    QVariantMap rollbackActionMetadata() const;

public slots:
    void checkForUpdates();
    void runInstaller();
    bool runPendingRollback();

signals:
    void updateFound();
    void manualUpdateCheckStarted();
    void manualUpdateCheckNoUpdates();
    void manualUpdateCheckFailed(const QString &error);
    void checkingChanged();
    void releasePolicyChanged();
    void updateHealthReceiptChanged();
    void rollbackAvailabilityChanged();

private:
    void onUpdateCheckFinished(bool updateAvailable);
    void onUpdateCheckFailed(const QString &error);

    UpdateController* m_updateController;
    bool m_manualCheckRunning = false;
    bool m_isChecking = false;
    bool m_manualCheckFailed = false;
};

#endif // UPDATEUICONTROLLER_H
