#include "updateUiController.h"

UpdateUiController::UpdateUiController(UpdateController* updateController, QObject *parent)
    : QObject(parent), m_updateController(updateController)
{
    if (m_updateController) {
        connect(m_updateController, &UpdateController::updateFound, this, &UpdateUiController::updateFound);
        connect(m_updateController, &UpdateController::updateCheckFinished,
                this, &UpdateUiController::onUpdateCheckFinished);
        connect(m_updateController, &UpdateController::updateCheckFailed,
                this, &UpdateUiController::onUpdateCheckFailed);
        connect(m_updateController, &UpdateController::installerHandoffFailed,
                this, &UpdateUiController::installerHandoffFailed);
        connect(m_updateController, &UpdateController::releasePolicyChanged,
                this, &UpdateUiController::releasePolicyChanged);
        connect(m_updateController, &UpdateController::updateHealthReceiptChanged,
                this, &UpdateUiController::updateHealthReceiptChanged);
        connect(m_updateController, &UpdateController::rollbackAvailabilityChanged,
                this, &UpdateUiController::rollbackAvailabilityChanged);
    }
}

QString UpdateUiController::getHeaderText() const
{
    if (!m_updateController) {
        return QString();
    }

    const QString version = m_updateController->getVersion();
    const QString releaseDate = m_updateController->getReleaseDate();
    if (releaseDate.trimmed().isEmpty()) {
        return tr("New version released: %1").arg(version);
    }

    return tr("New version released: %1 (%2)").arg(version, releaseDate);
}

QString UpdateUiController::getChangelogText() const
{
    if (!m_updateController) {
        return QString();
    }

    const QString rawChangelog = m_updateController->getRawChangelogText();
    if (rawChangelog.isEmpty()) {
        return tr("Failed to load changelog text");
    }

    QStringList lines = rawChangelog.split("\n");
    QStringList filteredChangeLogText;
    bool add = false;
    QString osSection;

#ifdef Q_OS_WINDOWS
    osSection = "### Windows";
#elif defined(Q_OS_MACOS)
    osSection = "### macOS";
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    osSection = "### Linux";
#endif

    for (const QString &line : lines) {
        if (line.startsWith("### General")) {
            add = true;
        } else if (line.startsWith("### ") && line != osSection) {
            add = false;
        } else if (line == osSection) {
            add = true;
        }

        if (add) {
            filteredChangeLogText.append(line);
        }
    }

    return filteredChangeLogText.join("\n");
}

QString UpdateUiController::getVersion() const
{
    return m_updateController ? m_updateController->getVersion() : QString();
}

bool UpdateUiController::isChecking() const
{
    return m_isChecking;
}

QString UpdateUiController::releaseChannel() const
{
    return m_updateController ? m_updateController->getReleaseChannel() : QString();
}

qint64 UpdateUiController::releasePolicyGeneration() const
{
    return m_updateController ? m_updateController->getReleasePolicyGeneration() : 0;
}

QString UpdateUiController::releasePolicyDisposition() const
{
    return m_updateController ? m_updateController->getReleasePolicyDisposition()
                              : QStringLiteral("none");
}

bool UpdateUiController::healthConfirmationPending() const
{
    return m_updateController && m_updateController->isUpdateHealthConfirmationPending();
}

QVariantMap UpdateUiController::pendingHealthReceipt() const
{
    return m_updateController ? m_updateController->getPendingUpdateHealthReceipt() : QVariantMap();
}

QVariantMap UpdateUiController::lastHealthReceipt() const
{
    return m_updateController ? m_updateController->getLastUpdateHealthReceipt() : QVariantMap();
}

bool UpdateUiController::rollbackAvailable() const
{
    return m_updateController && m_updateController->isRollbackAvailable();
}

QVariantMap UpdateUiController::rollbackActionMetadata() const
{
    return m_updateController ? m_updateController->getRollbackActionMetadata() : QVariantMap();
}

void UpdateUiController::checkForUpdates()
{
    if (!m_updateController || m_manualCheckRunning) {
        return;
    }

    const bool wasUpdateCheckRunning = m_updateController->isUpdateCheckRunning();
    m_manualCheckRunning = true;
    m_manualCheckFailed = false;
    m_isChecking = true;
    emit checkingChanged();
    emit manualUpdateCheckStarted();

    if (!wasUpdateCheckRunning && !m_updateController->checkForUpdates()) {
        onUpdateCheckFinished(false);
    }
}

bool UpdateUiController::runInstaller()
{
    return m_updateController && m_updateController->runInstaller();
}

bool UpdateUiController::runPendingRollback()
{
    return m_updateController && m_updateController->runPendingRollback();
}

void UpdateUiController::onUpdateCheckFinished(bool updateAvailable)
{
    if (!m_manualCheckRunning) {
        return;
    }

    m_manualCheckRunning = false;
    m_isChecking = false;
    emit checkingChanged();

    if (!updateAvailable && !m_manualCheckFailed) {
        emit manualUpdateCheckNoUpdates();
    }
}

void UpdateUiController::onUpdateCheckFailed(const QString &error)
{
    if (!m_manualCheckRunning) {
        return;
    }
    m_manualCheckFailed = true;
    if (m_isChecking) {
        m_isChecking = false;
        emit checkingChanged();
    }
    emit manualUpdateCheckFailed(error);
}
