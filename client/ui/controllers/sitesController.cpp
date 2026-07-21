#include "sitesController.h"

#include <QCoreApplication>
#include <QFile>
#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrl>
#include <QtConcurrent>

#include "core/utils/constants/configKeys.h"
#include "core/utils/networkUtilities.h"
#include "ui/controllers/systemController.h"

using namespace amnezia;

namespace
{
QJsonObject sitesToJsonObject(const QVariantMap &sites)
{
    return QJsonObject::fromVariantMap(sites);
}

QJsonObject managedRoutingRulesPayload(SecureServersRepository *serversRepository, int serverIndex)
{
    const QVariantMap exceptSites = serversRepository->rawManagedVpnSites(serverIndex, RouteMode::VpnAllExceptSites);
    QJsonObject rules;
    const QJsonObject sites = sitesToJsonObject(exceptSites);
    rules.insert(QStringLiteral("version"), 1);
    rules.insert(configKey::serverExcept, sites);
    rules.insert(configKey::managedSplitTunnelExceptSourceSites, sites);
    rules.insert(configKey::managedSplitTunnelExceptSites, sites);
    if (serversRepository->rawManagedSplitTunnelingForceEnabled(serverIndex)) {
        rules.insert(configKey::managedSplitTunnelForceEnabled, true);
    }
    return rules;
}

bool readSitesJson(const QString &fileName, QJsonArray &jsonArray, QString &errorMessage)
{
    QByteArray jsonData;
    if (!SystemController::readFile(fileName, jsonData)) {
        errorMessage = QCoreApplication::translate("SitesController", "Can't open file: %1").arg(fileName);
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument jsonDocument = QJsonDocument::fromJson(jsonData, &parseError);
    if (parseError.error != QJsonParseError::NoError) {
        errorMessage = QCoreApplication::translate("SitesController", "Failed to parse JSON data: %1")
                               .arg(parseError.errorString());
        return false;
    }
    if (!jsonDocument.isArray()) {
        errorMessage = QCoreApplication::translate("SitesController", "The JSON data is not an array");
        return false;
    }

    jsonArray = jsonDocument.array();
    return true;
}

QString sanitizedIpList(const QString &value, bool *valid = nullptr)
{
    bool routesValid = false;
    const QStringList routes = managedRoutePolicy::validatedManagedRouteTokens(value, &routesValid);
    if (valid) {
        *valid = routesValid;
    }
    return routesValid ? routes.join(QStringLiteral(", ")) : QString();
}

bool managedSitesAreValid(const QVariantMap &sites)
{
    bool valid = false;
    managedRoutePolicy::canonicalSourceSites(QJsonObject::fromVariantMap(sites), &valid);
    return valid;
}
}

SitesController::SitesController(SecureServersRepository *serversRepository,
                                 ServersUiController *serversUiController,
                                 InstallController *installController,
                                 IpSplitTunnelingModel *managedExceptSitesModel,
                                 QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_serversUiController(serversUiController),
      m_installController(installController),
      m_managedExceptSitesModel(managedExceptSitesModel)
{
    reloadManagedSites();
}

int SitesController::currentServerIndex() const
{
    return m_serversUiController ? m_serversUiController->getProcessedServerIndex() : -1;
}

RouteMode SitesController::normalizeRouteMode(int routeMode) const
{
    Q_UNUSED(routeMode)
    return RouteMode::VpnAllExceptSites;
}

QVector<QPair<QString, QString>> SitesController::currentManagedSites(RouteMode routeMode) const
{
    return managedSitesForServer(currentServerIndex(), routeMode);
}

QVector<QPair<QString, QString>> SitesController::managedSitesForServer(int serverIndex, RouteMode routeMode) const
{
    QVector<QPair<QString, QString>> sites;
    const QVariantMap sitesMap = m_serversRepository->rawManagedVpnSites(serverIndex, routeMode);
    for (auto it = sitesMap.constBegin(); it != sitesMap.constEnd(); ++it) {
        sites.append(qMakePair(it.key(), it.value().toString()));
    }
    return sites;
}

QString SitesController::normalizeHostname(const QString &hostname) const
{
    QString normalized = hostname.trimmed();
    if (NetworkUtilities::checkIpSubnetFormat(normalized)) {
        return normalized;
    }

    const QUrl url = QUrl::fromUserInput(normalized);
    if (url.isValid() && !url.host().isEmpty()) {
        normalized = url.host();
    } else {
        normalized.replace(QStringLiteral("https://"), QString(), Qt::CaseInsensitive);
        normalized.replace(QStringLiteral("http://"), QString(), Qt::CaseInsensitive);
        normalized.replace(QStringLiteral("ftp://"), QString(), Qt::CaseInsensitive);
        normalized = normalized.split('/', Qt::SkipEmptyParts).first();
    }
    return normalized.trimmed().toLower();
}

bool SitesController::validateHostname(const QString &hostname) const
{
    return managedRoutePolicy::isAllowedManagedSiteKey(hostname);
}

bool SitesController::canEditManagedSites() const
{
    return m_serversUiController && m_serversUiController->isProcessedServerHasWriteAccess();
}

bool SitesController::isManagedSplitTunnelingForceEnabled() const
{
    return m_serversRepository->rawManagedSplitTunnelingForceEnabled(currentServerIndex());
}

bool SitesController::isDefaultManagedSplitTunnelingForceEnabled() const
{
    return m_serversRepository->rawManagedSplitTunnelingForceEnabled(m_serversRepository->defaultServerIndex());
}

void SitesController::setManagedSplitTunnelingForceEnabled(bool enabled)
{
    const int serverIndex = currentServerIndex();
    if (!canEditManagedSites() || serverIndex < 0) {
        emit errorOccurred(tr("Server routing rules are available only for server admins"));
        return;
    }

    const ManagedSplitTunnelingLocalState rollbackState = managedSplitTunnelingLocalState(serverIndex);
    m_serversRepository->setManagedSplitTunnelingForceEnabled(serverIndex, enabled);
    emit managedSplitTunnelingForceChanged();
    publishManagedSplitTunnelingRules(serverIndex, rollbackState,
                                      tr("Server routing policy updated"));
}

void SitesController::addManagedSite(int routeMode, const QString &hostname)
{
    const int serverIndex = currentServerIndex();
    const RouteMode mode = normalizeRouteMode(routeMode);
    const QString normalizedHostname = normalizeHostname(hostname);
    if (!canEditManagedSites() || serverIndex < 0) {
        emit errorOccurred(tr("Server routing rules are available only for server admins"));
        return;
    }
    if (!validateHostname(normalizedHostname)) {
        emit errorOccurred(tr("Site should be a domain, IP address, or subnet"));
        return;
    }

    const ManagedSplitTunnelingLocalState rollbackState = managedSplitTunnelingLocalState(serverIndex);
    QVariantMap candidateSites = m_serversRepository->rawManagedVpnSites(serverIndex, mode);
    candidateSites.insert(normalizedHostname, QString());
    if (!managedSitesAreValid(candidateSites)) {
        emit errorOccurred(tr("Managed route is too broad, unsafe, or exceeds the policy limit"));
        return;
    }
    if (!m_serversRepository->addManagedVpnSite(serverIndex, mode, normalizedHostname, QString())) {
        return;
    }
    reloadManagedSites();
    publishManagedSplitTunnelingRules(serverIndex, rollbackState,
                                      tr("Managed site updated: %1").arg(normalizedHostname));
}

void SitesController::removeManagedSite(int routeMode, int index)
{
    const int serverIndex = currentServerIndex();
    const RouteMode mode = normalizeRouteMode(routeMode);
    const QVector<QPair<QString, QString>> sites = currentManagedSites(mode);
    if (!canEditManagedSites() || serverIndex < 0 || index < 0 || index >= sites.size()) {
        return;
    }

    const QString hostname = sites.at(index).first;
    const ManagedSplitTunnelingLocalState rollbackState = managedSplitTunnelingLocalState(serverIndex);
    m_serversRepository->removeManagedVpnSite(serverIndex, mode, hostname);
    reloadManagedSites();
    publishManagedSplitTunnelingRules(serverIndex, rollbackState,
                                      tr("Managed site removed: %1").arg(hostname));
}

void SitesController::removeManagedSites(int routeMode)
{
    const int serverIndex = currentServerIndex();
    if (!canEditManagedSites() || serverIndex < 0) {
        return;
    }

    const ManagedSplitTunnelingLocalState rollbackState = managedSplitTunnelingLocalState(serverIndex);
    m_serversRepository->removeAllManagedVpnSites(serverIndex, normalizeRouteMode(routeMode));
    reloadManagedSites();
    publishManagedSplitTunnelingRules(serverIndex, rollbackState, tr("Site list cleared!"));
}

void SitesController::importManagedSites(int routeMode, const QString &fileName, bool replaceExisting)
{
    const int serverIndex = currentServerIndex();
    const RouteMode mode = normalizeRouteMode(routeMode);
    if (!canEditManagedSites() || serverIndex < 0) {
        emit errorOccurred(tr("Server routing rules are available only for server admins"));
        return;
    }

    QJsonArray jsonArray;
    QString errorMessage;
    if (!readSitesJson(fileName, jsonArray, errorMessage)) {
        emit errorOccurred(errorMessage);
        return;
    }

    QMap<QString, QString> sites;
    for (const auto &jsonValue : jsonArray) {
        const QJsonObject jsonObject = jsonValue.toObject();
        const QString hostname = normalizeHostname(jsonObject.value("hostname").toString(jsonObject.value("url").toString()));
        if (!validateHostname(hostname)) {
            qDebug() << hostname << "not look like ip address, subnet, or domain name";
            continue;
        }
        bool fallbackValid = false;
        const QString fallbackIps = sanitizedIpList(jsonObject.value("ip").toString(), &fallbackValid);
        if (!fallbackValid) {
            emit errorOccurred(tr("Imported route list contains an unsafe or oversized IP value"));
            return;
        }
        sites.insert(hostname, NetworkUtilities::checkIpSubnetFormat(hostname) ? QString() : fallbackIps);
    }

    const ManagedSplitTunnelingLocalState rollbackState = managedSplitTunnelingLocalState(serverIndex);
    QVariantMap candidateSites = replaceExisting
            ? QVariantMap() : m_serversRepository->rawManagedVpnSites(serverIndex, mode);
    for (auto it = sites.constBegin(); it != sites.constEnd(); ++it) {
        candidateSites.insert(it.key(), it.value());
    }
    if (!managedSitesAreValid(candidateSites)) {
        emit errorOccurred(tr("Imported route list is too large or contains an unsafe managed route"));
        return;
    }
    m_serversRepository->setManagedVpnSites(serverIndex, mode, candidateSites);
    reloadManagedSites();
    publishManagedSplitTunnelingRules(serverIndex, rollbackState, tr("Import completed"));
}

void SitesController::exportManagedSites(int routeMode, const QString &fileName)
{
    const QVector<QPair<QString, QString>> sites = currentManagedSites(normalizeRouteMode(routeMode));
    QJsonArray jsonArray;
    for (const auto &site : sites) {
        QJsonObject jsonObject;
        jsonObject["hostname"] = site.first;
        jsonObject["ip"] = site.second;
        jsonArray.append(jsonObject);
    }

    SystemController::saveFile(fileName, QString::fromUtf8(QJsonDocument(jsonArray).toJson()));
    emit finished(tr("Export completed"));
}

void SitesController::reloadManagedSites()
{
    if (!m_managedExceptSitesModel) {
        return;
    }
    m_managedExceptSitesModel->updateModel(currentManagedSites(RouteMode::VpnAllExceptSites));
}

void SitesController::reloadDefaultManagedSites()
{
    if (!m_managedExceptSitesModel) {
        return;
    }
    m_managedExceptSitesModel->updateModel(
            managedSitesForServer(m_serversRepository->defaultServerIndex(), RouteMode::VpnAllExceptSites));
}

QJsonObject SitesController::managedRoutingRulesPayload(int serverIndex) const
{
    return ::managedRoutingRulesPayload(m_serversRepository, serverIndex);
}

SitesController::ManagedSplitTunnelingLocalState
SitesController::managedSplitTunnelingLocalState(int serverIndex) const
{
    ManagedSplitTunnelingLocalState state;
    if (serverIndex >= 0 && serverIndex < m_serversRepository->serversCount()) {
        state.serverJsonSnapshot = m_serversRepository->serverJson(serverIndex);
    }
    return state;
}

bool SitesController::restoreManagedSplitTunnelingLocalState(
        const QString &serverId, const ManagedSplitTunnelingLocalState &state)
{
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (serverIndex < 0 || state.serverJsonSnapshot.isEmpty()) {
        emit managedSplitTunnelingRulesLocalRollbackFinished(
                serverIndex, false, tr("Local rollback snapshot is unavailable"));
        return false;
    }

    QJsonObject currentServerJson = m_serversRepository->serverJson(serverIndex);
    const QStringList routingKeys = {
        QString(configKey::serverExcept),
        QString(configKey::managedSplitTunnelForwardSites),
        QString(configKey::managedSplitTunnelExceptSites),
        QString(configKey::managedSplitTunnelExceptSourceSites),
        QString(configKey::managedSplitTunnelClientResolvedExceptSites),
        QString(configKey::managedSplitTunnelClientResolvedAt),
        QString(configKey::managedSplitTunnelForceEnabled),
    };
    for (const QString &key : routingKeys) {
        if (state.serverJsonSnapshot.contains(key)) {
            currentServerJson.insert(key, state.serverJsonSnapshot.value(key));
        } else {
            currentServerJson.remove(key);
        }
    }
    const QJsonObject beforeRollback = m_serversRepository->serverJson(serverIndex);
    if (beforeRollback == currentServerJson) {
        emit managedSplitTunnelingRulesLocalRollbackFinished(
                serverIndex, false, tr("Local routing state already matches the rollback snapshot"));
        return false;
    }

    m_serversRepository->editServerJson(serverIndex, currentServerJson);
    const bool restored = m_serversRepository->serverJson(serverIndex) == currentServerJson;
    if (serverIndex == currentServerIndex()) {
        reloadManagedSites();
        emit managedSplitTunnelingForceChanged();
    }
    if (restored) {
        emit managedSplitTunnelingRulesPublishRolledBack(serverIndex);
        // Reuse the established runtime-refresh signal so an active VPN drops
        // any unpublished draft routes and reconciles the restored LKG now.
        emit managedSplitTunnelingRulesPublished(serverIndex);
    }
    emit managedSplitTunnelingRulesLocalRollbackFinished(
            serverIndex, restored,
            restored ? tr("Local routing changes were rolled back")
                     : tr("Local routing changes could not be rolled back"));
    return restored;
}

void SitesController::publishManagedSplitTunnelingRules(
        int serverIndex, const ManagedSplitTunnelingLocalState &rollbackState,
        const QString &successMessage)
{
    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return;
    }

    const QString serverId = m_serversRepository->serverIdAt(serverIndex);
    const ServerCredentials credentials = m_serversRepository->serverCredentials(serverIndex);
    if (credentials.userName.isEmpty() || credentials.secretData.isEmpty()) {
        restoreManagedSplitTunnelingLocalState(serverId, rollbackState);
        emit managedSplitTunnelingRulesRemoteRollbackFinished(
                serverIndex, false, false, QStringLiteral("not_needed"));
        const QString reason = tr("Server credentials are unavailable; routing policy was not published");
        emit managedSplitTunnelingRulesPublishFailed(serverIndex, QStringLiteral("unknown"),
                                                     QStringLiteral("unknown"), reason, false);
        emit errorOccurred(reason);
        return;
    }

    ManagedSplitTunnelingPublishJob job;
    job.serverIndex = serverIndex;
    job.serverId = serverId;
    job.credentials = credentials;
    job.rules = managedRoutingRulesPayload(serverIndex);
    job.rollbackState = rollbackState;
    job.successMessage = successMessage;
    job.expectedRevision = m_lastPublishedRevisionByServerId.value(serverId, -1);
    const auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    job.container = adminConfig.has_value() ? adminConfig->defaultContainer : DockerContainer::None;

    for (int i = m_pendingManagedSplitTunnelingPublishJobs.size() - 1; i >= 0; --i) {
        if (m_pendingManagedSplitTunnelingPublishJobs.at(i).serverId == serverId) {
            // Coalesced edits still roll back to the state before the first
            // unpublished local mutation.
            job.rollbackState = m_pendingManagedSplitTunnelingPublishJobs.at(i).rollbackState;
            job.expectedRevision = m_pendingManagedSplitTunnelingPublishJobs.at(i).expectedRevision;
            if (job.successMessage.isEmpty()) {
                job.successMessage = m_pendingManagedSplitTunnelingPublishJobs.at(i).successMessage;
            }
            m_pendingManagedSplitTunnelingPublishJobs.removeAt(i);
        }
    }
    m_pendingManagedSplitTunnelingPublishJobs.append(job);
    emit managedSplitTunnelingRulesPublishPending(
            serverIndex, job.expectedRevision >= 0 ? QString::number(job.expectedRevision) : QStringLiteral("unknown"));
    startNextManagedSplitTunnelingPublish();
}

void SitesController::startNextManagedSplitTunnelingPublish()
{
    if (m_isManagedSplitTunnelingPublishInProgress) {
        return;
    }

    while (!m_pendingManagedSplitTunnelingPublishJobs.isEmpty()) {
        const ManagedSplitTunnelingPublishJob job = m_pendingManagedSplitTunnelingPublishJobs.takeFirst();
        const int serverIndex = m_serversRepository->indexOfServerId(job.serverId);
        if (serverIndex < 0 || job.credentials.userName.isEmpty() || job.credentials.secretData.isEmpty()) {
            continue;
        }

        m_isManagedSplitTunnelingPublishInProgress = true;
        auto *watcher = new QFutureWatcher<ServerRoutingRulesPublishResult>(this);
        connect(watcher, &QFutureWatcher<ServerRoutingRulesPublishResult>::finished, this, [this, watcher, job]() {
            const ServerRoutingRulesPublishResult result = watcher->result();
            watcher->deleteLater();
            m_isManagedSplitTunnelingPublishInProgress = false;
            const int serverIndex = m_serversRepository->indexOfServerId(job.serverId);
            if (!result.succeeded()) {
                emit managedSplitTunnelingRulesRemoteRollbackFinished(
                        serverIndex, result.remoteRollbackAttempted, result.remoteRollbackSucceeded,
                        result.remoteRollbackStatus.isEmpty() ? QStringLiteral("not_reported")
                                                              : result.remoteRollbackStatus);
                bool hasNewerPendingJob = false;
                for (int i = m_pendingManagedSplitTunnelingPublishJobs.size() - 1; i >= 0; --i) {
                    auto &pendingJob = m_pendingManagedSplitTunnelingPublishJobs[i];
                    if (pendingJob.serverId != job.serverId) {
                        continue;
                    }
                    if (result.conflict) {
                        m_pendingManagedSplitTunnelingPublishJobs.removeAt(i);
                    } else {
                        pendingJob.rollbackState = job.rollbackState;
                        hasNewerPendingJob = true;
                    }
                }
                if (result.conflict && result.currentRevision >= 0) {
                    // Rebase the next explicit user retry on the revision we
                    // just observed. We intentionally do not replay edits
                    // automatically after a CAS conflict.
                    m_lastPublishedRevisionByServerId.insert(job.serverId, result.currentRevision);
                } else if (result.remoteRollbackSucceeded && result.expectedRevision >= 0) {
                    m_lastPublishedRevisionByServerId.insert(job.serverId, result.expectedRevision);
                } else if (result.remoteRollbackAttempted && !result.remoteRollbackSucceeded) {
                    m_lastPublishedRevisionByServerId.remove(job.serverId);
                }
                if (!hasNewerPendingJob) {
                    restoreManagedSplitTunnelingLocalState(job.serverId, job.rollbackState);
                }

                const QString expectedRevision = result.expectedRevision >= 0
                        ? QString::number(result.expectedRevision)
                        : QStringLiteral("unknown");
                const QString currentRevision = result.currentRevision >= 0
                        ? QString::number(result.currentRevision)
                        : QStringLiteral("unknown");
                const QString reason = result.failureReason.isEmpty()
                        ? tr("Failed to publish server routing rules for clients")
                        : result.failureReason;
                emit managedSplitTunnelingRulesPublishFailed(serverIndex, expectedRevision, currentRevision,
                                                             reason, result.conflict);
                emit errorOccurred(reason);
                startNextManagedSplitTunnelingPublish();
                return;
            }

            m_lastPublishedRevisionByServerId.insert(job.serverId, result.publishedRevision);
            for (auto &pendingJob : m_pendingManagedSplitTunnelingPublishJobs) {
                if (pendingJob.serverId == job.serverId) {
                    pendingJob.expectedRevision = result.publishedRevision;
                }
            }

            qDebug() << "SitesController: published server routing rules revision" << result.publishedRevision
                     << "for server" << serverIndex;
            emit managedSplitTunnelingRulesPublishSucceeded(
                    serverIndex, QString::number(result.publishedRevision), result.contentSha256,
                    result.signatureAvailable);
            if (!result.signatureAvailable && !result.signingBlocker.isEmpty()) {
                emit managedSplitTunnelingRulesSigningBlocked(serverIndex, result.signingBlocker);
            }
            emit managedSplitTunnelingRulesPublished(serverIndex);
            if (!job.successMessage.isEmpty()) {
                emit finished(job.successMessage);
            }
            startNextManagedSplitTunnelingPublish();
        });

        watcher->setFuture(QtConcurrent::run([installController = m_installController, job]() {
            return installController->publishVersionedServerRoutingRules(
                    job.credentials, job.rules, job.container, job.expectedRevision);
        }));
        return;
    }
}
