#ifndef SITESCONTROLLER_H
#define SITESCONTROLLER_H

#include <QObject>
#include <QHash>
#include <QJsonObject>
#include <QVector>

#include "core/controllers/selfhosted/installController.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/commonStructs.h"
#include "core/utils/routeModes.h"
#include "ui/controllers/serversUiController.h"
#include "ui/models/ipSplitTunnelingModel.h"

class SitesController : public QObject
{
    Q_OBJECT

public:
    explicit SitesController(SecureServersRepository *serversRepository,
                             ServersUiController *serversUiController,
                             InstallController *installController,
                             IpSplitTunnelingModel *managedExceptSitesModel,
                             QObject *parent = nullptr);

public slots:
    bool canEditManagedSites() const;
    bool isManagedSplitTunnelingForceEnabled() const;
    bool isDefaultManagedSplitTunnelingForceEnabled() const;
    void setManagedSplitTunnelingForceEnabled(bool enabled);

    void addManagedSite(int routeMode, const QString &hostname);
    void removeManagedSite(int routeMode, int index);
    void removeManagedSites(int routeMode);
    void importManagedSites(int routeMode, const QString &fileName, bool replaceExisting);
    void exportManagedSites(int routeMode, const QString &fileName);
    void reloadManagedSites();
    void reloadDefaultManagedSites();

signals:
    void errorOccurred(const QString &errorMessage);
    void finished(const QString &message);
    void managedSplitTunnelingForceChanged();
    void managedSplitTunnelingRulesPublished(int serverIndex);
    void managedSplitTunnelingRulesPublishPending(int serverIndex, const QString &expectedRevision);
    void managedSplitTunnelingRulesPublishSucceeded(int serverIndex, const QString &publishedRevision,
                                                     const QString &contentSha256, bool signatureAvailable);
    void managedSplitTunnelingRulesPublishFailed(int serverIndex, const QString &expectedRevision,
                                                 const QString &currentRevision, const QString &reason,
                                                 bool conflict);
    void managedSplitTunnelingRulesSigningBlocked(int serverIndex, const QString &blocker);
    void managedSplitTunnelingRulesPublishRolledBack(int serverIndex);
    void managedSplitTunnelingRulesLocalRollbackFinished(int serverIndex, bool applied,
                                                         const QString &details);
    void managedSplitTunnelingRulesRemoteRollbackFinished(int serverIndex, bool attempted,
                                                          bool succeeded, const QString &status);

private:
    int currentServerIndex() const;
    amnezia::RouteMode normalizeRouteMode(int routeMode) const;
    QVector<QPair<QString, QString>> currentManagedSites(amnezia::RouteMode routeMode) const;
    QVector<QPair<QString, QString>> managedSitesForServer(int serverIndex, amnezia::RouteMode routeMode) const;
    QString normalizeHostname(const QString &hostname) const;
    bool validateHostname(const QString &hostname) const;
    QJsonObject managedRoutingRulesPayload(int serverIndex) const;
    struct ManagedSplitTunnelingLocalState {
        QJsonObject serverJsonSnapshot;
    };
    ManagedSplitTunnelingLocalState managedSplitTunnelingLocalState(int serverIndex) const;
    bool restoreManagedSplitTunnelingLocalState(const QString &serverId,
                                                const ManagedSplitTunnelingLocalState &state);
    void publishManagedSplitTunnelingRules(int serverIndex,
                                           const ManagedSplitTunnelingLocalState &rollbackState,
                                           const QString &successMessage = QString());
    void startNextManagedSplitTunnelingPublish();

    SecureServersRepository *m_serversRepository;
    ServersUiController *m_serversUiController;
    InstallController *m_installController;
    IpSplitTunnelingModel *m_managedExceptSitesModel;
    struct ManagedSplitTunnelingPublishJob {
        int serverIndex = -1;
        QString serverId;
        amnezia::ServerCredentials credentials;
        QJsonObject rules;
        amnezia::DockerContainer container = amnezia::DockerContainer::None;
        qint64 expectedRevision = -1;
        ManagedSplitTunnelingLocalState rollbackState;
        QString successMessage;
    };
    QVector<ManagedSplitTunnelingPublishJob> m_pendingManagedSplitTunnelingPublishJobs;
    QHash<QString, qint64> m_lastPublishedRevisionByServerId;
    bool m_isManagedSplitTunnelingPublishInProgress = false;
};

#endif // SITESCONTROLLER_H
