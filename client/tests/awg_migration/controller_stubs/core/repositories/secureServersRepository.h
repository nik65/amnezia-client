#pragma once
#include <QObject>
#include <QJsonObject>
#include <QJsonDocument>
#include "core/utils/serverConfigUtils.h"
#include "../../../../../../common/awgMigration.h"

// Test boundary only: primitive storage/CAS, no migration state transitions.
class SecureServersRepository : public QObject {
    Q_OBJECT
public:
    QJsonObject profile, journal;
    bool writesAllowed = true, casAllowed = true;
    int writes = 0, swaps = 0;
    QStringList states;
    int indexOfServerId(const QString &id) const { return id == "server" ? 0 : -1; }
    QJsonObject serverJson(int index) const { return index == 0 ? profile : QJsonObject{}; }
    QJsonObject migrationJournal(const QString &) const { return journal; }
    serverConfigUtils::ConfigType serverKind(const QString &) const { return serverConfigUtils::SelfHostedAdmin; }
    bool writeMigrationJournal(const QString &, const QJsonObject &value) {
        ++writes;
        if (!writesAllowed) return false;
        journal = QJsonDocument::fromJson(QJsonDocument(value).toJson()).object();
        states.append(journal.value("state").toString());
        return true;
    }
    bool compareAndSwapServer(const QString &id, const QString &expected, const QJsonObject &value) {
        ++swaps;
        if (!casAllowed || id != "server" || amnezia::awgMigration::digest(profile) != expected) return false;
        profile = value;
        emit serverEdited(id);
        return true;
    }
signals:
    void serverRemoved(const QString &, int);
    void serverEdited(const QString &);
};
