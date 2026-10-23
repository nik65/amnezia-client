#pragma once
#include "localpeerauthentication.h"
#include <QByteArray>
#include <QVariantMap>
#include <cerrno>

namespace amnezia::ipc::linuxSystemd {
inline bool isExecutableAccessDenied(qint64 readlinkResult, int error)
{
    return readlinkResult < 0 && (error == EACCES || error == EPERM);
}
// Typed facts collected from the pinned system manager; exposed for inert
// negative tests. Production authorization never accepts caller-provided facts.
struct Snapshot {
    QVariantMap unit;
    QVariantMap service;
    QString executable;
    QStringList arguments;
    quint32 execPid = 0;
    quint64 execStartMonotonic = 0;
    bool execAccountingAbsent = false;
    bool ignoreFailure = true;
    bool operator==(const Snapshot &other) const
    {
        const auto sameMap = [](const QVariantMap &left, const QVariantMap &right) {
            if (left.size() != right.size()) return false;
            for (auto it=left.constBegin();it!=left.constEnd();++it) {
                const auto found=right.constFind(it.key());
                if (found==right.constEnd() || found->metaType()!=it->metaType() || *found!=*it) return false;
            }
            return true;
        };
        return sameMap(unit,other.unit) && sameMap(service,other.service)
            && executable==other.executable && arguments==other.arguments
            && execPid==other.execPid && execStartMonotonic==other.execStartMonotonic
            && execAccountingAbsent==other.execAccountingAbsent
            && ignoreFailure==other.ignoreFailure;
    }
    bool operator!=(const Snapshot &other) const { return !(*this == other); }
};
bool validSnapshot(const Snapshot &snapshot, qint64 peerPid);
QString snapshotFailure(const Snapshot &snapshot, qint64 peerPid);
bool isPackagedUnit(const QByteArray &bytes);
bool authorize(QLocalSocket *socket, const QString &expected,
               LocalPeerIdentity &identity, QString *error);
}
