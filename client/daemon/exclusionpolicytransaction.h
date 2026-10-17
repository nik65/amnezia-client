#ifndef EXCLUSIONPOLICYTRANSACTION_H
#define EXCLUSIONPOLICYTRANSACTION_H

#include <QSet>
#include <QStringList>

namespace amnezia::exclusionPolicy {

// These values are also the bounded IPC receipt. Uncertain must never be
// interpreted as an acknowledgement of either policy.
enum Result { Unsupported = 0, Updated = 1, RolledBack = 2, Uncertain = 3, Rejected = 4 };

template <typename Firewall, typename AddRoute, typename RemoveRoute>
Result replace(const QStringList& before, const QStringList& after,
               Firewall firewall, AddRoute add, RemoveRoute remove)
{
    const QSet<QString> oldSet(before.begin(), before.end());
    const QSet<QString> newSet(after.begin(), after.end());
    QStringList common, added, removed;
    for (const auto& route : oldSet) {
        if (newSet.contains(route)) common.append(route);
        else removed.append(route);
    }
    for (const auto& route : newSet) {
        if (!oldSet.contains(route)) added.append(route);
    }
    if (added.isEmpty() && removed.isEmpty()) return Updated;
    common.sort(); added.sort(); removed.sort();

    // The WFP commit temporarily permits only bypasses common to both policies.
    // Keep the interface/peer and the VPN permits installed throughout.
    if (!firewall(common)) return Uncertain;
    QStringList attemptedAdds, attemptedRemovals;
    const auto rollback = [&]() {
        // A failed final commit may already have installed the new permits.
        // Re-establish the common fence before undoing any physical route.
        if (!firewall(common)) return Uncertain;
        bool restored = true;
        // A failed OS operation can still have mutated part of its state.
        for (const auto& route : attemptedAdds) restored = remove(route) && restored;
        for (const auto& route : attemptedRemovals) restored = add(route) && restored;
        // Never reopen old bypasses before their routes have been restored.
        if (!restored) return Uncertain;
        return firewall(before) ? RolledBack : Uncertain;
    };
    for (const auto& route : removed) {
        attemptedRemovals.append(route);
        if (!remove(route)) return rollback();
    }
    for (const auto& route : added) {
        attemptedAdds.append(route);
        if (!add(route)) return rollback();
    }
    if (!firewall(after)) return rollback();
    return Updated;
}

// KillSwitch-off has no deny fence to narrow while physical routes change.
// Install the new bypasses before removing the old ones, then roll back by
// restoring old bypasses before removing any new bypasses. Callers provide
// route callbacks that perform native readback and retain ownership on a
// failed OS operation.
template <typename AddRoute, typename RemoveRoute>
Result replaceRoutes(const QStringList& before, const QStringList& after,
                     AddRoute add, RemoveRoute remove)
{
    const QSet<QString> oldSet(before.begin(), before.end());
    const QSet<QString> newSet(after.begin(), after.end());
    QStringList added, removed;
    for (const auto &route : newSet) {
        if (!oldSet.contains(route)) {
            added.append(route);
        }
    }
    for (const auto &route : oldSet) {
        if (!newSet.contains(route)) {
            removed.append(route);
        }
    }
    if (added.isEmpty() && removed.isEmpty()) {
        return Updated;
    }
    added.sort();
    removed.sort();

    QStringList attemptedAdds, attemptedRemovals;
    const auto rollback = [&]() {
        bool restored = true;
        // Restore old physical bypasses first so existing traffic recovers
        // promptly after a failed transition.
        for (const auto &route : attemptedRemovals) {
            restored = add(route) && restored;
        }
        // Remove every new route whose add may have partially succeeded.
        for (const auto &route : attemptedAdds) {
            restored = remove(route) && restored;
        }
        return restored ? RolledBack : Uncertain;
    };

    // No deny fence exists in this mode, so preserve old bypasses until every
    // new route has a native success/readback receipt.
    for (const auto &route : added) {
        attemptedAdds.append(route);
        if (!add(route)) {
            return rollback();
        }
    }
    for (const auto &route : removed) {
        attemptedRemovals.append(route);
        if (!remove(route)) {
            return rollback();
        }
    }
    return Updated;
}
}
#endif
