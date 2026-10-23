#pragma once

#include "headlessProtocol.h"
#include "rollbackCoordinator.h"
#include <QJsonDocument>

namespace amnezia::headless {

// An authenticated daemon may already have scheduled the worker. Repeating
// scheduling can race that worker's exclusive lock and turn success into failure.
inline bool daemonScheduledRollback(const QByteArray &frame)
{
    const auto response = QJsonDocument::fromJson(frame).object();
    const auto coordinator = response.value(QStringLiteral("result")).toObject()
            .value(QStringLiteral("rollbackCoordinator")).toObject();
    const auto admission = coordinator.value(QStringLiteral("admission")).toObject();
    return response.value(QStringLiteral("ok")).isBool()
        && response.value(QStringLiteral("ok")).toBool()
        && coordinator.value(QStringLiteral("schema")).isDouble()
        && coordinator.value(QStringLiteral("schema")).toDouble() == 1.0
        && coordinator.value(QStringLiteral("workerStartRequested")).isBool()
        && coordinator.value(QStringLiteral("workerStartRequested")).toBool()
        && admission.value(QStringLiteral("authority")) == QStringLiteral("retained14Coordinator")
        && admission.value(QStringLiteral("phase")) == QStringLiteral("profiles_paused");
}

// This reports only a verified, scheduled coordinator request. It is never a
// daemon acknowledgement or a completed rollback/acceptance receipt.
inline QByteArray acceptedPendingRollbackResponse(
        const QString &requestId, const QString &transportError,
        const RollbackCoordinatorResult &scheduled)
{
    if (!scheduled.ok || scheduled.code != QStringLiteral("rollback_restart_pending")
        || scheduled.evidence.value(QStringLiteral("authority")) != QStringLiteral("retained14Coordinator")
        || scheduled.evidence.value(QStringLiteral("phase")) != QStringLiteral("rollback_requested")) {
        return {};
    }
    return encodeResponse(requestId, {
        {QStringLiteral("state"), QStringLiteral("rollback_coordinator_accepted_pending")},
        {QStringLiteral("pending"), true},
        {QStringLiteral("authority"), QStringLiteral("retained14CoordinatorRequest")},
        {QStringLiteral("transportFailure"), transportError},
        {QStringLiteral("coordinator"), scheduled.evidence},
    });
}

} // namespace amnezia::headless
