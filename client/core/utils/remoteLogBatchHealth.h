#ifndef REMOTELOGBATCHHEALTH_H
#define REMOTELOGBATCHHEALTH_H

#include <QStringList>
#include <QtGlobal>

namespace amnezia
{

inline constexpr qsizetype MaximumRemoteLogSanitizerExplicitSecrets = 64;

struct RemoteLogSanitizerSecretSet
{
    QStringList values;
    bool forceRedacted = false;
};

enum class RemoteLogPersistenceStatus
{
    Healthy,
    ReadError,
    FormatError,
    WriteError,
    SyncError
};

constexpr bool remoteLogPersistenceMustFailClosed(
        RemoteLogPersistenceStatus status) noexcept
{
    return status != RemoteLogPersistenceStatus::Healthy;
}

constexpr bool remoteLogRecoveryCheckpointCanRetry(
        int attempts, int maximumAttempts) noexcept
{
    return attempts >= 0 && attempts < maximumAttempts;
}

enum class RemoteLogRetryMarkerCapacityDecision
{
    Store,
    GlobalFailClosed
};

constexpr RemoteLogRetryMarkerCapacityDecision remoteLogRetryMarkerCapacityDecision(
        qsizetype markerCount,
        qsizetype maximumMarkers,
        bool markerAlreadyPresent,
        bool globalTombstone,
        RemoteLogPersistenceStatus persistenceStatus) noexcept
{
    return globalTombstone || remoteLogPersistenceMustFailClosed(persistenceStatus)
            || (!markerAlreadyPresent && markerCount >= maximumMarkers)
            ? RemoteLogRetryMarkerCapacityDecision::GlobalFailClosed
            : RemoteLogRetryMarkerCapacityDecision::Store;
}

struct RemoteLogSecretTransitionState
{
    bool present = false;
    bool awaitingStableSource = false;
    qint64 highWaterOffset = 0;
};

struct RemoteLogSecretTransitionEvidence
{
    bool markerValid = true;
    bool sourceIdentityMatches = true;
    bool cursorMatchesSource = true;
    bool markerCursorMatches = true;
    bool markerCursorIsAhead = false;
    bool lastAcceptedSecretSetMatches = true;
    bool markerSecretSetMatches = true;
    qint64 sourceSize = 0;
    qint64 acceptedCursorOffset = 0;
};

struct RemoteLogSecretTransitionResult
{
    RemoteLogSecretTransitionState state;
    bool forceRedacted = false;
    bool updateMarkerSecretSet = false;
    bool persistMarker = false;
    bool clearMarker = false;
    bool globalFailClosed = false;
};

constexpr RemoteLogSecretTransitionResult remoteLogAdvanceSecretTransition(
        RemoteLogSecretTransitionState state,
        const RemoteLogSecretTransitionEvidence &evidence) noexcept
{
    RemoteLogSecretTransitionResult result;
    result.state = state;
    if (!evidence.markerValid
        || evidence.sourceSize < 0
        || evidence.acceptedCursorOffset < 0
        || evidence.acceptedCursorOffset > evidence.sourceSize
        || (state.present
            && (!evidence.sourceIdentityMatches
                || !evidence.cursorMatchesSource
                || state.highWaterOffset < 0
                || evidence.sourceSize < state.highWaterOffset
                || evidence.acceptedCursorOffset > state.highWaterOffset))) {
        result.forceRedacted = true;
        result.globalFailClosed = true;
        return result;
    }

    if (!state.present) {
        if (evidence.lastAcceptedSecretSetMatches) {
            return result;
        }
        result.state.present = true;
        result.state.awaitingStableSource = false;
        result.state.highWaterOffset = evidence.sourceSize;
        result.updateMarkerSecretSet = true;
        result.persistMarker = true;
        result.forceRedacted = true;
        return result;
    }

    if (evidence.sourceSize > result.state.highWaterOffset) {
        result.state.highWaterOffset = evidence.sourceSize;
        result.state.awaitingStableSource = false;
        result.persistMarker = true;
    }
    if (!evidence.markerSecretSetMatches) {
        result.state.awaitingStableSource = false;
        result.updateMarkerSecretSet = true;
        result.persistMarker = true;
    }

    if (result.state.awaitingStableSource) {
        if (!evidence.markerCursorMatches) {
            if (evidence.markerCursorIsAhead
                && evidence.acceptedCursorOffset < result.state.highWaterOffset) {
                // Marker-first persistence is deliberate. A crash before the
                // matching cursor save leaves the confirmation ahead of the
                // durable cursor, so retry the redacted range instead of
                // mistaking this safe partial transaction for continuity.
                result.state.awaitingStableSource = false;
                result.persistMarker = true;
                result.forceRedacted = true;
                return result;
            }
            result.forceRedacted = true;
            result.globalFailClosed = true;
            return result;
        }
        if (evidence.lastAcceptedSecretSetMatches
            && evidence.sourceSize == evidence.acceptedCursorOffset
            && evidence.acceptedCursorOffset == result.state.highWaterOffset) {
            result.state = {};
            result.clearMarker = true;
            return result;
        }
        // The ACK is only phase one. If the next independent scan still has
        // bytes to consume, it must return to the upload phase before another
        // ACK can arm a fresh stable-source confirmation.
        if (evidence.acceptedCursorOffset < result.state.highWaterOffset) {
            result.state.awaitingStableSource = false;
            result.persistMarker = true;
        } else if (!evidence.lastAcceptedSecretSetMatches) {
            result.forceRedacted = true;
            result.globalFailClosed = true;
            return result;
        }
    }

    result.forceRedacted = true;
    return result;
}

constexpr RemoteLogSecretTransitionResult remoteLogArmStableSourceAfterAck(
        RemoteLogSecretTransitionState state,
        bool markerValid,
        bool sourceIdentityMatches,
        bool secretSetMatches,
        qint64 capturedSize,
        qint64 acceptedCursorOffset) noexcept
{
    RemoteLogSecretTransitionResult result;
    result.state = state;
    if (!state.present) {
        return result;
    }
    if (!markerValid || !sourceIdentityMatches || !secretSetMatches
        || capturedSize < state.highWaterOffset
        || acceptedCursorOffset < 0 || acceptedCursorOffset > capturedSize) {
        result.forceRedacted = true;
        result.globalFailClosed = true;
        return result;
    }
    result.state.highWaterOffset = capturedSize;
    result.state.awaitingStableSource = true;
    result.forceRedacted = true;
    result.persistMarker = true;
    return result;
}

constexpr bool remoteLogAcceptedTransitionCanClose(
        bool markerValid,
        bool sourceIdentityMatches,
        bool cursorMatchesSource,
        bool markerCursorMatches,
        bool secretSetMatches,
        qint64 capturedSize,
        qint64 acceptedCursorOffset,
        qint64 highWaterOffset) noexcept
{
    // A receipt only arms confirmation. Closure is allowed exclusively from a
    // later scan of the same source and exact accepted high-water position.
    return markerValid && sourceIdentityMatches && cursorMatchesSource
            && markerCursorMatches && secretSetMatches
            && highWaterOffset >= 0
            && capturedSize == acceptedCursorOffset
            && acceptedCursorOffset == highWaterOffset;
}

constexpr bool remoteLogByteIsRecordDelimiter(char value) noexcept
{
    return value == '\n' || value == '\r';
}

constexpr bool remoteLogCapturedReadIsExact(qint64 requestedBytes,
                                            qint64 actualBytes) noexcept
{
    return requestedBytes >= 0 && actualBytes == requestedBytes;
}

constexpr bool remoteLogCapturedTailIsPartial(qint64 byteCount,
                                              bool endsWithRecordDelimiter) noexcept
{
    return byteCount > 0 && !endsWithRecordDelimiter;
}

inline RemoteLogSanitizerSecretSet remoteLogSanitizerSecretUnion(
        const RemoteLogSanitizerSecretSet &inherited,
        const QStringList &current)
{
    RemoteLogSanitizerSecretSet result = inherited;
    if (result.forceRedacted) {
        return result;
    }

    for (const QString &value : current) {
        if (value.isEmpty() || result.values.contains(value)) {
            continue;
        }
        if (result.values.size() >= MaximumRemoteLogSanitizerExplicitSecrets) {
            // Never discard an inherited secret in favour of a bounded list:
            // redacting the complete payload is the only safe overflow policy.
            result.values.clear();
            result.forceRedacted = true;
            break;
        }
        result.values.append(value);
    }
    return result;
}

constexpr bool remoteLogBatchCanBecomeHealthy(bool batchHadFailure,
                                               bool allExpectedSourcesReadable,
                                               bool hasPendingSourceScan,
                                               bool rerunRequested,
                                               bool privacyFailClosed,
                                               bool privacyQuarantined,
                                               bool wholeRedactionUsed) noexcept
{
    return !batchHadFailure && allExpectedSourcesReadable
            && !hasPendingSourceScan && !rerunRequested
            && !privacyFailClosed && !privacyQuarantined
            && !wholeRedactionUsed;
}

} // namespace amnezia

#endif // REMOTELOGBATCHHEALTH_H
