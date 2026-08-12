#ifndef SELFHOSTEDUPDATEBOOTSTRAPPER_H
#define SELFHOSTEDUPDATEBOOTSTRAPPER_H

#include <QObject>
#include <QByteArray>
#include <QDir>
#include <QJsonObject>
#include <QList>
#include <QMetaObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QThread>
#include <QUrl>

#include <memory>
#include <type_traits>
#include <utility>

#include "core/utils/commonStructs.h"

class SecureServersRepository;

namespace amnezia::selfhostedUpdates
{
    constexpr qint64 maximumPolicyGeneration = 9007199254740991LL;
    constexpr qsizetype maximumBootstrapPhaseOutputBytes = 64 * 1024;
    constexpr int maximumAutomaticPublishAttempts = 3;
    constexpr int initialAutomaticPublishDelayMs = 15 * 1000;
    constexpr int firstAutomaticPublishRetryDelayMs = 60 * 1000;
    constexpr int secondAutomaticPublishRetryDelayMs = 5 * 60 * 1000;

    struct AutomaticPublishRetryState {
        bool scheduled = false;
        bool inProgress = false;
        bool succeeded = false;
        bool exhausted = false;
        int attemptCount = 0;
    };

    enum class AutomaticPublishStartDisposition {
        Schedule,
        Coalesce,
        Disabled,
    };

    enum class AutomaticPublishCompletionDisposition {
        Succeeded,
        Retry,
        Exhausted,
    };

    inline AutomaticPublishStartDisposition automaticPublishStartDisposition(
            const AutomaticPublishRetryState &state)
    {
        if (state.scheduled || state.inProgress) {
            return AutomaticPublishStartDisposition::Coalesce;
        }
        if (state.succeeded || state.exhausted
            || state.attemptCount >= maximumAutomaticPublishAttempts) {
            return AutomaticPublishStartDisposition::Disabled;
        }
        return AutomaticPublishStartDisposition::Schedule;
    }

    inline int automaticPublishDelayMs(const AutomaticPublishRetryState &state)
    {
        return state.attemptCount == 0
                ? initialAutomaticPublishDelayMs
                : (state.attemptCount == 1
                           ? firstAutomaticPublishRetryDelayMs
                           : secondAutomaticPublishRetryDelayMs);
    }

    inline void beginAutomaticPublishAttempt(AutomaticPublishRetryState &state)
    {
        state.scheduled = false;
        state.inProgress = true;
        ++state.attemptCount;
    }

    inline AutomaticPublishCompletionDisposition completeAutomaticPublishAttempt(
            AutomaticPublishRetryState &state, bool success)
    {
        state.inProgress = false;
        state.succeeded = success;
        if (success) {
            return AutomaticPublishCompletionDisposition::Succeeded;
        }
        if (state.attemptCount < maximumAutomaticPublishAttempts) {
            return AutomaticPublishCompletionDisposition::Retry;
        }

        // Keep the exhausted latch set while publishFinished(false) is emitted,
        // so a future direct signal receiver cannot re-enter a fourth attempt.
        state.attemptCount = 0;
        state.exhausted = true;
        return AutomaticPublishCompletionDisposition::Exhausted;
    }

    inline void rearmAutomaticPublishAfterNotification(AutomaticPublishRetryState &state)
    {
        state.exhausted = false;
    }

    inline bool accountBoundedRemoteOutput(qsizetype &acceptedBytes,
                                           const QString &chunk,
                                           qsizetype maximumBytes = maximumBootstrapPhaseOutputBytes)
    {
        if (maximumBytes < 0 || acceptedBytes < 0 || acceptedBytes > maximumBytes) {
            return false;
        }

        const qsizetype chunkBytes = chunk.toUtf8().size();
        if (chunkBytes > maximumBytes - acceptedBytes) {
            return false;
        }

        acceptedBytes += chunkBytes;
        return true;
    }

    using QueuedDeliveryContext = std::shared_ptr<QObject>;

    inline QueuedDeliveryContext makeQueuedDeliveryContext()
    {
        return QueuedDeliveryContext(new QObject, [](QObject *context) {
            context->deleteLater();
        });
    }

    template<typename Target, typename Callback>
    inline bool enqueueGuardedCompletion(QueuedDeliveryContext context,
                                         const QPointer<Target> &target,
                                         Callback &&callback)
    {
        QObject *const dispatchContext = context.get();
        using StoredCallback = std::decay_t<Callback>;
        return QMetaObject::invokeMethod(
                dispatchContext,
                [context = std::move(context),
                 target,
                 callback = StoredCallback(std::forward<Callback>(callback))]() mutable {
                    Q_UNUSED(context);
                    if (Target *const resolved = target.data()) {
                        callback(resolved);
                    }
                },
                Qt::QueuedConnection);
    }

    inline bool isCanonicalSha256(const QString &value)
    {
        if (value.size() != 64) {
            return false;
        }

        for (const QChar ch : value) {
            if (!((ch >= u'0' && ch <= u'9') || (ch >= u'a' && ch <= u'f'))) {
                return false;
            }
        }
        return true;
    }

    inline bool isCanonicalNonnegativeDecimal(const QString &value)
    {
        if (value.isEmpty() || (value.size() > 1 && value.startsWith(u'0'))) {
            return false;
        }
        for (const QChar ch : value) {
            if (ch < u'0' || ch > u'9') {
                return false;
            }
        }
        return true;
    }

    inline bool isCanonicalReleaseVersion(const QString &value)
    {
        const QStringList components = value.split(u'.', Qt::KeepEmptyParts);
        if (components.size() != 4) {
            return false;
        }
        for (const QString &component : components) {
            bool parsed = false;
            const qlonglong number = component.toLongLong(&parsed);
            if (!isCanonicalNonnegativeDecimal(component) || !parsed || number > 2147483647LL) {
                return false;
            }
        }
        return true;
    }

    struct BundledManifestIdentity {
        int schema = 0;
        QString version;
        QString generation;
        QByteArray payloadBytes;
        QJsonObject releaseContent;
    };

    enum class BundledPublishTransitionResult {
        Allowed,
        InvalidCandidate,
        InvalidCurrent,
        VersionDowngrade,
        SchemaDowngrade,
        GenerationRollback,
        GenerationRebound,
        SameVersionContentChanged,
    };

    enum class BundledPostCommitDisposition {
        FinalizeAndCleanup,
        RolledBackAndCleanup,
        PreserveRecoveryEvidence,
    };

    enum class BundledMutationReconciliation {
        Acknowledged,
        AppliedWithoutAcknowledgement,
        NotApplied,
        Indeterminate,
    };

    inline BundledMutationReconciliation reconcileBundledMutation(
            bool receiptAcknowledged,
            const QString &observedManifestSha256,
            const QString &desiredManifestSha256,
            const QString &priorManifestSha256)
    {
        if (receiptAcknowledged) {
            return BundledMutationReconciliation::Acknowledged;
        }
        if (observedManifestSha256 == desiredManifestSha256) {
            return BundledMutationReconciliation::AppliedWithoutAcknowledgement;
        }
        if (observedManifestSha256 == priorManifestSha256) {
            return BundledMutationReconciliation::NotApplied;
        }
        return BundledMutationReconciliation::Indeterminate;
    }

    inline BundledPostCommitDisposition bundledPostCommitDisposition(
            bool endpointVerified,
            bool candidateWasAlreadyCurrent,
            bool rollbackSucceeded)
    {
        if (endpointVerified || candidateWasAlreadyCurrent) {
            return BundledPostCommitDisposition::FinalizeAndCleanup;
        }
        return rollbackSucceeded
                ? BundledPostCommitDisposition::RolledBackAndCleanup
                : BundledPostCommitDisposition::PreserveRecoveryEvidence;
    }

    inline bool canonicalPolicyGeneration(const QString &value, qint64 &generationOut)
    {
        generationOut = -1;
        bool parsed = false;
        const qlonglong generation = value.toLongLong(&parsed);
        if (!parsed || !isCanonicalNonnegativeDecimal(value) || generation < 1
            || generation > maximumPolicyGeneration) {
            return false;
        }
        generationOut = generation;
        return true;
    }

    inline bool compareCanonicalReleaseVersions(const QString &left, const QString &right, int &comparisonOut)
    {
        comparisonOut = 0;
        if (!isCanonicalReleaseVersion(left) || !isCanonicalReleaseVersion(right)) {
            return false;
        }
        const QStringList leftComponents = left.split(u'.');
        const QStringList rightComponents = right.split(u'.');
        for (int index = 0; index < leftComponents.size(); ++index) {
            const qlonglong leftValue = leftComponents.at(index).toLongLong();
            const qlonglong rightValue = rightComponents.at(index).toLongLong();
            if (leftValue == rightValue) {
                continue;
            }
            comparisonOut = leftValue < rightValue ? -1 : 1;
            return true;
        }
        return true;
    }

    inline bool isValidBundledManifestIdentity(const BundledManifestIdentity &identity)
    {
        if ((identity.schema != 1 && identity.schema != 2)
            || !isCanonicalReleaseVersion(identity.version) || identity.payloadBytes.isEmpty()) {
            return false;
        }
        qint64 generation = -1;
        return identity.schema == 1
                ? identity.generation.isEmpty()
                : canonicalPolicyGeneration(identity.generation, generation);
    }

    inline BundledPublishTransitionResult validateBundledPublishTransition(
            const BundledManifestIdentity *current,
            const BundledManifestIdentity &candidate)
    {
        if (!isValidBundledManifestIdentity(candidate)) {
            return BundledPublishTransitionResult::InvalidCandidate;
        }
        if (!current) {
            return BundledPublishTransitionResult::Allowed;
        }
        if (!isValidBundledManifestIdentity(*current)) {
            return BundledPublishTransitionResult::InvalidCurrent;
        }

        int versionComparison = 0;
        if (!compareCanonicalReleaseVersions(candidate.version, current->version, versionComparison)) {
            return BundledPublishTransitionResult::InvalidCandidate;
        }
        if (versionComparison < 0) {
            return BundledPublishTransitionResult::VersionDowngrade;
        }

        qint64 currentGeneration = -1;
        qint64 candidateGeneration = -1;
        if (current->schema == 2) {
            if (candidate.schema != 2) {
                return BundledPublishTransitionResult::SchemaDowngrade;
            }
            if (!canonicalPolicyGeneration(current->generation, currentGeneration)) {
                return BundledPublishTransitionResult::InvalidCurrent;
            }
            if (!canonicalPolicyGeneration(candidate.generation, candidateGeneration)) {
                return BundledPublishTransitionResult::InvalidCandidate;
            }
            if (candidateGeneration < currentGeneration) {
                return BundledPublishTransitionResult::GenerationRollback;
            }
            if (candidateGeneration == currentGeneration
                && candidate.payloadBytes != current->payloadBytes) {
                return BundledPublishTransitionResult::GenerationRebound;
            }
        } else if (candidate.schema == 2
                   && !canonicalPolicyGeneration(candidate.generation, candidateGeneration)) {
            return BundledPublishTransitionResult::InvalidCandidate;
        }

        if (versionComparison == 0 && candidate.payloadBytes != current->payloadBytes) {
            const bool policyOnlyAdvance = candidate.schema == 2
                    && candidate.releaseContent == current->releaseContent
                    && (current->schema == 1 || candidateGeneration > currentGeneration);
            if (!policyOnlyAdvance) {
                return BundledPublishTransitionResult::SameVersionContentChanged;
            }
        }
        return BundledPublishTransitionResult::Allowed;
    }

    // Bundled update payloads are local files.  Keep the manifest URL as a
    // validated relative filesystem path so publishing retains the
    // content-addressed files/artifacts/<sha256>/<filename> hierarchy.
    inline bool bundledArtifactRelativePath(const QString &urlText,
                                            const QString &expectedSha256,
                                            QString &relativePathOut)
    {
        relativePathOut.clear();
        if (!isCanonicalSha256(expectedSha256)) {
            return false;
        }

        const QUrl url(urlText, QUrl::StrictMode);
        if (!url.isValid() || url.isEmpty() || !url.scheme().isEmpty() || !url.authority().isEmpty()
            || url.hasQuery() || url.hasFragment()) {
            return false;
        }

        const QString decodedPath = url.path(QUrl::FullyDecoded);
        if (decodedPath.isEmpty() || QDir::isAbsolutePath(decodedPath) || decodedPath.startsWith(u'\\')) {
            return false;
        }

        const QStringList segments = decodedPath.split(u'/', Qt::KeepEmptyParts);
        if (segments.size() != 4
            || segments.at(0) != QStringLiteral("files")
            || segments.at(1) != QStringLiteral("artifacts")
            || !isCanonicalSha256(segments.at(2))
            || segments.at(2) != expectedSha256) {
            return false;
        }

        const QString &fileName = segments.at(3);
        if (fileName.isEmpty() || fileName == QStringLiteral(".") || fileName == QStringLiteral("..")
            || fileName.contains(u'/') || fileName.contains(u'\\') || fileName.contains(u':')
            || fileName.contains(QChar::Null)) {
            return false;
        }
        for (const QChar ch : fileName) {
            if (ch.category() == QChar::Other_Control) {
                return false;
            }
        }

        relativePathOut = QStringLiteral("files/artifacts/%1/%2").arg(segments.at(2), fileName);
        return true;
    }

    inline bool bundledRollbackArtifactRelativePath(const QString &urlText,
                                                    const QString &expectedGeneration,
                                                    const QString &expectedVersion,
                                                    QString &relativePathOut)
    {
        relativePathOut.clear();
        if (!isCanonicalNonnegativeDecimal(expectedGeneration) || !isCanonicalReleaseVersion(expectedVersion)) {
            return false;
        }

        const QUrl url(urlText, QUrl::StrictMode);
        if (!url.isValid() || url.isEmpty() || !url.scheme().isEmpty() || !url.authority().isEmpty()
            || url.hasQuery() || url.hasFragment()) {
            return false;
        }

        const QString decodedPath = url.path(QUrl::FullyDecoded);
        if (decodedPath.isEmpty() || QDir::isAbsolutePath(decodedPath) || decodedPath.startsWith(u'\\')) {
            return false;
        }

        const QStringList segments = decodedPath.split(u'/', Qt::KeepEmptyParts);
        if (segments.size() != 5
            || segments.at(0) != QStringLiteral("files")
            || segments.at(1) != QStringLiteral("rollback")
            || !isCanonicalNonnegativeDecimal(segments.at(2))
            || segments.at(2) != expectedGeneration
            || !isCanonicalReleaseVersion(segments.at(3))
            || segments.at(3) != expectedVersion) {
            return false;
        }

        const QString &fileName = segments.at(4);
        if (fileName.isEmpty() || fileName == QStringLiteral(".") || fileName == QStringLiteral("..")
            || fileName.contains(u'/') || fileName.contains(u'\\') || fileName.contains(u':')
            || fileName.contains(QChar::Null)) {
            return false;
        }
        for (const QChar ch : fileName) {
            if (ch.category() == QChar::Other_Control) {
                return false;
            }
        }

        relativePathOut = QStringLiteral("files/rollback/%1/%2/%3").arg(
                segments.at(2), segments.at(3), fileName);
        return true;
    }

    inline QString bundledArtifactRequestPath(const QString &validatedRelativeUrl)
    {
        QString path = QUrl(validatedRelativeUrl, QUrl::StrictMode).path(QUrl::FullyEncoded);
        if (!path.startsWith(u'/')) {
            path.prepend(u'/');
        }
        return path;
    }

}

class SelfHostedUpdateBootstrapper : public QObject
{
    Q_OBJECT

public:
    explicit SelfHostedUpdateBootstrapper(SecureServersRepository *serversRepository, QObject *parent = nullptr);

    bool start();
    bool publishNow();

signals:
    void publishFinished(bool success);

private:
    struct PayloadFile {
        QString platform;
        QString localPath;
        QString relativePath;
        QString relativeUrlPath;
        QString sha256;
        qint64 size = -1;
        bool rollback = false;
    };

    struct Payload {
        QString rootDir;
        QString manifestPath;
        QString version;
        QList<PayloadFile> files;
        QByteArray manifestSha256;
        QByteArray manifestData;
        amnezia::selfhostedUpdates::BundledManifestIdentity manifestIdentity;
    };

    QString findPayloadDir() const;
    bool loadPayload(const QString &payloadDir, Payload &payload) const;
    bool selectServerCredentials(amnezia::ServerCredentials &credentials) const;
    static bool publishPayload(Payload payload, amnezia::ServerCredentials credentials);

    amnezia::selfhostedUpdates::AutomaticPublishRetryState m_publishRetryState;
    SecureServersRepository *m_serversRepository = nullptr;
};

#endif // SELFHOSTEDUPDATEBOOTSTRAPPER_H
