#include "selfHostedUpdateBootstrapper.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>
#include <QPointer>
#include <QRandomGenerator>
#include <QSet>
#include <QThreadPool>
#include <QTimer>
#include <QVariant>

#include <cmath>
#include <limits>

#include <openssl/evp.h>
#include <openssl/pem.h>

#if defined(Q_OS_WIN)
#include <windows.h>
#endif

#include "core/repositories/secureServersRepository.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/selfhosted/sshSession.h"
#include "logger.h"

namespace
{
    Logger logger("SelfHostedUpdateBootstrapper");

    constexpr auto kPayloadDirName = "selfhosted_updates";
    constexpr auto kManifestName = "manifest.json";
    constexpr auto kFilesDirName = "files";
    constexpr auto kInstallHostScript = ":/server_scripts/update_host/install_server_update_host.sh";
    constexpr auto kVerifiedInstallHostRunner = ":/server_scripts/update_host/run_verified_update_host_installer.sh";
    constexpr auto kBundledPublishScript = ":/server_scripts/update_host/publish_bundled_release.sh";
    constexpr auto kUpdateHostImage = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
    constexpr qsizetype kMaximumManifestBytes = 1024 * 1024;
    constexpr qsizetype kMaximumPublishMetadataBytes = 64 * 1024;
    constexpr qsizetype kMaximumBundledFiles = 64;
    constexpr qsizetype kMaximumRelativePathBytes = 1024;
    constexpr int kInstallerOuterSshTimeoutMs = 20 * 60 * 1000;

#ifndef SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64
#define SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 ""
#endif

    QString shellQuote(const QString &value)
    {
        return QStringLiteral("'") + QString(value).replace(QStringLiteral("'"), QStringLiteral("'\\''")) + QStringLiteral("'");
    }

    QByteArray fileSha256(const QString &path)
    {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            return {};
        }

        QCryptographicHash hash(QCryptographicHash::Sha256);
        if (!hash.addData(&file)) {
            return {};
        }
        return hash.result().toHex();
    }

    bool isPathWithinRoot(const QString &path, const QString &root)
    {
        const QString normalizedPath = QDir::cleanPath(path);
        const QString normalizedRoot = QDir::cleanPath(root);
#if defined(Q_OS_WIN)
        constexpr Qt::CaseSensitivity caseSensitivity = Qt::CaseInsensitive;
#else
        constexpr Qt::CaseSensitivity caseSensitivity = Qt::CaseSensitive;
#endif
        return normalizedPath.compare(normalizedRoot, caseSensitivity) == 0
                || normalizedPath.startsWith(normalizedRoot + u'/', caseSensitivity);
    }

    bool hasSymlinkOrReparsePoint(const QDir &root, const QString &relativePath)
    {
        QString componentPath = root.absolutePath();
        for (const QString &segment : relativePath.split(u'/', Qt::SkipEmptyParts)) {
            componentPath = QDir(componentPath).filePath(segment);
            const QFileInfo componentInfo(componentPath);
            if (componentInfo.isSymLink()) {
                return true;
            }
#if defined(Q_OS_WIN)
            const DWORD attributes = GetFileAttributesW(reinterpret_cast<LPCWSTR>(componentPath.utf16()));
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                return true;
            }
#endif
        }
        return false;
    }

    bool canonicalPolicyGenerationValue(const QJsonValue &value, QString &generationOut)
    {
        generationOut.clear();
        if (!value.isDouble()) {
            return false;
        }

        const double rawGeneration = value.toDouble(-1.0);
        if (!std::isfinite(rawGeneration) || rawGeneration < 1.0
            || rawGeneration > amnezia::selfhostedUpdates::maximumPolicyGeneration
            || std::floor(rawGeneration) != rawGeneration) {
            return false;
        }

        generationOut = QString::number(static_cast<qint64>(rawGeneration));
        return amnezia::selfhostedUpdates::isCanonicalNonnegativeDecimal(generationOut);
    }

    bool decodeStrictBase64(const QByteArray &encoded, QByteArray::Base64Options options, QByteArray &decoded)
    {
        const QByteArray::FromBase64Result result = QByteArray::fromBase64Encoding(
                encoded, options | QByteArray::AbortOnBase64DecodingErrors);
        if (!result) {
            decoded.clear();
            return false;
        }

        decoded = result.decoded;
        if (decoded.toBase64(options) != encoded) {
            decoded.clear();
            return false;
        }
        return true;
    }

    bool verifyManifestSignature(const QJsonObject &manifest)
    {
        if (manifest.value(QStringLiteral("schema")).toString() != QStringLiteral("amnezia-selfhosted-update-v1")
            || manifest.value(QStringLiteral("signatureAlgorithm")).toString() != QStringLiteral("Ed25519")) {
            return false;
        }

        QByteArray payload;
        QByteArray signature;
        QByteArray publicKeyPem;
        if (!decodeStrictBase64(manifest.value(QStringLiteral("payload")).toString().toUtf8(),
                                QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals,
                                payload)
            || !decodeStrictBase64(manifest.value(QStringLiteral("signature")).toString().toUtf8(),
                                   QByteArray::Base64Encoding,
                                   signature)
            || !decodeStrictBase64(QByteArray(SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64),
                                   QByteArray::Base64Encoding,
                                   publicKeyPem)
            || payload.isEmpty() || signature.size() != 64 || publicKeyPem.isEmpty()) {
            return false;
        }

        BIO *bio = BIO_new_mem_buf(publicKeyPem.constData(), publicKeyPem.size());
        if (!bio) {
            return false;
        }
        EVP_PKEY *publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!publicKey) {
            return false;
        }

        bool ok = false;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx) {
            ok = EVP_PKEY_base_id(publicKey) == EVP_PKEY_ED25519
                    && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, publicKey) == 1
                    && EVP_DigestVerify(ctx,
                                        reinterpret_cast<const unsigned char *>(signature.constData()),
                                        static_cast<size_t>(signature.size()),
                                        reinterpret_cast<const unsigned char *>(payload.constData()),
                                        static_cast<size_t>(payload.size())) == 1;
            EVP_MD_CTX_free(ctx);
        }
        EVP_PKEY_free(publicKey);
        return ok;
    }

    bool decodeManifestPayload(const QJsonObject &manifest, QJsonObject &payloadOut, QByteArray &payloadBytesOut)
    {
        const QByteArray encodedPayload = manifest.value(QStringLiteral("payload")).toString().toUtf8();
        QByteArray payloadBytes;
        if (encodedPayload.isEmpty()
            || !decodeStrictBase64(encodedPayload,
                                   QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals,
                                   payloadBytes)
            || payloadBytes.isEmpty()) {
            return false;
        }

        QJsonParseError error {};
        const QJsonDocument payloadDoc = QJsonDocument::fromJson(payloadBytes, &error);
        if (error.error != QJsonParseError::NoError || !payloadDoc.isObject()) {
            return false;
        }

        payloadOut = payloadDoc.object();
        payloadBytesOut = payloadBytes;
        return true;
    }

    bool parseVerifiedManifest(const QByteArray &manifestData,
                               QJsonObject &manifestOut,
                               QJsonObject &payloadOut,
                               amnezia::selfhostedUpdates::BundledManifestIdentity &identityOut)
    {
        if (manifestData.isEmpty() || manifestData.size() > kMaximumManifestBytes) {
            return false;
        }

        QJsonParseError error {};
        const QJsonDocument manifestDoc = QJsonDocument::fromJson(manifestData, &error);
        if (error.error != QJsonParseError::NoError || !manifestDoc.isObject()) {
            return false;
        }
        const QJsonObject manifest = manifestDoc.object();
        if (!verifyManifestSignature(manifest)) {
            return false;
        }

        QByteArray payloadBytes;
        QJsonObject payload;
        if (!decodeManifestPayload(manifest, payload, payloadBytes)) {
            return false;
        }

        const QJsonValue schemaValue = payload.value(QStringLiteral("schema"));
        if (!schemaValue.isDouble()) {
            return false;
        }
        const double rawSchema = schemaValue.toDouble(-1.0);
        if (!std::isfinite(rawSchema) || std::floor(rawSchema) != rawSchema
            || (rawSchema != 1.0 && rawSchema != 2.0)) {
            return false;
        }

        amnezia::selfhostedUpdates::BundledManifestIdentity identity;
        identity.schema = static_cast<int>(rawSchema);
        identity.version = payload.value(QStringLiteral("version")).toString();
        identity.payloadBytes = payloadBytes;
        identity.releaseContent = payload;
        identity.releaseContent.remove(QStringLiteral("schema"));
        identity.releaseContent.remove(QStringLiteral("releasePolicy"));

        if (identity.schema == 2) {
            const QJsonObject policy = payload.value(QStringLiteral("releasePolicy")).toObject();
            if (policy.value(QStringLiteral("schema")).toInt(-1) != 2
                || !canonicalPolicyGenerationValue(policy.value(QStringLiteral("generation")), identity.generation)) {
                return false;
            }
        }
        if (!amnezia::selfhostedUpdates::isValidBundledManifestIdentity(identity)) {
            return false;
        }

        manifestOut = manifest;
        payloadOut = payload;
        identityOut = identity;
        return true;
    }

    QString transitionFailureName(amnezia::selfhostedUpdates::BundledPublishTransitionResult result)
    {
        using Result = amnezia::selfhostedUpdates::BundledPublishTransitionResult;
        switch (result) {
        case Result::Allowed: return QStringLiteral("allowed");
        case Result::InvalidCandidate: return QStringLiteral("invalid_candidate");
        case Result::InvalidCurrent: return QStringLiteral("invalid_current");
        case Result::VersionDowngrade: return QStringLiteral("version_downgrade");
        case Result::SchemaDowngrade: return QStringLiteral("schema_downgrade");
        case Result::GenerationRollback: return QStringLiteral("generation_rollback");
        case Result::GenerationRebound: return QStringLiteral("generation_rebound");
        case Result::SameVersionContentChanged: return QStringLiteral("same_version_content_changed");
        }
        return QStringLiteral("unknown");
    }

    QString randomPublishRunId()
    {
        QString result;
        result.reserve(48);
        for (int index = 0; index < 6; ++index) {
            result += QString::number(QRandomGenerator::system()->generate(), 16).rightJustified(8, u'0');
        }
        return result;
    }

    bool hasExactHeadlessProvisioningFiles(const QJsonValue &value)
    {
        if (!value.isArray()) {
            return false;
        }
        static const QStringList expected {
            QStringLiteral("install_headless.sh"), QStringLiteral("amneziad"),
            QStringLiteral("amnezia-cli"), QStringLiteral("amneziad.service"),
            QStringLiteral("package-manifest.json"), QStringLiteral("runtime-dependencies.json"),
            QStringLiteral("runtime-dependencies.txt"), QStringLiteral("SHA256SUMS")
        };
        const QJsonArray files = value.toArray();
        if (files.size() != expected.size()) {
            return false;
        }
        for (qsizetype index = 0; index < files.size(); ++index) {
            if (!files.at(index).isString() || files.at(index).toString() != expected.at(index)) {
                return false;
            }
        }
        return true;
    }

}

SelfHostedUpdateBootstrapper::SelfHostedUpdateBootstrapper(SecureServersRepository *serversRepository, QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository)
{
}

bool SelfHostedUpdateBootstrapper::start()
{
    using namespace amnezia::selfhostedUpdates;
    const AutomaticPublishStartDisposition startDisposition =
            automaticPublishStartDisposition(m_publishRetryState);
    if (startDisposition == AutomaticPublishStartDisposition::Coalesce) {
        return true;
    }
    if (startDisposition == AutomaticPublishStartDisposition::Disabled) {
        return false;
    }

    Payload payload;
    const QString payloadDir = findPayloadDir();
    if (payloadDir.isEmpty() || !loadPayload(payloadDir, payload)) {
        return false;
    }

    amnezia::ServerCredentials credentials;
    if (!selectServerCredentials(credentials)) {
        logger.info() << "Bundled self-hosted update payload is present, but no writable self-hosted server credentials are available";
        return false;
    }

    m_publishRetryState.scheduled = true;
    const int delayMs = automaticPublishDelayMs(m_publishRetryState);
    QTimer::singleShot(delayMs, this, [this, payload, credentials]() {
        amnezia::selfhostedUpdates::beginAutomaticPublishAttempt(m_publishRetryState);
        QPointer<SelfHostedUpdateBootstrapper> self(this);
        auto deliveryContext = amnezia::selfhostedUpdates::makeQueuedDeliveryContext();
        QThreadPool::globalInstance()->start([self, deliveryContext, payload, credentials]() {
            const bool success = publishPayload(payload, credentials);
            amnezia::selfhostedUpdates::enqueueGuardedCompletion(
                    deliveryContext,
                    self,
                    [success](SelfHostedUpdateBootstrapper *bootstrapper) {
                        using namespace amnezia::selfhostedUpdates;
                        const AutomaticPublishCompletionDisposition completionDisposition =
                                completeAutomaticPublishAttempt(
                                        bootstrapper->m_publishRetryState, success);
                        emit bootstrapper->publishFinished(success);
                        if (completionDisposition == AutomaticPublishCompletionDisposition::Retry) {
                            bootstrapper->start();
                        } else if (completionDisposition
                                   == AutomaticPublishCompletionDisposition::Exhausted) {
                            // A later VPN Connected transition starts a fresh
                            // bounded cycle, but not re-entrantly from the
                            // completion signal above.
                            rearmAutomaticPublishAfterNotification(
                                    bootstrapper->m_publishRetryState);
                        }
                    });
        });
    });
    return true;
}

bool SelfHostedUpdateBootstrapper::publishNow()
{
    Payload payload;
    const QString payloadDir = findPayloadDir();
    if (payloadDir.isEmpty() || !loadPayload(payloadDir, payload)) {
        logger.warning() << "No valid bundled self-hosted update payload is available";
        return false;
    }

    amnezia::ServerCredentials credentials;
    if (!selectServerCredentials(credentials)) {
        logger.warning() << "Bundled self-hosted update payload is present, but no writable self-hosted server credentials are available";
        return false;
    }

    return publishPayload(payload, credentials);
}

QString SelfHostedUpdateBootstrapper::findPayloadDir() const
{
    const QString envDir = qEnvironmentVariable("SELFHOSTED_BUNDLED_UPDATE_PAYLOAD_DIR");
    if (!envDir.isEmpty() && QFileInfo::exists(QDir(envDir).filePath(kManifestName))) {
        return QDir(envDir).absolutePath();
    }

    const QString appDir = QCoreApplication::applicationDirPath();
    const QString payloadDir = QDir(appDir).filePath(kPayloadDirName);
    if (QFileInfo::exists(QDir(payloadDir).filePath(kManifestName))) {
        return QDir(payloadDir).absolutePath();
    }
    return {};
}

bool SelfHostedUpdateBootstrapper::loadPayload(const QString &payloadDir, Payload &payload) const
{
    const QDir root(payloadDir);
    const QString manifestPath = root.filePath(kManifestName);
    QFile manifestFile(manifestPath);
    if (!manifestFile.open(QIODevice::ReadOnly)) {
        logger.warning() << "Failed to open bundled update manifest" << manifestPath;
        return false;
    }
    if (manifestFile.size() <= 0 || manifestFile.size() > kMaximumManifestBytes) {
        logger.warning() << "Bundled update manifest exceeds the supported size";
        return false;
    }
    const QByteArray manifestData = manifestFile.read(kMaximumManifestBytes + 1);
    QJsonObject manifest;
    QJsonObject decodedPayload;
    amnezia::selfhostedUpdates::BundledManifestIdentity manifestIdentity;
    if (!parseVerifiedManifest(manifestData, manifest, decodedPayload, manifestIdentity)) {
        logger.warning() << "Bundled update manifest or signature is invalid";
        return false;
    }

    const QJsonObject platforms = decodedPayload.value(QStringLiteral("platforms")).toObject();
    if (platforms.isEmpty()) {
        logger.warning() << "Bundled update manifest has no platforms";
        return false;
    }

    constexpr auto kWindowsPlatform = "windows-x64";
    const QJsonObject windowsArtifact = platforms.value(QString::fromLatin1(kWindowsPlatform)).toObject();
    if (windowsArtifact.isEmpty() || windowsArtifact.value(QStringLiteral("openExternal")).toBool()) {
        logger.warning() << "Bundled update manifest is missing a local platform" << kWindowsPlatform;
        return false;
    }

    const QString canonicalRoot = QFileInfo(root.absolutePath()).canonicalFilePath();
    if (canonicalRoot.isEmpty()) {
        logger.warning() << "Bundled update payload root cannot be canonicalized" << root.absolutePath();
        return false;
    }

    QSet<QString> seenRelativePaths;
    QList<PayloadFile> files;
    const auto appendLocalArtifact = [&root, &canonicalRoot, &seenRelativePaths, &files](
                                             const QString &platform,
                                             const QJsonObject &platformObject,
                                             bool isRollback,
                                             const QString &rollbackGeneration,
                                             const QString &rollbackVersion) {
        const QString expectedSha256 = platformObject.value(QStringLiteral("sha256")).toString();
        if (!amnezia::selfhostedUpdates::isCanonicalSha256(expectedSha256)) {
            logger.warning() << "Bundled update manifest has invalid artifact sha256 for" << platform;
            return false;
        }

        const QString urlText = platformObject.value(QStringLiteral("url")).toString();
        QString relativePath;
        const bool safePath = isRollback
                ? amnezia::selfhostedUpdates::bundledRollbackArtifactRelativePath(
                        urlText, rollbackGeneration, rollbackVersion, relativePath)
                : amnezia::selfhostedUpdates::bundledArtifactRelativePath(urlText, expectedSha256, relativePath);
        if (!safePath) {
            logger.warning() << "Bundled update manifest has unsafe artifact URL for" << platform;
            return false;
        }
        if (seenRelativePaths.contains(relativePath)) {
            logger.warning() << "Bundled update manifest reuses an artifact path" << relativePath;
            return false;
        }
        if (relativePath.toUtf8().size() > kMaximumRelativePathBytes) {
            logger.warning() << "Bundled update artifact path is too long" << relativePath;
            return false;
        }
        seenRelativePaths.insert(relativePath);

        const QString filePath = root.filePath(relativePath);
        const QFileInfo artifactInfo(filePath);
        if (!artifactInfo.isFile()) {
            logger.warning() << "Bundled update artifact is missing" << filePath;
            return false;
        }
        if (hasSymlinkOrReparsePoint(root, relativePath)
            || !isPathWithinRoot(artifactInfo.canonicalFilePath(), canonicalRoot)) {
            logger.warning() << "Bundled update artifact escapes payload root" << filePath;
            return false;
        }

        bool sizeOk = false;
        const qint64 expectedSize = platformObject.value(QStringLiteral("size")).toVariant().toLongLong(&sizeOk);
        if (!sizeOk || expectedSize <= 0) {
            logger.warning() << "Bundled update manifest has invalid artifact size for" << platform;
            return false;
        }
        if (artifactInfo.size() != expectedSize) {
            logger.warning() << "Bundled update artifact size mismatch for" << platform << filePath;
            return false;
        }

        if (fileSha256(filePath) != expectedSha256.toLatin1()) {
            logger.warning() << "Bundled update artifact sha256 mismatch for" << platform << filePath;
            return false;
        }

        const QString relativeUrlPath =
                amnezia::selfhostedUpdates::bundledArtifactRequestPath(urlText);
        files.append({ platform, filePath, relativePath, relativeUrlPath, expectedSha256, expectedSize, isRollback });
        return true;
    };

    for (auto iterator = platforms.constBegin(); iterator != platforms.constEnd(); ++iterator) {
        const QString platform = iterator.key();
        if (platform.contains(QStringLiteral("headless"), Qt::CaseInsensitive)
            && platform != QStringLiteral("linux-headless-x64")) {
            logger.warning() << "Bundled update manifest uses a non-canonical Linux headless platform" << platform;
            return false;
        }
        const QJsonObject platformObject = iterator.value().toObject();
        if (platformObject.isEmpty()) {
            logger.warning() << "Bundled update manifest has invalid platform entry" << platform;
            return false;
        }
        if (platform == QStringLiteral("linux-headless-x64")
            && ((!platformObject.value(QStringLiteral("openExternal")).isUndefined()
                 && !platformObject.value(QStringLiteral("openExternal")).isBool())
                || platformObject.value(QStringLiteral("openExternal")).toBool())) {
            logger.warning() << "Bundled update manifest cannot publish Linux headless as an external artifact";
            return false;
        }
        if (platformObject.value(QStringLiteral("openExternal")).toBool()) {
            continue;
        }
        if (platform == QStringLiteral("linux-headless-x64")
            && platformObject.value(QStringLiteral("format")).toString()
                    != QStringLiteral("amnezia-headless-tar-v1")) {
            logger.warning() << "Bundled update manifest has an invalid Linux headless artifact format";
            return false;
        }
        if (!appendLocalArtifact(platform, platformObject, false, QString(), QString())) {
            return false;
        }
    }

    // The Ubuntu provisioning bundle is a signed release input as well.  It
    // is not a runnable client artifact, but it must travel through the same
    // content-addressed upload and publication transaction so ServerX cannot
    // receive an unsigned service unit or installer script beside a signed
    // manifest.  Convert its dedicated metadata into the common PayloadFile
    // list after validating the stronger format/version contract.
    const bool hasHeadlessPlatform = platforms.contains(QStringLiteral("linux-headless-x64"));
    const QJsonValue provisioningValue = decodedPayload.value(QStringLiteral("headlessProvisioning"));
    if (hasHeadlessPlatform != !provisioningValue.isUndefined()) {
        logger.warning() << "Bundled update manifest must bind Linux headless artifacts to provisioning metadata";
        return false;
    }
    if (!provisioningValue.isUndefined()) {
        if (!provisioningValue.isObject()) {
            logger.warning() << "Bundled update manifest has invalid headless provisioning metadata";
            return false;
        }
        const QJsonObject provisioning = provisioningValue.toObject();
        if (provisioning.size() != 9
            || !provisioning.contains(QStringLiteral("url"))
            || !provisioning.contains(QStringLiteral("sha256"))
            || !provisioning.contains(QStringLiteral("size"))
            || !provisioning.contains(QStringLiteral("format"))
            || !provisioning.contains(QStringLiteral("version"))
            || !provisioning.contains(QStringLiteral("packageManifestSha256"))
            || !provisioning.contains(QStringLiteral("checksumsSha256"))
            || !provisioning.contains(QStringLiteral("packageVersion"))
            || !provisioning.contains(QStringLiteral("packageFiles"))
            || provisioning.value(QStringLiteral("version")).toString() != manifestIdentity.version
            || provisioning.value(QStringLiteral("packageVersion")).toString() != manifestIdentity.version
            || provisioning.value(QStringLiteral("format")).toString()
                   != QStringLiteral("amnezia-headless-provisioning-tar-v1")
            || !provisioning.value(QStringLiteral("url")).isString()
            || !provisioning.value(QStringLiteral("sha256")).isString()
            || !amnezia::selfhostedUpdates::isCanonicalSha256(
                       provisioning.value(QStringLiteral("sha256")).toString())
            || !amnezia::selfhostedUpdates::isCanonicalSha256(
                       provisioning.value(QStringLiteral("packageManifestSha256")).toString())
            || !amnezia::selfhostedUpdates::isCanonicalSha256(
                       provisioning.value(QStringLiteral("checksumsSha256")).toString())
            || !hasExactHeadlessProvisioningFiles(provisioning.value(QStringLiteral("packageFiles")))) {
            logger.warning() << "Bundled update manifest has malformed headless provisioning metadata";
            return false;
        }
        const QJsonValue sizeValue = provisioning.value(QStringLiteral("size"));
        const double rawSize = sizeValue.isDouble() ? sizeValue.toDouble(-1.0) : -1.0;
        if (!std::isfinite(rawSize) || rawSize <= 0.0 || std::floor(rawSize) != rawSize
            || rawSize > static_cast<double>((std::numeric_limits<qint64>::max)())) {
            logger.warning() << "Bundled update manifest has invalid headless provisioning size";
            return false;
        }
        QJsonObject artifact {
            { QStringLiteral("url"), provisioning.value(QStringLiteral("url")) },
            { QStringLiteral("sha256"), provisioning.value(QStringLiteral("sha256")) },
            { QStringLiteral("size"), sizeValue },
        };
        if (!appendLocalArtifact(QStringLiteral("linux-headless-provisioning"), artifact,
                                  false, QString(), QString())) {
            return false;
        }
    }

    const QJsonObject releasePolicy = decodedPayload.value(QStringLiteral("releasePolicy")).toObject();
    if (releasePolicy.contains(QStringLiteral("rollback"))) {
        const QJsonObject rollback = releasePolicy.value(QStringLiteral("rollback")).toObject();
        if (rollback.isEmpty() || releasePolicy.value(QStringLiteral("schema")).toInt() != 2) {
            logger.warning() << "Bundled update manifest has invalid rollback policy";
            return false;
        }

        QString rollbackGeneration;
        const QString rollbackVersion = rollback.value(QStringLiteral("version")).toString();
        if (!canonicalPolicyGenerationValue(releasePolicy.value(QStringLiteral("generation")), rollbackGeneration)
            || !amnezia::selfhostedUpdates::isCanonicalReleaseVersion(rollbackVersion)
            || rollbackVersion != releasePolicy.value(QStringLiteral("previousVersion")).toString()) {
            logger.warning() << "Bundled update manifest has invalid rollback identity";
            return false;
        }

        const QJsonObject rollbackPlatforms = rollback.value(QStringLiteral("platforms")).toObject();
        if (rollbackPlatforms.isEmpty()) {
            logger.warning() << "Bundled update manifest has no rollback platforms";
            return false;
        }
        for (auto iterator = rollbackPlatforms.constBegin(); iterator != rollbackPlatforms.constEnd(); ++iterator) {
            const QString rollbackPlatform = iterator.key();
            if (rollbackPlatform.contains(QStringLiteral("headless"), Qt::CaseInsensitive)
                && rollbackPlatform != QStringLiteral("linux-headless-x64")) {
                logger.warning() << "Bundled rollback manifest uses a non-canonical Linux headless platform"
                                 << rollbackPlatform;
                return false;
            }
            const QString platform = QStringLiteral("rollback:") + iterator.key();
            const QJsonObject platformObject = iterator.value().toObject();
            if (platformObject.isEmpty()
                || (!platformObject.value(QStringLiteral("openExternal")).isUndefined()
                    && !platformObject.value(QStringLiteral("openExternal")).isBool())
                || platformObject.value(QStringLiteral("openExternal")).toBool()
                || (rollbackPlatform == QStringLiteral("linux-headless-x64")
                    && platformObject.value(QStringLiteral("format")).toString()
                           != QStringLiteral("amnezia-headless-tar-v1"))
                || !appendLocalArtifact(platform, platformObject, true, rollbackGeneration, rollbackVersion)) {
                logger.warning() << "Bundled update manifest has invalid rollback artifact" << platform;
                return false;
            }
        }
    }

    if (files.isEmpty() || files.size() > kMaximumBundledFiles) {
        logger.warning() << "Bundled update manifest has an unsupported local file count" << files.size();
        return false;
    }

    payload.rootDir = root.absolutePath();
    payload.manifestPath = manifestPath;
    payload.version = manifestIdentity.version;
    payload.files = files;
    payload.manifestData = manifestData;
    payload.manifestSha256 = QCryptographicHash::hash(manifestData, QCryptographicHash::Sha256).toHex();
    payload.manifestIdentity = manifestIdentity;
    return !payload.version.isEmpty() && !payload.manifestSha256.isEmpty();
}

bool SelfHostedUpdateBootstrapper::selectServerCredentials(amnezia::ServerCredentials &credentials) const
{
    if (!m_serversRepository) {
        return false;
    }

    const auto selectByServerId = [this, &credentials](const QString &serverId) {
        if (serverId.isEmpty()) {
            return false;
        }
        const auto config = m_serversRepository->selfHostedAdminConfig(serverId);
        if (!config || !config->hasCredentials()) {
            return false;
        }
        credentials = config->credentials();
        return credentials.isValid();
    };

    return selectByServerId(m_serversRepository->defaultServerId());
}

bool SelfHostedUpdateBootstrapper::publishPayload(Payload payload, amnezia::ServerCredentials credentials)
{
    logger.info() << "Publishing bundled self-hosted update payload" << payload.version;

    SshSession sshSession;
    const QString serverDir = QString::fromLatin1(amnezia::protocols::selfHostedUpdates::hostDirectory);
    const QString remoteManifest = serverDir + QStringLiteral("/") + QString::fromLatin1(kManifestName);
    if (serverDir != QStringLiteral("/opt/amnezia/client-updates")) {
        logger.warning() << "Bundled publisher root does not match the pinned server protocol" << serverDir;
        return false;
    }

    const QString runId = randomPublishRunId();
    const QString remoteTmp = QStringLiteral("/tmp/amnezia-client-updates.%1").arg(runId);
    const QString remotePublisherScript = remoteTmp + QStringLiteral("/publish_bundled_release.sh");
    amnezia::ErrorCode error = sshSession.runScript(credentials,
                                                    QStringLiteral("umask 077 && test ! -e %1 && "
                                                                   "mkdir -m 0700 -- %1 && "
                                                                   "test -d %1 && ! test -L %1")
                                                            .arg(shellQuote(remoteTmp)));
    if (error != amnezia::ErrorCode::NoError) {
        logger.warning() << "Failed to prepare remote update payload directory";
        return false;
    }
    const auto cleanupRemoteTmp = [&sshSession, &credentials, &remoteTmp]() {
        return sshSession.runScript(credentials, QStringLiteral("rm -rf -- %1").arg(shellQuote(remoteTmp)));
    };

    QFile publisherScriptFile(QString::fromLatin1(kBundledPublishScript));
    if (!publisherScriptFile.open(QIODevice::ReadOnly)) {
        logger.warning() << "Bundled release publisher script is missing";
        cleanupRemoteTmp();
        return false;
    }
    QByteArray publisherScript = publisherScriptFile.readAll();
    publisherScript.replace("\r\n", "\n");
    publisherScript.replace('\r', '\n');
    error = sshSession.uploadFileToHost(credentials, publisherScript, remotePublisherScript);
    if (error != amnezia::ErrorCode::NoError) {
        logger.warning() << "Failed to upload bundled release publisher script";
        cleanupRemoteTmp();
        return false;
    }

    QByteArray probeOutput;
    const auto captureProbeOutput = [&probeOutput](const QString &data, libssh::Client &) {
        probeOutput += data.toUtf8();
        return probeOutput.size() <= kMaximumManifestBytes + 32
                ? amnezia::ErrorCode::NoError : amnezia::ErrorCode::ReadError;
    };
    QString probeError;
    const auto captureProbeError = [&probeError](const QString &data, libssh::Client &) {
        if (probeError.size() < 2048) {
            probeError += data.left(2048 - probeError.size());
        }
        return amnezia::ErrorCode::NoError;
    };
    error = sshSession.runScript(credentials,
                                 QStringLiteral("sh %1 probe %2")
                                         .arg(shellQuote(remotePublisherScript), shellQuote(serverDir)),
                                 captureProbeOutput,
                                 captureProbeError);
    if (error != amnezia::ErrorCode::NoError) {
        logger.warning() << "Failed to read the currently published manifest" << probeError.trimmed();
        cleanupRemoteTmp();
        return false;
    }

    QByteArray expectedCurrentManifestSha256;
    QByteArray currentManifestData;
    amnezia::selfhostedUpdates::BundledManifestIdentity currentIdentity;
    const amnezia::selfhostedUpdates::BundledManifestIdentity *currentIdentityPointer = nullptr;
    if (probeOutput == QByteArrayLiteral("ABSENT\n")) {
        expectedCurrentManifestSha256 = QByteArrayLiteral("absent");
    } else if (probeOutput.startsWith(QByteArrayLiteral("PRESENT\n"))) {
        currentManifestData = probeOutput.mid(8);
        QJsonObject currentManifest;
        QJsonObject currentPayload;
        if (currentManifestData.isEmpty() || currentManifestData.size() > kMaximumManifestBytes
            || !parseVerifiedManifest(currentManifestData, currentManifest, currentPayload, currentIdentity)) {
            logger.warning() << "Published self-hosted update manifest or signature is invalid";
            cleanupRemoteTmp();
            return false;
        }
        expectedCurrentManifestSha256 = QCryptographicHash::hash(
                currentManifestData, QCryptographicHash::Sha256).toHex();
        currentIdentityPointer = &currentIdentity;
    } else {
        logger.warning() << "Bundled publisher returned an invalid manifest probe response";
        cleanupRemoteTmp();
        return false;
    }

    const auto transitionResult = amnezia::selfhostedUpdates::validateBundledPublishTransition(
            currentIdentityPointer, payload.manifestIdentity);
    if (transitionResult != amnezia::selfhostedUpdates::BundledPublishTransitionResult::Allowed) {
        logger.warning() << "Refusing unsafe bundled manifest transition"
                         << transitionFailureName(transitionResult);
        cleanupRemoteTmp();
        return false;
    }

    const auto installOrRefreshUpdateHost = [&sshSession, &credentials, &remoteTmp, &serverDir, &runId]() {
        QFile installScriptFile(QString::fromLatin1(kInstallHostScript));
        if (!installScriptFile.open(QIODevice::ReadOnly)) {
            logger.warning() << "Bundled update host install script is missing";
            return false;
        }
        QFile verifiedRunnerFile(QString::fromLatin1(kVerifiedInstallHostRunner));
        if (!verifiedRunnerFile.open(QIODevice::ReadOnly)) {
            logger.warning() << "Bundled verified installer runner is missing";
            return false;
        }

        const QString remoteInstallScript = remoteTmp + QStringLiteral("/install_server_update_host.sh");
        const QString sealedInstallScript = QStringLiteral("/opt/amnezia/.install-server-update-host.%1").arg(runId);
        qsizetype installOutputBytes = 0;
        const auto accountInstallOutput = [&installOutputBytes](const QString &data, libssh::Client &) {
            return amnezia::selfhostedUpdates::accountBoundedRemoteOutput(installOutputBytes, data)
                    ? amnezia::ErrorCode::NoError
                    : amnezia::ErrorCode::ReadError;
        };
        QByteArray installScript = installScriptFile.readAll();
        installScript.replace("\r\n", "\n");
        installScript.replace('\r', '\n');
        const QByteArray installScriptSha256 = QCryptographicHash::hash(
                installScript, QCryptographicHash::Sha256).toHex();

        QByteArray verifiedRunner = verifiedRunnerFile.readAll();
        verifiedRunner.replace("\r\n", "\n");
        verifiedRunner.replace('\r', '\n');
        while (verifiedRunner.endsWith('\n')) {
            verifiedRunner.chop(1);
        }
        if (verifiedRunner.isEmpty() || verifiedRunner.contains('\0')) {
            logger.warning() << "Bundled verified installer runner is invalid";
            return false;
        }
        const QByteArray verifiedRunnerSha256 = QCryptographicHash::hash(
                verifiedRunner, QCryptographicHash::Sha256).toHex();
        const QByteArray verifiedRunnerBase64 = verifiedRunner.toBase64();

        amnezia::ErrorCode error = sshSession.uploadFileToHost(credentials, installScript, remoteInstallScript);
        if (error == amnezia::ErrorCode::NoError) {
            const QString verifiedInstallCommand = QStringLiteral(
                    "set -eu; verifier_b64=%1; verifier_sha256=%2; "
                    "verifier=$(printf '%s' \"$verifier_b64\" | base64 -d); "
                    "test \"$(printf '%s' \"$verifier\" | sha256sum | awk '{print $1}')\" = \"$verifier_sha256\"; "
                    "sh -c \"$verifier\" amnezia-verified-installer %3 %4 %5 %6 %7")
                    .arg(shellQuote(QString::fromLatin1(verifiedRunnerBase64)),
                         shellQuote(QString::fromLatin1(verifiedRunnerSha256)),
                         shellQuote(remoteInstallScript),
                         shellQuote(sealedInstallScript),
                         shellQuote(QString::fromLatin1(installScriptSha256)),
                         shellQuote(QString::number(installScript.size())),
                         shellQuote(serverDir));
            error = sshSession.runScript(
                    credentials,
                    verifiedInstallCommand,
                    accountInstallOutput,
                    accountInstallOutput,
                    kInstallerOuterSshTimeoutMs);
        }
        if (error != amnezia::ErrorCode::NoError) {
            logger.warning() << "Failed to install or refresh self-hosted update server"
                             << "phase" << "installer"
                             << "errorCode" << static_cast<int>(error);
            return false;
        }
        return true;
    };

    const auto verifyRemoteUpdateHost = [&sshSession, &credentials, &payload, &serverDir, &remoteManifest]() {
        QString verifyScript = QStringLiteral(
                "set -eu\n"
                "tx_label=%5\n"
                "role_label=%6\n"
                "bind_label=%7\n"
                "probe_label=%8\n"
                "port_label=%9\n"
                "inspect_value() { sudo -n -- docker inspect -f \"$1\" \"$2\"; }\n"
                "is_ipv4_address() {\n"
                "  candidate=$1\n"
                "  case \"$candidate\" in ''|*/*) return 1 ;; esac\n"
                "  old_ifs=$IFS; IFS=.; set -- $candidate; IFS=$old_ifs\n"
                "  test \"$#\" -eq 4 || return 1\n"
                "  for octet do\n"
                "    case \"$octet\" in ''|*[!0-9]*) return 1 ;; esac\n"
                "    test \"$octet\" -ge 0 2>/dev/null && test \"$octet\" -le 255 2>/dev/null || return 1\n"
                "  done\n"
                "}\n"
                "is_port() {\n"
                "  case \"$1\" in ''|*[!0-9]*) return 1 ;; esac\n"
                "  test \"$1\" -ge 1 2>/dev/null && test \"$1\" -le 65535 2>/dev/null\n"
                "}\n"
                "verify_common() {\n"
                "  verify_id=$1; verify_name=$2; verify_role=$3\n"
                "  test \"$(inspect_value '{{.Id}}' \"$verify_id\")\" = \"$verify_id\"\n"
                "  test \"$(inspect_value '{{.Name}}' \"$verify_id\")\" = \"/$verify_name\"\n"
                "  test \"$(inspect_value '{{.State.Running}}' \"$verify_id\")\" = true\n"
                "  test \"$(inspect_value \"{{index .Config.Labels \\\"$tx_label\\\"}}\" \"$verify_id\")\" = \"$transaction_id\"\n"
                "  test \"$(inspect_value \"{{index .Config.Labels \\\"$role_label\\\"}}\" \"$verify_id\")\" = \"$verify_role\"\n"
                "  test \"$(inspect_value '{{.Config.Image}}' \"$verify_id\")\" = %3\n"
                "  test \"$(inspect_value '{{range .Mounts}}{{if eq .Destination \"/www\"}}{{.Source}}|{{.RW}}{{println}}{{end}}{{end}}' \"$verify_id\")\" = %4\n"
                "  test \"$(inspect_value \"{{index .Config.Labels \\\"$bind_label\\\"}}\" \"$verify_id\")\" = \"$host_bind\"\n"
                "  test \"$(inspect_value \"{{index .Config.Labels \\\"$probe_label\\\"}}\" \"$verify_id\")\" = \"$host_probe\"\n"
                "  test \"$(inspect_value \"{{index .Config.Labels \\\"$port_label\\\"}}\" \"$verify_id\")\" = \"$sync_port\"\n"
                "}\n"
                "test \"$(sha256sum %1 | awk '{print $1}')\" = %2\n"
                "bridge_id=$(inspect_value '{{.Id}}' amnezia-client-updates)\n"
                "test -n \"$bridge_id\"\n"
                "transaction_id=$(inspect_value \"{{index .Config.Labels \\\"$tx_label\\\"}}\" \"$bridge_id\")\n"
                "test \"${#transaction_id}\" -eq 48\n"
                "case \"$transaction_id\" in *[!0-9a-f]*) exit 1 ;; esac\n"
                "host_bind=$(inspect_value \"{{index .Config.Labels \\\"$bind_label\\\"}}\" \"$bridge_id\")\n"
                "host_probe=$(inspect_value \"{{index .Config.Labels \\\"$probe_label\\\"}}\" \"$bridge_id\")\n"
                "sync_port=$(inspect_value \"{{index .Config.Labels \\\"$port_label\\\"}}\" \"$bridge_id\")\n"
                "is_ipv4_address \"$host_bind\"\n"
                "is_ipv4_address \"$host_probe\"\n"
                "is_port \"$sync_port\"\n"
                "if test \"$host_bind\" = 0.0.0.0; then\n"
                "  test \"$host_probe\" = 127.0.0.1\n"
                "else\n"
                "  test \"$host_probe\" = \"$host_bind\"\n"
                "fi\n"
                "host_id=$(inspect_value '{{.Id}}' amnezia-client-updates-host)\n"
                "test -n \"$host_id\" && test \"$host_id\" != \"$bridge_id\"\n"
                "all_ids=$(sudo -n -- docker ps -aq --no-trunc --filter \"label=$tx_label=$transaction_id\")\n"
                "test -n \"$all_ids\"\n"
                "bridge_seen=0; host_seen=0; sidecar_count=0; container_count=0; seen_sidecar_roles=' '; sidecar_report=\n"
                "for container_id in $all_ids; do\n"
                "  actual_id=$(inspect_value '{{.Id}}' \"$container_id\")\n"
                "  test \"$actual_id\" = \"$container_id\"\n"
                "  container_name=$(inspect_value '{{.Name}}' \"$actual_id\"); container_name=${container_name#/}\n"
                "  role=$(inspect_value \"{{index .Config.Labels \\\"$role_label\\\"}}\" \"$actual_id\")\n"
                "  endpoint_probe=127.0.0.1\n"
                "  case \"$role\" in\n"
                "    bridge)\n"
                "      test \"$actual_id\" = \"$bridge_id\" && test \"$container_name\" = amnezia-client-updates\n"
                "      bridge_seen=$((bridge_seen + 1))\n"
                "      test \"$(inspect_value '{{.HostConfig.NetworkMode}}' \"$actual_id\")\" != host\n"
                "      ;;\n"
                "    host)\n"
                "      test \"$actual_id\" = \"$host_id\" && test \"$container_name\" = amnezia-client-updates-host\n"
                "      host_seen=$((host_seen + 1)); endpoint_probe=$host_probe\n"
                "      test \"$(inspect_value '{{.HostConfig.NetworkMode}}' \"$actual_id\")\" = host\n"
                "      ;;\n"
                "    tunnel-*)\n"
                "      suffix=${role#tunnel-}\n"
                "      case \"$suffix\" in ''|*[!A-Za-z0-9_.-]*) exit 1 ;; esac\n"
                "      test \"$container_name\" = \"amnezia-client-updates-vpn-$suffix\"\n"
                "      case \"$seen_sidecar_roles\" in *\" $role \"*) exit 1 ;; esac\n"
                "      seen_sidecar_roles=\"$seen_sidecar_roles$role \"\n"
                "      network_mode=$(inspect_value '{{.HostConfig.NetworkMode}}' \"$actual_id\")\n"
                "      case \"$network_mode\" in container:*) vpn_id=${network_mode#container:} ;; *) exit 1 ;; esac\n"
                "      test -n \"$vpn_id\"\n"
                "      test \"$(inspect_value '{{.Id}}' \"$vpn_id\")\" = \"$vpn_id\"\n"
                "      test \"$(inspect_value '{{.State.Running}}' \"$vpn_id\")\" = true\n"
                "      sidecar_count=$((sidecar_count + 1))\n"
                "      if test -n \"$sidecar_report\"; then sidecar_report=\"$sidecar_report,$container_name|$actual_id|$role\"; else sidecar_report=\"$container_name|$actual_id|$role\"; fi\n"
                "      ;;\n"
                "    *) exit 1 ;;\n"
                "  esac\n"
                "  verify_common \"$actual_id\" \"$container_name\" \"$role\"\n"
                "  test \"$(sudo -n -- docker exec \"$actual_id\" busybox wget -q -O - \"http://$endpoint_probe:$sync_port/manifest.json\" | sha256sum | awk '{print $1}')\" = %2\n"
                "  container_count=$((container_count + 1))\n"
                "done\n"
                "test \"$bridge_seen\" -eq 1 && test \"$host_seen\" -eq 1\n"
                "test \"$container_count\" -eq $((sidecar_count + 2))\n")
                .arg(shellQuote(remoteManifest))
                .arg(shellQuote(QString::fromLatin1(payload.manifestSha256)))
                .arg(shellQuote(QString::fromLatin1(kUpdateHostImage)))
                .arg(shellQuote(serverDir + QStringLiteral("|false")))
                .arg(shellQuote(QStringLiteral("org.amnezia.client-update-host.transaction")))
                .arg(shellQuote(QStringLiteral("org.amnezia.client-update-host.role")))
                .arg(shellQuote(QStringLiteral("org.amnezia.client-update-host.bind")))
                .arg(shellQuote(QStringLiteral("org.amnezia.client-update-host.probe")))
                .arg(shellQuote(QStringLiteral("org.amnezia.client-update-host.port")));

        for (const PayloadFile &file : payload.files) {
            verifyScript += QStringLiteral("test \"$(sha256sum %1 | awk '{print $1}')\" = %2\n")
                    .arg(shellQuote(serverDir + QStringLiteral("/") + file.relativePath),
                         shellQuote(file.sha256));

            const QString containerFetch = QStringLiteral(
                    "sudo -n -- docker exec \"$bridge_id\" busybox wget -q -O - "
                    "\"http://127.0.0.1:$sync_port\"%1")
                    .arg(shellQuote(file.relativeUrlPath));
            verifyScript += QStringLiteral("test \"$(%1 | sha256sum | awk '{print $1}')\" = %2\n")
                    .arg(containerFetch, shellQuote(file.sha256));
            verifyScript += QStringLiteral("test \"$(%1 | wc -c | tr -d ' ')\" = %2\n")
                    .arg(containerFetch, shellQuote(QString::number(file.size)));
        }

        verifyScript += QStringLiteral(
                "test \"$(sudo -n -- docker run --rm --log-driver none --network host --entrypoint sh %2 -c \"busybox wget -q -O - 'http://$host_probe:$sync_port/manifest.json'\" | sha256sum | awk '{print $1}')\" = %1\n"
                "printf 'transaction_id=%s\\nbridge_container_id=%s\\nhost_container_id=%s\\nhost_bind=%s\\nhost_probe_address=%s\\nsync_port=%s\\nsidecar_count=%s\\nvpn_sidecars=%s\\nmanifest_sha256=%s\\n' \"$transaction_id\" \"$bridge_id\" \"$host_id\" \"$host_bind\" \"$host_probe\" \"$sync_port\" \"$sidecar_count\" \"${sidecar_report:-none}\" %1\n")
                .arg(shellQuote(QString::fromLatin1(payload.manifestSha256)),
                     shellQuote(QString::fromLatin1(kUpdateHostImage)));

        qsizetype verificationOutputBytes = 0;
        const auto accountVerificationOutput = [&verificationOutputBytes](const QString &data, libssh::Client &) {
            return amnezia::selfhostedUpdates::accountBoundedRemoteOutput(verificationOutputBytes, data)
                    ? amnezia::ErrorCode::NoError
                    : amnezia::ErrorCode::ReadError;
        };

        const amnezia::ErrorCode error = sshSession.runScriptInSingleShell(
                credentials, verifyScript, accountVerificationOutput, accountVerificationOutput);
        if (error != amnezia::ErrorCode::NoError) {
            logger.warning() << "Remote self-hosted update host verification failed"
                             << "phase" << "verification"
                             << "errorCode" << static_cast<int>(error);
            return false;
        }

        logger.info() << "Remote self-hosted update host verified";
        return true;
    };

    QByteArray publishMetadata = QByteArrayLiteral("amnezia-bundled-publish-v1\t");
    publishMetadata += payload.manifestSha256;
    publishMetadata += '\t';
    publishMetadata += payload.manifestIdentity.version.toUtf8();
    publishMetadata += '\t';
    publishMetadata += QByteArray::number(payload.manifestIdentity.schema);
    publishMetadata += '\t';
    publishMetadata += payload.manifestIdentity.generation.isEmpty()
            ? QByteArrayLiteral("0") : payload.manifestIdentity.generation.toUtf8();
    publishMetadata += '\t';
    publishMetadata += QByteArray::number(payload.files.size());
    publishMetadata += '\n';
    for (const PayloadFile &file : payload.files) {
        if (file.relativePath.contains(u'\t') || file.relativePath.contains(u'\r')
            || file.relativePath.contains(u'\n')) {
            logger.warning() << "Bundled update artifact path cannot be represented safely" << file.relativePath;
            cleanupRemoteTmp();
            return false;
        }
        publishMetadata += file.rollback ? 'R' : 'A';
        publishMetadata += '\t';
        publishMetadata += file.relativePath.toUtf8();
        publishMetadata += '\t';
        publishMetadata += file.sha256.toUtf8();
        publishMetadata += '\t';
        publishMetadata += QByteArray::number(file.size);
        publishMetadata += '\n';
    }
    if (publishMetadata.size() > kMaximumPublishMetadataBytes) {
        logger.warning() << "Bundled publication metadata exceeds the supported size";
        cleanupRemoteTmp();
        return false;
    }
    const QByteArray publishMetadataSha256 = QCryptographicHash::hash(
            publishMetadata, QCryptographicHash::Sha256).toHex();

    for (const PayloadFile &file : payload.files) {
        const QString remotePath = remoteTmp + QStringLiteral("/") + file.relativePath;
        const QString remoteDirectory = remoteTmp + QStringLiteral("/")
                + file.relativePath.left(file.relativePath.lastIndexOf(u'/'));
        error = sshSession.runScript(credentials, QStringLiteral("mkdir -p -- %1").arg(shellQuote(remoteDirectory)));
        if (error == amnezia::ErrorCode::NoError) {
            error = sshSession.uploadLocalFileToHost(credentials, file.localPath, remotePath);
        }
        if (error != amnezia::ErrorCode::NoError) {
            logger.warning() << "Failed to upload bundled update artifact" << file.localPath;
            cleanupRemoteTmp();
            return false;
        }
    }

    error = sshSession.uploadFileToHost(credentials, payload.manifestData, remoteTmp + QStringLiteral("/manifest.json"));
    if (error != amnezia::ErrorCode::NoError) {
        logger.warning() << "Failed to upload bundled update manifest";
        cleanupRemoteTmp();
        return false;
    }
    if (!currentManifestData.isEmpty()) {
        error = sshSession.uploadFileToHost(
                credentials, currentManifestData, remoteTmp + QStringLiteral("/previous-manifest.json"));
        if (error != amnezia::ErrorCode::NoError) {
            logger.warning() << "Failed to upload the verified previous manifest rollback input";
            cleanupRemoteTmp();
            return false;
        }
    }
    error = sshSession.uploadFileToHost(credentials, publishMetadata, remoteTmp + QStringLiteral("/publish.meta"));
    if (error != amnezia::ErrorCode::NoError) {
        logger.warning() << "Failed to upload bundled publication metadata";
        cleanupRemoteTmp();
        return false;
    }

    const QString expectedCurrent = QString::fromLatin1(expectedCurrentManifestSha256);
    const QString candidateSha256 = QString::fromLatin1(payload.manifestSha256);
    const QString metadataSha256 = QString::fromLatin1(publishMetadataSha256);
    const QString fileCount = QString::number(payload.files.size());
    const auto publisherCommand = [&remotePublisherScript,
                                   &serverDir,
                                   &runId,
                                   &expectedCurrent,
                                   &candidateSha256,
                                   &metadataSha256,
                                   &fileCount](const QString &mode) {
        return QStringLiteral("sh %1 %2 %3 %4 %5 %6 %7 %8")
                .arg(shellQuote(remotePublisherScript),
                     shellQuote(mode),
                     shellQuote(serverDir),
                     shellQuote(runId),
                     shellQuote(expectedCurrent),
                     shellQuote(candidateSha256),
                     shellQuote(metadataSha256),
                     shellQuote(fileCount));
    };

    QByteArray publisherOutput;
    QString publisherError;
    const auto capturePublisherOutput = [&publisherOutput](const QString &data, libssh::Client &) {
        const QByteArray bytes = data.toUtf8();
        if (publisherOutput.size() + bytes.size() > 4096) {
            return amnezia::ErrorCode::ReadError;
        }
        publisherOutput += bytes;
        return amnezia::ErrorCode::NoError;
    };
    const auto capturePublisherError = [&publisherError](const QString &data, libssh::Client &) {
        if (publisherError.size() < 2048) {
            publisherError += data.left(2048 - publisherError.size());
        }
        return amnezia::ErrorCode::NoError;
    };
    const auto runPublisher = [&sshSession,
                               &credentials,
                               &publisherCommand,
                               &publisherOutput,
                               &publisherError,
                               &capturePublisherOutput,
                               &capturePublisherError](const QString &mode) {
        publisherOutput.clear();
        publisherError.clear();
        return sshSession.runScript(
                credentials,
                publisherCommand(mode),
                capturePublisherOutput,
                capturePublisherError);
    };
    const auto exactMachineReceipt = [&runId,
                                      &expectedCurrent,
                                      &candidateSha256,
                                      &metadataSha256,
                                      &fileCount](const QByteArray &output,
                                                  const QByteArray &kind,
                                                  const QByteArray &result,
                                                  const QByteArray &phase) {
        return output == kind + '\t' + runId.toLatin1() + '\t'
                + expectedCurrent.toLatin1() + '\t' + candidateSha256.toLatin1() + '\t'
                + metadataSha256.toLatin1() + '\t' + fileCount.toLatin1() + '\t'
                + result + '\t' + phase + '\n';
    };
    const auto reconcilePublication = [&runPublisher,
                                       &publisherOutput,
                                       &exactMachineReceipt]() {
        const amnezia::ErrorCode reconcileError = runPublisher(QStringLiteral("reconcile"));
        if (reconcileError != amnezia::ErrorCode::NoError) {
            return amnezia::selfhostedUpdates::BundledMutationReconciliation::Indeterminate;
        }
        for (const QByteArray &phase : {
                     QByteArrayLiteral("committed"),
                     QByteArrayLiteral("finalizing"),
                     QByteArrayLiteral("finalized") }) {
            if (exactMachineReceipt(
                        publisherOutput,
                        QByteArrayLiteral("AMNEZIA_PUBLISH_RECONCILE_V1"),
                        QByteArrayLiteral("APPLIED"),
                        phase)) {
                return amnezia::selfhostedUpdates::BundledMutationReconciliation::AppliedWithoutAcknowledgement;
            }
        }
        for (const QByteArray &phase : {
                     QByteArrayLiteral("aborted"),
                     QByteArrayLiteral("abort_finalizing"),
                     QByteArrayLiteral("finalized_aborted") }) {
            if (exactMachineReceipt(
                        publisherOutput,
                        QByteArrayLiteral("AMNEZIA_PUBLISH_RECONCILE_V1"),
                        QByteArrayLiteral("NOT_APPLIED"),
                        phase)) {
                return amnezia::selfhostedUpdates::BundledMutationReconciliation::NotApplied;
            }
        }
        return amnezia::selfhostedUpdates::BundledMutationReconciliation::Indeterminate;
    };
    const auto finalizeExact = [&runPublisher,
                                &publisherOutput,
                                &publisherError,
                                &exactMachineReceipt](const QString &mode,
                                                      const QByteArray &kind,
                                                      const QByteArray &result,
                                                      const QByteArray &phase) {
        const amnezia::ErrorCode finalizeError = runPublisher(mode);
        const bool acknowledged = finalizeError == amnezia::ErrorCode::NoError
                && exactMachineReceipt(publisherOutput, kind, result, phase);
        if (!acknowledged) {
            logger.warning() << "Publication cleanup was not acknowledged; durable state is preserved"
                             << publisherError.trimmed();
        }
        return acknowledged;
    };
    const auto abortUncommitted = [&reconcilePublication, &finalizeExact]() {
        const auto reconciliation = reconcilePublication();
        if (reconciliation == amnezia::selfhostedUpdates::BundledMutationReconciliation::NotApplied) {
            if (!finalizeExact(
                    QStringLiteral("finalize-abort"),
                    QByteArrayLiteral("AMNEZIA_PUBLISH_FINALIZE_ABORT_V1"),
                    QByteArrayLiteral("NOT_APPLIED"),
                    QByteArrayLiteral("finalized_aborted"))) {
                return amnezia::selfhostedUpdates::BundledMutationReconciliation::Indeterminate;
            }
        }
        return reconciliation;
    };

    error = runPublisher(QStringLiteral("prepare"));
    const bool prepareAcknowledged = error == amnezia::ErrorCode::NoError
            && exactMachineReceipt(
                    publisherOutput,
                    QByteArrayLiteral("AMNEZIA_PUBLISH_PREPARE_V1"),
                    QByteArrayLiteral("READY"),
                    QByteArrayLiteral("prepared"));
    if (!prepareAcknowledged) {
        const auto reconciliation = abortUncommitted();
        logger.warning() << "Failed to prepare the pinned bundled update channel"
                         << publisherError.trimmed();
        if (reconciliation == amnezia::selfhostedUpdates::BundledMutationReconciliation::Indeterminate) {
            logger.error() << "RECOVERY_REQUIRED: prepare state is indeterminate; preserving the remote stage"
                           << "run_id=" << runId << "remote_stage=" << remoteTmp;
        }
        return false;
    }

    if (!installOrRefreshUpdateHost()) {
        const auto reconciliation = abortUncommitted();
        if (reconciliation == amnezia::selfhostedUpdates::BundledMutationReconciliation::Indeterminate) {
            logger.error() << "RECOVERY_REQUIRED: installer failure could not abort prepared publication"
                           << "run_id=" << runId << "remote_stage=" << remoteTmp;
        }
        return false;
    }

    error = runPublisher(QStringLiteral("commit"));
    auto commitReconciliation =
            error == amnezia::ErrorCode::NoError
                    && exactMachineReceipt(
                            publisherOutput,
                            QByteArrayLiteral("AMNEZIA_PUBLISH_COMMIT_V1"),
                            QByteArrayLiteral("APPLIED"),
                            QByteArrayLiteral("committed"))
            ? amnezia::selfhostedUpdates::BundledMutationReconciliation::Acknowledged
            : reconcilePublication();
    if (commitReconciliation
        == amnezia::selfhostedUpdates::BundledMutationReconciliation::NotApplied) {
        finalizeExact(
                QStringLiteral("finalize-abort"),
                QByteArrayLiteral("AMNEZIA_PUBLISH_FINALIZE_ABORT_V1"),
                QByteArrayLiteral("NOT_APPLIED"),
                QByteArrayLiteral("finalized_aborted"));
        logger.warning() << "Bundled publication was not applied";
        return false;
    }
    if (commitReconciliation
        == amnezia::selfhostedUpdates::BundledMutationReconciliation::Indeterminate) {
        logger.error() << "RECOVERY_REQUIRED: bundled commit state is indeterminate; preserving recovery evidence"
                       << "run_id=" << runId
                       << "remote_stage=" << remoteTmp
                       << "channel_root=" << serverDir;
        return false;
    }
    if (commitReconciliation
        == amnezia::selfhostedUpdates::BundledMutationReconciliation::AppliedWithoutAcknowledgement) {
        logger.warning() << "Bundled commit acknowledgement was lost; durable state reconciled APPLIED";
    }

    if (!verifyRemoteUpdateHost()) {
        if (expectedCurrent == candidateSha256) {
            if (!finalizeExact(
                    QStringLiteral("finalize"),
                    QByteArrayLiteral("AMNEZIA_PUBLISH_FINALIZE_V1"),
                    QByteArrayLiteral("APPLIED"),
                    QByteArrayLiteral("finalized"))) {
                logger.error() << "RECOVERY_REQUIRED: finalization acknowledgement failed after pre-existing candidate verification";
                return false;
            }
            logger.error() << "Pre-existing bundled candidate failed endpoint verification; manifest was not changed";
            return false;
        }

        error = runPublisher(QStringLiteral("rollback"));
        auto rollbackReconciliation =
                error == amnezia::ErrorCode::NoError
                        && exactMachineReceipt(
                                publisherOutput,
                                QByteArrayLiteral("AMNEZIA_PUBLISH_ROLLBACK_V1"),
                                QByteArrayLiteral("APPLIED"),
                                QByteArrayLiteral("rolled_back"))
                ? amnezia::selfhostedUpdates::BundledMutationReconciliation::Acknowledged
                : amnezia::selfhostedUpdates::BundledMutationReconciliation::Indeterminate;
        if (rollbackReconciliation
            == amnezia::selfhostedUpdates::BundledMutationReconciliation::Indeterminate) {
            const amnezia::ErrorCode reconcileError =
                    runPublisher(QStringLiteral("reconcile-rollback"));
            if (reconcileError == amnezia::ErrorCode::NoError) {
                for (const QByteArray &phase : {
                             QByteArrayLiteral("rolled_back"),
                             QByteArrayLiteral("rollback_finalizing"),
                             QByteArrayLiteral("rollback_finalized") }) {
                    if (exactMachineReceipt(
                                publisherOutput,
                                QByteArrayLiteral("AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1"),
                                QByteArrayLiteral("APPLIED"),
                                phase)) {
                        rollbackReconciliation =
                                amnezia::selfhostedUpdates::BundledMutationReconciliation::AppliedWithoutAcknowledgement;
                        break;
                    }
                }
                if (exactMachineReceipt(
                            publisherOutput,
                            QByteArrayLiteral("AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1"),
                            QByteArrayLiteral("NOT_APPLIED"),
                            QByteArrayLiteral("rollback_aborted"))) {
                    rollbackReconciliation =
                            amnezia::selfhostedUpdates::BundledMutationReconciliation::NotApplied;
                }
            }
        }
        const bool rollbackSucceeded =
                rollbackReconciliation
                        == amnezia::selfhostedUpdates::BundledMutationReconciliation::Acknowledged
                || rollbackReconciliation
                        == amnezia::selfhostedUpdates::BundledMutationReconciliation::AppliedWithoutAcknowledgement;
        if (rollbackSucceeded) {
            if (!finalizeExact(
                    QStringLiteral("finalize-rollback"),
                    QByteArrayLiteral("AMNEZIA_PUBLISH_FINALIZE_ROLLBACK_V1"),
                    QByteArrayLiteral("APPLIED"),
                    QByteArrayLiteral("rollback_finalized"))) {
                logger.error() << "RECOVERY_REQUIRED: rollback succeeded but finalization acknowledgement failed";
                return false;
            }
            logger.error() << "Bundled candidate failed endpoint verification; previous manifest was restored";
            return false;
        }

        logger.error() << "RECOVERY_REQUIRED: bundled candidate verification and lock-fenced rollback failed;"
                          " preserving durable state and the remote recovery stage"
                       << "run_id=" << runId
                       << "remote_stage=" << remoteTmp
                       << "channel_root=" << serverDir;
        return false;
    }

    if (!finalizeExact(
            QStringLiteral("finalize"),
            QByteArrayLiteral("AMNEZIA_PUBLISH_FINALIZE_V1"),
            QByteArrayLiteral("APPLIED"),
            QByteArrayLiteral("finalized"))) {
        logger.error() << "RECOVERY_REQUIRED: bundled publication finalization was not acknowledged";
        return false;
    }

    const amnezia::ErrorCode cleanupError = cleanupRemoteTmp();
    if (cleanupError != amnezia::ErrorCode::NoError) {
        // Publication is already atomically acknowledged; retain that result
        // while surfacing a bounded hygiene warning for the operator.
        logger.warning() << "Bundled self-hosted publication succeeded but remote staging cleanup failed"
                         << "errorCode" << static_cast<int>(cleanupError);
    }

    logger.info() << "Bundled self-hosted update payload published" << payload.version;
    return true;
}
