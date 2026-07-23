#include "selfHostedUpdateBootstrapper.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>
#include <QPointer>
#include <QSet>
#include <QThreadPool>
#include <QTimer>
#include <QVariant>

#include <cmath>

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
    constexpr auto kUpdateHostImage = "docker.io/library/busybox:1.36.1";

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

    bool canonicalPolicyGeneration(const QJsonValue &value, QString &generationOut)
    {
        generationOut.clear();
        if (!value.isDouble()) {
            return false;
        }

        constexpr qint64 kMaximumPolicyGeneration = 9007199254740991LL;
        const double rawGeneration = value.toDouble(-1.0);
        if (!std::isfinite(rawGeneration) || rawGeneration < 1.0 || rawGeneration > kMaximumPolicyGeneration
            || std::floor(rawGeneration) != rawGeneration) {
            return false;
        }

        generationOut = QString::number(static_cast<qint64>(rawGeneration));
        return amnezia::selfhostedUpdates::isCanonicalNonnegativeDecimal(generationOut);
    }

    bool decodeManifestPayload(const QJsonObject &manifest, QJsonObject &payloadOut)
    {
        const QString payloadText = manifest.value(QStringLiteral("payload")).toString();
        if (payloadText.isEmpty()) {
            return false;
        }

        QByteArray payloadBytes = QByteArray::fromBase64(payloadText.toUtf8(),
                                                         QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        QJsonParseError error {};
        const QJsonDocument payloadDoc = QJsonDocument::fromJson(payloadBytes, &error);
        if (error.error != QJsonParseError::NoError || !payloadDoc.isObject()) {
            return false;
        }

        payloadOut = payloadDoc.object();
        return true;
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

}

SelfHostedUpdateBootstrapper::SelfHostedUpdateBootstrapper(SecureServersRepository *serversRepository, QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository)
{
}

bool SelfHostedUpdateBootstrapper::start()
{
    if (m_publishScheduled || m_publishInProgress) {
        return true;
    }
    if (m_publishSucceeded) {
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

    m_publishScheduled = true;
    QTimer::singleShot(15000, this, [this, payload, credentials]() {
        m_publishScheduled = false;
        m_publishInProgress = true;
        QPointer<SelfHostedUpdateBootstrapper> self(this);
        QThreadPool::globalInstance()->start([self, payload, credentials]() {
            const bool success = publishPayload(payload, credentials);
            if (!self) {
                return;
            }
            QMetaObject::invokeMethod(self, [self, success]() {
                if (!self) {
                    return;
                }
                self->m_publishInProgress = false;
                self->m_publishSucceeded = success;
                emit self->publishFinished(success);
            }, Qt::QueuedConnection);
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

    QJsonParseError error {};
    const QJsonDocument manifestDoc = QJsonDocument::fromJson(manifestFile.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !manifestDoc.isObject()) {
        logger.warning() << "Bundled update manifest is not valid JSON:" << error.errorString();
        return false;
    }

    if (!verifyManifestSignature(manifestDoc.object())) {
        logger.warning() << "Bundled update manifest signature verification failed";
        return false;
    }

    QJsonObject decodedPayload;
    if (!decodeManifestPayload(manifestDoc.object(), decodedPayload)) {
        logger.warning() << "Bundled update manifest has invalid signed payload";
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

        const QString relativeUrlPath = QUrl(urlText, QUrl::StrictMode).path(QUrl::FullyEncoded);
        files.append({ platform, filePath, relativePath, relativeUrlPath, expectedSha256, expectedSize });
        return true;
    };

    for (auto iterator = platforms.constBegin(); iterator != platforms.constEnd(); ++iterator) {
        const QString platform = iterator.key();
        const QJsonObject platformObject = iterator.value().toObject();
        if (platformObject.isEmpty()) {
            logger.warning() << "Bundled update manifest has invalid platform entry" << platform;
            return false;
        }
        if (platformObject.value(QStringLiteral("openExternal")).toBool()) {
            continue;
        }
        if (!appendLocalArtifact(platform, platformObject, false, QString(), QString())) {
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
        if (!canonicalPolicyGeneration(releasePolicy.value(QStringLiteral("generation")), rollbackGeneration)
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
            const QString platform = QStringLiteral("rollback:") + iterator.key();
            const QJsonObject platformObject = iterator.value().toObject();
            if (platformObject.isEmpty() || platformObject.value(QStringLiteral("openExternal")).toBool()
                || !appendLocalArtifact(platform, platformObject, true, rollbackGeneration, rollbackVersion)) {
                logger.warning() << "Bundled update manifest has invalid rollback artifact" << platform;
                return false;
            }
        }
    }

    payload.rootDir = root.absolutePath();
    payload.manifestPath = manifestPath;
    payload.version = decodedPayload.value(QStringLiteral("version")).toString();
    payload.files = files;
    payload.manifestSha256 = fileSha256(manifestPath);
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
    QString remoteTmp;
    auto readRemoteTmp = [&remoteTmp](const QString &data, libssh::Client &) {
        remoteTmp += data.trimmed();
        return amnezia::ErrorCode::NoError;
    };
    amnezia::ErrorCode error = sshSession.runScript(credentials,
                                                    QStringLiteral("remote_tmp=$(mktemp -d /tmp/amnezia-client-updates.XXXXXX) && "
                                                                   "chmod 700 \"$remote_tmp\" && "
                                                                   "mkdir -p \"$remote_tmp/files\" && "
                                                                   "printf '%s' \"$remote_tmp\""),
                                                    readRemoteTmp);
    if (error != amnezia::ErrorCode::NoError) {
        logger.warning() << "Failed to prepare remote update payload directory";
        return false;
    }
    if (!remoteTmp.startsWith(QStringLiteral("/tmp/amnezia-client-updates."))) {
        logger.warning() << "Remote update payload directory is invalid";
        return false;
    }

    const auto cleanupRemoteTmp = [&sshSession, &credentials, &remoteTmp]() {
        sshSession.runScript(credentials, QStringLiteral("rm -rf %1").arg(shellQuote(remoteTmp)));
    };

    const auto installOrRefreshUpdateHost = [&sshSession, &credentials, &remoteTmp, &serverDir, &cleanupRemoteTmp]() {
        QFile installScriptFile(QString::fromLatin1(kInstallHostScript));
        if (!installScriptFile.open(QIODevice::ReadOnly)) {
            logger.warning() << "Bundled update host install script is missing";
            cleanupRemoteTmp();
            return false;
        }

        const QString remoteInstallScript = remoteTmp + QStringLiteral("/install_server_update_host.sh");
        QString installOutput;
        const auto captureInstallOutput = [&installOutput](const QString &data, libssh::Client &) {
            installOutput += data;
            return amnezia::ErrorCode::NoError;
        };
        QByteArray installScript = installScriptFile.readAll();
        installScript.replace("\r\n", "\n");
        installScript.replace('\r', '\n');

        amnezia::ErrorCode error = sshSession.uploadFileToHost(credentials, installScript, remoteInstallScript);
        if (error == amnezia::ErrorCode::NoError) {
            error = sshSession.runScript(credentials,
                                         QStringLiteral("sh %1 %2").arg(shellQuote(remoteInstallScript), shellQuote(serverDir)),
                                         captureInstallOutput,
                                         captureInstallOutput);
        }
        if (error != amnezia::ErrorCode::NoError) {
            logger.warning() << "Failed to install or refresh self-hosted update server" << installOutput.trimmed();
            cleanupRemoteTmp();
            return false;
        }
        return true;
    };

    const auto verifyRemoteUpdateHost = [&sshSession, &credentials, &payload, &serverDir, &remoteManifest]() {
        QString verifyScript = QStringLiteral(
                "test \"$(sha256sum %1 | awk '{print $1}')\" = %2\n")
                .arg(shellQuote(remoteManifest), shellQuote(QString::fromLatin1(payload.manifestSha256)));

        for (const PayloadFile &file : payload.files) {
            verifyScript += QStringLiteral("test \"$(sha256sum %1 | awk '{print $1}')\" = %2\n")
                    .arg(shellQuote(serverDir + QStringLiteral("/") + file.relativePath),
                         shellQuote(file.sha256));

            const QString localHttpUrl = QStringLiteral("http://127.0.0.1:17865/%1").arg(file.relativeUrlPath);
            const QString containerFetch = QStringLiteral(
                    "sudo docker exec amnezia-client-updates busybox wget -q -O - %1")
                    .arg(shellQuote(localHttpUrl));
            verifyScript += QStringLiteral("test \"$(%1 | sha256sum | awk '{print $1}')\" = %2\n")
                    .arg(containerFetch, shellQuote(file.sha256));
            verifyScript += QStringLiteral("test \"$(%1 | wc -c | tr -d ' ')\" = %2\n")
                    .arg(containerFetch, shellQuote(QString::number(file.size)));
        }

        verifyScript += QStringLiteral(
                "sudo docker ps --format '{{.Names}}' | grep -qx 'amnezia-client-updates'\n"
                "test \"$(sudo docker exec amnezia-client-updates sh -c \"busybox wget -q -O - 'http://127.0.0.1:17865/manifest.json'\" | sha256sum | awk '{print $1}')\" = %1\n"
                "test \"$(sudo docker run --rm --log-driver none --network host --entrypoint sh %2 -c \"busybox wget -q -O - 'http://127.0.0.1:17865/manifest.json'\" | sha256sum | awk '{print $1}')\" = %1\n"
                "printf 'manifest_sha256=%s\\ncontainer_manifest_sha256=%s\\nhost_manifest_sha256=%s\\nport_map=%s\\n' %1 \"$(sudo docker exec amnezia-client-updates sh -c \"busybox wget -q -O - 'http://127.0.0.1:17865/manifest.json'\" | sha256sum | awk '{print $1}')\" \"$(sudo docker run --rm --log-driver none --network host --entrypoint sh %2 -c \"busybox wget -q -O - 'http://127.0.0.1:17865/manifest.json'\" | sha256sum | awk '{print $1}')\" \"$(sudo docker port amnezia-client-updates 17865 2>/dev/null || true)\"\n")
                .arg(shellQuote(QString::fromLatin1(payload.manifestSha256)),
                     shellQuote(QString::fromLatin1(kUpdateHostImage)));

        QString verifyOutput;
        const auto captureOutput = [&verifyOutput](const QString &data, libssh::Client &) {
            verifyOutput += data;
            return amnezia::ErrorCode::NoError;
        };

        const amnezia::ErrorCode error = sshSession.runScript(credentials, verifyScript, captureOutput, captureOutput);
        if (error != amnezia::ErrorCode::NoError) {
            logger.warning() << "Remote self-hosted update host verification failed";
            return false;
        }

        logger.info() << "Remote self-hosted update host verified" << verifyOutput.trimmed();
        return true;
    };

    for (const PayloadFile &file : payload.files) {
        const QString remotePath = remoteTmp + QStringLiteral("/") + file.relativePath;
        const QString remoteDirectory = remoteTmp + QStringLiteral("/")
                + file.relativePath.left(file.relativePath.lastIndexOf(u'/'));
        error = sshSession.runScript(credentials, QStringLiteral("mkdir -p %1").arg(shellQuote(remoteDirectory)));
        if (error == amnezia::ErrorCode::NoError) {
            error = sshSession.uploadLocalFileToHost(credentials, file.localPath, remotePath);
        }
        if (error != amnezia::ErrorCode::NoError) {
            logger.warning() << "Failed to upload bundled update artifact" << file.localPath;
            cleanupRemoteTmp();
            return false;
        }
    }

    error = sshSession.uploadLocalFileToHost(credentials, payload.manifestPath, remoteTmp + QStringLiteral("/manifest.json"));
    if (error != amnezia::ErrorCode::NoError) {
        logger.warning() << "Failed to upload bundled update manifest";
        cleanupRemoteTmp();
        return false;
    }

    if (!installOrRefreshUpdateHost()) {
        return false;
    }

    const QString publishScript = QStringLiteral(
            "set -eu\n"
            "sudo mkdir -p %1 %2\n"
            "sudo cp -a %3 %2/\n"
            "sudo cp -a %4 %5\n"
            "sudo mv -f %5 %6\n"
            "rm -rf %7")
            .arg(shellQuote(serverDir),
                 shellQuote(serverDir + QStringLiteral("/files")),
                 shellQuote(remoteTmp + QStringLiteral("/files/.")),
                 shellQuote(remoteTmp + QStringLiteral("/manifest.json")),
                 shellQuote(serverDir + QStringLiteral("/manifest.json.tmp")),
                 shellQuote(remoteManifest),
                 shellQuote(remoteTmp));

    error = sshSession.runScript(credentials, publishScript);
    if (error != amnezia::ErrorCode::NoError) {
        logger.warning() << "Failed to publish bundled self-hosted update payload";
        return false;
    }
    if (!verifyRemoteUpdateHost()) {
        return false;
    }

    logger.info() << "Bundled self-hosted update payload published" << payload.version;
    return true;
}
