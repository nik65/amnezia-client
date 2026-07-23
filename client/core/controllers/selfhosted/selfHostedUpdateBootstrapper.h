#ifndef SELFHOSTEDUPDATEBOOTSTRAPPER_H
#define SELFHOSTEDUPDATEBOOTSTRAPPER_H

#include <QObject>
#include <QDir>
#include <QList>
#include <QString>
#include <QStringList>
#include <QUrl>

#include "core/utils/commonStructs.h"

class SecureServersRepository;

namespace amnezia::selfhostedUpdates
{
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
    };

    struct Payload {
        QString rootDir;
        QString manifestPath;
        QString version;
        QList<PayloadFile> files;
        QByteArray manifestSha256;
    };

    QString findPayloadDir() const;
    bool loadPayload(const QString &payloadDir, Payload &payload) const;
    bool selectServerCredentials(amnezia::ServerCredentials &credentials) const;
    static bool publishPayload(Payload payload, amnezia::ServerCredentials credentials);

    bool m_publishScheduled = false;
    bool m_publishInProgress = false;
    bool m_publishSucceeded = false;
    SecureServersRepository *m_serversRepository = nullptr;
};

#endif // SELFHOSTEDUPDATEBOOTSTRAPPER_H
