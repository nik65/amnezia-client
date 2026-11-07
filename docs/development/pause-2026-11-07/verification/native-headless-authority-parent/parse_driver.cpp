// The subject functions and declarations are copied exactly from the actual decoder.
// Only its fixed-anchor filesystem IO and its storage-owning constructor are inert.
#include "headlessUpdateManager.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <cstdio>

namespace anchor_model {
inline QByteArray bytes;
inline QString mode;
inline int queries = 0;
inline int opens = 0;
inline QString fixed() { return QStringLiteral("/etc/amnezia/update-public-key.pem"); }
struct FileInfo {
    QString path;
    explicit FileInfo(const QString &value) : path(value) {}
    QString canonicalFilePath() const { ++queries; return path == fixed() ? path : QString(); }
    bool isFile() const { ++queries; return path == fixed() && mode != QStringLiteral("not-regular"); }
    bool isSymLink() const { ++queries; return mode == QStringLiteral("symlink"); }
    uint ownerId() const { ++queries; return mode == QStringLiteral("wrong-owner") ? 1000u : 0u; }
    QFileDevice::Permissions permissions() const {
        ++queries;
        return QFileDevice::ReadOwner | (mode == QStringLiteral("writable") ? QFileDevice::WriteOther
                                                                          : QFileDevice::ReadGroup);
    }
};
struct File {
    QString path;
    explicit File(const QString &value) : path(value) {}
    bool open(QIODevice::OpenMode flags) {
        ++opens;
        return flags == QIODevice::ReadOnly && path == fixed() && mode != QStringLiteral("open-failed");
    }
    qint64 size() const { return mode == QStringLiteral("oversize") ? 16385 : bytes.size(); }
    QByteArray readAll() const {
        if (mode == QStringLiteral("partial-read")) return bytes.left(1);
        if (mode == QStringLiteral("changed-key")) return QByteArray(bytes.size(), 'x');
        return bytes;
    }
};
}

#include "actual_decoder.inc"

class HeadlessUpdateTest {
public:
    static amnezia::headless::HeadlessUpdateResult parse(const QByteArray &raw, const QByteArray &key,
                                                       const QString &current) {
        using namespace amnezia::headless;
        HeadlessUpdateManager manager;
        HeadlessUpdateManager::Candidate candidate;
        Profile profile;
        profile.forwardRoutes = QStringList{QStringLiteral("127.0.0.1/32")};
        const QString path = anchor_model::mode == QStringLiteral("wrong-path")
            ? QStringLiteral("/not-the-fixed-key") : anchor_model::fixed();
        return manager.parseManifest(raw, QUrl(QStringLiteral("http://127.0.0.1:8080/manifest.json")),
            profile, path, key, current, candidate);
    }
};

int main(int argc, char **argv) {
    QCoreApplication application(argc, argv);
    if (argc != 6) return 2;
    // Only the caller-supplied owned manifest and TEST public key are read.
    QFile manifest(QString::fromLocal8Bit(argv[1]));
    QFile publicKey(QString::fromLocal8Bit(argv[2]));
    if (!manifest.open(QIODevice::ReadOnly) || !publicKey.open(QIODevice::ReadOnly)) return 2;
    anchor_model::bytes = publicKey.readAll();
    anchor_model::mode = QString::fromLocal8Bit(argv[4]);
    const auto result = HeadlessUpdateTest::parse(manifest.readAll(), anchor_model::bytes,
                                                QString::fromLocal8Bit(argv[5]));
    const QString expected = QString::fromLocal8Bit(argv[3]);
    const bool positive = expected == QStringLiteral("update_available") || expected == QStringLiteral("no_update");
    const bool ok = result.code == expected && result.ok == positive;
    std::printf("%s actual-parseManifest code=%s expected=%s anchorQueries=%d anchorOpens=%d\n",
        ok ? "PASS" : "FAIL", qUtf8Printable(result.code), qUtf8Printable(expected),
        anchor_model::queries, anchor_model::opens);
    return ok ? 0 : 1;
}
