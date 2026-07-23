#include <QCoreApplication>
#include <QTextStream>

#include "core/controllers/selfhosted/selfHostedUpdateBootstrapper.h"

using amnezia::selfhostedUpdates::bundledArtifactRelativePath;
using amnezia::selfhostedUpdates::bundledRollbackArtifactRelativePath;

namespace
{
    class TestRunner
    {
    public:
        void check(bool condition, const char *expression, int line)
        {
            ++m_assertions;
            if (condition) {
                return;
            }
            ++m_failures;
            QTextStream(stderr) << "FAIL line " << line << ": " << expression << Qt::endl;
        }

        int finish() const
        {
            QTextStream stream(m_failures == 0 ? stdout : stderr);
            stream << (m_failures == 0 ? "PASS" : "FAIL") << ": "
                   << m_assertions << " assertions, " << m_failures << " failures" << Qt::endl;
            return m_failures == 0 ? 0 : 1;
        }

    private:
        int m_assertions = 0;
        int m_failures = 0;
    };
}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    TestRunner runner;

    const QString digest(64, QLatin1Char('a'));
    const QString contentAddressedPath = QStringLiteral("files/artifacts/%1/AmneziaVPN_4.9.2.1_windows_x64.exe")
            .arg(digest);
    QString relativePath;

    // A Windows-only bundle needs only its own platform artifact, and its
    // content-addressed path must survive parsing exactly.
    CHECK(bundledArtifactRelativePath(contentAddressedPath, digest, relativePath));
    CHECK(relativePath == contentAddressedPath);
    const QString encodedNamePath = QStringLiteral("files/artifacts/") + digest
            + QStringLiteral("/AmneziaVPN%20candidate.exe");
    CHECK(bundledArtifactRelativePath(encodedNamePath, digest, relativePath));
    CHECK(relativePath == QStringLiteral("files/artifacts/%1/AmneziaVPN candidate.exe").arg(digest));
    const QString shellCharactersPath = QStringLiteral("files/artifacts/") + digest
            + QStringLiteral("/Amnezia%24%28id%29%60x%60%22.exe");
    CHECK(bundledArtifactRelativePath(shellCharactersPath, digest, relativePath));
    CHECK(relativePath == QStringLiteral("files/artifacts/%1/Amnezia$(id)`x`\".exe").arg(digest));

    const QStringList unsafeUrls {
        QStringLiteral("https://updates.example.invalid/") + contentAddressedPath,
        QStringLiteral("//updates.example.invalid/") + contentAddressedPath,
        QStringLiteral("/") + contentAddressedPath,
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/../AmneziaVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/%2E%2E/AmneziaVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/..%2FAmneziaVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/Amnezia%5CVPN.exe"),
        QStringLiteral("files\\artifacts\\") + digest + QStringLiteral("\\AmneziaVPN.exe"),
        QStringLiteral("C:/") + contentAddressedPath,
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/Amnezia%3AVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/Amnezia%0AVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/AmneziaVPN.exe?cache=1"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/AmneziaVPN.exe#fragment"),
    };
    for (const QString &unsafeUrl : unsafeUrls) {
        CHECK(!bundledArtifactRelativePath(unsafeUrl, digest, relativePath));
    }
    CHECK(!bundledArtifactRelativePath(contentAddressedPath, QString(64, QLatin1Char('b')), relativePath));
    CHECK(!bundledArtifactRelativePath(contentAddressedPath, digest.toUpper(), relativePath));
    CHECK(!bundledArtifactRelativePath(
            QStringLiteral("files/artifacts/%1/AmneziaVPN.exe").arg(digest.toUpper()), digest, relativePath));

    const QString rollbackGeneration = QStringLiteral("42");
    const QString rollbackVersion = QStringLiteral("4.9.0.11");
    const QString rollbackPath = QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/")
            + rollbackVersion + QStringLiteral("/AmneziaVPN_4.9.0.11_windows_x64.exe");
    CHECK(bundledRollbackArtifactRelativePath(
            rollbackPath, rollbackGeneration, rollbackVersion, relativePath));
    CHECK(relativePath == rollbackPath);
    const QString encodedRollbackPath = QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/")
            + rollbackVersion + QStringLiteral("/AmneziaVPN%20rollback.exe");
    CHECK(bundledRollbackArtifactRelativePath(
            encodedRollbackPath, rollbackGeneration, rollbackVersion, relativePath));
    CHECK(relativePath == QStringLiteral("files/rollback/%1/%2/AmneziaVPN rollback.exe").arg(
            rollbackGeneration, rollbackVersion));

    const QStringList unsafeRollbackUrls {
        QStringLiteral("https://updates.example.invalid/") + rollbackPath,
        QStringLiteral("/") + rollbackPath,
        QStringLiteral("files/rollback/042/") + rollbackVersion + QStringLiteral("/AmneziaVPN.exe"),
        QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/4.09.0.11/AmneziaVPN.exe"),
        QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/") + rollbackVersion
                + QStringLiteral("/..%2FAmneziaVPN.exe"),
        QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/") + rollbackVersion
                + QStringLiteral("/Amnezia%5CVPN.exe"),
        QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/") + rollbackVersion
                + QStringLiteral("/AmneziaVPN.exe?cache=1"),
    };
    for (const QString &unsafeUrl : unsafeRollbackUrls) {
        CHECK(!bundledRollbackArtifactRelativePath(
                unsafeUrl, rollbackGeneration, rollbackVersion, relativePath));
    }
    CHECK(!bundledRollbackArtifactRelativePath(rollbackPath, QStringLiteral("042"), rollbackVersion, relativePath));
    CHECK(!bundledRollbackArtifactRelativePath(rollbackPath, rollbackGeneration, QStringLiteral("4.9.0.011"), relativePath));

    return runner.finish();
}
