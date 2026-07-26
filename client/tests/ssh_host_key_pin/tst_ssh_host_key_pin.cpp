#include <QCoreApplication>
#include <QDebug>
#include <QJsonObject>

#include "core/models/selfhosted/selfHostedAdminServerConfig.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/selfhosted/sshHostKeyPin.h"

using namespace amnezia;

namespace
{
const QString ServerXHost = QStringLiteral("85.208.87.69");
const QString ServerXPin = QStringLiteral("SHA256:2UtHIoVd4Lft+s4E/LZlA8+reysEexYyhkt03rg8Rdg");
const QString AlternatePin = QStringLiteral("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

int failures = 0;

void verify(bool condition, const char *description)
{
    if (!condition) {
        qCritical().noquote() << "FAIL:" << description;
        ++failures;
    }
}

void testCanonicalValidation()
{
    verify(sshHostKeyPin::isCanonicalFingerprint(ServerXPin), "ServerX fingerprint is canonical");
    verify(sshHostKeyPin::isCanonicalFingerprint(AlternatePin), "32 zero bytes are canonical");
    verify(!sshHostKeyPin::isCanonicalFingerprint(QString()), "empty fingerprint is rejected");
    verify(!sshHostKeyPin::isCanonicalFingerprint(ServerXPin + QLatin1Char('=')), "padding is rejected");
    verify(!sshHostKeyPin::isCanonicalFingerprint(QLatin1Char(' ') + ServerXPin), "leading whitespace is rejected");
    verify(!sshHostKeyPin::isCanonicalFingerprint(ServerXPin + QLatin1Char(' ')), "trailing whitespace is rejected");
    verify(!sshHostKeyPin::isCanonicalFingerprint(
                   QStringLiteral("sha256:2UtHIoVd4Lft+s4E/LZlA8+reysEexYyhkt03rg8Rdg")),
           "prefix is case-sensitive");
    verify(!sshHostKeyPin::isCanonicalFingerprint(
                   QStringLiteral("SHA256:2UtHIoVd4Lft-s4E_LZlA8-reysEexYyhkt03rg8Rdg")),
           "URL-safe Base64 is rejected");
    verify(!sshHostKeyPin::isCanonicalFingerprint(
                   QStringLiteral("SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")),
           "non-canonical trailing Base64 bits are rejected");
}

void testResolutionPrecedence()
{
    const auto explicitResolution = sshHostKeyPin::resolve(QStringLiteral("unconfigured.example"), AlternatePin);
    verify(explicitResolution.isResolved(), "valid explicit fingerprint resolves");
    verify(explicitResolution.source == sshHostKeyPin::Source::Explicit, "explicit fingerprint records its source");
    verify(explicitResolution.fingerprint == AlternatePin, "explicit fingerprint wins over compiled settings");

    const auto fallbackResolution = sshHostKeyPin::resolve(ServerXHost, QString());
    verify(fallbackResolution.isResolved(), "exact compiled hostname resolves");
    verify(fallbackResolution.source == sshHostKeyPin::Source::CompiledFallback,
           "compiled fingerprint records its source");
    verify(fallbackResolution.fingerprint == ServerXPin, "compiled fingerprint is returned unchanged");

    const auto caseMismatch = sshHostKeyPin::resolve(QStringLiteral("85.208.87.69 "), QString());
    verify(caseMismatch.error == sshHostKeyPin::Error::Missing, "non-exact original hostname cannot use fallback");
    verify(!caseMismatch.isResolved(), "non-exact hostname remains unresolved");

    const auto missing = sshHostKeyPin::resolve(QStringLiteral("server.example"), QString());
    verify(missing.error == sshHostKeyPin::Error::Missing, "unknown hostname reports missing pin");

    const auto malformed = sshHostKeyPin::resolve(ServerXHost, ServerXPin + QLatin1Char('='));
    verify(malformed.error == sshHostKeyPin::Error::Malformed, "malformed explicit pin reports malformed");
    verify(malformed.source == sshHostKeyPin::Source::None, "malformed explicit pin never falls back");
    verify(malformed.fingerprint.isEmpty(), "malformed explicit pin exposes no trusted value");
}

void testDigestComparison()
{
    const QByteArray serverXDigest = QByteArray::fromHex(
            "d94b4722855de0b7edface04fcb66503cfab7b2b047b1632864b74deb83c45d8");
    QByteArray decoded;
    verify(sshHostKeyPin::decodeFingerprint(ServerXPin, decoded), "canonical fingerprint strictly decodes");
    verify(decoded == serverXDigest, "strict decode returns the expected raw 32-byte digest");
    verify(sshHostKeyPin::matchesFingerprint(ServerXPin, serverXDigest),
           "constant-time helper accepts an identical digest");

    QByteArray mismatch = serverXDigest;
    mismatch[17] = static_cast<char>(mismatch.at(17) ^ 0x01);
    verify(!sshHostKeyPin::matchesFingerprint(ServerXPin, mismatch),
           "constant-time helper rejects a same-length mismatch");
    verify(!sshHostKeyPin::matchesFingerprint(ServerXPin, serverXDigest.left(31)),
           "constant-time helper rejects a short digest");
    verify(!sshHostKeyPin::matchesFingerprint(ServerXPin, serverXDigest + QByteArray(1, '\0')),
           "constant-time helper rejects a long digest");
    verify(!sshHostKeyPin::matchesFingerprint(ServerXPin + QLatin1Char('='), serverXDigest),
           "constant-time helper rejects a malformed expected fingerprint");
}

void testAdminJsonRoundTrip()
{
    SelfHostedAdminServerConfig original;
    original.hostName = ServerXHost;
    original.userName = QStringLiteral("operator");
    original.password = QStringLiteral("not-a-real-secret");
    original.sshHostKeyFingerprint = ServerXPin;
    original.port = 22;

    const QJsonObject json = original.toJson();
    verify(json.value(QStringLiteral("sshHostKeyFingerprint")).toString() == ServerXPin,
           "admin JSON persists the fingerprint under the stable key");

    const SelfHostedAdminServerConfig restored = SelfHostedAdminServerConfig::fromJson(json);
    verify(restored.sshHostKeyFingerprint == ServerXPin, "admin JSON round-trip restores the fingerprint");
    verify(restored.credentials().sshHostKeyFingerprint == ServerXPin,
           "admin credentials propagate the restored fingerprint");

    QJsonObject legacy = json;
    legacy.remove(QStringLiteral("sshHostKeyFingerprint"));
    const SelfHostedAdminServerConfig restoredLegacy = SelfHostedAdminServerConfig::fromJson(legacy);
    verify(restoredLegacy.sshHostKeyFingerprint.isEmpty(), "legacy JSON without a pin remains readable");
    verify(!restoredLegacy.toJson().contains(QStringLiteral("sshHostKeyFingerprint")),
           "legacy empty pin is not synthesized or persisted");
}
} // namespace

namespace amnezia::ContainerUtils
{
DockerContainer containerFromString(const QString &)
{
    return DockerContainer::None;
}

QString containerToString(DockerContainer)
{
    return QStringLiteral("none");
}

ServiceType containerService(DockerContainer)
{
    return ServiceType::Other;
}
} // namespace amnezia::ContainerUtils

namespace amnezia
{
void ProtocolConfig::clearClientConfig()
{
}

QJsonObject ContainerConfig::toJson() const
{
    return {};
}

ContainerConfig ContainerConfig::fromJson(const QJsonObject &)
{
    return {};
}
} // namespace amnezia

bool NetworkUtilities::checkIPv4Format(const QString &)
{
    return true;
}

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    Q_UNUSED(application)

    testCanonicalValidation();
    testResolutionPrecedence();
    testDigestComparison();
    testAdminJsonRoundTrip();

    if (failures != 0) {
        qCritical() << failures << "SSH host-key pin test(s) failed";
        return 1;
    }
    qInfo() << "SSH host-key pin policy and schema tests passed";
    return 0;
}
