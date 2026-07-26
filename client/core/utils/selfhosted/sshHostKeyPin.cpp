#include "sshHostKeyPin.h"

#include <QByteArray>

#ifndef SELFHOSTED_SSH_TRUSTED_HOST
#define SELFHOSTED_SSH_TRUSTED_HOST ""
#endif

#ifndef SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256
#define SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 ""
#endif

namespace amnezia::sshHostKeyPin
{
namespace
{
constexpr qsizetype PrefixLength = 7;
constexpr qsizetype EncodedDigestLength = 43;
constexpr qsizetype CanonicalFingerprintLength = PrefixLength + EncodedDigestLength;
constexpr qsizetype Sha256DigestLength = 32;

const QString &compiledTrustedHost()
{
    static const QString host = QString::fromUtf8(SELFHOSTED_SSH_TRUSTED_HOST);
    return host;
}

const QString &compiledTrustedFingerprint()
{
    static const QString fingerprint = QString::fromUtf8(SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256);
    return fingerprint;
}
} // namespace

bool isCanonicalFingerprint(const QString &fingerprint)
{
    QByteArray digest;
    return decodeFingerprint(fingerprint, digest);
}

bool decodeFingerprint(const QString &fingerprint, QByteArray &digest)
{
    digest.clear();
    if (fingerprint.size() != CanonicalFingerprintLength
        || !fingerprint.startsWith(QLatin1String("SHA256:"))) {
        return false;
    }

    const QByteArray encoded = fingerprint.sliced(PrefixLength).toLatin1();
    for (const char character : encoded) {
        const bool isUpper = character >= 'A' && character <= 'Z';
        const bool isLower = character >= 'a' && character <= 'z';
        const bool isDigit = character >= '0' && character <= '9';
        if (!isUpper && !isLower && !isDigit && character != '+' && character != '/') {
            return false;
        }
    }

    const QByteArray::FromBase64Result decoded = QByteArray::fromBase64Encoding(
            encoded, QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded || decoded.decoded.size() != Sha256DigestLength) {
        return false;
    }

    if (decoded.decoded.toBase64(QByteArray::Base64Encoding | QByteArray::OmitTrailingEquals) != encoded) {
        return false;
    }

    digest = decoded.decoded;
    return true;
}

bool matchesFingerprint(const QString &expectedFingerprint, const QByteArray &actualSha256Digest)
{
    QByteArray expectedDigest;
    if (!decodeFingerprint(expectedFingerprint, expectedDigest)
        || actualSha256Digest.size() != Sha256DigestLength) {
        return false;
    }

    unsigned char difference = 0;
    for (qsizetype index = 0; index < Sha256DigestLength; ++index) {
        difference |= static_cast<unsigned char>(expectedDigest.at(index))
                ^ static_cast<unsigned char>(actualSha256Digest.at(index));
    }
    return difference == 0;
}

Resolution resolve(const QString &originalHostName, const QString &explicitFingerprint)
{
    if (!explicitFingerprint.isEmpty()) {
        if (!isCanonicalFingerprint(explicitFingerprint)) {
            return { {}, Source::None, Error::Malformed };
        }
        return { explicitFingerprint, Source::Explicit, Error::None };
    }

    const QString &trustedHost = compiledTrustedHost();
    const QString &trustedFingerprint = compiledTrustedFingerprint();
    if (trustedHost.isEmpty() || originalHostName != trustedHost) {
        return { {}, Source::None, Error::Missing };
    }
    if (!isCanonicalFingerprint(trustedFingerprint)) {
        return { {}, Source::None, Error::Malformed };
    }
    return { trustedFingerprint, Source::CompiledFallback, Error::None };
}

} // namespace amnezia::sshHostKeyPin
