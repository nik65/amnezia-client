#ifndef SSHHOSTKEYPIN_H
#define SSHHOSTKEYPIN_H

#include <QByteArray>
#include <QString>

namespace amnezia::sshHostKeyPin
{

enum class Source
{
    None,
    Explicit,
    CompiledFallback
};

enum class Error
{
    None,
    Missing,
    Malformed
};

struct Resolution
{
    QString fingerprint;
    Source source = Source::None;
    Error error = Error::None;

    bool isResolved() const
    {
        return error == Error::None && !fingerprint.isEmpty();
    }
};

bool isCanonicalFingerprint(const QString &fingerprint);
bool decodeFingerprint(const QString &fingerprint, QByteArray &digest);
bool matchesFingerprint(const QString &expectedFingerprint, const QByteArray &actualSha256Digest);
Resolution resolve(const QString &originalHostName, const QString &explicitFingerprint);

} // namespace amnezia::sshHostKeyPin

#endif // SSHHOSTKEYPIN_H
