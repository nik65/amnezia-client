#pragma once
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QStandardPaths>
#include <QCryptographicHash>
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

// Migration-only Linux storage. Protects offline settings copies and other
// local users. A process already running as this user can read the private key;
// this is deliberately not a claim of protection from a compromised account.
namespace awgMigrationSecretStore {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
inline bool privateFile(const QString &path, QByteArray *bytes)
{
    const auto name = QFile::encodeName(path);
    const int fd = ::open(name.constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st{};
    const bool safe = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid()
            && (st.st_mode & 077) == 0 && st.st_size >= 0 && st.st_size <= 65536;
    if (!safe) { ::close(fd); return false; }
    QFile file;
    if (!file.open(fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) { ::close(fd); return false; }
    *bytes = file.readAll();
    return bytes->size() == st.st_size;
}
inline bool atomicWrite(const QString &path, const QByteArray &bytes)
{
    struct stat st{};
    const auto name = QFile::encodeName(path);
    if (::lstat(name.constData(), &st) == 0
        && (!S_ISREG(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 077))) return false;
    QSaveFile file(path);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly) || !file.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
        || file.write(bytes) != bytes.size()) return false;
    return file.commit();
}
inline QString directory()
{
    const QString home = QDir::homePath();
    const QString path = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)
            + QStringLiteral("/awg-migration-secrets");
    if (!path.startsWith(home + '/')) return {};
    QString current = home;
    for (const auto &part : path.mid(home.size() + 1).split('/')) {
        struct stat st{};
        const auto parent = QFile::encodeName(current);
        if (::lstat(parent.constData(), &st) != 0 || !S_ISDIR(st.st_mode)
            || st.st_uid != ::geteuid() || (st.st_mode & 022)) return {};
        current += '/' + part;
        const auto name = QFile::encodeName(current);
        if (::mkdir(name.constData(), 0700) != 0 && errno != EEXIST) return {};
    }
    struct stat st{};
    const auto name = QFile::encodeName(path);
    if (::lstat(name.constData(), &st) != 0 || !S_ISDIR(st.st_mode)
        || st.st_uid != ::geteuid() || (st.st_mode & 077)) return {};
    return path;
}
inline QByteArray key(const QString &directory)
{
    QByteArray result;
    const QString path = directory + "/key";
    struct stat st{};
    if (::lstat(QFile::encodeName(path).constData(), &st) == 0)
        return privateFile(path, &result) && result.size() == 32 ? result : QByteArray{};
    if (errno != ENOENT) return {};
    // Losing an existing store key must never silently reset signer pins or
    // generation watermarks by manufacturing a replacement key.
    if (!QDir(directory).entryList(QDir::Files | QDir::Hidden | QDir::System).isEmpty()) return {};
    result.resize(32);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(result.data()), result.size()) != 1) return {};
    const int fd = ::open(QFile::encodeName(path).constData(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return privateFile(path, &result) && result.size() == 32 ? result : QByteArray{};
    const bool stored = ::write(fd, result.constData(), result.size()) == result.size() && ::fsync(fd) == 0;
    ::close(fd);
    if (!stored) return {};
    return result;
}
inline QByteArray crypt(const QByteArray &input, const QByteArray &key, bool encrypt)
{
    if (key.size() != 32 || (!encrypt && (input.size() < 32 || !input.startsWith("AMG1")))) return {};
    QByteArray nonce = encrypt ? QByteArray(12, '\0') : input.mid(4, 12);
    if (encrypt && RAND_bytes(reinterpret_cast<unsigned char *>(nonce.data()), 12) != 1) return {};
    const QByteArray body = encrypt ? input : input.mid(16, input.size() - 32);
    QByteArray output(body.size() + 16, '\0');
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};
    int size = 0, finalSize = 0;
    bool ok = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
            reinterpret_cast<const unsigned char *>(key.constData()),
            reinterpret_cast<const unsigned char *>(nonce.constData()), encrypt ? 1 : 0) == 1;
    if (!encrypt) ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
            const_cast<char *>(input.constData() + input.size() - 16)) == 1;
    ok = ok && EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char *>(output.data()), &size,
            reinterpret_cast<const unsigned char *>(body.constData()), body.size()) == 1;
    ok = ok && EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(output.data()) + size, &finalSize) == 1;
    output.resize(size + finalSize);
    QByteArray tag(16, '\0');
    if (encrypt) ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return {};
    return encrypt ? QByteArray("AMG1") + nonce + output + tag : output;
}
inline QString journalPath(const QString &directory, const QString &id)
{
    return directory + '/' + QString::fromLatin1(QCryptographicHash::hash(id.toUtf8(), QCryptographicHash::Sha256).toHex());
}
inline bool available() { const auto dir = directory(); return !dir.isEmpty() && key(dir).size() == 32; }
inline QByteArray read(const QString &id)
{
    const auto dir = directory();
    if (dir.isEmpty()) return {};
    QByteArray bytes;
    return privateFile(journalPath(dir, id), &bytes) ? crypt(bytes, key(dir), false) : QByteArray{};
}
inline bool write(const QString &id, const QByteArray &bytes)
{
    const auto dir = directory();
    if (dir.isEmpty()) return false;
    const auto encrypted = crypt(bytes, key(dir), true);
    return !encrypted.isEmpty() && atomicWrite(journalPath(dir, id), encrypted) && read(id) == bytes;
}
#endif
}
