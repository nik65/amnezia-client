#pragma once
#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
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
inline constexpr qint64 maximumPrivateFileSize = 65536;
inline bool syncDescriptor(int fd)
{
    int result;
    do { result = ::fsync(fd); } while (result != 0 && errno == EINTR);
    return result == 0;
}
inline bool syncDirectory(const QString &path)
{
    const auto name = QFile::encodeName(path);
    const int fd = ::open(name.constData(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st{};
    const bool synced = ::fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)
            && st.st_uid == ::geteuid() && (st.st_mode & 07022) == 0 && syncDescriptor(fd);
    return ::close(fd) == 0 && synced;
}
inline bool safePrivateFile(const struct stat &st)
{
    return S_ISREG(st.st_mode) && st.st_uid == ::geteuid()
            && (st.st_mode & 07077) == 0 && st.st_size >= 0 && st.st_size <= maximumPrivateFileSize;
}
inline bool privateFile(const QString &path, QByteArray *bytes)
{
    if (!bytes) return false;
    bytes->clear();
    const auto name = QFile::encodeName(path);
    // Reject FIFOs and device nodes without waiting for their producer first.
    const int fd = ::open(name.constData(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !safePrivateFile(st)) { ::close(fd); return false; }
    // A bounded sentinel read also catches growth after the initial fstat.
    QByteArray result(maximumPrivateFileSize + 1, '\0');
    qint64 count = 0;
    bool complete = false;
    while (count < result.size()) {
        const ssize_t received = ::read(fd, result.data() + count,
                                        static_cast<size_t>(result.size() - count));
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) break;
        if (received == 0) { complete = true; break; }
        count += received;
    }
    struct stat after{};
    const bool stable = complete && count == st.st_size && ::fstat(fd, &after) == 0
            && safePrivateFile(after) && after.st_size == st.st_size
            && after.st_dev == st.st_dev && after.st_ino == st.st_ino && after.st_mode == st.st_mode
            && after.st_mtim.tv_sec == st.st_mtim.tv_sec && after.st_mtim.tv_nsec == st.st_mtim.tv_nsec
            && after.st_ctim.tv_sec == st.st_ctim.tv_sec && after.st_ctim.tv_nsec == st.st_ctim.tv_nsec;
    const bool closed = ::close(fd) == 0;
    if (!stable || !closed) return false;
    result.resize(count);
    *bytes = result;
    return true;
}
inline bool atomicWrite(const QString &path, const QByteArray &bytes)
{
    if (bytes.size() > maximumPrivateFileSize) return false;
    struct stat st{};
    const auto name = QFile::encodeName(path);
    if (::lstat(name.constData(), &st) == 0) {
        if (!safePrivateFile(st)) return false;
    } else if (errno != ENOENT) return false;
    QSaveFile file(path);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly) || !file.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
        || file.write(bytes) != bytes.size() || !file.flush() || !syncDescriptor(file.handle())) return false;
    // A committed rename is not durable until the containing directory is.
    return file.commit() && syncDirectory(QFileInfo(path).absolutePath());
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
            || st.st_uid != ::geteuid() || (st.st_mode & 07022)) return {};
        current += '/' + part;
        const auto name = QFile::encodeName(current);
        if (::mkdir(name.constData(), 0700) == 0) {
            if (!syncDirectory(QFileInfo(current).absolutePath())) return {};
        } else if (errno != EEXIST) return {};
    }
    struct stat st{};
    const auto name = QFile::encodeName(path);
    if (::lstat(name.constData(), &st) != 0 || !S_ISDIR(st.st_mode)
        || st.st_uid != ::geteuid() || (st.st_mode & 07077)) return {};
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
    qint64 written = 0;
    while (written < result.size()) {
        const ssize_t count = ::write(fd, result.constData() + written,
                                      static_cast<size_t>(result.size() - written));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        written += count;
    }
    const bool stored = written == result.size() && syncDescriptor(fd);
    const bool closed = ::close(fd) == 0;
    // Preserve a failed/partial key file. It must never be replaced with a
    // newly generated key on the next call, which would reset durable pins.
    if (!stored || !closed || !syncDirectory(directory)) return {};
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
