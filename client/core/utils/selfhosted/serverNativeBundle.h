#ifndef AMNEZIA_SERVER_NATIVE_BUNDLE_H
#define AMNEZIA_SERVER_NATIVE_BUNDLE_H

#include <QByteArray>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QSet>
#include <QString>
#include <functional>
#include <optional>
#include <limits>

namespace amnezia::serverNative {
enum class Architecture { X86_64, Aarch64 };
inline QString architectureName(Architecture architecture)
{
    return architecture == Architecture::X86_64 ? QStringLiteral("x86_64") : QStringLiteral("aarch64");
}
inline std::optional<Architecture> parseArchitecture(const QString &name)
{
    if (name == QStringLiteral("x86_64")) return Architecture::X86_64;
    if (name == QStringLiteral("aarch64")) return Architecture::Aarch64;
    return std::nullopt;
}
struct Binary {
    QString role;
    Architecture architecture;
    QByteArray bytes;
    QString sha256;
};
struct Bundle {
    bool present = false;
    bool valid = false;
    QString error;
    QList<Binary> binaries;
    std::optional<Binary> find(const QString &role, Architecture architecture) const
    {
        if (!valid) return std::nullopt;
        for (const auto &binary : binaries)
            if (binary.role == role && binary.architecture == architecture) return binary;
        return std::nullopt;
    }
};
constexpr qsizetype maximumBinaryBytes = 32 * 1024 * 1024;
constexpr qsizetype maximumManifestBytes = 16 * 1024;

// Distribution contract: a static 64-bit little-endian Linux ET_EXEC. Shared
// loaders/libraries and static PIE are intentionally excluded from this recipe.
// Validate data only; never execute an uploaded or embedded binary to inspect it.
inline bool staticLinuxExecutable(const QByteArray &data, Architecture architecture)
{
    if (data.size() < 64 || data.size() > maximumBinaryBytes
            || data.left(7) != QByteArray::fromHex("7f454c46020101")) return false;
    const auto u8 = [&](qsizetype at) { return quint8(data.at(at)); };
    const auto le = [&](qsizetype at, int count) {
        quint64 result = 0;
        for (int i = 0; i < count; ++i) result |= quint64(u8(at + i)) << (8 * i);
        return result;
    };
    if ((u8(7) != 0 && u8(7) != 3) || u8(8) != 0 || le(16, 2) != 2
            || le(18, 2) != (architecture == Architecture::X86_64 ? 62 : 183)
            || le(20, 4) != 1 || le(52, 2) != 64 || le(54, 2) != 56) return false;
    const quint64 table = le(32, 8), count = le(56, 2), entry = le(24, 8);
    const quint64 size = quint64(data.size());
    if (!count || count > 128 || table < 64 || table > size || count > (size - table) / 56) return false;
    bool executableEntry = false;
    for (quint64 i = 0; i < count; ++i) {
        const qsizetype at = qsizetype(table + i * 56);
        const quint64 type = le(at, 4), flags = le(at + 4, 4);
        const quint64 offset = le(at + 8, 8), address = le(at + 16, 8);
        const quint64 fileSize = le(at + 32, 8), memorySize = le(at + 40, 8);
        const quint64 alignment = le(at + 48, 8);
        if (type == 2 || type == 3 || offset > size || fileSize > size - offset) return false;
        if (type == 1) {
            if (fileSize > memorySize || memorySize > (std::numeric_limits<quint64>::max)() - address)
                return false;
            const quint64 page = architecture == Architecture::Aarch64 ? 65536 : 4096;
            if (offset % page != address % page || (alignment > 1
                    && ((alignment & (alignment - 1)) != 0 || offset % alignment != address % alignment)))
                return false;
            if ((flags & 1) && entry >= address && entry - address < fileSize) executableEntry = true;
        }
    }
    return executableEntry;
}

using Reader = std::function<QByteArray(const QString &, qsizetype)>;
inline Bundle loadBundle(const QByteArray &manifest, const Reader &read)
{
    Bundle bundle;
    bundle.present = true;
    const auto fail = [&](const char *reason) {
        Bundle failed;
        failed.present = true;
        failed.error = QString::fromLatin1(reason);
        return failed;
    };
    if (manifest.isEmpty() || manifest.size() > maximumManifestBytes || !read)
        return fail("native_bundle_manifest_size_or_reader");
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(manifest, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
        return fail("native_bundle_manifest_json");
    // Canonical JSON also rejects duplicate keys and lossy numeric spellings.
    // Resources originate in the client build; this is an exact, bounded format.
    const QByteArray canonical = document.toJson(QJsonDocument::Compact);
    if (manifest != canonical && manifest != canonical + '\n')
        return fail("native_bundle_manifest_not_canonical");
    const QJsonObject root = document.object();
    if (root.size() != 2 || !root.value(QStringLiteral("schema")).isDouble()
            || root.value(QStringLiteral("schema")).toDouble() != 1
            || !root.value(QStringLiteral("binaries")).isArray())
        return fail("native_bundle_manifest_schema");
    const QJsonArray rows = root.value(QStringLiteral("binaries")).toArray();
    if (rows.isEmpty() || rows.size() > 6) return fail("native_bundle_manifest_members");
    QSet<QString> identities;
    for (const QJsonValue &value : rows) {
        if (!value.isObject()) return fail("native_bundle_binary_schema");
        const QJsonObject row = value.toObject();
        if (row.size() != 5) return fail("native_bundle_binary_schema");
        for (const char *key : {"role", "architecture", "path", "sha256"})
            if (!row.value(QString::fromLatin1(key)).isString()) return fail("native_bundle_binary_schema");
        const QString role = row.value(QStringLiteral("role")).toString();
        if (role != QStringLiteral("collector") && role != QStringLiteral("collector-route")
                && role != QStringLiteral("awg-feed")) return fail("native_bundle_binary_role");
        const auto architecture = parseArchitecture(row.value(QStringLiteral("architecture")).toString());
        if (!architecture) return fail("native_bundle_binary_architecture");
        const QString path = architectureName(*architecture) + QLatin1Char('/') + role;
        if (row.value(QStringLiteral("path")).toString() != path || identities.contains(path))
            return fail("native_bundle_binary_path_or_duplicate");
        identities.insert(path);
        const QString hash = row.value(QStringLiteral("sha256")).toString();
        if (hash.size() != 64) return fail("native_bundle_binary_hash");
        for (QChar ch : hash)
            if (!((ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
                    || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f'))))
                return fail("native_bundle_binary_hash");
        const QJsonValue sizeValue = row.value(QStringLiteral("size"));
        const double size = sizeValue.toDouble(-1);
        if (!sizeValue.isDouble() || size < 64 || size > maximumBinaryBytes || size != qsizetype(size))
            return fail("native_bundle_binary_size");
        const QByteArray bytes = read(path, qsizetype(size) + 1);
        if (bytes.size() != qsizetype(size)
                || QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()) != hash)
            return fail("native_bundle_binary_content");
        if (!staticLinuxExecutable(bytes, *architecture)) return fail("native_bundle_binary_elf");
        bundle.binaries.append(Binary { role, *architecture, bytes, hash });
    }
    bundle.valid = true;
    return bundle;
}
inline Bundle loadResourceBundle()
{
    QFile manifest(QStringLiteral(":/server_native/manifest.json"));
    if (!manifest.exists()) return {};
    if (!manifest.open(QIODevice::ReadOnly)) {
        Bundle failed;
        failed.present = true;
        failed.error = QStringLiteral("native_bundle_resource_unreadable");
        return failed;
    }
    return loadBundle(manifest.read(maximumManifestBytes + 1), [](const QString &path, qsizetype limit) {
        QFile binary(QStringLiteral(":/server_native/") + path);
        if (!binary.open(QIODevice::ReadOnly)) return QByteArray();
        return binary.read(limit);
    });
}
} // namespace amnezia::serverNative
#endif
