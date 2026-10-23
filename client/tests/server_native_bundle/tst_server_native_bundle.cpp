#include "core/utils/selfhosted/serverNativeBundle.h"
#include <cstdio>
#include <limits>
using namespace amnezia::serverNative;
namespace {
void number(QByteArray &bytes, qsizetype at, quint64 value, int count)
{
    for (int i = 0; i < count; ++i) bytes[at + i] = char(value >> (8 * i));
}
QByteArray elf(Architecture architecture = Architecture::X86_64)
{
    QByteArray bytes(256, '\0');
    bytes.replace(0, 7, QByteArray::fromHex("7f454c46020101"));
    number(bytes, 16, 2, 2);
    number(bytes, 18, architecture == Architecture::X86_64 ? 62 : 183, 2);
    number(bytes, 20, 1, 4);
    number(bytes, 24, 0x400080, 8);
    number(bytes, 32, 64, 8);
    number(bytes, 52, 64, 2);
    number(bytes, 54, 56, 2);
    number(bytes, 56, 1, 2);
    number(bytes, 64, 1, 4);
    number(bytes, 68, 5, 4);
    number(bytes, 80, 0x400000, 8);
    number(bytes, 96, quint64(bytes.size()), 8);
    number(bytes, 104, quint64(bytes.size()), 8);
    number(bytes, 112, 4096, 8);
    return bytes;
}
QJsonObject row(const QByteArray &bytes, const QString &role = QStringLiteral("collector"),
                Architecture architecture = Architecture::X86_64)
{
    const QString arch = architectureName(architecture);
    return {{QStringLiteral("architecture"), arch}, {QStringLiteral("path"), arch + QLatin1Char('/') + role},
            {QStringLiteral("role"), role},
            {QStringLiteral("sha256"), QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex())},
            {QStringLiteral("size"), qint64(bytes.size())}};
}
QByteArray manifest(const QJsonArray &rows)
{
    return QJsonDocument(QJsonObject {{QStringLiteral("binaries"), rows}, {QStringLiteral("schema"), 1}})
            .toJson(QJsonDocument::Compact);
}
}
int main()
{
    int failures = 0, checks = 0;
    const auto check = [&](bool condition, const char *name) {
        ++checks;
        if (!condition) { ++failures; std::fprintf(stderr, "FAIL %s\n", name); }
    };
    const QByteArray good = elf();
    int reads = 0;
    const Reader reader = [&](const QString &path, qsizetype limit) {
        ++reads;
        check(path == QStringLiteral("x86_64/collector"), "reader exact relative path");
        check(limit == good.size() + 1, "reader bounded length");
        return good;
    };
    check(!loadResourceBundle().present, "absent bundle remains absent");
    auto bundle = loadBundle(manifest({row(good)}), reader);
    check(bundle.present && bundle.valid && bundle.error.isEmpty(), "valid canonical bundle");
    check(bundle.find(QStringLiteral("collector"), Architecture::X86_64).has_value(), "exact member selected");
    check(!bundle.find(QStringLiteral("collector-route"), Architecture::X86_64), "missing role not substituted");
    check(!bundle.find(QStringLiteral("collector"), Architecture::Aarch64), "missing architecture not substituted");
    check(reads == 1, "single artifact read");
    check(parseArchitecture(QStringLiteral("aarch64")) == Architecture::Aarch64, "arm architecture");
    check(!parseArchitecture(QStringLiteral("x86_64\n")), "uname suffix rejected");
    check(!parseArchitecture(QStringLiteral("amd64")), "alias not silently mapped");
    const auto validRow = row(good);
    const auto rejectRows = [&](QJsonArray rows, const char *name) {
        const Bundle result = loadBundle(manifest(rows), [&](const QString &, qsizetype) { return good; });
        check(result.present && !result.valid && !result.error.isEmpty() && result.binaries.isEmpty(), name);
    };
    rejectRows({}, "empty member list");
    rejectRows({validRow, validRow}, "duplicate identity");
    rejectRows({false}, "nonobject member");
    for (const char *key : {"role", "architecture", "path", "sha256", "size"}) {
        QJsonObject changed = validRow;
        changed.remove(QString::fromLatin1(key));
        rejectRows({changed}, "missing required field");
    }
    QJsonObject changed = validRow;
    changed.insert(QStringLiteral("other"), true);
    rejectRows({changed}, "unknown field");
    changed = validRow; changed[QStringLiteral("path")] = QStringLiteral("../collector");
    rejectRows({changed}, "traversal rejected before read");
    changed = validRow; changed[QStringLiteral("role")] = QStringLiteral("shell");
    rejectRows({changed}, "unsupported role");
    changed = validRow; changed[QStringLiteral("architecture")] = QStringLiteral("arm64");
    rejectRows({changed}, "unsupported architecture");
    changed = validRow; changed[QStringLiteral("size")] = true;
    rejectRows({changed}, "boolean size");
    changed = validRow; changed[QStringLiteral("size")] = 256.5;
    rejectRows({changed}, "fractional size");
    changed = validRow; changed[QStringLiteral("size")] = int(maximumBinaryBytes + 1);
    rejectRows({changed}, "oversized artifact declaration");
    changed = validRow; changed[QStringLiteral("sha256")] = QString(64, QLatin1Char('F'));
    rejectRows({changed}, "noncanonical digest");
    changed = validRow; changed[QStringLiteral("sha256")] = QString(64, QLatin1Char('0'));
    rejectRows({changed}, "wrong digest");
    const auto rejectRaw = [&](const QByteArray &raw, const char *name) {
        const auto result = loadBundle(raw, reader);
        check(result.present && !result.valid && result.binaries.isEmpty(), name);
    };
    rejectRaw({}, "empty manifest");
    rejectRaw(QByteArray(maximumManifestBytes + 1, ' '), "manifest limit");
    rejectRaw(manifest({validRow}) + "suffix", "trailing bytes");
    rejectRaw(manifest({validRow}) + QByteArray(1, '\0'), "NUL suffix");
    rejectRaw("{\"schema\":1,\"schema\":1,\"binaries\":[]}", "duplicate JSON keys");
    rejectRaw(QJsonDocument(QJsonObject {{QStringLiteral("binaries"), QJsonArray {validRow}},
                                       {QStringLiteral("schema"), true}}).toJson(QJsonDocument::Compact), "boolean schema");
    check(loadBundle(manifest({validRow}) + '\n', reader).valid, "single trailing LF");
    rejectRaw(manifest({validRow}) + "\n\n", "extra LF canonical boundary");
    const auto shortRead = loadBundle(manifest({validRow}), [&](const QString &, qsizetype) { return good.left(64); });
    check(!shortRead.valid, "short artifact");
    const auto longRead = loadBundle(manifest({validRow}), [&](const QString &, qsizetype) { return good + 'x'; });
    check(!longRead.valid, "appended artifact");
    check(staticLinuxExecutable(good, Architecture::X86_64), "x86 executable");
    check(staticLinuxExecutable(elf(Architecture::Aarch64), Architecture::Aarch64), "aarch64 executable");
    check(!staticLinuxExecutable(good, Architecture::Aarch64), "ELF architecture mismatch");
    for (const auto &test : QList<QPair<int, quint64>> {{16, 3}, {52, 63}, {54, 55}, {56, 0}, {56, 129}}) {
        QByteArray bad = good; number(bad, test.first, test.second, 2);
        check(!staticLinuxExecutable(bad, Architecture::X86_64), "ELF structural field");
    }
    for (quint64 type : {quint64(2), quint64(3)}) {
        QByteArray bad = good; number(bad, 64, type, 4);
        check(!staticLinuxExecutable(bad, Architecture::X86_64), "dynamic or interpreter rejected");
    }
    for (const auto &test : QList<QPair<int, quint64>> {{32, std::numeric_limits<quint64>::max()},
            {72, 257}, {96, 257}, {104, 255}, {24, 0}, {68, 4}}) {
        QByteArray bad = good; number(bad, test.first, test.second, test.first == 68 ? 4 : 8);
        check(!staticLinuxExecutable(bad, Architecture::X86_64), "ELF range or executable-entry check");
    }
    for (const auto &test : QList<QPair<int, quint64>> {{80, 0xfffffffffffff000ULL},
            {80, 0x400001}, {112, 3}, {112, 8192}}) {
        QByteArray bad = good;
        if (test.first == 80 && test.second == 0xfffffffffffff000ULL) {
            number(bad, 24, test.second + 128, 8);
            number(bad, 104, 8192, 8);
        }
        if (test.first == 112 && test.second == 8192) {
            number(bad, 80, 0x401000, 8);
            number(bad, 24, 0x401080, 8);
        }
        number(bad, test.first, test.second, 8);
        check(!staticLinuxExecutable(bad, Architecture::X86_64), "ELF overflow or segment alignment");
    }
    QByteArray multi = good;
    const auto arm = elf(Architecture::Aarch64);
    const auto both = loadBundle(manifest({validRow, row(arm, QStringLiteral("awg-feed"), Architecture::Aarch64)}),
        [&](const QString &path, qsizetype) { return path.startsWith(QStringLiteral("aarch64/")) ? arm : multi; });
    check(both.valid && both.binaries.size() == 2, "mixed role and architecture");
    const auto partial = loadBundle(manifest({validRow, row(arm, QStringLiteral("awg-feed"), Architecture::Aarch64)}),
        [&](const QString &path, qsizetype) { return path.startsWith(QStringLiteral("aarch64/")) ? QByteArray() : good; });
    check(!partial.valid && partial.binaries.isEmpty(), "invalid later member discards partial selection");
    std::printf("native bundle: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
