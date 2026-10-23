#include <QCoreApplication>
#include <QFile>
#include <cstdio>
#include "core/controllers/selfhosted/manualPublicationPermit.h"

using namespace amnezia::selfhostedUpdates;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "failed line %d: %s\n", __LINE__, #x); return 1; } } while(false)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    const QString manifest(64, u'1'), publisher(64, u'2');
    QJsonArray artifacts;
    for (int i = 0; i < 5; ++i) artifacts.append(QJsonObject {
        { "path", QStringLiteral("files/artifacts/%1/item").arg(i) },
        { "sha256", QString(64, QChar(u'0' + i)) }, { "size", 10 } });
    QJsonObject permit { { "schema", 1 }, { "policyId", "amnezia-manual-release-50313-v1" },
        { "manifestSha256", manifest }, { "publisherSha256", publisher },
        { "version", "5.0.3.13" }, { "androidVersionCode", 2199 },
        { "issuedAt", "2026-10-19T00:00:00Z" }, { "expiresAt", "2026-10-19T01:00:00Z" },
        { "artifacts", artifacts }, { "acceptanceStatus", "manual-approved-unverified" },
        { "unverifiedTargets", QJsonArray { "android-real-device", "linux-gui", "linux-headless", "windows-runtime" } },
        { "invocation", "manual" } };
    const QDateTime now = QDateTime::fromString("2026-10-19T00:30:00Z", Qt::ISODate);
    const auto accepts = [&](const QJsonObject &p) {
        return validateManualPublicationPermit(p, manifest, publisher, "5.0.3.13", 2199, artifacts, now, PublicationMode::ManualUnverified13);
    };
    CHECK(accepts(permit));
    CHECK(!validateManualPublicationPermit(permit, manifest, publisher, "5.0.3.13", 2199, artifacts, now, PublicationMode::FullAccepted));
    CHECK(!validateReleaseAcceptance(permit, manifest, publisher, "5.0.3.13", 2199, artifacts, now));
    const QList<QPair<QString, QJsonValue>> invalid {
        { "policyId", "amnezia-release-full-v1" }, { "schema", true },
        { "version", "5.0.3.14" }, { "androidVersionCode", 2200 },
        { "manifestSha256", QString(64, u'f') }, { "publisherSha256", QString(64, u'f') },
        { "acceptanceStatus", "PASS" }, { "invocation", "automatic" },
        { "receipts", QJsonArray {} }, { "unverifiedTargets", QJsonArray {} },
        { "issuedAt", "2026-10-19T00:31:00Z" }, { "expiresAt", "2026-10-19T00:30:00Z" },
        { "expiresAt", "2026-10-20T00:00:01Z" }, { "expiresAt", "2026-10-19T01:00:00+00:00" },
        { "issuedAt", "2026-10-19T00:00:00.000Z" }, { "artifacts", QJsonArray { artifacts.at(0) } }
    };
    for (const auto &entry : invalid) { auto p = permit; p.insert(entry.first, entry.second); CHECK(!accepts(p)); }
    for (const QString &key : permit.keys()) { auto p = permit; p.remove(key); CHECK(!accepts(p)); }
    auto changed = permit; auto wrongClosure = artifacts; auto item = wrongClosure.at(0).toObject(); item["size"] = 11;
    wrongClosure.replace(0, item); changed["artifacts"] = wrongClosure; CHECK(!accepts(changed));
    auto invalidPath = artifacts; item = invalidPath.at(0).toObject(); item["path"] = "files/../escape"; invalidPath.replace(0, item);
    changed["artifacts"] = invalidPath;
    CHECK(!validateManualPublicationPermit(changed, manifest, publisher, "5.0.3.13", 2199, invalidPath, now, PublicationMode::ManualUnverified13));
    char executable[] = "client"; char command[] = "--publish-unaccepted-bundled-updates-once";
    char extra[] = "--json"; char separator[] = "--";
    char *validArgv[] = { executable, command }; char *mixedArgv[] = { executable, command, extra };
    char *afterSeparator[] = { executable, separator, command }; char *valueArgv[] = { executable, extra, command };
    CHECK(isManualPublicationCommand(2, validArgv)); CHECK(!isManualPublicationCommand(3, mixedArgv));
    CHECK(!isManualPublicationCommand(3, afterSeparator)); CHECK(!isManualPublicationCommand(3, valueArgv));
    CHECK(!isManualPublicationCommand(1, validArgv));
    char equalValue[] = "--publish-unaccepted-bundled-updates-once=foo";
    char equalEmpty[] = "--publish-unaccepted-bundled-updates-once=";
    char *equalArgv[] = { executable, equalValue }; char *emptyArgv[] = { executable, equalEmpty };
    CHECK(hasManualPublicationOption(2, equalArgv) && !isManualPublicationCommand(2, equalArgv));
    CHECK(hasManualPublicationOption(2, emptyArgv) && !isManualPublicationCommand(2, emptyArgv));
    CHECK(hasManualPublicationOption(3, afterSeparator) && !isManualPublicationCommand(3, afterSeparator));
    CHECK(hasManualPublicationOption(3, valueArgv) && !isManualPublicationCommand(3, valueArgv));

    int commits = 0, aborts = 0;
    CHECK(runAuthorizedPublicationCommit([&]() { return accepts(permit); }, [&]() { ++aborts; }, [&]() { ++commits; }));
    CHECK(commits == 1 && aborts == 0);
    const QDateTime afterPrepare = QDateTime::fromString("2026-10-19T01:00:00Z", Qt::ISODate);
    CHECK(!runAuthorizedPublicationCommit([&]() {
        return validateManualPublicationPermit(permit, manifest, publisher, "5.0.3.13", 2199, artifacts, afterPrepare, PublicationMode::ManualUnverified13);
    }, [&]() { ++aborts; }, [&]() { ++commits; }));
    changed = permit; changed["manifestSha256"] = QString(64, u'f');
    CHECK(!runAuthorizedPublicationCommit([&]() { return accepts(changed); }, [&]() { ++aborts; }, [&]() { ++commits; }));
    CHECK(commits == 1 && aborts == 2);
    if (argc == 4) {
        QFile envelope(QString::fromLocal8Bit(argv[1])), publicKey(QString::fromLocal8Bit(argv[2]));
        CHECK(envelope.open(QIODevice::ReadOnly)); CHECK(publicKey.open(QIODevice::ReadOnly));
        const QByteArray bytes = envelope.readAll(), key = publicKey.readAll(); QJsonObject decoded;
        QFile expectedFile(QString::fromLocal8Bit(argv[3])); CHECK(expectedFile.open(QIODevice::ReadOnly));
        const QJsonObject expected = QJsonDocument::fromJson(expectedFile.readAll()).object();
        const QJsonObject expectedPayload = expected.value("payload").toObject();
        CHECK(decodeManualPublicationPermit(bytes, key, decoded)); CHECK(decoded == expectedPayload);
        CHECK(validateManualPublicationPermit(decoded, expectedPayload.value("manifestSha256").toString(),
            expectedPayload.value("publisherSha256").toString(), "5.0.3.13", 2199,
            expectedPayload.value("artifacts").toArray(), now, PublicationMode::ManualUnverified13));
        auto extraEnvelope = QJsonDocument::fromJson(bytes).object(); extraEnvelope["extra"] = true;
        CHECK(!decodeManualPublicationPermit(QJsonDocument(extraEnvelope).toJson(QJsonDocument::Compact), key, decoded));
        CHECK(!decodeReleaseAcceptance(bytes, key, decoded));
        CHECK(!decodeManualPublicationPermit(bytes + '\n', key, decoded));
        QByteArray damaged = bytes; damaged[damaged.size() / 2] = damaged.at(damaged.size() / 2) == 'a' ? 'b' : 'a';
        CHECK(!decodeManualPublicationPermit(damaged, key, decoded));
        std::puts("pythonSignedInterop=true");
    }
    std::puts("manualPolicyCases=passed fullGateRejects=true canonicalCliOnly=true");
    return 0;
}
