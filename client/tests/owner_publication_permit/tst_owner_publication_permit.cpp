#include <QCoreApplication>
#include <QFile>
#include <cstdio>
#include "core/controllers/selfhosted/ownerPublicationPermit.h"

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
    QJsonObject permit { { "schema", 1 }, { "policyId", "amnezia-owner-release-50313-v1" },
        { "manifestSha256", manifest }, { "publisherSha256", publisher },
        { "version", "5.0.3.13" }, { "androidVersionCode", 2199 },
        { "issuedAt", "2026-10-19T00:00:00Z" }, { "expiresAt", "2026-10-19T01:00:00Z" },
        { "artifacts", artifacts }, { "acceptanceStatus", "owner-approved-unverified" },
        { "unverifiedTargets", QJsonArray { "android-real-device", "linux-gui", "linux-headless", "windows-runtime" } },
        { "invocation", "normal" } };
    const QDateTime now = QDateTime::fromString("2026-10-19T00:30:00Z", Qt::ISODate);
    const auto accepts = [&](const QJsonObject &p) {
        return validateOwnerPublicationPermit(p, manifest, publisher, "5.0.3.13", 2199, artifacts, now, PublicationAuthorization::OwnerUnverified13);
    };
    CHECK(accepts(permit));
    CHECK(!validateOwnerPublicationPermit(permit, manifest, publisher, "5.0.3.13", 2199, artifacts, now, PublicationAuthorization::FullAccepted));
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
    CHECK(!validateOwnerPublicationPermit(changed, manifest, publisher, "5.0.3.13", 2199, invalidPath, now, PublicationAuthorization::OwnerUnverified13));
    PublicationAuthorization selected = PublicationAuthorization::FullAccepted;
    int ownerCalls = 0;
    CHECK(selectPublicationAuthorization([]() { return true; }, [&]() { ++ownerCalls; return true; }, selected));
    CHECK(selected == PublicationAuthorization::FullAccepted && ownerCalls == 0);
    CHECK(selectPublicationAuthorization([]() { return false; }, [&]() { ++ownerCalls; return accepts(permit); }, selected));
    CHECK(selected == PublicationAuthorization::OwnerUnverified13 && ownerCalls == 1);
    CHECK(!selectPublicationAuthorization([]() { return false; }, []() { return false; }, selected));
    int commits = 0, aborts = 0;
    CHECK(runAuthorizedPublicationCommit([&]() { return accepts(permit); }, [&]() { ++aborts; }, [&]() { ++commits; }));
    CHECK(commits == 1 && aborts == 0);
    const QDateTime afterPrepare = QDateTime::fromString("2026-10-19T01:00:00Z", Qt::ISODate);
    CHECK(!runAuthorizedPublicationCommit([&]() {
        return validateOwnerPublicationPermit(permit, manifest, publisher, "5.0.3.13", 2199, artifacts, afterPrepare, PublicationAuthorization::OwnerUnverified13);
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
        CHECK(decodeOwnerPublicationPermit(bytes, key, decoded)); CHECK(decoded == expectedPayload);
        CHECK(validateOwnerPublicationPermit(decoded, expectedPayload.value("manifestSha256").toString(),
            expectedPayload.value("publisherSha256").toString(), "5.0.3.13", 2199,
            expectedPayload.value("artifacts").toArray(), now, PublicationAuthorization::OwnerUnverified13));
        auto extraEnvelope = QJsonDocument::fromJson(bytes).object(); extraEnvelope["extra"] = true;
        CHECK(!decodeOwnerPublicationPermit(QJsonDocument(extraEnvelope).toJson(QJsonDocument::Compact), key, decoded));
        CHECK(!decodeReleaseAcceptance(bytes, key, decoded));
        CHECK(!decodeOwnerPublicationPermit(bytes + '\n', key, decoded));
        QByteArray damaged = bytes; damaged[damaged.size() / 2] = damaged.at(damaged.size() / 2) == 'a' ? 'b' : 'a';
        CHECK(!decodeOwnerPublicationPermit(damaged, key, decoded));
        std::puts("pythonSignedInterop=true");
    }
    std::puts("ownerPolicyCases=passed fullGateRejects=true normalStartupSignedFallback=true");
    return 0;
}
