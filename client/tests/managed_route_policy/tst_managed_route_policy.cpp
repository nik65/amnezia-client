#include <QtTest/QtTest>

#include <QCoreApplication>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>

#include "core/utils/managedRoutePolicy.h"

using namespace amnezia;

namespace
{
    const QDateTime referenceNow = QDateTime::fromString(QStringLiteral("2026-07-21T12:00:00.000Z"), Qt::ISODateWithMs);

    QJsonObject sourceSites(const QString &address = QStringLiteral("93.184.216.34"))
    {
        return { { QStringLiteral("example.test"), address } };
    }

    QJsonObject versionedPayload(qint64 revision, const QDateTime &issuedAt = referenceNow.addSecs(-60),
                                 const QDateTime &expiresAt = referenceNow.addSecs(3600),
                                 const QString &address = QStringLiteral("93.184.216.34"))
    {
        QJsonObject payload {
            { QStringLiteral("managedSplitTunnelExceptSourceSites"), sourceSites(address) },
            { QStringLiteral("managedSplitTunnelForceEnabled"), true },
        };

        bool contentValid = false;
        const QJsonObject content = managedRoutePolicy::canonicalSourcePolicyContent(payload, &contentValid);
        if (!contentValid) {
            qFatal("versionedPayload produced invalid canonical content");
        }

        payload.insert(QStringLiteral("policy"),
                       QJsonObject {
                               { QStringLiteral("schemaVersion"), 1 },
                               { QStringLiteral("revision"), static_cast<double>(revision) },
                               { QStringLiteral("issuedAt"), issuedAt.toUTC().toString(Qt::ISODateWithMs) },
                               { QStringLiteral("expiresAt"), expiresAt.toUTC().toString(Qt::ISODateWithMs) },
                               { QStringLiteral("contentSha256"), managedRoutePolicy::derivedRevision(content) },
                               { QStringLiteral("content"), content },
                       });
        return payload;
    }

    ManagedRoutePolicyMetadata validatedMetadata(const QJsonObject &payload)
    {
        QString error;
        const auto metadata = managedRoutePolicy::validateCandidate(payload, std::nullopt, referenceNow, &error);
        if (!metadata.has_value()) {
            qFatal("validatedMetadata rejected test fixture: %s", qPrintable(error));
        }
        return metadata.value_or(ManagedRoutePolicyMetadata {});
    }

    QJsonObject effectiveServerConfig(const QJsonObject &payload, const ManagedRoutePolicyMetadata &metadata)
    {
        QJsonObject serverConfig = payload;
        serverConfig.remove(QStringLiteral("policy"));
        const bool changed = managedRoutePolicy::storeLastKnownGood(serverConfig, metadata);
        if (!changed) {
            qFatal("effectiveServerConfig failed to persist test metadata");
        }
        return serverConfig;
    }

    QJsonObject withStoredMetadata(const QJsonObject &serverConfig, const QJsonObject &metadata)
    {
        QJsonObject result = serverConfig;
        result.insert(managedRoutePolicy::stateKey(),
                      QJsonObject {
                              { QStringLiteral("schemaVersion"), 1 },
                              { managedRoutePolicy::lastKnownGoodKey(), metadata },
                      });
        return result;
    }
}

class ManagedRoutePolicyTest final : public QObject
{
    Q_OBJECT

private slots:
    void persistedVersionedMetadataRequiresLifecycleAndIntegrity();
    void validPersistedPolicyIsEffective();
    void expiredOrMismatchedPolicyFailsClosed();
    void candidateRevisionIsMonotonicAndContentBound();
    void canonicalSourceSitesEnforcesMaximumCount();
    void metadataLessLegacyPolicyRequiresSafeBoundedContent();
    void managedRouteSafetyHelpersRejectBroadAndSpecialRoutes();
    void managedRouteSafetyHelpersEnforceRouteCaps();
};

void ManagedRoutePolicyTest::persistedVersionedMetadataRequiresLifecycleAndIntegrity()
{
    const QJsonObject payload = versionedPayload(7);
    const ManagedRoutePolicyMetadata metadata = validatedMetadata(payload);
    const QJsonObject validJson = metadata.toJson();

    QVERIFY(managedRoutePolicy::metadataFromJson(validJson).has_value());

    const QJsonObject serverConfig = effectiveServerConfig(payload, metadata);
    QVERIFY(!managedRoutePolicy::isEffective(
            withStoredMetadata(serverConfig, QJsonObject()), referenceNow));
    const QStringList requiredFields {
        QStringLiteral("revisionNumber"),
        QStringLiteral("contentHash"),
        QStringLiteral("declaredContentHash"),
        QStringLiteral("contentMatchesDeclaration"),
        QStringLiteral("issuedAt"),
        QStringLiteral("expiresAt"),
    };
    for (const QString &field : requiredFields) {
        QJsonObject incomplete = validJson;
        incomplete.remove(field);
        QVERIFY2(!managedRoutePolicy::metadataFromJson(incomplete).has_value(),
                 qPrintable(QStringLiteral("missing persisted field was accepted: %1").arg(field)));
        QVERIFY2(!managedRoutePolicy::isEffective(withStoredMetadata(serverConfig, incomplete), referenceNow),
                 qPrintable(QStringLiteral("missing persisted field stayed effective: %1").arg(field)));
    }

    QJsonObject malformedHash = validJson;
    malformedHash.insert(QStringLiteral("contentHash"), QStringLiteral("sha256:not-a-digest"));
    QVERIFY(!managedRoutePolicy::metadataFromJson(malformedHash).has_value());
    QVERIFY(!managedRoutePolicy::isEffective(withStoredMetadata(serverConfig, malformedHash), referenceNow));

    QJsonObject malformedDeclaredHash = validJson;
    malformedDeclaredHash.insert(QStringLiteral("declaredContentHash"), QStringLiteral("not-a-digest"));
    QVERIFY(!managedRoutePolicy::metadataFromJson(malformedDeclaredHash).has_value());
    QVERIFY(!managedRoutePolicy::isEffective(
            withStoredMetadata(serverConfig, malformedDeclaredHash), referenceNow));

    QJsonObject malformedExpiry = validJson;
    malformedExpiry.insert(QStringLiteral("expiresAt"), QStringLiteral("not-a-time"));
    QVERIFY(!managedRoutePolicy::metadataFromJson(malformedExpiry).has_value());
    QVERIFY(!managedRoutePolicy::isEffective(withStoredMetadata(serverConfig, malformedExpiry), referenceNow));

    QJsonObject malformedIssuedAt = validJson;
    malformedIssuedAt.insert(QStringLiteral("issuedAt"), QStringLiteral("not-a-time"));
    QVERIFY(!managedRoutePolicy::metadataFromJson(malformedIssuedAt).has_value());
    QVERIFY(!managedRoutePolicy::isEffective(withStoredMetadata(serverConfig, malformedIssuedAt), referenceNow));

    QJsonObject relabelledLegacy = validJson;
    relabelledLegacy.insert(QStringLiteral("policyType"), QStringLiteral("legacy"));
    relabelledLegacy.remove(QStringLiteral("issuedAt"));
    relabelledLegacy.remove(QStringLiteral("expiresAt"));
    QVERIFY(!managedRoutePolicy::metadataFromJson(relabelledLegacy).has_value());
    QVERIFY(!managedRoutePolicy::isEffective(withStoredMetadata(serverConfig, relabelledLegacy), referenceNow));
}

void ManagedRoutePolicyTest::validPersistedPolicyIsEffective()
{
    const QJsonObject payload = versionedPayload(7);
    const ManagedRoutePolicyMetadata accepted = validatedMetadata(payload);
    QJsonObject serverConfig = effectiveServerConfig(payload, accepted);

    QVERIFY(accepted.versioned);
    QCOMPARE(accepted.revisionNumber, 7);
    QVERIFY(!accepted.contentHash.isEmpty());
    QCOMPARE(accepted.contentHash, accepted.declaredContentHash);
    QVERIFY(accepted.acceptedAt.isValid());

    const auto retained = managedRoutePolicy::lastKnownGood(serverConfig);
    QVERIFY(retained.has_value());
    QCOMPARE(retained->revisionNumber, 7);
    QVERIFY(managedRoutePolicy::isEffective(serverConfig, referenceNow));

    const auto effective = managedRoutePolicy::lastKnownGoodForEffectiveContent(serverConfig);
    QVERIFY(effective.has_value());
    QVERIFY(effective->contentMatchesDeclaration);
    QCOMPARE(effective->contentHash, accepted.contentHash);
    QCOMPARE(effective->trustState, QStringLiteral("unsigned"));

    QVERIFY(!managedRoutePolicy::storeLastKnownGood(serverConfig, accepted));
}

void ManagedRoutePolicyTest::expiredOrMismatchedPolicyFailsClosed()
{
    const QJsonObject payload = versionedPayload(7);
    const ManagedRoutePolicyMetadata accepted = validatedMetadata(payload);
    const QJsonObject serverConfig = effectiveServerConfig(payload, accepted);

    QVERIFY(managedRoutePolicy::isEffective(serverConfig, accepted.expiresAt.addMSecs(-1)));
    QVERIFY(!managedRoutePolicy::isEffective(serverConfig, accepted.expiresAt));

    QJsonObject changedContent = serverConfig;
    changedContent.insert(QStringLiteral("managedSplitTunnelExceptSourceSites"),
                          sourceSites(QStringLiteral("93.184.216.35")));
    QVERIFY(!managedRoutePolicy::isEffective(changedContent, referenceNow));
    const auto mismatch = managedRoutePolicy::lastKnownGoodForEffectiveContent(changedContent);
    QVERIFY(mismatch.has_value());
    QVERIFY(!mismatch->contentMatchesDeclaration);
    QVERIFY(mismatch->contentHash != mismatch->declaredContentHash);

    QJsonObject malformedState = serverConfig;
    QJsonObject state = malformedState.value(managedRoutePolicy::stateKey()).toObject();
    QJsonObject retained = state.value(managedRoutePolicy::lastKnownGoodKey()).toObject();
    retained.insert(QStringLiteral("schemaVersion"), 2);
    state.insert(managedRoutePolicy::lastKnownGoodKey(), retained);
    malformedState.insert(managedRoutePolicy::stateKey(), state);
    QVERIFY(!managedRoutePolicy::isEffective(malformedState, referenceNow));
}

void ManagedRoutePolicyTest::candidateRevisionIsMonotonicAndContentBound()
{
    QString error;
    const QJsonObject revisionSeven = versionedPayload(7);
    const auto current = managedRoutePolicy::validateCandidate(revisionSeven, std::nullopt, referenceNow, &error);
    QVERIFY2(current.has_value(), qPrintable(error));

    auto candidate = managedRoutePolicy::validateCandidate(versionedPayload(6), current, referenceNow, &error);
    QVERIFY(!candidate.has_value());
    QVERIFY(error.contains(QStringLiteral("older than last-known-good")));

    candidate = managedRoutePolicy::validateCandidate(
            versionedPayload(7, current->issuedAt, current->expiresAt, QStringLiteral("93.184.216.35")), current,
            referenceNow, &error);
    QVERIFY(!candidate.has_value());
    QVERIFY(error.contains(QStringLiteral("content changed without a new revision")));

    candidate = managedRoutePolicy::validateCandidate(
            versionedPayload(7, current->issuedAt, current->expiresAt.addSecs(60)), current, referenceNow, &error);
    QVERIFY(!candidate.has_value());
    QVERIFY(error.contains(QStringLiteral("lifecycle changed without a new revision")));

    candidate = managedRoutePolicy::validateCandidate(
            versionedPayload(8, current->issuedAt.addSecs(-1), current->expiresAt), current, referenceNow, &error);
    QVERIFY(!candidate.has_value());
    QVERIFY(error.contains(QStringLiteral("issue time is older than last-known-good")));

    candidate = managedRoutePolicy::validateCandidate(
            versionedPayload(8, current->issuedAt.addSecs(1), current->expiresAt.addSecs(60)), current, referenceNow,
            &error);
    QVERIFY2(candidate.has_value(), qPrintable(error));
    QCOMPARE(candidate->revisionNumber, 8);

    QJsonObject legacy = revisionSeven;
    legacy.remove(QStringLiteral("policy"));
    candidate = managedRoutePolicy::validateCandidate(legacy, current, referenceNow, &error);
    QVERIFY(!candidate.has_value());
    QVERIFY(error.contains(QStringLiteral("legacy policy cannot replace a versioned policy")));
}

void ManagedRoutePolicyTest::canonicalSourceSitesEnforcesMaximumCount()
{
    QJsonObject maximumSites;
    for (qsizetype index = 0; index < managedRoutePolicy::maximumSiteCount; ++index) {
        maximumSites.insert(QStringLiteral("site-%1.test").arg(index), QStringLiteral("93.184.216.34"));
    }

    bool valid = false;
    const QJsonObject canonical = managedRoutePolicy::canonicalSourceSites(maximumSites, &valid);
    QVERIFY(valid);
    QCOMPARE(canonical.size(), managedRoutePolicy::maximumSiteCount);

    maximumSites.insert(QStringLiteral("one-too-many.test"), QStringLiteral("93.184.216.34"));
    managedRoutePolicy::canonicalSourceSites(maximumSites, &valid);
    QVERIFY(!valid);

    QJsonArray oversizedArray;
    for (qsizetype index = 0; index <= managedRoutePolicy::maximumSiteCount; ++index) {
        oversizedArray.append(QJsonObject {
                { QStringLiteral("hostname"), QStringLiteral("array-%1.test").arg(index) },
                { QStringLiteral("ip"), QStringLiteral("93.184.216.34") },
        });
    }
    managedRoutePolicy::canonicalSourceSites(oversizedArray, &valid);
    QVERIFY(!valid);
}

void ManagedRoutePolicyTest::metadataLessLegacyPolicyRequiresSafeBoundedContent()
{
    const QJsonObject safeLegacy {
        { QStringLiteral("managedSplitTunnelExceptSourceSites"),
          QJsonObject { { QStringLiteral("legacy.example.test"), QStringLiteral("93.184.216.34") } } },
        { QStringLiteral("managedSplitTunnelForceEnabled"), false },
    };
    QVERIFY(!safeLegacy.contains(managedRoutePolicy::stateKey()));
    QVERIFY(managedRoutePolicy::isEffective(safeLegacy, referenceNow));

    QJsonObject broadBypass = safeLegacy;
    broadBypass.insert(QStringLiteral("managedSplitTunnelExceptSourceSites"),
                       QJsonObject { { QStringLiteral("legacy.example.test"), QStringLiteral("0.0.0.0/0") } });
    QVERIFY(!managedRoutePolicy::isEffective(broadBypass, referenceNow));

    QVERIFY(!managedRoutePolicy::isEffective(QJsonObject {}, referenceNow));
}

void ManagedRoutePolicyTest::managedRouteSafetyHelpersRejectBroadAndSpecialRoutes()
{
    quint32 address = 0;
    int prefixLength = -1;
    QVERIFY(managedRoutePolicy::parseCanonicalIpv4Route(QStringLiteral("93.184.0.0/16"), &address, &prefixLength));
    QCOMPARE(prefixLength, 16);
    QVERIFY(address != 0);
    QVERIFY(!managedRoutePolicy::parseCanonicalIpv4Route(QStringLiteral("93.184.216.34/16")));
    QVERIFY(!managedRoutePolicy::parseCanonicalIpv4Route(QStringLiteral("093.184.216.34")));
    QVERIFY(!managedRoutePolicy::parseCanonicalIpv4Route(QStringLiteral("2001:db8::/32")));

    const QStringList allowed {
        QStringLiteral("93.184.0.0/16"), QStringLiteral("93.184.216.34"),  QStringLiteral("10.0.0.0/8"),
        QStringLiteral("172.16.0.0/12"), QStringLiteral("192.168.0.0/16"),
    };
    for (const QString &route : allowed) {
        QVERIFY2(managedRoutePolicy::isAllowedManagedIpv4Route(route), qPrintable(route));
    }

    const QStringList forbidden {
        QStringLiteral("0.0.0.0/0"),      QStringLiteral("8.0.0.0/8"),     QStringLiteral("93.184.0.0/15"),
        QStringLiteral("93.0.0.0/8"),     QStringLiteral("100.64.0.0/10"), QStringLiteral("127.0.0.1"),
        QStringLiteral("169.254.0.0/16"), QStringLiteral("192.0.2.1"),     QStringLiteral("198.51.100.1"),
        QStringLiteral("203.0.113.1"),    QStringLiteral("224.0.0.0/4"),   QStringLiteral("255.255.255.255"),
    };
    for (const QString &route : forbidden) {
        QVERIFY2(!managedRoutePolicy::isAllowedManagedIpv4Route(route), qPrintable(route));
    }

    QVERIFY(managedRoutePolicy::isAllowedManagedSiteKey(QStringLiteral("example.test")));
    QVERIFY(managedRoutePolicy::isAllowedManagedSiteKey(QStringLiteral("93.184.216.34")));
    QVERIFY(!managedRoutePolicy::isAllowedManagedSiteKey(QStringLiteral("203.0.113.1")));
    QVERIFY(!managedRoutePolicy::isAllowedManagedSiteKey(QStringLiteral("bad/site")));
    QVERIFY(!managedRoutePolicy::isAllowedManagedSiteKey(QString(254, QLatin1Char('a'))));

    bool sitesValid = false;
    const QJsonObject directRoute = managedRoutePolicy::canonicalSourceSites(
            QJsonObject { { QStringLiteral("10.0.0.0/8"), QString() } }, &sitesValid);
    QVERIFY(sitesValid);
    QCOMPARE(directRoute.value(QStringLiteral("10.0.0.0/8")).toString(), QString());

    const QJsonObject aliasRoutes = managedRoutePolicy::canonicalSourceSites(
            QJsonObject {
                    { QStringLiteral("8.8.8.8"), QString() },
                    { QStringLiteral("8.8.8.8/32"), QString() },
            },
            &sitesValid);
    QVERIFY(sitesValid);
    QCOMPARE(aliasRoutes.size(), 1);
    QVERIFY(aliasRoutes.contains(QStringLiteral("8.8.8.8")));

    managedRoutePolicy::canonicalSourceSites(
            QJsonObject { { QStringLiteral("10.0.0.0/8"), QStringLiteral("8.8.8.8") } },
            &sitesValid);
    QVERIFY(!sitesValid);
}

void ManagedRoutePolicyTest::managedRouteSafetyHelpersEnforceRouteCaps()
{
    QStringList perSite;
    for (qsizetype index = 0; index < managedRoutePolicy::maximumRoutesPerSite; ++index) {
        perSite.append(QStringLiteral("8.8.4.%1").arg(index));
    }

    bool valid = false;
    QCOMPARE(managedRoutePolicy::validatedManagedRouteTokens(perSite.join(QLatin1Char(',')), &valid), perSite);
    QVERIFY(valid);

    perSite.append(QStringLiteral("8.8.4.250"));
    QVERIFY(managedRoutePolicy::validatedManagedRouteTokens(perSite.join(QLatin1Char(',')), &valid).isEmpty());
    QVERIFY(!valid);

    QStringList totalRoutes;
    for (qsizetype index = 0; index < managedRoutePolicy::maximumTotalRouteCount; ++index) {
        const qsizetype thirdOctet = index / 256;
        const qsizetype fourthOctet = index % 256;
        totalRoutes.append(QStringLiteral("8.1.%1.%2").arg(thirdOctet).arg(fourthOctet));
    }
    QCOMPARE(managedRoutePolicy::validatedManagedRoutes(totalRoutes, &valid), totalRoutes);
    QVERIFY(valid);

    QCOMPARE(managedRoutePolicy::validatedManagedRoutes(
                     { QStringLiteral("8.8.8.8"), QStringLiteral("8.8.8.8/32") }, &valid),
             QStringList { QStringLiteral("8.8.8.8") });
    QVERIFY(valid);

    totalRoutes.append(QStringLiteral("8.2.0.0"));
    QVERIFY(managedRoutePolicy::validatedManagedRoutes(totalRoutes, &valid).isEmpty());
    QVERIFY(!valid);

    const QString oversizedValue(managedRoutePolicy::maximumStoredRouteValueLength + 1, QLatin1Char('8'));
    QVERIFY(managedRoutePolicy::validatedManagedRouteTokens(oversizedValue, &valid).isEmpty());
    QVERIFY(!valid);
}

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    ManagedRoutePolicyTest test;
    return QTest::qExec(&test, argc, argv);
}

#include "tst_managed_route_policy.moc"
