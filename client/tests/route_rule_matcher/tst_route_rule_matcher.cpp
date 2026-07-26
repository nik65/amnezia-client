#include <QtTest/QtTest>

#include <QHostAddress>
#include <QVariantMap>

#include "core/utils/routeRuleMatcher.h"
#include "core/utils/managedRoutePolicy.h"
#include "core/controllers/routeInspectorController.h"

using namespace amnezia;

namespace
{
QHostAddress address(const char *value)
{
    return QHostAddress(QString::fromLatin1(value));
}
}

class RouteRuleMatcherTest final : public QObject
{
    Q_OBJECT

private slots:
    void canonicalizesUnicodeAndAceBothWays();
    void strictBareInputRejectsUrlsAndWhitespace();
    void policyOnlyExactDomainMatchesWithoutRuntimeAddress();
    void resolvedDomainRequiresRuntimeIpv4Evidence();
    void domainRulesAreExactNotSuffixes();
    void scansAllCidrsAndChoosesMoreSpecific();
    void managedMoreSpecificBeatsLocal();
    void localWinsEqualScoreTie();
    void storedRouteSpecificityWins();
    void keyCidrScoreBeatsStoredCidr();
    void domainScoreBeatsAddressAndStoredRoutes();
    void fullTieKeepsFirstQMapCandidate();
    void unsafeLocalAndManagedRoutesRemainRejectedEvidence();
    void unresolvedHostnameCannotMatchStoredAddress();
    void boundedInputsAndStoredRouteCountAreEnforced();
    void matchedValueIsBoundedAndReportsTruncation();
    void oversizedRuleMapsExposeIncompleteCoverage();
    void oversizedStoredValuesExposeIncompleteCoverage();
    void dnsBoundProcessesSeventeenthAddress();
    void dnsBoundMarksSixtyFifthAddressUnexamined();
    void managedPolicyIdentityRequiresCanonicalExactPair();
    void effectiveManagedPolicyIdentityTracksLifecycleRevision();
};

void RouteRuleMatcherTest::canonicalizesUnicodeAndAceBothWays()
{
    const QString unicode = QString::fromUtf8("пример.рф");
    const QString ace = QStringLiteral("xn--e1afmkfd.xn--p1ai");

    QCOMPARE(routeRuleMatcher::normalizeTarget(unicode).host, ace);
    QCOMPARE(routeRuleMatcher::normalizeTarget(ace).host, ace);

    QVariantMap unicodeRule;
    unicodeRule.insert(unicode, QString());
    auto result = routeRuleMatcher::matchRules(
            unicodeRule, {}, ace, address("93.184.216.34"));
    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, ace);
    QCOMPARE(result.accepted.matchType, QStringLiteral("domain"));

    QVariantMap aceRule;
    aceRule.insert(ace, QString());
    result = routeRuleMatcher::matchRules(
            aceRule, {}, unicode, address("93.184.216.34"));
    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, ace);
    QCOMPARE(result.accepted.matchType, QStringLiteral("domain"));
}

void RouteRuleMatcherTest::strictBareInputRejectsUrlsAndWhitespace()
{
    const auto genericUrl = routeRuleMatcher::normalizeTarget(
            QStringLiteral("https://Example.COM/path"));
    QCOMPARE(genericUrl.host, QStringLiteral("example.com"));
    QVERIFY(genericUrl.error.isEmpty());

    const auto bareUrl = routeRuleMatcher::normalizeTarget(
            QStringLiteral("https://example.com"),
            routeRuleMatcher::InputPolicy::BareHostOrAddress);
    QCOMPARE(bareUrl.error, QStringLiteral("invalid_host"));

    const auto paddedHost = routeRuleMatcher::normalizeTarget(
            QStringLiteral(" example.com "),
            routeRuleMatcher::InputPolicy::BareHostOrAddress);
    QCOMPARE(paddedHost.error, QStringLiteral("invalid_host"));

    const auto literalIpv6 = routeRuleMatcher::normalizeTarget(
            QStringLiteral("[2001:db8::1]"),
            routeRuleMatcher::InputPolicy::BareHostOrAddress);
    QVERIFY(literalIpv6.error.isEmpty());
    QCOMPARE(literalIpv6.literalAddress, address("2001:db8::1"));
}

void RouteRuleMatcherTest::policyOnlyExactDomainMatchesWithoutRuntimeAddress()
{
    const QVariantMap managedRules {
        { QStringLiteral("Example.COM."), QStringLiteral("stored-policy-value") },
    };
    const auto result = routeRuleMatcher::matchRules(
            {}, managedRules, QStringLiteral("example.com"), QHostAddress(),
            routeRuleMatcher::DomainMatchPolicy::PolicyOnly);

    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.source, QStringLiteral("managed"));
    QCOMPARE(result.accepted.rule, QStringLiteral("example.com"));
    QCOMPARE(result.accepted.configuredRule, QStringLiteral("Example.COM."));
    QCOMPARE(result.accepted.matchedValue, QStringLiteral("stored-policy-value"));
    QCOMPARE(result.accepted.matchType, QStringLiteral("domain"));
}

void RouteRuleMatcherTest::resolvedDomainRequiresRuntimeIpv4Evidence()
{
    const QVariantMap localRules {
        { QStringLiteral("example.test"), QStringLiteral("93.184.216.34") },
    };
    auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("example.test"), QHostAddress(),
            routeRuleMatcher::DomainMatchPolicy::RequireResolvedIpv4);
    QVERIFY(!result.accepted.matched);

    result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("example.test"), address("93.184.216.34"),
            routeRuleMatcher::DomainMatchPolicy::RequireResolvedIpv4);
    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.matchType, QStringLiteral("domain"));

    result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("example.test"), address("2001:db8::1"),
            routeRuleMatcher::DomainMatchPolicy::RequireResolvedIpv4);
    QVERIFY(!result.accepted.matched);
}

void RouteRuleMatcherTest::domainRulesAreExactNotSuffixes()
{
    const QVariantMap localRules {
        { QStringLiteral("example.com"), QString() },
        { QStringLiteral("*.sub.example.com"), QString() },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("www.example.com"), QHostAddress(),
            routeRuleMatcher::DomainMatchPolicy::PolicyOnly);

    QVERIFY(!result.accepted.matched);
    QVERIFY(!result.rejected.matched);
}

void RouteRuleMatcherTest::scansAllCidrsAndChoosesMoreSpecific()
{
    const QVariantMap localRules {
        { QStringLiteral("93.184.0.0/16"), QString() },
        { QStringLiteral("93.184.216.0/24"), QString() },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("unrelated.test"), address("93.184.216.34"));

    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, QStringLiteral("93.184.216.0/24"));
    QCOMPARE(result.accepted.matchType, QStringLiteral("address"));
    QCOMPARE(result.accepted.score, routeRuleMatcher::addressScoreBase + 24);
}

void RouteRuleMatcherTest::managedMoreSpecificBeatsLocal()
{
    const QVariantMap localRules {
        { QStringLiteral("93.184.0.0/16"), QString() },
    };
    const QVariantMap managedRules {
        { QStringLiteral("93.184.216.0/24"), QString() },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, managedRules, QStringLiteral("unrelated.test"),
            address("93.184.216.34"));

    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.source, QStringLiteral("managed"));
    QCOMPARE(result.accepted.rule, QStringLiteral("93.184.216.0/24"));
}

void RouteRuleMatcherTest::localWinsEqualScoreTie()
{
    const QVariantMap localRules {
        { QStringLiteral("93.184.216.0/24"), QString() },
    };
    const QVariantMap managedRules {
        { QStringLiteral("93.184.216.0/24"), QString() },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, managedRules, QStringLiteral("unrelated.test"),
            address("93.184.216.34"));

    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.source, QStringLiteral("local"));
    QCOMPARE(result.accepted.score, routeRuleMatcher::addressScoreBase + 24);
}

void RouteRuleMatcherTest::storedRouteSpecificityWins()
{
    const QVariantMap localRules {
        { QStringLiteral("alpha.test"), QStringLiteral("93.184.0.0/16") },
        { QStringLiteral("beta.test"), QStringLiteral("93.184.216.0/24") },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("unrelated.test"), address("93.184.216.34"));

    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, QStringLiteral("beta.test"));
    QCOMPARE(result.accepted.matchType, QStringLiteral("resolvedAddress"));
    QCOMPARE(result.accepted.score, routeRuleMatcher::resolvedAddressScoreBase + 24);
}

void RouteRuleMatcherTest::keyCidrScoreBeatsStoredCidr()
{
    const QVariantMap localRules {
        { QStringLiteral("93.184.0.0/16"), QString() },
        { QStringLiteral("stored.test"), QStringLiteral("93.184.216.34") },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("unrelated.test"), address("93.184.216.34"));

    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, QStringLiteral("93.184.0.0/16"));
    QCOMPARE(result.accepted.matchType, QStringLiteral("address"));
    QCOMPARE(result.accepted.score, routeRuleMatcher::addressScoreBase + 16);
}

void RouteRuleMatcherTest::domainScoreBeatsAddressAndStoredRoutes()
{
    const QVariantMap localRules {
        { QStringLiteral("93.184.216.0/24"), QString() },
        { QStringLiteral("alias.test"), QStringLiteral("93.184.216.34") },
        { QStringLiteral("example.test"), QString() },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("example.test"), address("93.184.216.34"));

    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, QStringLiteral("example.test"));
    QCOMPARE(result.accepted.matchType, QStringLiteral("domain"));
    QCOMPARE(result.accepted.score,
             routeRuleMatcher::domainScoreBase + QStringLiteral("example.test").size());
}

void RouteRuleMatcherTest::fullTieKeepsFirstQMapCandidate()
{
    const QVariantMap localRules {
        { QStringLiteral("beta.test"), QStringLiteral("93.184.216.34") },
        { QStringLiteral("alpha.test"), QStringLiteral("93.184.216.34") },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("unrelated.test"), address("93.184.216.34"));

    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, QStringLiteral("alpha.test"));
    QCOMPARE(result.accepted.score, routeRuleMatcher::resolvedAddressScoreBase + 32);
}

void RouteRuleMatcherTest::unsafeLocalAndManagedRoutesRemainRejectedEvidence()
{
    const QVariantMap unsafeLocal {
        { QStringLiteral("10.0.0.0/8"), QString() },
    };
    auto result = routeRuleMatcher::matchRules(
            unsafeLocal, {}, QStringLiteral("private.test"), address("10.1.2.3"));
    QVERIFY(!result.accepted.matched);
    QVERIFY(result.rejected.matched);
    QCOMPARE(result.rejected.source, QStringLiteral("local"));
    QCOMPARE(result.rejected.rule, QStringLiteral("10.0.0.0/8"));
    QCOMPARE(result.rejected.safetyTransform, QStringLiteral("client_cidr_rejected"));

    const QVariantMap trustedManaged {
        { QStringLiteral("10.0.0.0/8"), QString() },
    };
    result = routeRuleMatcher::matchRules(
            {}, trustedManaged, QStringLiteral("private.test"), address("10.1.2.3"));
    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.source, QStringLiteral("managed"));
    QCOMPARE(result.accepted.rule, QStringLiteral("10.0.0.0/8"));
    QVERIFY(!result.rejected.matched);

    const QVariantMap malformedManaged {
        { QStringLiteral("93.184.216.34/24"), QString() },
    };
    result = routeRuleMatcher::matchRules(
            {}, malformedManaged, QStringLiteral("managed.test"), address("93.184.216.34"));
    QVERIFY(!result.accepted.matched);
    QVERIFY(result.rejected.matched);
    QCOMPARE(result.rejected.source, QStringLiteral("managed"));
    QCOMPARE(result.rejected.safetyTransform,
             QStringLiteral("unsupported_managed_cidr_rejected"));
}

void RouteRuleMatcherTest::unresolvedHostnameCannotMatchStoredAddress()
{
    const QVariantMap localRules {
        { QStringLiteral("stored.example"), QStringLiteral("93.184.216.34") },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("unresolved.example"), QHostAddress());

    QVERIFY(!result.accepted.matched);
    QVERIFY(!result.rejected.matched);
}

void RouteRuleMatcherTest::boundedInputsAndStoredRouteCountAreEnforced()
{
    const auto oversized = routeRuleMatcher::normalizeTarget(
            QString(routeRuleMatcher::maximumInputLength + 1, QLatin1Char('a')));
    QCOMPARE(oversized.error, QStringLiteral("invalid_host"));

    QStringList storedRoutes;
    for (int index = 1; index <= routeRuleMatcher::maximumStoredRoutesPerRule + 1; ++index) {
        storedRoutes.append(QStringLiteral("8.8.0.%1").arg(index));
    }
    const QVariantMap localRules {
        { QStringLiteral("bounded.example"), storedRoutes.join(QLatin1Char(',')) },
    };

    auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("unrelated.test"), address("8.8.0.64"));
    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, QStringLiteral("bounded.example"));
    QVERIFY(!result.coverageComplete);
    QVERIFY(result.storedValuesTruncated);

    result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("unrelated.test"), address("8.8.0.65"));
    QVERIFY(!result.accepted.matched);
    QVERIFY(!result.coverageComplete);

    const QVariantMap oversizedRule {
        { QString(300, QLatin1Char('x')), QStringLiteral("8.8.8.8") },
    };
    result = routeRuleMatcher::matchRules(
            oversizedRule, {}, QStringLiteral("unrelated.test"), address("8.8.8.8"));
    QVERIFY(result.accepted.matched);
    QCOMPARE(result.accepted.rule, QStringLiteral("configured-rule"));
    QVERIFY(result.accepted.rule.size() <= routeRuleMatcher::maximumRuleOutputLength);
}

void RouteRuleMatcherTest::matchedValueIsBoundedAndReportsTruncation()
{
    const QString oversizedValue(
            routeRuleMatcher::maximumMatchedValueLength + 37, QLatin1Char('v'));
    const QVariantMap localRules {
        { QStringLiteral("bounded.example"), oversizedValue },
    };
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("bounded.example"), QHostAddress(),
            routeRuleMatcher::DomainMatchPolicy::PolicyOnly);

    QVERIFY(result.accepted.matched);
    QVERIFY(result.accepted.matchedValueTruncated);
    QCOMPARE(result.accepted.matchedValue.size(),
             routeRuleMatcher::maximumMatchedValueLength);
    QCOMPARE(result.accepted.matchedValue,
             oversizedValue.left(routeRuleMatcher::maximumMatchedValueLength));
}

void RouteRuleMatcherTest::oversizedRuleMapsExposeIncompleteCoverage()
{
    QVariantMap localRules;
    for (int index = 0; index < routeRuleMatcher::maximumRulesPerSource + 8; ++index) {
        localRules.insert(QStringLiteral("rule-%1.example").arg(index, 5, 10, QLatin1Char('0')),
                          QString());
    }
    const auto result = routeRuleMatcher::matchRules(
            localRules, {}, QStringLiteral("missing.example"), QHostAddress(),
            routeRuleMatcher::DomainMatchPolicy::PolicyOnly);

    QVERIFY(!result.accepted.matched);
    QVERIFY(!result.coverageComplete);
    QVERIFY(result.localRulesTruncated);
    QCOMPARE(result.localRulesInspected, routeRuleMatcher::maximumRulesPerSource);
}

void RouteRuleMatcherTest::oversizedStoredValuesExposeIncompleteCoverage()
{
    const QString oversizedValue =
            QStringLiteral("8.8.8.8,")
            + QString(routeRuleMatcher::maximumRawStoredValueLength, QLatin1Char('x'))
            + QStringLiteral(",9.9.9.9");
    const QVariantMap rules {
        { QStringLiteral("oversized.example"), oversizedValue },
    };

    auto result = routeRuleMatcher::matchRules(
            rules, {}, QStringLiteral("unrelated.example"), address("8.8.8.8"));
    QVERIFY(result.accepted.matched);
    QVERIFY(!result.coverageComplete);
    QVERIFY(result.storedValuesTruncated);

    result = routeRuleMatcher::matchRules(
            rules, {}, QStringLiteral("unrelated.example"), address("9.9.9.9"));
    QVERIFY(!result.accepted.matched);
    QVERIFY(!result.coverageComplete);
    QVERIFY(result.storedValuesTruncated);
}

void RouteRuleMatcherTest::dnsBoundProcessesSeventeenthAddress()
{
    QList<QHostAddress> addresses;
    for (int index = 1; index <= 17; ++index) {
        addresses.append(QHostAddress(QStringLiteral("8.8.0.%1").arg(index)));
    }

    const auto bounded = routeInspectorBounds::boundedDnsAddresses(addresses);
    QCOMPARE(bounded.observedCount, 17);
    QCOMPARE(bounded.processedCount, 17);
    QCOMPARE(bounded.ipv4.size(), 17);
    QVERIFY(bounded.ipv4.contains(QStringLiteral("8.8.0.17")));
    QVERIFY(!bounded.processingTruncated);
}

void RouteRuleMatcherTest::dnsBoundMarksSixtyFifthAddressUnexamined()
{
    QList<QHostAddress> addresses;
    for (int index = 1; index <= 65; ++index) {
        const int thirdOctet = (index - 1) / 254;
        const int fourthOctet = ((index - 1) % 254) + 1;
        addresses.append(QHostAddress(
                QStringLiteral("8.9.%1.%2").arg(thirdOctet).arg(fourthOctet)));
    }

    const auto bounded = routeInspectorBounds::boundedDnsAddresses(addresses);
    QCOMPARE(bounded.observedCount, 65);
    QCOMPARE(bounded.processedCount,
             routeInspectorBounds::maximumProcessedDnsAddresses);
    QCOMPARE(bounded.ipv4.size(),
             routeInspectorBounds::maximumProcessedDnsAddresses);
    QVERIFY(!bounded.ipv4.contains(QStringLiteral("8.9.0.65")));
    QVERIFY(bounded.processingTruncated);
}

void RouteRuleMatcherTest::managedPolicyIdentityRequiresCanonicalExactPair()
{
    const QString hash = QStringLiteral("sha256:") + QString(64, QLatin1Char('a'));
    QVERIFY(managedRoutePolicy::isCanonicalPolicyIdentity({}, {}));
    QVERIFY(managedRoutePolicy::isCanonicalPolicyIdentity(QStringLiteral("17"), hash));
    QVERIFY(managedRoutePolicy::isCanonicalPolicyIdentity(hash, hash));

    QVERIFY(!managedRoutePolicy::isCanonicalPolicyIdentity(QStringLiteral("17"), {}));
    QVERIFY(!managedRoutePolicy::isCanonicalPolicyIdentity({}, hash));
    QVERIFY(!managedRoutePolicy::isCanonicalPolicyIdentity(QStringLiteral(" 17"), hash));
    QVERIFY(!managedRoutePolicy::isCanonicalPolicyIdentity(QStringLiteral("017"), hash));
    QVERIFY(!managedRoutePolicy::isCanonicalPolicyIdentity(
            QStringLiteral("17"), hash.toUpper()));
}

void RouteRuleMatcherTest::effectiveManagedPolicyIdentityTracksLifecycleRevision()
{
    QJsonObject serverConfig {
        { QStringLiteral("managedSplitTunnelExceptSourceSites"),
          QJsonObject { { QStringLiteral("example.com"),
                          QStringLiteral("8.8.8.8") } } },
        { QStringLiteral("managedSplitTunnelForceEnabled"), true },
    };
    bool contentValid = false;
    const QString contentHash = managedRoutePolicy::canonicalSourcePolicyHash(
            serverConfig, &contentValid);
    QVERIFY(contentValid);
    QCOMPARE(managedRoutePolicy::effectiveRevision(serverConfig), contentHash);
    QCOMPARE(managedRoutePolicy::effectiveContentHash(serverConfig), contentHash);

    const QDateTime now = QDateTime::fromString(
            QStringLiteral("2026-07-26T00:00:00Z"), Qt::ISODate);
    const QJsonObject lastKnownGood {
        { QStringLiteral("schemaVersion"), 1 },
        { QStringLiteral("policyType"), QStringLiteral("versioned") },
        { QStringLiteral("revision"), QStringLiteral("42") },
        { QStringLiteral("revisionNumber"), 42 },
        { QStringLiteral("contentHash"), contentHash },
        { QStringLiteral("declaredContentHash"), contentHash },
        { QStringLiteral("contentMatchesDeclaration"), true },
        { QStringLiteral("issuedAt"), now.addSecs(-60).toString(Qt::ISODate) },
        { QStringLiteral("expiresAt"), now.addSecs(60).toString(Qt::ISODate) },
        { QStringLiteral("acceptedAt"), now.toString(Qt::ISODate) },
        { QStringLiteral("source"), QStringLiteral("unit-test") },
        { QStringLiteral("trustState"), QStringLiteral("unsigned") },
    };
    serverConfig.insert(
            managedRoutePolicy::stateKey(),
            QJsonObject { { managedRoutePolicy::lastKnownGoodKey(),
                            lastKnownGood } });

    QCOMPARE(managedRoutePolicy::effectiveRevision(serverConfig, now),
             QStringLiteral("42"));
    QCOMPARE(managedRoutePolicy::effectiveContentHash(serverConfig, now),
             contentHash);
    QVERIFY(managedRoutePolicy::effectiveRevision(
                    serverConfig, now.addSecs(61)).isEmpty());
    QVERIFY(managedRoutePolicy::effectiveContentHash(
                    serverConfig, now.addSecs(61)).isEmpty());
}

QTEST_APPLESS_MAIN(RouteRuleMatcherTest)

#include "tst_route_rule_matcher.moc"
