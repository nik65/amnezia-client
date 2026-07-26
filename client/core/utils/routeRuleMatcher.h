#ifndef ROUTERULEMATCHER_H
#define ROUTERULEMATCHER_H

#include <QHostAddress>
#include <QString>
#include <QVariantMap>

namespace amnezia::routeRuleMatcher
{
inline constexpr int maximumInputLength = 2048;
inline constexpr int maximumHostLength = 253;
inline constexpr int maximumRuleOutputLength = 255;
inline constexpr int maximumStoredRouteLength = 128;
inline constexpr int maximumStoredRoutesPerRule = 64;
inline constexpr int maximumMatchedValueLength = 2048;
inline constexpr int maximumRawStoredValueLength = 4096;
inline constexpr int maximumRulesPerSource = 512;

inline constexpr int resolvedAddressScoreBase = 7000;
inline constexpr int addressScoreBase = 8000;
inline constexpr int domainScoreBase = 10032;

enum class InputPolicy {
    HostOrUrl,
    BareHostOrAddress,
};

enum class DomainMatchPolicy {
    RequireResolvedIpv4,
    PolicyOnly,
};

struct NormalizedTarget
{
    QString host;
    QHostAddress literalAddress;
    QString error;
};

struct RuleMatch
{
    bool matched = false;
    QString source;
    QString rule;
    QString configuredRule;
    QString matchedValue;
    QString matchType;
    QString safetyTransform;
    bool matchedValueTruncated = false;
    int score = -1;
};

struct MatchResult
{
    RuleMatch accepted;
    RuleMatch rejected;
    // A no-match is authoritative only when every configured rule and every
    // stored route token was examined within the public resource limits.
    bool coverageComplete = true;
    bool localRulesTruncated = false;
    bool managedRulesTruncated = false;
    bool storedValuesTruncated = false;
    int localRulesInspected = 0;
    int managedRulesInspected = 0;
};

// Canonicalizes a host, URL-like input or literal address exactly as the route
// inspector does. Hostnames are returned as lowercase ASCII Compatible
// Encoding (ACE); scoped IPv6 literals and privacy-risking malformed input are
// rejected with a stable symbolic error.
NormalizedTarget normalizeTarget(const QString &input,
                                 InputPolicy inputPolicy = InputPolicy::HostOrUrl);

// Scans every local and managed rule candidate for one already resolved
// address, while enforcing the explicit input and stored-token bounds. The
// host is canonicalized internally, so Unicode and ACE callers share one
// comparison domain. RequireResolvedIpv4 deliberately prevents domain and
// stored-address matches without runtime address evidence. PolicyOnly adds an
// exact configured-domain match for offline policy explanation; it never turns
// a mapped stored address into hostname evidence.
//
// Selection is deterministic: highest score wins, local wins an equal-score
// cross-source tie, and QMap iteration order preserves the first candidate on
// a complete tie. Unsafe matches are returned separately as rejected evidence.
MatchResult matchRules(const QVariantMap &localRules,
                       const QVariantMap &managedRules,
                       const QString &host,
                       const QHostAddress &resolvedAddress,
                       DomainMatchPolicy domainMatchPolicy =
                               DomainMatchPolicy::RequireResolvedIpv4);
}

#endif // ROUTERULEMATCHER_H
