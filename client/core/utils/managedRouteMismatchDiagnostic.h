#pragma once
#include <array>
#include <cstdint>
#include <string>

namespace managedRouteMismatchDiagnostic {
// Public diagnostic schema: booleans and bounded counts only. Never accept route text.
constexpr std::int64_t maximumCount = 1000000;
constexpr std::array<const char *, 10> names {{
    "expectedRoutesValid", "desiredRoutesValid", "authoritativeBasePresent",
    "baseRevision", "connectionEpoch", "serverBinding", "routeMode",
    "expectedRoutes", "policyRevision", "policyContent"
}};
struct Result {
    std::uint16_t mismatchMask = 0;
    std::string mismatchNames;
    std::array<std::int64_t, 3> counts;
    const char *desiredEqualsApplied;
};
inline Result describe(const std::array<bool, 10> &matches,
                       std::int64_t oldCount, std::int64_t newCount,
                       std::int64_t appliedCount, bool desiredComparisonKnown,
                       bool desiredMatchesApplied) {
    Result result {0, "", {{oldCount, newCount, appliedCount}},
                   desiredComparisonKnown ? (desiredMatchesApplied ? "true" : "false") : "unknown"};
    for (std::size_t i = 0; i < matches.size(); ++i) {
        if (!matches[i]) {
            result.mismatchMask |= static_cast<std::uint16_t>(1u << i);
            if (!result.mismatchNames.empty()) result.mismatchNames += ",";
            result.mismatchNames += names[i];
        }
    }
    if (result.mismatchNames.empty()) result.mismatchNames = "none";
    for (auto &count : result.counts)
        if (count < 0 || count > maximumCount) count = -1; // Unknown/out of diagnostic bounds.
    return result;
}
} // namespace managedRouteMismatchDiagnostic
