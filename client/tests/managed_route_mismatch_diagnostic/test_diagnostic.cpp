#include "../../core/utils/managedRouteMismatchDiagnostic.h"
#include <cassert>
#include <limits>
#include <string>
int main() {
    using namespace managedRouteMismatchDiagnostic;
    std::array<bool, 10> matches; matches.fill(true);
    auto r = describe(matches, 0, 1, maximumCount, true, true);
    assert(r.mismatchMask == 0 && r.mismatchNames == "none");
    assert(std::string(r.desiredEqualsApplied) == "true");
    for (std::size_t i = 0; i < matches.size(); ++i) {
        matches[i] = false;
        r = describe(matches, 2, 3, 4, true, false);
        assert(r.mismatchMask == (1u << i));
        assert(r.mismatchNames == names[i]);
        assert(std::string(r.desiredEqualsApplied) == "false");
        matches[i] = true;
    }
    matches.fill(false);
    r = describe(matches, -1, maximumCount + 1, std::numeric_limits<std::int64_t>::max(), false, true);
    assert(r.mismatchMask == 1023 && r.counts[0] == -1 && r.counts[1] == -1 && r.counts[2] == -1);
    assert(std::string(r.desiredEqualsApplied) == "unknown");
    // Output is exclusively a fixed vocabulary, even for invalid/count overflow inputs.
    assert(r.mismatchNames.size() < 256);
    for (char c : r.mismatchNames) assert((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ',');
    r = describe(matches, 0, maximumCount, 1, true, false);
    assert(r.counts[0] == 0 && r.counts[1] == maximumCount && r.counts[2] == 1);
}
