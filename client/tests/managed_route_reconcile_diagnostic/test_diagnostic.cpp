#include "../../core/utils/managedRouteReconcileDiagnostic.h"
#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <string>

using namespace amnezia::managedRouteReconcileDiagnostic;

int main()
{
    // Exercise the production mask for every combination, not a second policy model.
    for (unsigned expected = 0; expected < 128; ++expected) {
        std::array<bool, 7> matches;
        for (unsigned bit = 0; bit < matches.size(); ++bit) matches[bit] = !(expected & (1u << bit));
        const unsigned mask = contextMismatchMask(matches);
        assert(mask == expected);
        assert(alreadyApplied(true, true, mask, true) == (expected == 0));
        assert(!alreadyApplied(false, true, mask, true));
        assert(!alreadyApplied(true, false, mask, true));
        assert(!alreadyApplied(true, true, mask, false));
    }
    assert(!alreadyApplied(true, true, 128, true));

    struct Expected { int value; bool updated; bool uncertain; Reason reason; };
    const Expected expected[] = {
        {0, false, false, Reason::NativeUnsupported},
        {1, true, false, Reason::NativeUpdated},
        {2, false, false, Reason::NativeRolledBack},
        {3, false, true, Reason::NativeUncertain},
        {4, false, true, Reason::NativeRejected},
    };
    for (const auto &item : expected) {
        for (const bool attempted : {false, true}) {
            const auto decision = nativeDecision(item.value, attempted);
            assert(decision.updated == item.updated);
            assert(decision.uncertain == item.uncertain);
            assert(decision.boundedResult == item.value);
            const auto reason = !attempted && (item.value == 0 || item.value == 2)
                    ? Reason::IpcUnavailable : item.reason;
            assert(decision.reason == reason);
        }
    }
    for (const int invalid : {-1, 5, std::numeric_limits<int>::min(), std::numeric_limits<int>::max()}) {
        for (const bool attempted : {false, true}) {
            const auto decision = nativeDecision(invalid, attempted);
            assert(!decision.updated && decision.uncertain == attempted);
            assert(decision.boundedResult == -1);
            assert(decision.reason == (attempted ? Reason::NativeInvalidResult : Reason::IpcUnavailable));
        }
    }

    assert(boundedCount(std::numeric_limits<std::int64_t>::min()) == 0);
    assert(boundedCount(-1) == 0);
    assert(boundedCount(0) == 0);
    assert(boundedCount(1266) == 1266);
    assert(boundedCount(1000000) == 1000000);
    assert(boundedCount(1000001) == 1000000);
    assert(boundedCount(std::numeric_limits<std::int64_t>::max()) == 1000000);

    // Diagnostic text has only fixed, bounded public vocabulary.
    for (int value = 0; value <= static_cast<int>(Reason::PlatformUnsupported); ++value) {
        const std::string text = name(static_cast<Reason>(value));
        assert(!text.empty() && text.size() < 64);
        for (const char ch : text) assert((ch >= 'a' && ch <= 'z') || ch == '_');
    }
    assert(std::string(name(static_cast<Reason>(999))) == "unknown");
}
