#pragma once

#include <array>
#include <cstdint>

namespace amnezia::managedRouteReconcileDiagnostic {

enum class Reason {
    AlreadyApplied, BaseMismatch, ContextMismatch, UpdateAttempted, WorkerThread, ProtocolState,
    DnsPending, InvalidOldRoutes, InvalidNewRoutes, EmptyDelta, DeltaLimit, NonceMissing,
    IpcUnavailable, NativeUpdated, NativeUnsupported, NativeRolledBack,
    NativeUncertain, NativeRejected, NativeInvalidResult, RemovalRequiresReconnect,
    InvalidGateway, RouteAddUpdated, RouteAddUncertain, PlatformUnsupported
};

inline const char *name(Reason reason)
{
    switch (reason) {
    case Reason::AlreadyApplied: return "already_applied";
    case Reason::BaseMismatch: return "base_mismatch";
    case Reason::ContextMismatch: return "runtime_context_mismatch";
    case Reason::UpdateAttempted: return "update_attempted";
    case Reason::WorkerThread: return "worker_thread";
    case Reason::ProtocolState: return "protocol_state_or_mode";
    case Reason::DnsPending: return "local_dns_pending";
    case Reason::InvalidOldRoutes: return "invalid_old_routes";
    case Reason::InvalidNewRoutes: return "invalid_new_routes";
    case Reason::EmptyDelta: return "empty_delta";
    case Reason::DeltaLimit: return "delta_limit";
    case Reason::NonceMissing: return "nonce_missing";
    case Reason::IpcUnavailable: return "ipc_unavailable";
    case Reason::NativeUpdated: return "native_updated";
    case Reason::NativeUnsupported: return "native_unsupported";
    case Reason::NativeRolledBack: return "native_rolled_back";
    case Reason::NativeUncertain: return "native_uncertain";
    case Reason::NativeRejected: return "native_rejected";
    case Reason::NativeInvalidResult: return "native_invalid_result";
    case Reason::RemovalRequiresReconnect: return "removal_requires_reconnect";
    case Reason::InvalidGateway: return "invalid_gateway";
    case Reason::RouteAddUpdated: return "route_add_updated";
    case Reason::RouteAddUncertain: return "route_add_uncertain";
    case Reason::PlatformUnsupported: return "platform_unsupported";
    }
    return "unknown";
}

// Bits: base present, epoch, server, mode, applied mode, local sites, protected hosts.
inline unsigned contextMismatchMask(const std::array<bool, 7> &matches)
{
    unsigned mask = 0;
    for (unsigned i = 0; i < matches.size(); ++i) {
        if (!matches[i]) mask |= 1u << i;
    }
    return mask;
}

inline bool alreadyApplied(bool oldValid, bool newValid, unsigned contextMask,
                           bool desiredEqualsApplied)
{
    return oldValid && newValid && contextMask == 0 && desiredEqualsApplied;
}

inline std::int64_t boundedCount(std::int64_t count)
{
    return count < 0 ? 0 : count > 1000000 ? 1000000 : count;
}

struct NativeDecision {
    bool updated;
    bool uncertain;
    Reason reason;
    int boundedResult;
};

// Keep the existing native result mapping: 0 unsupported, 1 updated,
// 2 rolled back, 3 uncertain, 4 rejected. Never log an unbounded IPC value.
inline NativeDecision nativeDecision(int result, bool attempted)
{
    const int bounded = result >= 0 && result <= 4 ? result : -1;
    if (result == 1) return {true, false, Reason::NativeUpdated, bounded};
    if (result == 3) return {false, true, Reason::NativeUncertain, bounded};
    if (result == 4) return {false, true, Reason::NativeRejected, bounded};
    if (attempted && bounded == -1) return {false, true, Reason::NativeInvalidResult, bounded};
    if (!attempted) return {false, false, Reason::IpcUnavailable, bounded};
    return {false, false, result == 2 ? Reason::NativeRolledBack : Reason::NativeUnsupported, bounded};
}

} // namespace amnezia::managedRouteReconcileDiagnostic
