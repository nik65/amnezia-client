#pragma once
// S1 native AWG prepare sequencer.
// Orchestration parity with client/server_scripts/awg_migration/prepare.py.
// Every process/Docker/control effect is injected; this header never opens a
// socket, starts a process, or mutates the host. Filesystem mutation is limited
// to the explicitly supplied migration root and private generation directory.
#include "policy.h"
#include "ready_config.h"
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace amnezia::awgMigration::prepare {
class PrepareError final : public std::runtime_error {
public:
    explicit PrepareError(const std::string &code) : std::runtime_error(code) {}
};

struct Request {
    std::string source, image, host;
    unsigned port = 0;
    std::uint64_t generation = 0;
    bool automatic = false;
    bool preflight = false;
    // Explicit producer binding. false keeps the legacy native-feed/Python
    // control generation byte-for-byte on its existing boundary; true selects
    // the native-control-http-v1 PID1 producer and requires nativeFeedSha256.
    bool nativeControl = false;
    std::string nativeFeedSha256;  // exact captured feed digest, native mode only
    // Exact captured native log collector digest. Required with
    // --native-control; empty keeps the legacy Python logs collector.
    std::string nativeCollectorSha256;
};

struct SourceObservation {
    std::string sourceId, startedAt, rawConfig, sourceIface;
    policy::Snapshot snapshot;
    std::optional<policy::Epoch> epoch;
    std::vector<std::string> ownedComments;
    std::vector<std::string> networkOptions;             // exact docker --network pairs
    std::map<std::string, policy::Fields> networkBinding; // networkId/interface/default
    std::map<std::string, std::string> expectedFeedSha;  // port -> sha256 hex
};

struct CommandResult {
    int status = 0;
    std::string output, error;
};

// Read-only automatic planning seam. The production adapter composes the
// canonical automatic_plan + trusted_image + source_config primitives; tests
// inject an inert inventory while still executing the real selection logic.
class AutomaticPlannerPort {
public:
    virtual ~AutomaticPlannerPort() = default;
    virtual void planAutomatic(const std::filesystem::path &root, const Request &,
                               const SourceObservation &, Request &resolved) = 0;
};

struct Readiness {
    bool ready = false;
    std::string detail;
};

// Narrow boundary. The production adapter is deliberately not part of S1:
// process, Docker, PID1 and control observation remain a separate wiring step.
class EffectPort {
public:
    virtual ~EffectPort() = default;
    virtual CommandResult command(const std::vector<std::string> &argv) = 0;
    // Writes only inside the generation directory; mode is exactly 0600/0755.
    virtual void write(const std::filesystem::path &path, const std::string &bytes,
                       unsigned mode) = 0;
    // Ed25519 signing key creation/copy + public DER suffix, exactly prepare.py.
    virtual std::string signingPublicKey(const std::filesystem::path &directory) = 0;
    // Readiness is a read-only attestation supplied by the reviewed observer.
    virtual Readiness ready(const SourceObservation &, const std::vector<std::string> &targetConfig,
                            const std::string &serverKey, bool automatic) = 0;
    virtual void installNativeFeed(const std::filesystem::path &directory,
                                   const std::string &sha256) = 0;
    // Stages the private native-control build context below the generation
    // directory: Dockerfile plus the exact captured /app/awg-feed bytes. The
    // context never contains VPN, signing, receipt or log material. The
    // implementation must verify sha256 equals its trusted captured bytes.
    virtual std::filesystem::path stageNativeControl(const std::filesystem::path &directory,
                                                     const std::string &sha256) = 0;
    // Capture every selected executable payload exactly once, before any
    // filesystem, transaction, signer or container mutation. Implementations
    // must enforce owner/regular/single-link/mode/static-ELF and operator SHA
    // and cache the authenticated bytes for all later use; a second call or a
    // later recapture is a failure, never a new trust decision.
    virtual void capturePayloads(const std::string &, const std::string &) {}
    // Stage the cached collector bytes in a private executable image context
    // below the generation directory. Empty unless native-control selected it.
    virtual std::filesystem::path stageNativeCollector(const std::filesystem::path &,
                                                       const std::string &) { return {}; }
    // Bounded readiness pause; production sleeps, inert fixtures only record.
    virtual void pause(unsigned milliseconds) = 0;
    // Automatic-only final UDP bind check before Docker publishes the port.
    // Tests record it; the production adapter performs the canonical probe.
    virtual void verifyAutomaticPort(unsigned port) { (void)port; }
};

struct ObservationPort {
    virtual ~ObservationPort() = default;
    virtual SourceObservation observe(const Request &) = 0;
    virtual bool componentExists(const std::string &name) = 0;
    virtual bool sourceControlBound() = 0;
    virtual std::map<std::string, policy::Fields> binding(const std::string &container) = 0;
    virtual policy::Snapshot targetSnapshot(const std::string &container, const ReadyConfig &,
                                            const std::string &iface,
                                            const std::vector<std::string> &owners) = 0;
};

struct Outcome {
    bool prepared = false;
    bool preflight = false;
    bool eligible = false;     // strictly after all read-only preflight gates
    std::string requestJson;   // selected request after automatic planning
    std::string receiptJson;   // exact receipt JSON when prepared
    std::string failure;       // exact PrepareError code / cleanup code
    std::vector<std::string> phases;
    bool cleaned = false;
};

// Phase order (fixed):
// validate -> observe -> preflight|recover -> layout -> journal -> signing ->
// generation -> target -> ready-attest -> feeds -> logs -> controls ->
// control-attestation boundary.
Outcome run(const std::filesystem::path &root, const Request &, ObservationPort &,
            EffectPort &, AutomaticPlannerPort * = nullptr);
}  // namespace amnezia::awgMigration::prepare
