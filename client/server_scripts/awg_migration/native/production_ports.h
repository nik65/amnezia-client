#pragma once
#include "prepare_sequencer.h"
#include "trusted_image.h"
#include "automatic_plan.h"
#include <sys/types.h>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace amnezia::awgMigration::prepareProduction {
// Concrete prepare adapters. Every effect/observation is performed by the
// already-reviewed bounded primitives in the canonical native directory.
// This class never invokes system(3), a shell, a socket, or an installer.
class ProductionPorts final : public prepare::EffectPort, public prepare::ObservationPort,
                              public prepare::AutomaticPlannerPort {
public:
    // Production defaults are the canonical /opt trust paths. The ownership
    // fields are an inert metadata model for fixtures; production always
    // requires uid 0 and mode 0755 for the captured static ELF, exactly as the
    // Python capture does. Passing a fixture owner never grants trust to host
    // installer bytes and never widens the default.
    struct DataPaths {
        DataPaths() = default;
        std::filesystem::path policyRoot = "/opt/amnezia/server-routing-rules";
        std::filesystem::path updatesRoot = "/opt/amnezia/client-updates";
        uid_t feedOwner = 0;
        mode_t feedMode = 0755;
    };

    ProductionPorts(std::filesystem::path root, std::filesystem::path nativeFeed,
                    std::string nativeFeedSha256);
    ProductionPorts(std::filesystem::path root, std::filesystem::path nativeFeed,
                    std::string nativeFeedSha256, DataPaths paths);
    ProductionPorts(std::filesystem::path root, std::filesystem::path nativeFeed,
                    std::string nativeFeedSha256, DataPaths paths,
                    std::filesystem::path nativeCollector, std::string nativeCollectorSha256);
    ~ProductionPorts() override = default;

    prepare::CommandResult command(const std::vector<std::string> &argv) override;
    void write(const std::filesystem::path &path, const std::string &bytes, unsigned mode) override;
    std::string signingPublicKey(const std::filesystem::path &directory) override;
    prepare::Readiness ready(const prepare::SourceObservation &, const std::vector<std::string> &targetConfig,
                             const std::string &serverKey, bool automatic) override;
    void installNativeFeed(const std::filesystem::path &directory, const std::string &sha256) override;
    std::filesystem::path stageNativeControl(const std::filesystem::path &directory,
                                             const std::string &sha256) override;
    void capturePayloads(const std::string &feedSha256,
                         const std::string &collectorSha256) override;
    std::filesystem::path stageNativeCollector(const std::filesystem::path &directory,
                                               const std::string &sha256) override;
    void pause(unsigned milliseconds) override;
    void verifyAutomaticPort(unsigned port) override;

    // Canonical automatic planning: source ListenPort, trusted image resolution,
    // bounded UDP inventory and automaticPlan. Read-only; no generation is made.
    // On success the selected request becomes this adapter's request state so
    // every later write/stage/control path follows the planned generation.
    void planAutomatic(const std::filesystem::path &root, const prepare::Request &,
                       const prepare::SourceObservation &, prepare::Request &resolved) override;

    prepare::SourceObservation observe(const prepare::Request &) override;
    bool componentExists(const std::string &name) override;
    bool sourceControlBound() override;
    std::map<std::string, policy::Fields> binding(const std::string &container) override;
    policy::Snapshot targetSnapshot(const std::string &container, const ReadyConfig &,
                                    const std::string &iface,
                                    const std::vector<std::string> &owners) override;

private:
    std::string inspectIdentity(const std::string &name);
    std::string inspectId(const std::string &name);
    std::string pinJson(const std::string &name);
    std::map<std::string, policy::Fields> networkBinding(const std::string &container,
                                                         std::vector<std::string> *options = nullptr);
    std::vector<std::string> ownedComments();
    const std::string &capturedFeed();
    const std::string &capturedCollector();
    std::optional<policy::Epoch> policyEpoch();
    std::map<std::string, std::string> expectedFeedSha(const policy::Snapshot &snapshot);

    std::filesystem::path root_;
    std::filesystem::path nativeFeed_;
    std::string nativeFeedSha256_;
    std::filesystem::path nativeCollector_;
    std::string nativeCollectorSha256_;
    std::string capturedFeedRaw_, capturedCollectorRaw_;
    std::string capturedFeedSha256_, capturedCollectorSha256_;
    bool captured_ = false;
    DataPaths data_;
    prepare::Request request_{};
    std::string sourceRaw_;
    bool observed_ = false;
};
} // namespace amnezia::awgMigration::prepareProduction
