#pragma once
#include <json-c/json.h>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace amnezia::awgMigration {
class NetworkTopologyError final : public std::runtime_error {
public:
    NetworkTopologyError() : std::runtime_error("unsupported_source_network_topology") {}
};
struct NetworkEndpointRole {
    std::string networkId;
    std::string interface;
    bool defaultRoute{};
};
struct NetworkTopologyObservations {
    std::string version, container, addresses, routes;
    std::map<std::string, std::string> networks;
};
struct NetworkTopologyResult {
    std::vector<std::string> options;
    std::map<std::string, NetworkEndpointRole> binding;
};
struct StoppedNetworkTopologyObservations {
    std::string identity, container;
    std::map<std::string, NetworkEndpointRole> binding;
    std::map<std::string, std::string> networks;
};
// Pure observed-data validation. No process runner, socket or network side effect.
std::vector<std::string> networkTopologyNames(std::string_view rawContainer);
NetworkTopologyResult validateNetworkTopology(const NetworkTopologyObservations &);
// Validates supplied created/stopped Docker metadata only; never starts a target.
void validateStoppedNetworkTopology(const StoppedNetworkTopologyObservations &);
namespace topologyDetail {
struct JsonDelete { void operator()(json_object *value) const noexcept { if (value) json_object_put(value); } };
using Json = std::unique_ptr<json_object, JsonDelete>;
// Shared by the private runtime and core; strict keys/UTF-8/depth/finite-number checks.
Json parse(std::string_view, std::size_t limit);
}
}
