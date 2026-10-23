#pragma once
#include "network_topology.h"
#include <functional>

namespace amnezia::awgMigration {
using NetworkObserverRunner = std::function<std::string(const std::vector<std::string> &)>;
// Read-only observations only. Name inputs are resolved once; IP reads use that ID.
NetworkTopologyResult observeNetworkTopology(const std::string &container, const NetworkObserverRunner &);
void observeStoppedNetworkTopology(const std::string &identity,
    const std::map<std::string,NetworkEndpointRole> &binding, const NetworkObserverRunner &);
// Fixed /usr/bin/docker via the existing bounded transport; no caller-selected budget.
NetworkObserverRunner productionNetworkObserverRunner();
}
