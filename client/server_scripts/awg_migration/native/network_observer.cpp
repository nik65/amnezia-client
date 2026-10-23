#include "network_observer.h"
#include "bounded_docker.h"
#include <algorithm>
#include <cstdint>
#include <rapidjson/encodings.h>
#include <rapidjson/memorystream.h>
#include <set>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t observationLimit = 1024 * 1024;
[[noreturn]] void reject() { throw NetworkTopologyError(); }
bool id(const std::string &value) {
    return value.size() == 64 && std::all_of(value.begin(),value.end(),[](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
bool target(const std::string &value) {
    if (id(value) || value == "amnezia-awg" || value == "amnezia-awg2") return true;
    for (const auto *source : {"amnezia-awg-migration-","amnezia-awg2-migration-"}) {
        const std::string prefix(source);
        if (value.compare(0,prefix.size(),prefix)) continue;
        const auto suffix = value.substr(prefix.size());
        if (suffix.empty() || suffix.size() > 16 || suffix.front() == '0') return false;
        std::uint64_t generation = 0;
        for (unsigned char c : suffix) {
            if (c < '0' || c > '9') return false;
            generation = generation * 10 + (c-'0');
        }
        return generation <= 9007199254740991ULL;
    }
    return false;
}
bool network(const std::string &value) { return value == "bridge" || value == "amnezia-dns-net"; }
void allowed(const std::vector<std::string> &args) {
    if (args == std::vector<std::string>{"docker","version","--format","{{.Server.Version}}"}) return;
    if (args.size() == 3 && args[0] == "docker" && args[1] == "inspect" && target(args[2])) return;
    if (args.size() == 4 && args[0] == "docker" && args[1] == "network" && args[2] == "inspect" && network(args[3])) return;
    if (args.size() >= 3 && id(args[2])
        && (args == std::vector<std::string>{"docker","exec",args[2],"ip","-j","-4","address","show"}
            || args == std::vector<std::string>{"docker","exec",args[2],"ip","-j","-4","route","show","default"})) return;
    reject();
}
void validUtf8(const std::string &value) {
    rapidjson::MemoryStream input(value.data(),value.size());
    while (input.Tell() < value.size()) {
        unsigned codepoint = 0;
        if (!rapidjson::UTF8<>::Decode(input,&codepoint)) reject();
    }
}
std::string capture(const NetworkObserverRunner &runner, const std::vector<std::string> &args) {
    allowed(args);
    auto value = runner(args);
    if (value.size() > observationLimit) reject();
    validUtf8(value);
    return value;
}
topologyDetail::Json array(const std::string &raw, bool single = false) {
    auto value = topologyDetail::parse(raw,observationLimit);
    if (!json_object_is_type(value.get(),json_type_array)
        || (single && json_object_array_length(value.get()) != 1)) reject();
    return value;
}
std::string observedId(const std::string &raw) {
    auto value = array(raw,true);
    auto *metadata = json_object_array_get_idx(value.get(),0);
    json_object *identity = nullptr;
    if (!metadata || !json_object_is_type(metadata,json_type_object)
        || !json_object_object_get_ex(metadata,"Id",&identity) || !identity || !json_object_is_type(identity,json_type_string)) reject();
    std::string result(json_object_get_string(identity),static_cast<std::size_t>(json_object_get_string_len(identity)));
    if (!id(result)) reject();
    return result;
}
void validBinding(const std::map<std::string,NetworkEndpointRole> &binding) {
    if (binding.size() != 1 && binding.size() != 2) reject();
    std::set<std::string> names, interfaces, identities;
    unsigned defaults = 0;
    for (const auto &entry : binding) {
        if (!network(entry.first) || entry.second.networkId.empty() || entry.second.networkId.size() > 1024
            || std::any_of(entry.second.networkId.begin(),entry.second.networkId.end(),[](unsigned char c) { return c < 32 || c == 127; })
            || (entry.second.interface != "eth0" && entry.second.interface != "eth1")
            || !interfaces.insert(entry.second.interface).second || !identities.insert(entry.second.networkId).second) reject();
        names.insert(entry.first);
        defaults += entry.second.defaultRoute ? 1 : 0;
    }
    if ((names != std::set<std::string>{"bridge"} && names != std::set<std::string>{"bridge","amnezia-dns-net"})
        || interfaces != (binding.size() == 1 ? std::set<std::string>{"eth0"} : std::set<std::string>{"eth0","eth1"})
        || defaults != 1) reject();
}
}
NetworkTopologyResult observeNetworkTopology(const std::string &container, const NetworkObserverRunner &runner) {
    try {
        if (!target(container)) reject();
        NetworkTopologyObservations observations;
        observations.version = capture(runner,{"docker","version","--format","{{.Server.Version}}"});
        observations.container = capture(runner,{"docker","inspect",container});
        const auto pinned = observedId(observations.container);
        if (id(container) && pinned != container) reject();
        const auto names = networkTopologyNames(observations.container);
        observations.addresses = capture(runner,{"docker","exec",pinned,"ip","-j","-4","address","show"});
        array(observations.addresses);
        observations.routes = capture(runner,{"docker","exec",pinned,"ip","-j","-4","route","show","default"});
        array(observations.routes);
        for (const auto &name : names) {
            auto raw = capture(runner,{"docker","network","inspect",name});
            array(raw,true);
            observations.networks.emplace(name,std::move(raw));
        }
        return validateNetworkTopology(observations);
    } catch (...) { reject(); }
}
void observeStoppedNetworkTopology(const std::string &identity,
    const std::map<std::string,NetworkEndpointRole> &binding, const NetworkObserverRunner &runner) {
    try {
        if (!id(identity)) reject();
        validBinding(binding);
        StoppedNetworkTopologyObservations observations{identity,"",binding,{}};
        observations.container = capture(runner,{"docker","inspect",identity});
        if (observedId(observations.container) != identity) reject();
        const auto names = networkTopologyNames(observations.container);
        if (names.size() != binding.size()) reject();
        for (const auto &name : names) {
            if (!binding.count(name)) reject();
            auto raw = capture(runner,{"docker","network","inspect",name});
            array(raw,true);
            observations.networks.emplace(name,std::move(raw));
        }
        validateStoppedNetworkTopology(observations);
    } catch (...) { reject(); }
}
NetworkObserverRunner productionNetworkObserverRunner() {
    return [](const std::vector<std::string> &args) {
        try {
            allowed(args);
            return runBoundedDocker(args,observationLimit);
        } catch (...) { reject(); }
    };
}
}
