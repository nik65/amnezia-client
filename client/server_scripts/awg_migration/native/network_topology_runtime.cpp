#include "network_topology_runtime.h"
#include "network_topology.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <iostream>
#include <poll.h>
#include <set>
#include <unistd.h>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t frameLimit = 8 * 1024 * 1024, observedLimit = 1024 * 1024, outputLimit = 16 * 1024;
[[noreturn]] void reject() { throw NetworkTopologyError(); }
json_object *member(json_object *root, const char *key, json_type type) {
    json_object *value = nullptr;
    if (!root || !json_object_is_type(root,json_type_object) || !json_object_object_get_ex(root,key,&value)
        || !value || !json_object_is_type(value,type)) reject();
    return value;
}
std::string text(json_object *root, const char *key) {
    auto *value = member(root,key,json_type_string);
    const auto size = static_cast<std::size_t>(json_object_get_string_len(value));
    if (size > observedLimit) reject();
    return {json_object_get_string(value),size};
}
void exact(json_object *root, std::set<std::string> keys) {
    if (!root || !json_object_is_type(root,json_type_object)) reject();
    json_object_object_foreach(root,key,value) { (void)value; if (!keys.erase(key)) reject(); }
    if (!keys.empty()) reject();
}
std::map<std::string,NetworkEndpointRole> bindingValue(json_object *input) {
    std::map<std::string,NetworkEndpointRole> result;
    auto *binding = member(input,"binding",json_type_object);
    json_object_object_foreach(binding,name,role) {
        if (std::string(name) != "bridge" && std::string(name) != "amnezia-dns-net") reject();
        exact(role,{"networkId","interface","default"});
        result.emplace(name,NetworkEndpointRole{text(role,"networkId"),text(role,"interface"),
            json_object_get_boolean(member(role,"default",json_type_boolean)) != 0});
    }
    return result;
}
topologyDetail::Json topologyValue(const NetworkTopologyResult &validated) {
    topologyDetail::Json value(json_object_new_object());
    auto *options = json_object_new_array();
    for (const auto &option : validated.options) json_object_array_add(options,json_object_new_string(option.c_str()));
    json_object_object_add(value.get(),"options",options);
    auto *binding = json_object_new_object();
    for (const auto &entry : validated.binding) {
        auto *role = json_object_new_object();
        json_object_object_add(role,"networkId",json_object_new_string_len(entry.second.networkId.data(),static_cast<int>(entry.second.networkId.size())));
        json_object_object_add(role,"interface",json_object_new_string(entry.second.interface.c_str()));
        json_object_object_add(role,"default",json_object_new_boolean(entry.second.defaultRoute));
        json_object_object_add(binding,entry.first.c_str(),role);
    }
    json_object_object_add(value.get(),"binding",binding);
    return value;
}
std::string readInput() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    std::string result;
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
        if (left <= 0) reject();
        pollfd fd{STDIN_FILENO,POLLIN,0};
        const auto ready = ::poll(&fd,1,static_cast<int>(left));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || (fd.revents & (POLLNVAL | POLLERR))) reject();
        std::array<char,8192> data{};
        const auto count = ::read(STDIN_FILENO,data.data(),data.size());
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) reject();
        if (!count) return result;
        result.append(data.data(),static_cast<std::size_t>(count));
        if (result.size() > frameLimit) reject();
    }
}
}
std::string networkTopologyRuntimeRequest(const std::string &raw, const NetworkObserverRunner &runner) {
    auto input = topologyDetail::parse(raw,frameLimit);
    const auto op = text(input.get(),"op");
    topologyDetail::Json value;
    if (op == "capability") {
        exact(input.get(),{"op"});
        value.reset(json_object_new_object());
        json_object_object_add(value.get(),"observerVersion",json_object_new_int(1));
    } else if (op == "snapshot") {
        exact(input.get(),{"op","container"});
        value = topologyValue(observeNetworkTopology(text(input.get(),"container"),runner));
    } else if (op == "stopped-snapshot") {
        exact(input.get(),{"op","identity","binding"});
        observeStoppedNetworkTopology(text(input.get(),"identity"),bindingValue(input.get()),runner);
        value.reset(json_object_new_boolean(true));
    } else if (op == "networks") {
        exact(input.get(),{"op","container"});
        value.reset(json_object_new_array());
        for (const auto &name : networkTopologyNames(text(input.get(),"container")))
            json_object_array_add(value.get(),json_object_new_string(name.c_str()));
    } else if (op == "validate") {
        exact(input.get(),{"op","version","container","addresses","routes","networks"});
        NetworkTopologyObservations observed{text(input.get(),"version"),text(input.get(),"container"),
            text(input.get(),"addresses"),text(input.get(),"routes"),{}};
        auto *networks = member(input.get(),"networks",json_type_object);
        json_object_object_foreach(networks,name,item) {
            (void)item;
            if (std::string(name) != "bridge" && std::string(name) != "amnezia-dns-net") reject();
            observed.networks.emplace(name,text(networks,name));
        }
        value = topologyValue(validateNetworkTopology(observed));
    } else if (op == "stopped") {
        exact(input.get(),{"op","identity","binding","container","networks"});
        StoppedNetworkTopologyObservations observed{text(input.get(),"identity"),text(input.get(),"container"),bindingValue(input.get()), {}};
        auto *networks = member(input.get(),"networks",json_type_object);
        json_object_object_foreach(networks,networkName,item) {
            (void)item;
            if (std::string(networkName) != "bridge" && std::string(networkName) != "amnezia-dns-net") reject();
            observed.networks.emplace(networkName,text(networks,networkName));
        }
        validateStoppedNetworkTopology(observed);
        value.reset(json_object_new_boolean(true));
    } else reject();
    topologyDetail::Json result(json_object_new_object());
    json_object_object_add(result.get(),"result",value.release());
    std::string output = json_object_to_json_string_ext(result.get(),JSON_C_TO_STRING_PLAIN);
    if (output.size() > outputLimit) reject();
    return output;
}
std::string networkTopologyRuntimeRequest(const std::string &raw) {
    return networkTopologyRuntimeRequest(raw,productionNetworkObserverRunner());
}
int networkTopologyJsonMain(const NetworkObserverRunner &runner) {
    try {
        std::cout << networkTopologyRuntimeRequest(readInput(),runner) << '\n';
        return 0;
    } catch (...) {
        std::cout << "{\"error\":\"unsupported_source_network_topology\"}\n";
        return 2;
    }
}
int networkTopologyJsonMain() {
    return networkTopologyJsonMain(productionNetworkObserverRunner());
}
}
