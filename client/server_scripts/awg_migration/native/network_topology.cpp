#include "network_topology.h"
#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <cstdint>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <set>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t observedLimit = 1024 * 1024;
[[noreturn]] void reject() { throw NetworkTopologyError(); }
struct UniqueKeys : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, UniqueKeys> {
    struct Frame { bool object; std::set<std::string> keys; };
    std::vector<Frame> stack;
    bool StartObject() { if (stack.size() >= 32) return false; stack.push_back({true,{}}); return true; }
    bool StartArray() { if (stack.size() >= 32) return false; stack.push_back({false,{}}); return true; }
    bool EndObject(rapidjson::SizeType) { if (stack.empty() || !stack.back().object) return false; stack.pop_back(); return true; }
    bool EndArray(rapidjson::SizeType) { if (stack.empty() || stack.back().object) return false; stack.pop_back(); return true; }
    bool Key(const char *data, rapidjson::SizeType size, bool) {
        if (stack.empty() || !stack.back().object) return false;
        std::string key(data,size);
        return key.find('\0') == std::string::npos && stack.back().keys.insert(std::move(key)).second;
    }
};
json_object *member(json_object *parent, const char *key, json_type type) {
    json_object *value = nullptr;
    if (!parent || !json_object_is_type(parent,json_type_object)
        || !json_object_object_get_ex(parent,key,&value) || !value || !json_object_is_type(value,type)) reject();
    return value;
}
std::string text(json_object *parent, const char *key, std::size_t limit = 1024) {
    auto *value = member(parent,key,json_type_string);
    std::string result(json_object_get_string(value),static_cast<std::size_t>(json_object_get_string_len(value)));
    if (result.size() > limit || std::any_of(result.begin(),result.end(),[](unsigned char c) { return c < 32 || c == 127; })) reject();
    return result;
}
unsigned prefix(json_object *parent, const char *key) {
    auto *value = member(parent,key,json_type_int);
    const auto number = json_object_get_int64(value);
    if (number < 0 || number > 32) reject();
    return static_cast<unsigned>(number);
}
void falseOrMissing(json_object *parent, const char *key) {
    json_object *value = nullptr;
    if (!json_object_object_get_ex(parent,key,&value) || !value) return;
    if (!json_object_is_type(value,json_type_boolean) || json_object_get_boolean(value)) reject();
}
json_object *only(json_object *array) {
    if (!array || !json_object_is_type(array,json_type_array) || json_object_array_length(array) != 1) reject();
    auto *value = json_object_array_get_idx(array,0);
    if (!value || !json_object_is_type(value,json_type_object)) reject();
    return value;
}
json_object *endpoints(json_object *container) {
    return member(member(only(container),"NetworkSettings",json_type_object),"Networks",json_type_object);
}
std::vector<std::string> names(json_object *value) {
    std::set<std::string> found;
    json_object_object_foreach(value,key,endpoint) {
        if (!endpoint || !json_object_is_type(endpoint,json_type_object)) reject();
        found.emplace(key);
    }
    if (found != std::set<std::string>{"bridge"} && found != std::set<std::string>{"bridge","amnezia-dns-net"}) reject();
    return {found.begin(),found.end()};
}
bool pythonWhitespace(unsigned codepoint) {
    return (codepoint >= 9 && codepoint <= 13) || (codepoint >= 28 && codepoint <= 32)
        || codepoint == 0x85 || codepoint == 0xa0 || codepoint == 0x1680
        || (codepoint >= 0x2000 && codepoint <= 0x200a) || codepoint == 0x2028 || codepoint == 0x2029
        || codepoint == 0x202f || codepoint == 0x205f || codepoint == 0x3000;
}
std::string strippedVersion(const std::string &raw) {
    if (raw.size() > observedLimit) reject();
    rapidjson::MemoryStream stream(raw.data(),raw.size());
    std::size_t begin = raw.size(), end = 0;
    while (stream.Tell() < raw.size()) {
        const auto before = stream.Tell();
        unsigned codepoint = 0;
        if (!rapidjson::UTF8<>::Decode(stream,&codepoint)) reject();
        if (!pythonWhitespace(codepoint)) {
            if (begin == raw.size()) begin = before;
            end = stream.Tell();
        }
    }
    return end ? raw.substr(begin,end-begin) : std::string();
}
void validateVersion(const std::string &raw) {
    const auto version = strippedVersion(raw);
    std::size_t at = 0;
    std::string major;
    for (unsigned component = 0; component < 3; ++component) {
        const auto start = at;
        while (at < version.size() && version[at] >= '0' && version[at] <= '9') ++at;
        if (at == start) reject();
        if (!component) major = version.substr(start,at-start);
        if (component < 2 && (at == version.size() || version[at++] != '.')) reject();
    }
    if (at < version.size()) {
        if ((version[at] != '-' && version[at] != '+') || ++at == version.size()) reject();
        for (;at < version.size();++at) {
            const auto c = static_cast<unsigned char>(version[at]);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                  || c == '_' || c == '.' || c == '-')) reject();
        }
    }
    const auto nonzero = major.find_first_not_of('0');
    if (nonzero == std::string::npos) reject();
    major.erase(0,nonzero);
    if (major.size() < 2 || (major.size() == 2 && major < "28")) reject();
}
std::uint32_t ipv4(const std::string &raw) {
    in_addr value{};
    if (::inet_pton(AF_INET,raw.c_str(),&value) != 1) reject();
    return ntohl(value.s_addr);
}
std::string canonical(std::uint32_t value) {
    return std::to_string(value >> 24) + '.' + std::to_string((value >> 16) & 255)
        + '.' + std::to_string((value >> 8) & 255) + '.' + std::to_string(value & 255);
}
bool maskPrefix(std::uint32_t mask, unsigned &result) {
    result = 0;
    bool zero = false;
    for (int bit = 31;bit >= 0;--bit) {
        if (mask & (std::uint32_t(1) << bit)) { if (zero) return false; ++result; }
        else zero = true;
    }
    return true;
}
struct Subnet { std::uint32_t network, mask; unsigned bits; };
Subnet subnet(const std::string &raw) {
    const auto slash = raw.find('/');
    const auto address = ipv4(raw.substr(0,slash));
    unsigned bits = 32;
    if (slash != std::string::npos) {
        const auto suffix = raw.substr(slash+1);
        if (suffix.find('.') != std::string::npos) {
            const auto mask = ipv4(suffix);
            if (!maskPrefix(mask,bits) && !maskPrefix(~mask,bits)) reject();
        } else {
            const auto parsed = std::from_chars(suffix.data(),suffix.data()+suffix.size(),bits);
            if (suffix.empty() || parsed.ec != std::errc{} || parsed.ptr != suffix.data()+suffix.size() || bits > 32) reject();
        }
    }
    const auto mask = bits ? (std::uint32_t(0xffffffff) << (32-bits)) : 0;
    if ((address & mask) != address) reject();
    return {address,mask,bits};
}
std::string matchingInterface(json_object *addresses, std::uint32_t address, unsigned bits) {
    if (!addresses || !json_object_is_type(addresses,json_type_array)) reject();
    std::vector<std::string> matches;
    for (std::size_t i = 0;i < json_object_array_length(addresses);++i) {
        auto *row = json_object_array_get_idx(addresses,i);
        if (!row || !json_object_is_type(row,json_type_object)) reject();
        json_object *items = nullptr;
        if (!json_object_object_get_ex(row,"addr_info",&items)) continue;
        if (!items || !json_object_is_type(items,json_type_array)) reject();
        bool matching = false;
        for (std::size_t k = 0;k < json_object_array_length(items);++k) {
            auto *item = json_object_array_get_idx(items,k);
            if (!item || !json_object_is_type(item,json_type_object)) reject();
            json_object *family = nullptr;
            if (!json_object_object_get_ex(item,"family",&family)) continue;
            if (text(item,"family",32) != "inet") continue;
            if (text(item,"local",15) == canonical(address) && prefix(item,"prefixlen") == bits) matching = true;
        }
        if (matching) matches.push_back(text(row,"ifname",32));
    }
    if (matches.size() != 1 || (matches[0] != "eth0" && matches[0] != "eth1")) reject();
    return matches[0];
}
}
namespace topologyDetail {
Json parse(std::string_view raw, std::size_t limit) {
    if (raw.empty() || raw.size() > limit || raw.size() > 8 * 1024 * 1024 || raw.find('\0') != std::string_view::npos) reject();
    rapidjson::MemoryStream stream(raw.data(),raw.size());
    rapidjson::Reader reader;
    UniqueKeys keys;
    if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream,keys) || !keys.stack.empty() || stream.Tell() != raw.size()) reject();
    auto tok = std::unique_ptr<json_tokener,decltype(&json_tokener_free)>(json_tokener_new_ex(32),json_tokener_free);
    if (!tok) reject();
    json_tokener_set_flags(tok.get(),JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    Json value(json_tokener_parse_ex(tok.get(),raw.data(),static_cast<int>(raw.size())));
    if (!value || json_tokener_get_error(tok.get()) != json_tokener_success) reject();
    return value;
}
}
std::vector<std::string> networkTopologyNames(std::string_view rawContainer) {
    auto container = topologyDetail::parse(rawContainer,observedLimit);
    return names(endpoints(container.get()));
}
NetworkTopologyResult validateNetworkTopology(const NetworkTopologyObservations &observed) {
    validateVersion(observed.version);
    auto container = topologyDetail::parse(observed.container,observedLimit);
    auto *endpointMap = endpoints(container.get());
    const auto networkNames = names(endpointMap);
    if (observed.networks.size() != networkNames.size()) reject();
    auto addresses = topologyDetail::parse(observed.addresses,observedLimit);
    auto routes = topologyDetail::parse(observed.routes,observedLimit);
    auto *route = only(routes.get());
    const auto defaultDevice = text(route,"dev",32);
    if (text(route,"dst",32) != "default" || (defaultDevice != "eth0" && defaultDevice != "eth1")) reject();
    NetworkTopologyResult result;
    std::set<std::string> interfaces, networkIds;
    unsigned defaultCount = 0;
    for (const auto &name : networkNames) {
        auto raw = observed.networks.find(name);
        if (raw == observed.networks.end()) reject();
        auto networkArray = topologyDetail::parse(raw->second,observedLimit);
        auto *network = only(networkArray.get());
        auto *endpoint = member(endpointMap,name.c_str(),json_type_object);
        if (text(network,"Name",32) != name || text(network,"Driver",32) != "bridge" || text(network,"Scope",32) != "local") reject();
        falseOrMissing(network,"Internal"); falseOrMissing(network,"EnableIPv6");
        auto *config = only(member(member(network,"IPAM",json_type_object),"Config",json_type_array));
        const auto id = text(endpoint,"NetworkID");
        if (id.empty() || id != text(network,"Id") || !networkIds.insert(id).second) reject();
        const auto range = subnet(text(config,"Subnet",64));
        const auto address = ipv4(text(endpoint,"IPAddress",15)), gateway = ipv4(text(endpoint,"Gateway",15));
        if ((address & range.mask) != range.network || (gateway & range.mask) != range.network
            || address == gateway || text(config,"Gateway",15) != canonical(gateway)
            || prefix(endpoint,"IPPrefixLen") != range.bits) reject();
        const auto interface = matchingInterface(addresses.get(),address,range.bits);
        if (!interfaces.insert(interface).second) reject();
        const bool isDefault = defaultDevice == interface;
        if (isDefault && text(route,"gateway",15) != canonical(gateway)) reject();
        defaultCount += isDefault ? 1 : 0;
        result.binding.emplace(name,NetworkEndpointRole{id,interface,isDefault});
        result.options.push_back("--network");
        result.options.push_back("name=" + name + ",driver-opt=com.docker.network.endpoint.ifname=" + interface
                                 + ",gw-priority=" + (isDefault ? "1" : "0"));
    }
    const std::set<std::string> expected = networkNames.size() == 1 ? std::set<std::string>{"eth0"} : std::set<std::string>{"eth0","eth1"};
    if (interfaces != expected || defaultCount != 1) reject();
    return result;
}
void validateStoppedNetworkTopology(const StoppedNetworkTopologyObservations &observed) {
    const auto validIdentity = [](const std::string &value) {
        return !value.empty() && value.size() <= 1024
            && std::none_of(value.begin(),value.end(),[](unsigned char c) { return c < 32 || c == 127; });
    };
    if (!validIdentity(observed.identity) || (observed.binding.size() != 1 && observed.binding.size() != 2)
        || observed.networks.size() != observed.binding.size()) reject();
    std::set<std::string> bindingNames, interfaces, ids;
    unsigned defaultCount = 0;
    for (const auto &entry : observed.binding) {
        bindingNames.insert(entry.first);
        if (!validIdentity(entry.second.networkId)
            || (entry.second.interface != "eth0" && entry.second.interface != "eth1")
            || !ids.insert(entry.second.networkId).second || !interfaces.insert(entry.second.interface).second) reject();
        defaultCount += entry.second.defaultRoute ? 1 : 0;
    }
    if ((bindingNames != std::set<std::string>{"bridge"} && bindingNames != std::set<std::string>{"bridge","amnezia-dns-net"})
        || interfaces != (observed.binding.size() == 1 ? std::set<std::string>{"eth0"} : std::set<std::string>{"eth0","eth1"})
        || defaultCount != 1) reject();
    auto container = topologyDetail::parse(observed.container,observedLimit);
    auto *metadata = only(container.get());
    auto *state = member(metadata,"State",json_type_object);
    if (text(metadata,"Id") != observed.identity || text(state,"Status",32) != "created"
        || json_object_get_int64(member(state,"Pid",json_type_int)) != 0
        || json_object_get_boolean(member(state,"Running",json_type_boolean))
        || text(state,"StartedAt",128) != "0001-01-01T00:00:00Z"
        || text(member(metadata,"HostConfig",json_type_object),"NetworkMode",32) != "bridge") reject();
    auto *endpointMap = endpoints(container.get());
    const auto endpointNames = names(endpointMap);
    if (std::set<std::string>(endpointNames.begin(),endpointNames.end()) != bindingNames) reject();
    for (const auto &entry : observed.binding) {
        auto rawNetwork = observed.networks.find(entry.first);
        if (rawNetwork == observed.networks.end()) reject();
        auto network = topologyDetail::parse(rawNetwork->second,observedLimit);
        if (text(only(network.get()),"Id") != entry.second.networkId) reject();
        auto *endpoint = member(endpointMap,entry.first.c_str(),json_type_object);
        auto *options = member(endpoint,"DriverOpts",json_type_object);
        if (json_object_object_length(options) != 1
            || text(options,"com.docker.network.endpoint.ifname",32) != entry.second.interface
            || json_object_get_int64(member(endpoint,"GwPriority",json_type_int)) != (entry.second.defaultRoute ? 1 : 0)) reject();
        const auto networkId = text(endpoint,"NetworkID");
        if (!networkId.empty() && networkId != entry.second.networkId) reject();
        for (const auto *field : {"EndpointID","IPAddress","Gateway","GlobalIPv6Address","IPv6Gateway"}) {
            json_object *value = nullptr;
            if (!json_object_object_get_ex(endpoint,field,&value) || !value) continue;
            if (!json_object_is_type(value,json_type_string) || json_object_get_string_len(value) != 0) reject();
        }
    }
}
}
