#include "network_topology.h"
#include "network_topology_runtime.h"
#include <functional>
#include <iostream>

using namespace amnezia::awgMigration;
namespace {
using Json = topologyDetail::Json;
unsigned cases = 0;
void check(bool value) { if (!value) throw std::runtime_error("pure topology assertion"); }
std::string encoded(json_object *value) { return json_object_to_json_string_ext(value,JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE); }
void set(json_object *parent, const char *key, const std::string &value) {
    json_object_object_add(parent,key,json_object_new_string_len(value.data(),static_cast<int>(value.size())));
}
void replace(std::string &value, const std::string &before, const std::string &after) {
    const auto at = value.find(before); check(at != std::string::npos); value.replace(at,before.size(),after);
}
void rejects(const std::function<void()> &run) {
    try { run(); }
    catch (const NetworkTopologyError &error) { check(std::string(error.what()) == "unsupported_source_network_topology"); ++cases; return; }
    throw std::runtime_error("expected pure topology rejection");
}
NetworkTopologyObservations fixture(bool dual = false, bool dnsDefault = true) {
    NetworkTopologyObservations result;
    result.version = "29.0.0";
    Json endpoints(json_object_new_object()), addresses(json_object_new_array()), routes(json_object_new_array());
    for (const auto &name : dual ? std::vector<std::string>{"amnezia-dns-net","bridge"} : std::vector<std::string>{"bridge"}) {
        const bool dns = name == "amnezia-dns-net";
        const std::string base = dns ? "172.29.172." : "172.17.0.", id = name + "-id";
        const unsigned bits = dns ? 24 : 16;
        const std::string iface = !dual || (dns == dnsDefault) ? "eth0" : "eth1";
        auto *endpoint = json_object_new_object(); set(endpoint,"NetworkID",id); set(endpoint,"IPAddress",base+"2");
        set(endpoint,"Gateway",base+"1"); json_object_object_add(endpoint,"IPPrefixLen",json_object_new_int(bits));
        json_object_object_add(endpoints.get(),name.c_str(),endpoint);
        auto *row = json_object_new_object(); set(row,"ifname",iface);
        auto *items = json_object_new_array(), *item = json_object_new_object();
        set(item,"family","inet"); set(item,"local",base+"2"); json_object_object_add(item,"prefixlen",json_object_new_int(bits));
        json_object_array_add(items,item); json_object_object_add(row,"addr_info",items); json_object_array_add(addresses.get(),row);
        if (iface == "eth0") { auto *route = json_object_new_object(); set(route,"dst","default"); set(route,"dev",iface); set(route,"gateway",base+"1"); json_object_array_add(routes.get(),route); }
        Json network(json_object_new_object()); set(network.get(),"Name",name); set(network.get(),"Id",id);
        set(network.get(),"Driver","bridge"); set(network.get(),"Scope","local");
        json_object_object_add(network.get(),"Internal",json_object_new_boolean(false));
        json_object_object_add(network.get(),"EnableIPv6",json_object_new_boolean(false));
        auto *ipam = json_object_new_object(), *configs = json_object_new_array(), *config = json_object_new_object();
        set(config,"Subnet",base+"0/"+std::to_string(bits)); set(config,"Gateway",base+"1"); json_object_array_add(configs,config);
        json_object_object_add(ipam,"Config",configs); json_object_object_add(network.get(),"IPAM",ipam);
        Json array(json_object_new_array()); json_object_array_add(array.get(),network.release()); result.networks[name] = encoded(array.get());
    }
    Json container(json_object_new_object()); auto *settings = json_object_new_object();
    json_object_object_add(settings,"Networks",endpoints.release()); json_object_object_add(container.get(),"NetworkSettings",settings);
    Json array(json_object_new_array()); json_object_array_add(array.get(),container.release()); result.container = encoded(array.get());
    result.addresses = encoded(addresses.get()); result.routes = encoded(routes.get());
    return result;
}
std::string request(const NetworkTopologyObservations &value, bool names = false) {
    Json input(json_object_new_object()); set(input.get(),"op",names ? "networks" : "validate"); set(input.get(),"container",value.container);
    if (!names) {
        set(input.get(),"version",value.version); set(input.get(),"addresses",value.addresses); set(input.get(),"routes",value.routes);
        auto *networks = json_object_new_object();
        for (const auto &item : value.networks) set(networks,item.first.c_str(),item.second);
        json_object_object_add(input.get(),"networks",networks);
    }
    return encoded(input.get());
}
void valid(NetworkTopologyObservations value) {
    const auto actual = validateNetworkTopology(value);
    check(actual.options.size() == value.networks.size()*2 && actual.binding.size() == value.networks.size());
    const auto wrapper = topologyDetail::parse(networkTopologyRuntimeRequest(request(value)),16*1024);
    json_object *result = nullptr;
    check(json_object_object_get_ex(wrapper.get(),"result",&result) && json_object_get_type(result) == json_type_object);
    check(networkTopologyNames(value.container).size() == value.networks.size()); ++cases;
}
StoppedNetworkTopologyObservations stoppedFixture(bool dual = false, bool dnsDefault = true) {
    const auto running = fixture(dual,dnsDefault);
    StoppedNetworkTopologyObservations result{"owned-created-id","",validateNetworkTopology(running).binding,running.networks};
    Json metadata(json_object_new_object()); set(metadata.get(),"Id",result.identity);
    auto *state = json_object_new_object(); set(state,"Status","created"); set(state,"StartedAt","0001-01-01T00:00:00Z");
    json_object_object_add(state,"Pid",json_object_new_int(0)); json_object_object_add(state,"Running",json_object_new_boolean(false));
    json_object_object_add(metadata.get(),"State",state);
    auto *host = json_object_new_object(); set(host,"NetworkMode","bridge"); json_object_object_add(metadata.get(),"HostConfig",host);
    auto *settings = json_object_new_object(), *endpoints = json_object_new_object();
    for (const auto &entry : result.binding) {
        auto *endpoint = json_object_new_object(), *options = json_object_new_object();
        set(endpoint,"NetworkID",""); set(options,"com.docker.network.endpoint.ifname",entry.second.interface);
        json_object_object_add(endpoint,"DriverOpts",options);
        json_object_object_add(endpoint,"GwPriority",json_object_new_int(entry.second.defaultRoute ? 1 : 0));
        json_object_object_add(endpoints,entry.first.c_str(),endpoint);
    }
    json_object_object_add(settings,"Networks",endpoints); json_object_object_add(metadata.get(),"NetworkSettings",settings);
    Json array(json_object_new_array()); json_object_array_add(array.get(),metadata.release()); result.container = encoded(array.get());
    return result;
}
std::string stoppedRequest(const StoppedNetworkTopologyObservations &observed) {
    Json value(json_object_new_object()); set(value.get(),"op","stopped"); set(value.get(),"identity",observed.identity);
    set(value.get(),"container",observed.container);
    auto *binding = json_object_new_object(), *networks = json_object_new_object();
    for (const auto &entry : observed.binding) {
        auto *role = json_object_new_object(); set(role,"networkId",entry.second.networkId); set(role,"interface",entry.second.interface);
        json_object_object_add(role,"default",json_object_new_boolean(entry.second.defaultRoute)); json_object_object_add(binding,entry.first.c_str(),role);
    }
    for (const auto &entry : observed.networks) set(networks,entry.first.c_str(),entry.second);
    json_object_object_add(value.get(),"binding",binding); json_object_object_add(value.get(),"networks",networks);
    return encoded(value.get());
}
void validStopped(const StoppedNetworkTopologyObservations &value) {
    validateStoppedNetworkTopology(value);
    check(networkTopologyRuntimeRequest(stoppedRequest(value)) == "{\"result\":true}"); ++cases;
}
void badStopped(const StoppedNetworkTopologyObservations &value) {
    rejects([&] { validateStoppedNetworkTopology(value); });
    rejects([&] { networkTopologyRuntimeRequest(stoppedRequest(value)); });
}
void endpointField(StoppedNetworkTopologyObservations &value, const char *field, json_object *item) {
    auto container = topologyDetail::parse(value.container,1024*1024);
    json_object *settings = nullptr, *endpoints = nullptr, *endpoint = nullptr;
    check(json_object_object_get_ex(json_object_array_get_idx(container.get(),0),"NetworkSettings",&settings));
    check(json_object_object_get_ex(settings,"Networks",&endpoints)); check(json_object_object_get_ex(endpoints,"bridge",&endpoint));
    json_object_object_add(endpoint,field,item); value.container = encoded(container.get());
}
void stoppedCases() {
    validStopped(stoppedFixture()); validStopped(stoppedFixture(true,true)); validStopped(stoppedFixture(true,false));
    { auto value = stoppedFixture(); endpointField(value,"NetworkID",json_object_new_string("bridge-id")); validStopped(value); }
    { auto value = stoppedFixture(); replace(value.container,value.identity,u8"owned-café-😀"); value.identity = u8"owned-café-😀"; validStopped(value); }
    for (const auto *field : {"EndpointID","IPAddress","Gateway","GlobalIPv6Address","IPv6Gateway"}) {
        auto value = stoppedFixture(); endpointField(value,field,nullptr); validStopped(value);
        endpointField(value,field,json_object_new_string("")); validStopped(value);
        for (unsigned kind = 0;kind < 5;++kind) {
            json_object *item = kind == 0 ? json_object_new_string("assigned") : kind == 1 ? json_object_new_boolean(false)
                : kind == 2 ? json_object_new_int(0) : kind == 3 ? json_object_new_array() : json_object_new_object();
            endpointField(value,field,item); badStopped(value);
        }
    }
    const std::vector<std::function<void(StoppedNetworkTopologyObservations &)>> invalid = {
        [](auto &v) { v.identity.clear(); }, [](auto &v) { v.identity.assign(1025,'x'); },
        [](auto &v) { v.identity = std::string("owned\0id",8); }, [](auto &v) { v.identity = "owned\tid"; },
        [](auto &v) { v.identity = "different-id"; }, [](auto &v) { v.binding.clear(); },
        [](auto &v) { v.binding = {{"amnezia-dns-net",{"dns-id","eth0",true}}}; },
        [](auto &v) { v.binding["foreign"] = {"foreign-id","eth1",false}; },
        [](auto &v) { v.binding["bridge"].networkId.clear(); },
        [](auto &v) { v.binding["bridge"].networkId.assign(1025,'x'); },
        [](auto &v) { v.binding["bridge"].networkId = std::string("bridge\0id",9); },
        [](auto &v) { v.binding["bridge"].interface = "eth1"; },
        [](auto &v) { v.binding["bridge"].interface = "eth2"; },
        [](auto &v) { v.binding["bridge"].defaultRoute = false; },
        [](auto &v) { v.container = "[]"; }, [](auto &v) { v.container = "[null]"; },
        [](auto &v) { v.container = "{}"; }, [](auto &v) { v.container = "[{},{}]"; },
        [](auto &v) { replace(v.container,"\"State\":","\"OtherState\":"); },
        [](auto &v) { replace(v.container,"\"Status\":\"created\"","\"Status\":\"running\""); },
        [](auto &v) { replace(v.container,"\"Pid\":0","\"Pid\":1"); },
        [](auto &v) { replace(v.container,"\"Pid\":0","\"Pid\":-1"); },
        [](auto &v) { replace(v.container,"\"Pid\":0","\"Pid\":false"); },
        [](auto &v) { replace(v.container,"\"Pid\":0","\"Pid\":0.0"); },
        [](auto &v) { replace(v.container,"\"Pid\":0","\"OtherPid\":0"); },
        [](auto &v) { replace(v.container,"\"Running\":false","\"Running\":true"); },
        [](auto &v) { replace(v.container,"\"Running\":false","\"Running\":0"); },
        [](auto &v) { replace(v.container,"\"Running\":false","\"Running\":null"); },
        [](auto &v) { replace(v.container,"\"Running\":false","\"OtherRunning\":false"); },
        [](auto &v) { replace(v.container,"0001-01-01T00:00:00Z","2026-10-21T00:00:00Z"); },
        [](auto &v) { replace(v.container,"\"NetworkMode\":\"bridge\"","\"NetworkMode\":\"host\""); },
        [](auto &v) { replace(v.container,"\"Networks\":{\"bridge\"","\"Networks\":{\"foreign\""); },
        [](auto &v) { replace(v.container,"\"DriverOpts\":","\"OtherDriverOpts\":"); },
        [](auto &v) { replace(v.container,"\"com.docker.network.endpoint.ifname\":\"eth0\"","\"com.docker.network.endpoint.ifname\":\"eth1\""); },
        [](auto &v) { replace(v.container,"\"com.docker.network.endpoint.ifname\":\"eth0\"","\"extra\":0,\"com.docker.network.endpoint.ifname\":\"eth0\""); },
        [](auto &v) { replace(v.container,"\"GwPriority\":1","\"GwPriority\":0"); },
        [](auto &v) { replace(v.container,"\"GwPriority\":1","\"GwPriority\":true"); },
        [](auto &v) { replace(v.container,"\"GwPriority\":1","\"GwPriority\":1.0"); },
        [](auto &v) { replace(v.container,"\"GwPriority\":1","\"GwPriority\":\"1\""); },
        [](auto &v) { replace(v.container,"\"NetworkID\":\"\"","\"NetworkID\":null"); },
        [](auto &v) { replace(v.container,"\"NetworkID\":\"\"","\"OtherNetworkID\":\"\""); },
        [](auto &v) { replace(v.container,"\"NetworkID\":\"\"","\"NetworkID\":\"wrong\""); },
        [](auto &v) { v.networks.clear(); }, [](auto &v) { v.networks["foreign"] = "[]"; },
        [](auto &v) { v.networks["bridge"] = "[]"; }, [](auto &v) { v.networks["bridge"] = "{}"; },
        [](auto &v) { replace(v.networks["bridge"],"bridge-id","wrong-id"); },
        [](auto &v) { replace(v.container,"\"State\":","\"State\":{},\"State\":"); },
        [](auto &v) { replace(v.container,"\"State\":","\"ignored\":NaN,\"State\":"); },
        [](auto &v) { v.container.assign(1024*1024+1,' '); },
        [](auto &v) { v.networks["bridge"].assign(1024*1024+1,' '); },
    };
    for (const auto &change : invalid) { auto value = stoppedFixture(); change(value); badStopped(value); }
    { auto value = stoppedFixture(true); value.binding["bridge"].networkId = value.binding["amnezia-dns-net"].networkId; badStopped(value); }
    { auto value = stoppedFixture(true); value.binding["bridge"].interface = "eth0"; badStopped(value); }
    { auto value = stoppedFixture(true); value.binding["bridge"].defaultRoute = true; badStopped(value); }
    for (const auto &change : std::vector<std::pair<std::string,std::string>>{
        {"\"default\":true","\"default\":1"}, {"\"default\":true","\"default\":true,\"default\":true"},
        {"\"networkId\":\"bridge-id\"","\"networkId\":\"bridge-id\",\"extra\":0"},
        {"\"binding\":{","\"binding\":{\"foreign\":{},"}, {"\"op\":\"stopped\"","\"op\":\"stopped\",\"extra\":0"}}) {
        auto raw = stoppedRequest(stoppedFixture()); replace(raw,change.first,change.second); rejects([&] { networkTopologyRuntimeRequest(raw); });
    }
}
}
int main() {
    valid(fixture()); valid(fixture(true,true)); valid(fixture(true,false));
    check(networkTopologyRuntimeRequest(request(fixture(true),true)) == "{\"result\":[\"amnezia-dns-net\",\"bridge\"]}"); ++cases;
    const auto dual = validateNetworkTopology(fixture(true));
    check(dual.options == std::vector<std::string>{"--network","name=amnezia-dns-net,driver-opt=com.docker.network.endpoint.ifname=eth0,gw-priority=1",
        "--network","name=bridge,driver-opt=com.docker.network.endpoint.ifname=eth1,gw-priority=0"}); ++cases;
    for (const auto &version : {"28.0.0","028.00.00","29.0.0-ce.1","28.1.2+debian-1"," \t29.0.0\r\n",u8"\u2003\u00a029.0.0\u3000"}) {
        auto value = fixture(); value.version = version; valid(value);
    }
    { auto value = fixture(); value.version = std::string(128,'9')+".0.0"; valid(value); }
    for (const auto &version : {"","27.99.99","0.0.0","28.0","28.0.0rc1","28.0.0+","28.0.0+bad suffix","28.0.0+bad+suffix",u8"٢٨.٠.٠","28.\n0.0"}) {
        auto value = fixture(); value.version = version; rejects([&] { validateNetworkTopology(value); });
    }
    for (const auto &mask : {"172.17.0.0/255.255.0.0","172.17.0.0/0.0.255.255","172.17.0.0/016"}) {
        auto value = fixture(); replace(value.networks["bridge"],"172.17.0.0/16",mask); valid(value);
    }
    for (const auto &range : std::vector<std::pair<std::string,unsigned>>{{"0.0.0.0/0",0},{"128.0.0.0/1",1},{"128.0.0.0/127.255.255.255",1}}) {
        auto value = fixture(); replace(value.networks["bridge"],"172.17.0.0/16",range.first);
        replace(value.container,"\"IPPrefixLen\":16","\"IPPrefixLen\":"+std::to_string(range.second));
        replace(value.addresses,"\"prefixlen\":16","\"prefixlen\":"+std::to_string(range.second)); valid(value);
    }
    { auto value = fixture(); replace(value.networks["bridge"],"172.17.0.0/16","172.17.0.0/31");
      replace(value.container,"\"IPPrefixLen\":16","\"IPPrefixLen\":31"); replace(value.container,"172.17.0.2","172.17.0.0");
      replace(value.addresses,"\"prefixlen\":16","\"prefixlen\":31"); replace(value.addresses,"172.17.0.2","172.17.0.0"); valid(value); }
    const std::vector<std::function<void(NetworkTopologyObservations &)>> bad = {
        [](auto &v) { v.container = "[]"; }, [](auto &v) { v.container = "{}"; },
        [](auto &v) { replace(v.container,"NetworkSettings","OtherSettings"); },
        [](auto &v) { replace(v.container,"\"bridge\"","\"unknown\""); },
        [](auto &v) { replace(v.container,"bridge-id","different-id"); },
        [](auto &v) { replace(v.container,"bridge-id",""); },
        [](auto &v) { replace(v.container,"bridge-id","bridge-id\\u0000suffix"); replace(v.networks["bridge"],"bridge-id","bridge-id\\u0000suffix"); },
        [](auto &v) { replace(v.container,"\"IPPrefixLen\":16","\"IPPrefixLen\":true"); },
        [](auto &v) { replace(v.container,"\"IPPrefixLen\":16","\"IPPrefixLen\":16.0"); },
        [](auto &v) { replace(v.container,"\"IPPrefixLen\":16","\"IPPrefixLen\":17"); },
        [](auto &v) { replace(v.container,"172.17.0.2","172.18.0.2"); },
        [](auto &v) { replace(v.container,"172.17.0.2","172.017.0.2"); },
        [](auto &v) { replace(v.container,"172.17.0.2","172.17.0.1"); },
        [](auto &v) { replace(v.addresses,"eth0","eth1"); replace(v.routes,"eth0","eth1"); },
        [](auto &v) { replace(v.addresses,"eth0","eth2"); },
        [](auto &v) { replace(v.addresses,"\"prefixlen\":16","\"prefixlen\":true"); },
        [](auto &v) { replace(v.addresses,"172.17.0.2","172.18.0.2"); },
        [](auto &v) { v.addresses = "[]"; }, [](auto &v) { v.addresses = "[null]"; },
        [](auto &v) { v.routes = "[]"; }, [](auto &v) { v.routes = "[null]"; },
        [](auto &v) { replace(v.routes,"default","not-default"); },
        [](auto &v) { replace(v.routes,"eth0","eth2"); },
        [](auto &v) { replace(v.routes,"172.17.0.1","172.17.0.5"); },
        [](auto &v) { v.networks.clear(); }, [](auto &v) { v.networks["extra"] = "[]"; },
        [](auto &v) { v.networks["bridge"] = "[]"; },
        [](auto &v) { replace(v.networks["bridge"],"\"Driver\":\"bridge\"","\"Driver\":\"host\""); },
        [](auto &v) { replace(v.networks["bridge"],"\"Scope\":\"local\"","\"Scope\":\"swarm\""); },
        [](auto &v) { replace(v.networks["bridge"],"\"Internal\":false","\"Internal\":true"); },
        [](auto &v) { replace(v.networks["bridge"],"\"Internal\":false","\"Internal\":0"); },
        [](auto &v) { replace(v.networks["bridge"],"\"EnableIPv6\":false","\"EnableIPv6\":true"); },
        [](auto &v) { replace(v.networks["bridge"],"172.17.0.0/16","172.17.0.1/16"); },
        [](auto &v) { replace(v.networks["bridge"],"172.17.0.0/16","172.17.0.0/33"); },
        [](auto &v) { replace(v.networks["bridge"],"172.17.0.0/16","172.17.0.0/255.0.255.0"); },
        [](auto &v) { replace(v.networks["bridge"],"172.17.0.0/16","172.17.0.2/32"); },
        [](auto &v) { replace(v.networks["bridge"],"\"Name\":\"bridge\"","\"Name\":\"bridge\",\"Name\":\"bridge\""); },
        [](auto &v) { v.networks["bridge"] = "[{\"ignored\":NaN}]"; },
        [](auto &v) { v.container = std::string(1024*1024+1,' '); },
        [](auto &v) { v.networks["bridge"] = std::string(1024*1024+1,' '); },
        [](auto &v) { v.routes = std::string(1024*1024+1,' '); },
        [](auto &v) { v.addresses = std::string(1024*1024+1,' '); },
    };
    for (const auto &change : bad) { auto value = fixture(); change(value); rejects([&] { validateNetworkTopology(value); }); }
    { auto value = fixture(true); replace(value.container,"bridge-id","amnezia-dns-net-id"); replace(value.networks["bridge"],"bridge-id","amnezia-dns-net-id"); rejects([&] { validateNetworkTopology(value); }); }
    { auto value = fixture(); value.container.insert(2,"\"ignored\":\""+std::string(1,static_cast<char>(0xff))+"\","); rejects([&] { validateNetworkTopology(value); }); }
    for (const auto &raw : {"{}","[]","null","{\"op\":\"unknown\"}","{\"op\":\"networks\",\"container\":true}",
        "{\"op\":\"networks\",\"op\":\"networks\",\"container\":\"[]\"}","{\"op\":\"networks\",\"container\":\"[]\",\"extra\":0}"})
        rejects([&] { networkTopologyRuntimeRequest(raw); });
    rejects([] { networkTopologyRuntimeRequest(std::string(8*1024*1024+1,' ')); });
    const auto originalCases = cases;
    stoppedCases();
    std::cout << cases << " pure network topology cases PASS (" << originalCases
              << " original, " << cases-originalCases << " stopped); no process/socket/network/file effects\n";
}
