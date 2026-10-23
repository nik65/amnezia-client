#include "network_observer.h"
#include "network_topology_runtime.h"
#include <functional>
#include <iostream>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

using namespace amnezia::awgMigration;
namespace {
using Args = std::vector<std::string>;
const std::string identity(64,'a');
unsigned cases = 0;
int unexpectedExecMarker = -1;
void check(bool value) { if (!value) throw std::runtime_error("network observer assertion"); }
void rejects(const std::function<void()> &operation) {
    try { operation(); }
    catch (const NetworkTopologyError &error) { check(std::string(error.what()) == "unsupported_source_network_topology"); ++cases; return; }
    throw std::runtime_error("expected observer refusal");
}
std::string runningMetadata(const std::string &id = identity) {
    return "[{\"Id\":\""+id+"\",\"NetworkSettings\":{\"Networks\":{"
        "\"bridge\":{\"NetworkID\":\"bridge-id\",\"IPAddress\":\"172.17.0.2\",\"Gateway\":\"172.17.0.1\",\"IPPrefixLen\":16},"
        "\"amnezia-dns-net\":{\"NetworkID\":\"dns-id\",\"IPAddress\":\"172.29.172.2\",\"Gateway\":\"172.29.172.1\",\"IPPrefixLen\":24}}}}]";
}
std::string stoppedMetadata() {
    return "[{\"Id\":\""+identity+"\",\"State\":{\"Status\":\"created\",\"Pid\":0,\"Running\":false,\"StartedAt\":\"0001-01-01T00:00:00Z\"},"
        "\"HostConfig\":{\"NetworkMode\":\"bridge\"},\"NetworkSettings\":{\"Networks\":{"
        "\"bridge\":{\"NetworkID\":\"\",\"GwPriority\":0,\"DriverOpts\":{\"com.docker.network.endpoint.ifname\":\"eth1\"}},"
        "\"amnezia-dns-net\":{\"NetworkID\":\"\",\"GwPriority\":1,\"DriverOpts\":{\"com.docker.network.endpoint.ifname\":\"eth0\"}}}}}]";
}
std::map<std::string,NetworkEndpointRole> binding() { return {{"bridge",{"bridge-id","eth1",false}},{"amnezia-dns-net",{"dns-id","eth0",true}}}; }
struct Fake {
    std::map<Args,std::string> responses;
    std::vector<Args> calls;
    std::size_t failAt{};
    enum class Failure { Exception, Utf8, Limit, Json } failure = Failure::Exception;
    explicit Fake(const std::string &target = "amnezia-awg", bool stopped = false) {
        responses[{"docker","version","--format","{{.Server.Version}}"}] = "29.0.0\n";
        responses[{"docker","inspect",target}] = stopped ? stoppedMetadata() : runningMetadata();
        responses[{"docker","exec",identity,"ip","-j","-4","address","show"}] =
            "[{\"ifname\":\"eth0\",\"addr_info\":[{\"family\":\"inet\",\"local\":\"172.29.172.2\",\"prefixlen\":24}]},"
            "{\"ifname\":\"eth1\",\"addr_info\":[{\"family\":\"inet\",\"local\":\"172.17.0.2\",\"prefixlen\":16}]}]";
        responses[{"docker","exec",identity,"ip","-j","-4","route","show","default"}] = "[{\"dst\":\"default\",\"dev\":\"eth0\",\"gateway\":\"172.29.172.1\"}]";
        responses[{"docker","network","inspect","amnezia-dns-net"}] =
            "[{\"Name\":\"amnezia-dns-net\",\"Id\":\"dns-id\",\"Driver\":\"bridge\",\"Scope\":\"local\",\"Internal\":false,\"EnableIPv6\":false,"
            "\"IPAM\":{\"Config\":[{\"Subnet\":\"172.29.172.0/24\",\"Gateway\":\"172.29.172.1\"}]}}]";
        responses[{"docker","network","inspect","bridge"}] =
            "[{\"Name\":\"bridge\",\"Id\":\"bridge-id\",\"Driver\":\"bridge\",\"Scope\":\"local\",\"Internal\":false,\"EnableIPv6\":false,"
            "\"IPAM\":{\"Config\":[{\"Subnet\":\"172.17.0.0/16\",\"Gateway\":\"172.17.0.1\"}]}}]";
    }
    NetworkObserverRunner runner() {
        return [this](const Args &args) {
            calls.push_back(args);
            if (calls.size() == failAt) {
                if (failure == Failure::Exception) throw std::runtime_error("owned private backend failure");
                if (failure == Failure::Utf8) return std::string(1,static_cast<char>(0xff));
                if (failure == Failure::Limit) return std::string(1024*1024+1,'x');
                return std::string("[private-fixture");
            }
            const auto found = responses.find(args);
            if (found == responses.end()) throw std::runtime_error("unexpected fixed fake argv");
            return found->second;
        };
    }
};
std::string stoppedRequest() {
    return "{\"op\":\"stopped-snapshot\",\"identity\":\""+identity+"\",\"binding\":{"
        "\"bridge\":{\"networkId\":\"bridge-id\",\"interface\":\"eth1\",\"default\":false},"
        "\"amnezia-dns-net\":{\"networkId\":\"dns-id\",\"interface\":\"eth0\",\"default\":true}}}";
}
void replace(std::string &value, const std::string &before, const std::string &after) {
    const auto at = value.find(before); check(at != std::string::npos); value.replace(at,before.size(),after);
}
}
// Test-only safety net: even a future whitelist regression cannot execute Docker.
extern "C" int execve(const char *, char *const[], char *const[]) noexcept {
    if (unexpectedExecMarker >= 0) {
        const char marker = 'x';
        if (::write(unexpectedExecMarker,&marker,1) != 1) _exit(116);
    }
    _exit(115);
}
int main() {
    int execTrace[2];
    check(::pipe2(execTrace,O_CLOEXEC | O_NONBLOCK) == 0);
    unexpectedExecMarker = execTrace[1];
    {
        Fake fake;
        check(networkTopologyRuntimeRequest("{\"op\":\"capability\"}",fake.runner()) == "{\"result\":{\"observerVersion\":1}}");
        check(fake.calls.empty()); ++cases;
        check(networkTopologyRuntimeRequest("{\"op\":\"capability\"}") == "{\"result\":{\"observerVersion\":1}}"); ++cases;
    }
    for (const auto &target : {"amnezia-awg","amnezia-awg2","amnezia-awg-migration-1","amnezia-awg2-migration-9007199254740991"}) {
        Fake fake(target); const auto result = observeNetworkTopology(target,fake.runner());
        check(result.binding.size() == 2 && result.binding.at("amnezia-dns-net").defaultRoute);
        check(fake.calls.size() == 6 && fake.calls[2][2] == identity && fake.calls[3][2] == identity);
        check(fake.calls[4] == Args{"docker","network","inspect","amnezia-dns-net"}
            && fake.calls[5] == Args{"docker","network","inspect","bridge"}); ++cases;
    }
    { Fake fake(identity); check(observeNetworkTopology(identity,fake.runner()).binding.size() == 2); ++cases; }
    for (const auto &target : {"","owned-id","foreign","/amnezia-awg","amnezia-awg-migration-0","amnezia-awg-migration-01",
        "amnezia-awg-migration-9007199254740992","amnezia-awg2-migration-10000000000000000","amnezia-awg-migration-1x",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}) {
        Fake fake; rejects([&] { observeNetworkTopology(target,fake.runner()); }); check(fake.calls.empty());
    }
    { Fake fake; rejects([&] { observeNetworkTopology(std::string("amnezia-awg\0suffix",18),fake.runner()); }); check(fake.calls.empty()); }
    { Fake fake(identity); fake.responses[{"docker","inspect",identity}] = runningMetadata(std::string(64,'b'));
      rejects([&] { observeNetworkTopology(identity,fake.runner()); }); check(fake.calls.size() == 2); }
    { Fake fake; fake.responses[{"docker","inspect","amnezia-awg"}] = runningMetadata("owned-id");
      rejects([&] { observeNetworkTopology("amnezia-awg",fake.runner()); }); check(fake.calls.size() == 2); }
    for (auto failure : {Fake::Failure::Exception,Fake::Failure::Utf8,Fake::Failure::Limit,Fake::Failure::Json}) {
        for (std::size_t step = failure == Fake::Failure::Json ? 2 : 1;step <= 6;++step) {
            Fake fake; fake.failAt = step; fake.failure = failure;
            rejects([&] { observeNetworkTopology("amnezia-awg",fake.runner()); }); check(fake.calls.size() == step);
        }
    }
    {
        Fake fake(identity,true); observeStoppedNetworkTopology(identity,binding(),fake.runner());
        check(fake.calls.size() == 3 && fake.calls[0] == Args{"docker","inspect",identity}); ++cases;
    }
    { Fake fake(identity,true); check(networkTopologyRuntimeRequest(stoppedRequest(),fake.runner()) == "{\"result\":true}"); ++cases; }
    for (const auto &badIdentity : {std::string("amnezia-awg"),std::string("owned-id"),std::string(64,'A')}) {
        Fake fake(identity,true); rejects([&] { observeStoppedNetworkTopology(badIdentity,binding(),fake.runner()); }); check(fake.calls.empty());
    }
    for (unsigned variant = 0;variant < 8;++variant) {
        Fake fake(identity,true); auto roles = binding();
        if (variant == 0) roles.clear();
        if (variant == 1) roles["foreign"] = {"id","eth0",false};
        if (variant == 2) roles["bridge"].networkId = "dns-id";
        if (variant == 3) roles["bridge"].interface = "eth0";
        if (variant == 4) roles["bridge"].interface = "eth2";
        if (variant == 5) roles["bridge"].defaultRoute = true;
        if (variant == 6) roles["amnezia-dns-net"].defaultRoute = false;
        if (variant == 7) roles["bridge"].networkId = std::string("id\0suffix",9);
        rejects([&] { observeStoppedNetworkTopology(identity,roles,fake.runner()); }); check(fake.calls.empty());
    }
    for (auto failure : {Fake::Failure::Exception,Fake::Failure::Utf8,Fake::Failure::Limit,Fake::Failure::Json}) {
        for (std::size_t step = 1;step <= 3;++step) {
            Fake fake(identity,true); fake.failAt = step; fake.failure = failure;
            rejects([&] { observeStoppedNetworkTopology(identity,binding(),fake.runner()); }); check(fake.calls.size() == step);
        }
    }
    for (const auto &change : std::vector<std::pair<std::string,std::string>>{
        {"\"default\":true","\"default\":1"},{"\"default\":true","\"default\":true,\"default\":true"},
        {"\"op\":\"stopped-snapshot\"","\"op\":\"stopped-snapshot\",\"executable\":\"private-fixture\""},
        {"\"networkId\":\"bridge-id\"","\"networkId\":7"}}) {
        Fake fake(identity,true); auto raw = stoppedRequest(); replace(raw,change.first,change.second);
        rejects([&] { networkTopologyRuntimeRequest(raw,fake.runner()); }); check(fake.calls.empty());
    }
    for (const auto &raw : {"{\"op\":\"capability\",\"args\":[]}","{\"op\":\"snapshot\",\"container\":true}",
        "{\"op\":\"snapshot\",\"container\":\"amnezia-awg\",\"timeout\":1}"}) {
        Fake fake; rejects([&] { networkTopologyRuntimeRequest(raw,fake.runner()); }); check(fake.calls.empty());
    }
    for (const auto &args : std::vector<Args>{{},{"docker","stop",identity},{"docker","inspect","owned-id"},
        {"docker","network","inspect","foreign"},{"docker","version","--format","{{json .}}"},
        {"docker","exec","amnezia-awg","ip","-j","-4","address","show"}}) {
        rejects([&] { productionNetworkObserverRunner()(args); });
        char marker = 0;
        check(::read(execTrace[0],&marker,1) < 0 && errno == EAGAIN);
    }
    ::close(execTrace[0]); ::close(execTrace[1]); unexpectedExecMarker = -1;
    std::cout << cases << " network observer cases PASS; scripted runners and rejected production argv only\n";
}
