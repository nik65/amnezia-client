#include "policy.h"
#include <iostream>
using namespace amnezia::awgMigration::policy;
using namespace std::string_literals;
int main() {
    if (mtu("0576") != 576 || mtu("9000") != 9000) return 1;
    try { mtu("9001"); return 2; } catch (const Error &e) {
        if (std::string(e.what()) != "unsupported_mtu") return 3;
    }
    Fields interface{{"Address", "10.8.1.1/24"}, {"MTU", "1280"},
                     {"PostUp", "iptables -A FORWARD -i %i -j ACCEPT"}};
    validateHooks(interface, "wg0");
    auto noDns = dockerDnsRules({"-P PREROUTING ACCEPT"});
    if (noDns.present || noDns.remaining.size() != 1) return 4;
    Snapshot snapshot;
    snapshot.nat = {"-A PREROUTING -j FIXTURE", "-N FIXTURE"};
    if (firewallScript(snapshot) != "iptables -t nat -N FIXTURE\niptables -t nat -A PREROUTING -j FIXTURE\n") return 5;
    if (clientPolicyEpoch(false, std::nullopt)) return 6;
    unsigned boundaryChecks=0;
    const std::string hash="sha256:"+std::string(64,'a');
    const std::string valid="{\"policy\":{\"revision\":1,\"contentSha256\":\""+hash+"\"}}";
    const auto rejected=[&](const std::string &raw) {
        ++boundaryChecks;
        try { clientPolicyEpoch(true,raw); throw std::logic_error("expected rejection"); }
        catch(const Error &) {}
    };
    for(const auto &suffix:{std::string(1,'\0'),"\0garbage"s,"\0{}"s})rejected(valid+suffix);
    rejected("{\"policy\\u0000suffix\":{\"revision\":1,\"contentSha256\":\""+hash+"\"}}");
    rejected("{\"policy\":{\"revision\\u0000suffix\":1,\"contentSha256\":\""+hash+"\"}}");
    rejected("{\"policy\":{\"revision\":1,\"contentSha256\\u0000suffix\":\""+hash+"\"}}");
    for(const auto &raw:{valid+" \n\t",
        "{\"policy\":{\"revision\":2,\"revision\":1,\"contentSha256\":\""+hash+"\"}}",
        "{\"policy\":{\"revision\":1,\"revision\\u0000suffix\":false,\"contentSha256\":\""+hash+"\"},\"unrelated\":\"\\u0000\"}",
        "{\"unrelated\":\"\\\\u0000\",\"policy\":{\"revision\":1,\"contentSha256\":\""+hash+"\"}}"}) {
        ++boundaryChecks;auto epoch=clientPolicyEpoch(true,raw);
        if(!epoch||epoch->revision!=1||epoch->contentSha256!=hash)return 7;
    }
    for(const auto &value:{"10.8.1.1\0suffix/24"s,"10.8.1.1/255.255.255.0\0suffix"s}) {
        ++boundaryChecks;
        try { validateHooks({{"Address",value}},"wg0");return 8; }catch(const Error &) {}
    }
    ++boundaryChecks;
    validateHooks({{"Address","fe80::1%zone\0scope/128"s}},"wg0");
    const Lines dns={
        "-N DOCKER_OUTPUT", "-N DOCKER_POSTROUTING",
        "-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT",
        "-A POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING",
        "-A DOCKER_OUTPUT -d 127.0.0.11/32 -p tcp -m tcp --dport 53 -j DNAT --to-destination 127.0.0.11:44919",
        "-A DOCKER_OUTPUT -d 127.0.0.11/32 -p udp -m udp --dport 53 -j DNAT --to-destination 127.0.0.11:44920",
        "-A DOCKER_POSTROUTING -s 127.0.0.11/32 -p tcp -m tcp --sport 44919 -j SNAT --to-source :53",
        "-A DOCKER_POSTROUTING -s 127.0.0.11/32 -p udp -m udp --sport 44920 -j SNAT --to-source :53"
    };
    const auto alterPort=[&](const std::string &replacement) {
        auto result=dns;
        for(auto &line:result) {
            auto at=line.find("44919");
            if(at!=std::string::npos)line.replace(at,5,replacement);
        }
        return result;
    };
    ++boundaryChecks;
    if(!dockerDnsRules(alterPort(std::string(50000,'0')+"44919")).present)return 9;
    for(const auto &value:{std::string(50000,'9'),std::string(50000,'0')+"65536",std::string(50000,'0')+"1023"}) {
        ++boundaryChecks;
        try { dockerDnsRules(alterPort(value));return 10; }
        catch(const Error &e) { if(std::string(e.what())!="unsupported_namespace_firewall")return 11; }
    }
    std::cout << "policy native typed API tests passed; " << boundaryChecks << " boundary checks\n";
}
