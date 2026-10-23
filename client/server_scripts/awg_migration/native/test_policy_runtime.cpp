#include "policy_runtime.h"
#include <cassert>
#include <iostream>
#include <unistd.h>
using namespace amnezia::awgMigration::policy;
// Link-time test interposer: accepted runner argv reaches an owned child only.
// It never invokes Docker or any other executable.
extern "C" int execve(const char *, char *const[], char *const[]) noexcept
{
    _exit(0);
}
int main()
{
    int calls = 0;
    const std::string baselineRules="0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n";
    std::string rulesOutput=baselineRules,linkOutput="1: wg0: mtu 1420";
    auto fake = [&](const Lines &a) {
        ++calls;
        assert(a[0] == "docker" && a[1] == "exec" && a[2] == "amnezia-awg");
        Lines v(a.begin() + 3, a.end());
        if (v == Lines { "ip", "-o", "link", "show", "dev", "wg0" })
            return linkOutput;
        if (v == Lines { "ip", "rule", "show" })
            return rulesOutput;
        if (v[0] == "iptables")
            return std::string("-P INPUT ACCEPT\n");
        if (v == Lines { "ip", "route", "show", "table", "main" })
            return std::string("default via 172.18.0.1 dev eth0\n");
        if (v.size() == 4 && v[1] == "route" && v[2] == "get")
            return std::string("dev eth0");
        throw Error("unexpected_fake_command");
    };
    const auto valid = std::string(R"({"op":"mtu","value":"1420"})");
    assert(runtimeRequest(R"({"\u006fp":"mtu","value":"1420"})", fake) == "{\"result\":1420}");
    for(const auto &request: {
            std::string(R"({"op\u0000suffix":"mtu","value":"1420"})"),
            std::string(R"({"op":"mtu","value\u0000suffix":"1420"})"),
            std::string(R"({"op":"mtu","op":"mtu","value":"1420"})"),
            std::string(R"({"op":"mtu","value":"9001","val\u0075e":"1420"})"),
            valid+std::string(1,'\0'),valid+std::string("\0extra",6),valid+"{}",valid+"garbage",
            std::string(R"({"op":"snapshot","container":"amnezia-awg","interface":{"Address":"10.8.1.1/24","Address":"10.8.1.1/24"},"iface":"wg0","ownedComments":[]})"),
            std::string(R"({"op":"snapshot","container":"amnezia-awg","interface":{"Address\u0000suffix":"10.8.1.1/24"},"iface":"wg0","ownedComments":[]})")}) {
        bool rejected=false;
        try { runtimeRequest(request,fake); } catch(const Error &e) { rejected=std::string(e.what())=="native_policy_rejected"; }
        assert(rejected&&calls==0);
    }
    assert(runtimeRequest(valid+" \n\t",fake)=="{\"result\":1420}");
    auto result = runtimeRequest(
            R"({"op":"snapshot","container":"amnezia-awg","interface":{"Address":"10.8.1.1/24","MTU":"1420"},"iface":"wg0","ownedComments":[]})",
            fake);
    assert(runtimeRequest(
                   R"({"op":"firewall","snapshot":{"mtu":1420,"filter":[],"nat":[],"routes":[],"egress":{"1.1.1.1":"eth0","8.8.8.8":"eth0","172.29.172.254":"eth0","172.29.172.253":"eth0"},"dockerDns":false}})",
                   fake)
           == "{\"result\":\"\\n\"}");
    assert(calls == 11);
    assert(result.find("1420") != std::string::npos);
    assert(result.find("dockerDns") != std::string::npos);
    assert(runtimeRequest(R"({"op":"mtu","value":"1420"})", fake) == "{\"result\":1420}");
    for (auto request :
         { R"({"op":"mtu","value":"1"})", R"({"op":"epoch","responses":{}})",
           R"({"op":"snapshot","container":"amnezia-awg","interface":{"Address":"10.8.1.1/24","surprise":"x"},"iface":"wg0","ownedComments":[]})",
           R"({"op":"firewall","snapshot":{"filter":[],"nat":[],"surprise":true}})",
           R"({"op":"firewall","snapshot":{"filter":["-A INPUT ; touch /tmp/no"],"nat":[]}})" }) {
        bool rejected = false;
        try {
            runtimeRequest(request, fake);
        } catch (const Error &) {
            rejected = true;
        }
        assert(rejected);
    }
    for (auto command : { Lines { "docker", "exec", "amnezia-awg", "sh", "-c", "true" },
                          Lines { "docker", "exec", "--privileged", "ip", "rule", "show" } }) {
        bool rejected = false;
        try {
            runReadOnlyDocker(command);
        } catch (const Error &) {
            rejected = true;
        }
        assert(rejected);
    }
    const auto digits = std::string(200000, '1');
    const auto largeContainer = std::string("amnezia-awg-migration-") + digits;
    assert(runReadOnlyDocker({ "docker", "exec", largeContainer, "ip", "rule", "show" }).empty());
    bool longNameRejected = false;
    try {
        runReadOnlyDocker({ "docker", "exec", largeContainer + "x", "ip", "rule", "show" });
    } catch (const Error &) {
        longNameRejected = true;
    }
    assert(longNameRejected);
    const auto firewallRequest = [](const std::string &rule) {
        return std::string(R"({"op":"firewall","snapshot":{"mtu":1420,"filter":[")") + rule
                + R"("],"nat":[],"routes":[],"egress":{"1.1.1.1":"eth0","8.8.8.8":"eth0","172.29.172.254":"eth0","172.29.172.253":"eth0"},"dockerDns":false}})";
    };
    const auto longRule = std::string("-A ") + std::string(200000, 'A');
    assert(runtimeRequest(firewallRequest(longRule), fake).find(longRule) != std::string::npos);
    bool longRuleRejected = false;
    try {
        runtimeRequest(firewallRequest(longRule + ";"), fake);
    } catch (const Error &) {
        longRuleRejected = true;
    }
    assert(longRuleRejected);
    const std::string snapshotFrame=R"({"op":"snapshot","container":"amnezia-awg","interface":{"Address":"10.8.1.1/24","MTU":"1420"},"iface":"wg0","ownedComments":[]})";
    unsigned outputChecks=0;
    for(const std::string separator:{"\n","\r\n","\r","\v","\f","\x1c","\x1d","\x1e","\xc2\x85","\xe2\x80\xa8","\xe2\x80\xa9"}) {
        rulesOutput.clear();
        for(char c:baselineRules)rulesOutput+=(c=='\n'?separator:std::string(1,c));
        assert(runtimeRequest(snapshotFrame,fake).find("1420")!=std::string::npos);++outputChecks;
        rulesOutput="0:"+separator+"from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n";
        bool rejected=false;
        try { runtimeRequest(snapshotFrame,fake); } catch(const Error &e) { rejected=std::string(e.what())=="unsupported_namespace_ip_rule"; }
        assert(rejected);++outputChecks;
    }
    for(const std::string space:{"\x1c","\x1d","\x1e","\x1f","\xc2\x85","\xc2\xa0","\xe1\x9a\x80","\xe2\x80\x80","\xe2\x80\x8a","\xe2\x80\xa8","\xe2\x80\xa9","\xe2\x80\xaf","\xe2\x81\x9f","\xe3\x80\x80"}) {
        rulesOutput=space;bool rejected=false;
        try { runtimeRequest(snapshotFrame,fake); } catch(const Error &e) { rejected=std::string(e.what())=="incomplete_namespace_ip_rules"; }
        assert(rejected);++outputChecks;
        rulesOutput=space+baselineRules+space;
        assert(runtimeRequest(snapshotFrame,fake).find("1420")!=std::string::npos);++outputChecks;
    }
    rulesOutput=std::string(50000,'0')+baselineRules;
    assert(runtimeRequest(snapshotFrame,fake).find("1420")!=std::string::npos);++outputChecks;
    rulesOutput=baselineRules;
    for(const std::string &value:{std::string(50000,'0')+"1420",std::string(50000,'9')}) {
        linkOutput="mtu "+value;bool rejected=false;
        try { runtimeRequest(snapshotFrame,fake); } catch(const Error &e) { rejected=std::string(e.what())=="unsupported_mtu"; }
        assert(rejected);++outputChecks;
    }
    linkOutput="mtu 1280x mtu 1420";
    assert(runtimeRequest(snapshotFrame,fake).find("1420")!=std::string::npos);++outputChecks;
    linkOutput="mtu 9001 mtu 1420";
    bool firstMtuRejected=false;
    try { runtimeRequest(snapshotFrame,fake); } catch(const Error &e) { firstMtuRejected=std::string(e.what())=="unsupported_mtu"; }
    assert(firstMtuRejected);++outputChecks;
    std::cout << "policy runtime fake runner checks passed; " << outputChecks << " output boundary checks\n";
}
