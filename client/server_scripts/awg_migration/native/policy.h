#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
namespace amnezia::awgMigration::policy  {
    using Fields=std::map<std::string,std::string>;
    using Lines=std::vector<std::string>;
    using Runner=std::function<std::string(const Lines &)>;
    class Error final:public std::runtime_error  {
        public: explicit Error(const std::string &code):std::runtime_error(code) {
        }
    };
    struct Snapshot  {
        int mtu=0;
        Lines filter,nat,routes;
        Fields egress;
        bool dockerDns=false;
    };
    struct Epoch  {
        std::int64_t revision;
        std::string contentSha256;
    };
    int mtu(const std::string &value);
    Lines standardFilter(const std::string &iface,const std::string &network);
    std::string normalize(const std::string &rule,const std::string &iface);
    void validateHooks(const Fields &interface,const std::string &iface);
    struct DockerDns  {
        Lines remaining;
        bool present=false;
    };
    DockerDns dockerDnsRules(const Lines &lines);
    Lines serverDnsProxyRules(const Lines &lines,const std::string &sourceAddress);
    Snapshot namespaceSnapshot(const Runner &run,const std::string &container,const Fields &interface,const std::string &iface,const Lines &ownedComments= {
    });
    std::string firewallScript(const Snapshot &snapshot);
    // Pure input form permits FakeRunner/fixtures without touching /opt.
    std::optional<Epoch> clientPolicyEpoch(bool directoryExists,const std::optional<std::string> &rulesJson);
    // Filesystem adapter only; no process/network operations.
    std::optional<Epoch> clientPolicyEpoch(const std::string &directory="/opt/amnezia/server-routing-rules");
}
