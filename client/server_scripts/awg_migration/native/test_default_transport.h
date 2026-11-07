// Inert external-transport fixture for the actual default production path.
// This translation unit replaces ONLY the bounded Docker/ss process boundary at
// link time; every production primitive above it (source config, policy,
// topology, automatic planner, trusted image, generation, journal, ready
// attestation) is the real reviewed code. No fork/exec/socket/namespace is
// ever performed: the OS fences below reject anything outside this file.
#pragma once
#include "automatic_plan.h"
#include "trusted_image.h"
#include "bounded_docker.h"
#include <json-c/json.h>
#include <openssl/evp.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace defaultFixture {
using namespace amnezia::awgMigration;

inline std::string rep(char c, std::size_t n) { return std::string(n, c); }
inline std::string idFor(const std::string &name) {
    std::ostringstream out;
    for (unsigned char c : name) out << std::hex << (c % 16);
    std::string value = out.str();
    value.resize(64, '0');
    return value.substr(0, 64);
}
inline const std::string kSourceId = rep('a', 64);
inline const std::string kStartedAt = "2026-11-07T00:00:00Z";
inline const std::string kTarget = "amnezia-awg-migration-1";
inline const std::string kPeerKey = rep('B', 43) + "=";
inline const std::string kPsk = rep('C', 43) + "=";
inline const std::string kPrivateKey = rep('A', 43) + "=";
inline const std::string kNetworkId = rep('b', 64);

inline std::string rawConfig() {
    return "[Interface]\nPrivateKey = " + kPrivateKey + "\nAddress = 10.8.0.2/24\nListenPort = 51820\n"
        "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 16\nS2 = 16\nS3 = 16\nS4 = 16\n"
        "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nHeaderProtectionKey = " + rep('D', 43) + "=\n"
        "ContentPaddingAddition = 0\nRekeyAfterTime = 120\nRekeyTimeout = 5\n"
        "RejectAfterTime = 180\nKeepaliveTimeout = 10\nMaxHandshakeAttempts = 20\n"
        "RandomTrailers = 0\nDisableCookies = 0\n"
        "[Peer]\nPublicKey = " + kPeerKey + "\nPresharedKey = " + kPsk + "\nAllowedIPs = 10.8.0.3/32\n";
}
inline std::vector<std::pair<std::string, std::string>> parameters() {
    return {{"Jc","4"},{"Jmin","10"},{"Jmax","50"},{"S1","16"},{"S2","16"},{"S3","16"},{"S4","16"},
        {"H1","1"},{"H2","2"},{"H3","3"},{"H4","4"},{"HeaderProtectionKey",rep('D',43)+"="},
        {"ContentPaddingAddition","0"},{"RekeyAfterTime","120"},{"RekeyTimeout","5"},
        {"RejectAfterTime","180"},{"KeepaliveTimeout","10"},{"MaxHandshakeAttempts","20"},
        {"RandomTrailers","0"},{"DisableCookies","0"}};
}
inline std::string base64(const unsigned char *data, std::size_t size) {
    std::string out(4 * ((size + 2) / 3), '\0');
    const int length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data, int(size));
    out.resize(length < 0 ? 0 : static_cast<std::size_t>(length));
    return out;
}
inline std::string serverKey(const std::string &raw) {
    const auto at = raw.find("PrivateKey = ");
    if (at == std::string::npos) return {};
    const auto end = raw.find('\n', at);
    const std::string text = raw.substr(at + 13, end - at - 13);
    std::string decoded((text.size() * 3) / 4, '\0');
    const int length = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(decoded.data()),
        reinterpret_cast<const unsigned char *>(text.data()), int(text.size()));
    std::size_t padding = 0;
    for (auto it = text.rbegin(); it != text.rend() && *it == '='; ++it) ++padding;
    if (length < 0) return {};
    decoded.resize(static_cast<std::size_t>(length) - padding);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
            reinterpret_cast<const unsigned char *>(decoded.data()), decoded.size()), EVP_PKEY_free);
    unsigned char publicBytes[32]; std::size_t publicSize = sizeof publicBytes;
    if (!key || EVP_PKEY_get_raw_public_key(key.get(), publicBytes, &publicSize) != 1) return {};
    return base64(publicBytes, publicSize);
}

struct Container {
    std::string id, name, image, owner, startedAt, config;
    bool running = false;
};

struct State {
    std::string mode = "full";           // full | first-io
    std::string policyRoot, updatesRoot;
    std::string feedPath;
    std::string iface = "wg0";
    std::string configPath;
    std::vector<std::string> calls;
    std::map<std::string, Container> containers;
    std::map<std::string, std::string> images;
    bool sentinel = false;
    bool fatal = false;
    std::string fatalDetail;
    unsigned plannerInfoCalls = 0;
    bool twoFeeds = false;
    // One-shot inert test stimulus fired at the first external boundary call.
    std::function<void()> onFirstCommand;
    explicit State() {
        Container source;
        source.id = kSourceId; source.name = "amnezia-awg";
        source.image = "sha256:" + rep('e', 64);
        source.owner = rep('0', 32); source.startedAt = kStartedAt;
        source.config = rawConfig(); source.running = true;
        containers["amnezia-awg"] = source;
        images[TrustedImage] = TrustedImageId;
        images["python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"]
            = "sha256:" + rep('f', 64);
    }
    Container *find(const std::string &nameOrId) {
        auto it = containers.find(nameOrId);
        if (it != containers.end()) return &it->second;
        for (auto &entry : containers)
            if (entry.second.id == nameOrId) return &entry.second;
        return nullptr;
    }
};

inline State &state() { static State value; return value; }

inline std::string plain(std::vector<std::pair<std::string, std::string>> fields, bool quote = true) {
    std::string out = "{";
    bool first = true;
    for (auto &field : fields) {
        if (!first) out += ",";
        first = false;
        out += "\"" + field.first + "\":";
        out += quote ? "\"" + field.second + "\"" : field.second;
    }
    return out + "}";
}
inline std::string identityJson(const Container &c, bool runningField) {
    std::string out = "{\"id\":\"" + c.id + "\",\"name\":\"/" + c.name + "\",\"image\":\"" + c.image
        + "\",\"owner\":\"" + c.owner + "\",\"startedAt\":\"" + c.startedAt + "\"";
    if (runningField) out += ",\"running\":" + std::string(c.running ? "true" : "false");
    return out + "}";
}
inline std::string metadataJson(const Container &c) {
    const std::string net = "\"Networks\":{\"bridge\":{\"NetworkID\":\"" + kNetworkId
        + "\",\"IPAddress\":\"172.17.0.2\",\"Gateway\":\"172.17.0.1\",\"IPPrefixLen\":16,"
        "\"DriverOpts\":{\"com.docker.network.endpoint.ifname\":\"eth0\"},\"GwPriority\":1}}";
    return "[{\"Id\":\"" + c.id + "\",\"Name\":\"/" + c.name + "\",\"Image\":\"" + c.image
        + "\",\"Config\":{\"Labels\":{\"amnezia.migration.owner\":\"" + c.owner + "\"}},"
        "\"State\":{\"Running\":" + std::string(c.running ? "true" : "false")
        + ",\"Status\":\"" + std::string(c.running ? "running" : "created")
        + "\",\"Pid\":" + std::string(c.running ? "4242" : "0")
        + ",\"StartedAt\":\"" + (c.running ? c.startedAt : "0001-01-01T00:00:00Z") + "\"},"
        "\"NetworkSettings\":{" + net + "}}]";
}
inline void record(const std::vector<std::string> &a, std::size_t limit, unsigned budget) {
    if (a.empty() || a.front() != "docker") {
        state().fatal = true; state().fatalDetail = "non-docker command boundary";
        throw BoundedDockerError();
    }
    if (limit == 0 || limit > 16u * 1024u * 1024u) {
        state().fatal = true; state().fatalDetail = "widened output budget";
        throw BoundedDockerError();
    }
    if (budget != 3 && budget != 10 && budget != 30 && budget != 180) {
        state().fatal = true; state().fatalDetail = "unapproved timeout budget";
        throw BoundedDockerError();
    }
    if (state().onFirstCommand) {
        auto hook = std::move(state().onFirstCommand);
        state().onFirstCommand = nullptr;
        hook();
    }
    std::ostringstream line;
    for (std::size_t i = 0; i < a.size(); ++i) line << (i ? " " : "") << a[i];
    state().calls.push_back(line.str());
}

inline std::string respond(const std::vector<std::string> &a) {
    State &s = state();
    const std::string &verb = a.size() > 1 ? a[1] : std::string();
    if (verb == "info") {
        ++s.plannerInfoCalls;
        if (s.mode == "first-io") {
            s.sentinel = true;
            throw BoundedDockerError(BoundedDockerFailureKind::Other);
        }
        return "{\"OSType\":\"linux\",\"Architecture\":\"x86_64\"}";
    }
    if (verb == "version") return "28.0.1\n";
    if (verb == "network") {
        return "[{\"Name\":\"bridge\",\"Driver\":\"bridge\",\"Scope\":\"local\",\"Internal\":false,"
            "\"EnableIPv6\":false,\"Id\":\"" + kNetworkId + "\",\"IPAM\":{\"Config\":[{\"Subnet\":"
            "\"172.17.0.0/16\",\"Gateway\":\"172.17.0.1\"}]}}]";
    }
    if (verb == "image" && a.size() == 6 && a[2] == "inspect" && a[3] == "--format"
        && a[4] == "{{.Id}}") {
        const auto it = s.images.find(a[5]);
        return (it == s.images.end() ? TrustedImageId : it->second) + "\n";
    }
    if (verb == "image" && a.size() == 4 && a[2] == "inspect") {
        if (a[3] == TrustedImage) {
            return "[{\"Id\":\"" + std::string(TrustedImageId) + "\",\"RepoDigests\":[\"" + TrustedImage
                + "\"],\"Os\":\"linux\",\"Architecture\":\"amd64\",\"Descriptor\":{\"digest\":\""
                + std::string(TrustedImage).substr(std::string(TrustedImage).find('@') + 1) + "\"}}]";
        }
        return "[{\"Id\":\"" + rep('e', 64) + "\"}]";
    }
    if (verb == "pull") return "";
    if (verb == "ps" && a.size() == 3 && a[2] == "-q") return "";
    if (verb == "ps") return "";
    if (verb == "run") {
        bool sandbox = std::find(a.begin(), a.end(), "--rm") != a.end();
        if (sandbox) {
            if (std::find(a.begin(), a.end(), "sha256sum") != a.end())
                return std::string(TrustedBinarySha256) + "  /usr/bin/amneziawg-go\n";
            if (std::find(a.begin(), a.end(), "--version") != a.end())
                return std::string(TrustedReportedVersion) + "\n";
            return "ready";
        }
        std::string name, owner, image;
        for (std::size_t i = 0; i + 1 < a.size(); ++i) {
            if (a[i] == "--name") name = a[i + 1];
            if (a[i] == "--label" && a[i + 1].rfind("amnezia.migration.owner=", 0) == 0)
                owner = a[i + 1].substr(std::string("amnezia.migration.owner=").size());
            if (a[i] == "--entrypoint" && i + 2 < a.size()) image = a[i + 2];
        }
        Container c;
        c.id = idFor(name); c.name = name;
        const auto mapped = s.images.find(image);
        c.image = mapped == s.images.end() ? image : mapped->second;
        c.owner = owner; c.startedAt = kStartedAt; c.running = true;
        s.containers[name] = c;
        return c.id + "\n";
    }
    if (verb == "create") {
        std::string name, owner, image;
        for (std::size_t i = 0; i + 1 < a.size(); ++i) {
            if (a[i] == "--name") name = a[i + 1];
            if (a[i] == "--label" && a[i + 1].rfind("amnezia.migration.owner=", 0) == 0)
                owner = a[i + 1].substr(std::string("amnezia.migration.owner=").size());
            if (a[i] == "--entrypoint" && i + 2 < a.size()) image = a[i + 2];
        }
        Container c;
        c.id = idFor(name); c.name = name;
        const auto mapped = s.images.find(image);
        c.image = mapped == s.images.end() ? image : mapped->second;
        c.owner = owner; c.startedAt = kStartedAt; c.running = false;
        s.containers[name] = c;
        return c.id + "\n";
    }
    if (verb == "start") {
        Container *c = s.find(a.size() > 2 ? a[2] : std::string());
        if (!c) throw BoundedDockerError();
        c->running = true;
        return a[2] + "\n";
    }
    if (verb == "build") {
        std::string tag;
        for (std::size_t i = 0; i + 1 < a.size(); ++i) if (a[i] == "-t") tag = a[i + 1];
        s.images[tag] = "sha256:" + idFor(tag);
        return "";
    }
    if (verb == "rm") return "";
    if (verb == "inspect" && a.size() >= 4 && a[2] == "--format") {
        const std::string &format = a[3];
        const std::string target = a.back();
        Container *found = s.find(target);
        Container sourceCopy;
        if (!found) {
            const bool sourceIdentity = target == "amnezia-awg";
            if (!sourceIdentity) return "";
            sourceCopy = s.containers["amnezia-awg"];
            found = &sourceCopy;
        }
        const Container &c = *found;
        if (format == "{{.Id}}") return c.id + "\n";
        if (format.find("startedAt") != std::string::npos && format.find("running") != std::string::npos)
            return identityJson(c, true);
        if (format.find("startedAt") != std::string::npos) {
            return "{\"id\":\"" + c.id + "\",\"startedAt\":\"" + c.startedAt + "\"}";
        }
        return identityJson(c, true);
    }
    if (verb == "inspect") {
        Container *found = s.find(a.size() > 2 ? a[2] : std::string());
        if (!found) throw BoundedDockerError(BoundedDockerFailureKind::Exit);
        return metadataJson(*found);
    }
    if (verb == "exec") {
        const std::string joined = [&] { std::string out; for (auto &v : a) out += v + " "; return out; }();
        if (joined.find("cat /proc/net/tcp") != std::string::npos)
            return "  sl  local_address rem_address   st\n";
        if (joined.find("cat /opt/amnezia/awg/") != std::string::npos)
            return s.containers["amnezia-awg"].config;
        if (joined.find("ip -o link show dev") != std::string::npos) {
            const auto at = joined.find("show dev ");
            const auto end = joined.find(' ', at + 9);
            s.iface = joined.substr(at + 9, end == std::string::npos ? end : end - at - 9);
            return "7: " + s.iface + ": <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN\n";
        }
        if (joined.find("ip rule show") != std::string::npos)
            return "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n";
        if (joined.find("iptables -t raw -S") != std::string::npos
            || joined.find("iptables -t mangle -S") != std::string::npos)
            return "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n";
        if (joined.find("iptables -t filter -S") != std::string::npos)
            return "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
                "-A INPUT -i awg0 -j ACCEPT\n-A FORWARD -i awg0 -j ACCEPT\n-A OUTPUT -o awg0 -j ACCEPT\n"
                "-A FORWARD -s 10.8.0.0/24 -i awg0 -o eth0 -j ACCEPT\n"
                "-A FORWARD -s 10.8.0.0/24 -i awg0 -o eth1 -j ACCEPT\n"
                "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
                "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
                "-A FORWARD -i awg0 -o eth0 -j ACCEPT\n-A FORWARD -i awg0 -o eth1 -j ACCEPT\n";
        if (joined.find("iptables -t nat -S") != std::string::npos)
            return "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n"
                "-A PREROUTING -d 172.29.172.253/32 -i awg0 -p tcp -m tcp --dport 17864 -j REDIRECT --to-ports 17864\n"
                + (s.twoFeeds ? std::string("-A PREROUTING -d 172.29.172.252/32 -i awg0 -p tcp -m tcp --dport 17865 -j REDIRECT --to-ports 17865\n") : std::string()) +
                "-A PREROUTING -d 172.29.172.251/32 -i awg0 -p tcp -m tcp --dport 17866 -j REDIRECT --to-ports 17866\n"
                "-A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE\n"
                "-A POSTROUTING -s 10.8.0.0/24 -o eth1 -j MASQUERADE\n"
                "-A POSTROUTING -o eth0 -j MASQUERADE\n-A POSTROUTING -o eth1 -j MASQUERADE\n";
        if (joined.find("ip route show table main") != std::string::npos)
            return "default via 10.0.0.1 dev eth0\n10.8.0.0/24 dev " + s.iface
                + " proto kernel scope link src 10.8.0.2\n";
        if (joined.find("ip route get") != std::string::npos)
            return "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 1000\n";
        if (joined.find("ip -j -4 address show") != std::string::npos)
            return "[{\"ifname\":\"eth0\",\"addr_info\":[{\"family\":\"inet\",\"local\":\"172.17.0.2\",\"prefixlen\":16}]}]";
        if (joined.find("ip -j -4 route show default") != std::string::npos)
            return "[{\"dst\":\"default\",\"dev\":\"eth0\",\"gateway\":\"172.17.0.1\"}]";
        if (joined.find("awg show awg0 dump") != std::string::npos) {
            return "private\t" + serverKey(rawConfig()) + "\t51821\t0\n" + kPeerKey + "\t" + kPsk
                + "\t(none)\t10.8.0.3/32\t0\t0\t0\t0\n";
        }
        if (joined.find("awg showconf awg0") != std::string::npos) {
            // The generated target config is the live container's source of
            // truth; echo its Interface fields in awg showconf shape.
            if (!s.configPath.empty()) {
                std::ifstream stream(s.configPath, std::ios::binary);
                std::ostringstream raw; raw << stream.rdbuf();
                std::istringstream lines(raw.str());
                std::string line, out;
                bool interface = false;
                while (std::getline(lines, line)) {
                    if (line == "[Peer]") break;
                    if (line == "[Interface]") { interface = true; continue; }
                    if (interface && !line.empty()) out += line + "\n";
                }
                if (!out.empty()) return out;
            }
            std::string out;
            for (auto &kv : parameters()) out += kv.first + " = " + kv.second + "\n";
            return out;
        }
        if (joined.find("engine.pid") != std::string::npos)
            return std::string(TrustedBinarySha256) + "  /proc/4242/exe\n";
        if (joined.find("--verify-control-live") != std::string::npos) return "";
        if (joined.find("--check-feed") != std::string::npos) return "";
        if (joined.find("sh -c") != std::string::npos) return "";
        return "";
    }
    state().fatal = true;
    state().fatalDetail = "undeclared docker verb";
    throw BoundedDockerError(BoundedDockerFailureKind::Other);
}
} // namespace defaultFixture

namespace amnezia::awgMigration {
std::string runBoundedDockerWithBudget(const std::vector<std::string> &a,
        std::size_t limit, unsigned budget) {
    defaultFixture::record(a, limit, budget);
    return defaultFixture::respond(a);
}
std::string runBoundedDocker(const std::vector<std::string> &a, std::size_t limit) {
    defaultFixture::record(a, limit, 3);
    return defaultFixture::respond(a);
}
std::string runBoundedSs(std::size_t limit) {
    if (limit == 0 || limit > 1024 * 1024) throw BoundedDockerError();
    defaultFixture::state().calls.push_back("ss -H -uan");
    return "";
}
} // namespace amnezia::awgMigration
