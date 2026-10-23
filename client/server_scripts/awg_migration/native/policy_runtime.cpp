#include "policy_runtime.h"
#include "bounded_docker.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <json-c/json.h>
#include <memory>
#include <poll.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <regex>
#include <set>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
namespace amnezia::awgMigration::policy
{
    namespace
    {
        constexpr size_t limit = 1024 * 1024;
        [[noreturn]] void reject()
        {
            throw Error("native_policy_rejected");
        }
        using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;
        // This private frame has exact fields: validate decoded names before
        // json-c's C-string keys can truncate them or collapse duplicates.
        struct UniqueKeys : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, UniqueKeys>
        {
            struct Frame { bool object; std::set<std::string> keys; };
            std::vector<Frame> stack;
            bool StartObject() { if (stack.size() >= 32) return false; stack.push_back({true, {}}); return true; }
            bool StartArray() { if (stack.size() >= 32) return false; stack.push_back({false, {}}); return true; }
            bool EndObject(rapidjson::SizeType) { if (stack.empty() || !stack.back().object) return false; stack.pop_back(); return true; }
            bool EndArray(rapidjson::SizeType) { if (stack.empty() || stack.back().object) return false; stack.pop_back(); return true; }
            bool Key(const char *data, rapidjson::SizeType size, bool) {
                if (stack.empty() || !stack.back().object) return false;
                std::string key(data, size);
                return key.find('\0') == std::string::npos && stack.back().keys.insert(std::move(key)).second;
            }
        };
        json_object *field(json_object *o, const char *k, json_type t)
        {
            json_object *v = nullptr;
            if (!o || !json_object_object_get_ex(o, k, &v) || json_object_get_type(v) != t)
                reject();
            return v;
        }
        std::string text(json_object *v)
        {
            if (!v || json_object_get_type(v) != json_type_string)
                reject();
            std::string s(json_object_get_string(v), json_object_get_string_len(v));
            if (s.find('\0') != std::string::npos)
                reject();
            return s;
        }
        std::string str(json_object *o, const char *k)
        {
            return text(field(o, k, json_type_string));
        }
        Lines list(json_object *v)
        {
            if (json_object_get_type(v) != json_type_array || json_object_array_length(v) > 4096)
                reject();
            Lines r;
            for (size_t i = 0; i < json_object_array_length(v); ++i)
                r.push_back(text(json_object_array_get_idx(v, i)));
            return r;
        }
        Fields fields(json_object *v)
        {
            if (json_object_get_type(v) != json_type_object)
                reject();
            Fields r;
            const std::set<std::string> allowed = { "Address", "MTU", "PostUp", "PostDown" };
            json_object_object_foreach(v, k, x)
            {
                if (!allowed.count(k))
                    reject();
                r[k] = text(x);
            }
            return r;
        }
        json_object *array(const Lines &v)
        {
            auto *a = json_object_new_array();
            for (auto &s : v)
                json_object_array_add(a, json_object_new_string_len(s.data(), s.size()));
            return a;
        }
        bool containerName(const std::string &name)
        {
            constexpr const char *prefix = "amnezia-awg";
            constexpr size_t prefixSize = 11;
            if (name.compare(0, prefixSize, prefix) != 0)
                return false;
            size_t offset = prefixSize;
            if (offset < name.size() && name[offset] == '2')
                ++offset;
            if (offset == name.size())
                return true;
            const std::string migration = "-migration-";
            if (name.compare(offset, migration.size(), migration) != 0)
                return false;
            offset += migration.size();
            if (offset == name.size())
                return false;
            for (; offset < name.size(); ++offset)
                if (name[offset] < '0' || name[offset] > '9')
                    return false;
            return true;
        }
        bool firewallRule(const std::string &rule)
        {
            if (rule.size() < 4 || rule[0] != '-' || (rule[1] != 'A' && rule[1] != 'N') || rule[2] != ' ')
                return false;
            for (size_t i = 3; i < rule.size(); ++i) {
                const unsigned char c = rule[i];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == ' '
                      || c == '.' || c == ':' || c == '/' || c == ',' || c == '=' || c == '-'))
                    return false;
            }
            return true;
        }
        void exact(json_object *o, std::set<std::string> keys)
        {
            json_object_object_foreach(o, k, v)
            {
                (void)v;
                if (!keys.erase(k))
                    reject();
            }
            if (!keys.empty())
                reject();
        }
    }
    std::string runReadOnlyDocker(const Lines &a)
    {
        if (a.size() < 4 || a[0] != "docker" || a[1] != "exec" || !containerName(a[2]))
            reject();
        Lines tail(a.begin() + 3, a.end());
        bool allowed = tail == Lines { "ip", "rule", "show" } || tail == Lines { "ip", "route", "show", "table", "main" };
        for (auto iface : { "wg0", "awg0" })
            allowed |= tail == Lines { "ip", "-o", "link", "show", "dev", iface };
        for (auto table : { "raw", "mangle", "filter", "nat" })
            allowed |= tail == Lines { "iptables", "-t", table, "-S" };
        for (auto ip : { "1.1.1.1", "8.8.8.8", "172.29.172.254", "172.29.172.253" })
            allowed |= tail == Lines { "ip", "route", "get", ip };
        if (!allowed)
            reject();
        try { return runBoundedDocker(a, limit); }
        catch (const BoundedDockerError &) { reject(); }
    }
    std::string runtimeRequest(const std::string &input, const Runner &runner)
    {
        if (input.empty() || input.size() > limit || input.find('\0') != std::string::npos) {
            reject();
        }
        rapidjson::MemoryStream stream(input.data(), input.size());
        rapidjson::Reader reader;
        UniqueKeys keys;
        if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, keys)
            || !keys.stack.empty() || stream.Tell() != input.size()) reject();
        auto tok = std::unique_ptr<json_tokener, decltype(&json_tokener_free)>(json_tokener_new(), json_tokener_free);
        if (!tok) reject();
        json_tokener_set_flags(tok.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
        Json root(json_tokener_parse_ex(tok.get(), input.data(), input.size()), json_object_put);
        if (json_tokener_get_error(tok.get()) != json_tokener_success || !root
            || json_object_get_type(root.get()) != json_type_object)
            reject();
        auto op = str(root.get(), "op");
        json_object *value = nullptr;
        if (op == "mtu") {
            exact(root.get(), { "op", "value" });
            value = json_object_new_int(mtu(str(root.get(), "value")));
        } else if (op == "epoch") {
            exact(root.get(), { "op" });
            auto e = clientPolicyEpoch();
            if (e) {
                value = json_object_new_object();
                json_object_object_add(value, "revision", json_object_new_int64(e->revision));
                json_object_object_add(value, "contentSha256", json_object_new_string(e->contentSha256.c_str()));
            }
        } else if (op == "snapshot") {
            exact(root.get(), { "op", "container", "interface", "iface", "ownedComments" });
            auto s = namespaceSnapshot(runner, str(root.get(), "container"),
                                       fields(field(root.get(), "interface", json_type_object)), str(root.get(), "iface"),
                                       list(field(root.get(), "ownedComments", json_type_array)));
            value = json_object_new_object();
            json_object_object_add(value, "mtu", json_object_new_int(s.mtu));
            json_object_object_add(value, "filter", array(s.filter));
            json_object_object_add(value, "nat", array(s.nat));
            json_object_object_add(value, "routes", array(s.routes));
            auto e = json_object_new_object();
            for (auto &kv : s.egress)
                json_object_object_add(e, kv.first.c_str(), json_object_new_string(kv.second.c_str()));
            json_object_object_add(value, "egress", e);
            json_object_object_add(value, "dockerDns", json_object_new_boolean(s.dockerDns));
        } else if (op == "firewall") {
            exact(root.get(), { "op", "snapshot" });
            auto s = field(root.get(), "snapshot", json_type_object);
            exact(s, { "mtu", "filter", "nat", "routes", "egress", "dockerDns" });
            field(s, "mtu", json_type_int);
            auto n = json_object_get_int64(field(s, "mtu", json_type_int));
            if (n < 576 || n > 9000)
                reject();
            list(field(s, "routes", json_type_array));
            field(s, "dockerDns", json_type_boolean);
            auto e = field(s, "egress", json_type_object);
            exact(e, { "1.1.1.1", "8.8.8.8", "172.29.172.254", "172.29.172.253" });
            json_object_object_foreach(e, k, v)
            {
                (void)k;
                auto iface = text(v);
                if (iface != "eth0" && iface != "eth1")
                    reject();
            }
            Snapshot snap;
            snap.filter = list(field(s, "filter", json_type_array));
            snap.nat = list(field(s, "nat", json_type_array));
            for (const auto &rules : { snap.filter, snap.nat })
                for (const auto &rule : rules)
                    if (!firewallRule(rule))
                        reject();
            auto output = firewallScript(snap);
            value = json_object_new_string_len(output.data(), output.size());
        } else {
            reject();
        }
        Json response(json_object_new_object(), json_object_put);
        json_object_object_add(response.get(), "result", value);
        auto output = std::string(json_object_to_json_string_ext(response.get(), JSON_C_TO_STRING_PLAIN));
        if (output.size() > limit)
            reject();
        return output;
    }
    int policyJsonMain()
    {
        try {
            std::string input;
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (true) {
                auto left =
                        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
                                .count();
                if (left <= 0)
                    reject();
                pollfd f { 0, POLLIN, 0 };
                if (poll(&f, 1, static_cast<int>(left)) <= 0)
                    reject();
                char b[8192];
                auto n = read(0, b, sizeof b);
                if (n < 0)
                    reject();
                if (!n)
                    break;
                input.append(b, n);
                if (input.size() > limit)
                    reject();
            }
            std::cout << runtimeRequest(input, runReadOnlyDocker) << "\n";
            return 0;
        } catch (const Error &e) {
            std::string code = e.what();
            if (!std::regex_match(code, std::regex("[a-z_]{1,80}")))
                code = "native_policy_rejected";
            std::cout << "{\"error\":\"" << code << "\"}\n";
            return 2;
        } catch (...) {
            std::cout << "{\"error\":\"native_policy_rejected\"}\n";
            return 2;
        }
    }
}
