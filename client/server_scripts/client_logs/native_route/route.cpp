#include "route.hpp"
#include "../../../core/utils/constants/protocolConstants.h"
#include <algorithm>
#include <cctype>
#include <climits>
#include <sstream>
#include <stdexcept>
namespace collector_route
{
    std::string collectorName(const std::string &scope)
    {
        return std::string(amnezia::protocols::clientLogs::tunnelContainerName) + "-" + scope;
    }
    namespace
    {
        const std::string image =
                "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df";
        const char *label = "org.amnezia.client-logs.route";
        const char *iface(const std::string &s)
        {
            if (s == "amnezia-awg2")
                return "awg0";
            if (s == "amnezia-awg" || s == "amnezia-wireguard")
                return "wg0";
            if (s == "amnezia-openvpn")
                return "tun0";
            throw Failure("scope");
        }
        json_object *field(json_object *p, const char *k, json_type t)
        {
            json_object *v = nullptr;
            if (!p || json_object_get_type(p) != json_type_object || !json_object_object_get_ex(p, k, &v) || !v
                || json_object_get_type(v) != t)
                throw Failure("JSON field type");
            return v;
        }
        std::string text(json_object *p, const char *k)
        {
            auto *v = field(p, k, json_type_string);
            std::string s(json_object_get_string(v), json_object_get_string_len(v));
            if (s.find('\0') != std::string::npos)
                throw Failure("NUL text");
            return s;
        }
        bool yes(json_object *p, const char *k)
        {
            return json_object_get_boolean(field(p, k, json_type_boolean));
        }
        void id(const std::string &s)
        {
            if (s.size() != 64 || !std::all_of(s.begin(), s.end(), [](unsigned char c) {
                    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                }))
                throw Failure("container ID");
        }
        void checked(Adapter &a, const Args &v)
        {
            if (a.run(v).code != 0)
                throw Failure("Docker command refused");
        }
        Container get(Adapter &a, const std::string &id, const Binding &b, const std::string &root, bool publication = false)
        {
            auto r = a.run({ "inspect", id });
            if (r.code)
                throw Failure("Docker inspect");
            return inspectDocument(r.output, b.scope, root, publication);
        }
        using Epoch = std::pair<std::string, std::string>;
        Epoch epoch(Adapter &a, const Container &c)
        {
            return { c.startedAt, a.netns(c) };
        }
    }
    Json parse(const std::string &s, std::size_t limit)
    {
        if (s.empty() || s.size() > limit || s.size() > INT_MAX || s.find('\0') != std::string::npos
            || s.find("\\u0000") != std::string::npos)
            throw Failure("JSON size");
        std::unique_ptr<json_tokener, decltype(&json_tokener_free)> t(json_tokener_new_ex(32), json_tokener_free);
        if (!t)
            throw Failure("JSON allocation");
        json_tokener_set_flags(t.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
        Json result(json_tokener_parse_ex(t.get(), s.data(), int(s.size())));
        if (!result || json_tokener_get_error(t.get()) != json_tokener_success)
            throw Failure("JSON syntax");
        for (auto n = json_tokener_get_parse_end(t.get()); n < s.size(); ++n)
            if (!std::isspace(static_cast<unsigned char>(s[n])))
                throw Failure("JSON trailing bytes");
        return result;
    }
    Binding binding(const std::string &s)
    {
        auto j = parse(s, 4096);
        auto *p = j.get();
        if (json_object_get_type(p) != json_type_object || json_object_object_length(p) != 4)
            throw Failure("binding keys");
        if (json_object_get_int64(field(p, "schema", json_type_int)) != 1)
            throw Failure("binding schema");
        Binding b { text(p, "scope"), text(p, "sourceId"), text(p, "collectorId") };
        iface(b.scope);
        id(b.sourceId);
        id(b.collectorId);
        return b;
    }
    std::string canonical(const Binding &b)
    {
        iface(b.scope);
        id(b.sourceId);
        id(b.collectorId);
        return "{\"collectorId\":\"" + b.collectorId + "\", \"schema\": 1, \"scope\":\"" + b.scope
                + "\", \"sourceId\":\"" + b.sourceId + "\"}";
    }
    Container inspectDocument(const std::string &s, const std::string &scope, const std::string &root, bool publication)
    {
        auto j = parse(s, 1024 * 1024);
        auto *a = j.get();
        if (json_object_get_type(a) != json_type_array || json_object_array_length(a) != 1)
            throw Failure("inspect singleton");
        auto *p = json_object_array_get_idx(a, 0);
        Container c;
        c.id = text(p, "Id");
        c.name = text(p, "Name");
        auto *state = field(p, "State", json_type_object);
        c.running = yes(state, "Running");
        c.pid = json_object_get_int64(field(state, "Pid", json_type_int));
        if (c.pid < 0 || c.pid > INT_MAX)
            throw Failure("PID range");
        json_object *v = nullptr;
        if (json_object_object_get_ex(state, "StartedAt", &v)) {
            if (!v || json_object_get_type(v) != json_type_string)
                throw Failure("epoch type");
            c.startedAt = text(state, "StartedAt");
        }
        if (c.name == "/" + collectorName(scope)) {
            auto *config = field(p, "Config", json_type_object);
            c.image = text(config, "Image");
            json_object *labels = nullptr;
            if (!json_object_object_get_ex(config, "Labels", &labels) || !labels) {
                if (!publication) throw Failure("collector labels");
            } else if (json_object_get_type(labels) != json_type_object) {
                throw Failure("collector labels type");
            }
            json_object *hash = nullptr;
            if (labels && json_object_object_get_ex(labels, "org.amnezia.client-logs.native-sha256", &hash)) {
                c.nativeSha256 = text(labels, "org.amnezia.client-logs.native-sha256");
                if (c.nativeSha256.size() != 64 || c.nativeSha256.find_first_not_of("0123456789abcdef") != std::string::npos)
                    throw Failure("native hash identity");
                c.nativeProcess = true;
            }
            json_object *routeLabel = nullptr;
            if (labels && json_object_object_get_ex(labels, label, &routeLabel))
                c.label = text(labels, label);
            else if (publication && !c.nativeProcess)
                c.label = scope;
            else
                throw Failure("collector route label");
            const auto exactArgs = [](json_object *v, const Args &expected) {
                if (!v || json_object_get_type(v) != json_type_array || json_object_array_length(v) != expected.size())
                    return false;
                for (std::size_t i = 0; i < expected.size(); ++i) {
                    auto *item = json_object_array_get_idx(v, i);
                    if (!item || json_object_get_type(item) != json_type_string
                        || std::string(json_object_get_string(item), json_object_get_string_len(item)) != expected[i])
                        return false;
                }
                return true;
            };
            if (!exactArgs(field(config, "Entrypoint", json_type_array),
                           c.nativeProcess ? Args { "/data/amnezia-client-logs-collector" } : Args { "python" })
                || !exactArgs(field(config, "Cmd", json_type_array),
                              c.nativeProcess ? Args { "--root", "/data" } : Args { "/data/collector.py" }))
                throw Failure("collector process identity");
            json_object *environment = nullptr;
            if (json_object_object_get_ex(config, "Env", &environment)) {
                if (!environment || json_object_get_type(environment) != json_type_array)
                    throw Failure("collector environment");
                unsigned matches = 0;
                for (std::size_t i = 0; i < json_object_array_length(environment); ++i) {
                    auto *entry = json_object_array_get_idx(environment, i);
                    if (!entry || json_object_get_type(entry) != json_type_string)
                        throw Failure("collector environment entry");
                    std::string value(json_object_get_string(entry), json_object_get_string_len(entry));
                    if (value.rfind("AMNEZIA_CLIENT_LOGS_SCOPE=", 0) == 0) {
                        if (value != "AMNEZIA_CLIENT_LOGS_SCOPE=" + scope)
                            throw Failure("collector environment scope");
                        ++matches;
                    }
                }
                c.scopeEnvironment = matches == 1;
            }
            c.network = text(field(p, "HostConfig", json_type_object), "NetworkMode");
            auto *mounts = field(p, "Mounts", json_type_array);
            int found = 0;
            for (std::size_t i = 0; i < json_object_array_length(mounts); ++i) {
                auto *m = json_object_array_get_idx(mounts, i);
                if (text(m, "Destination") == "/data") {
                    ++found;
                    c.mountValid = text(m, "Source") == root && yes(m, "RW");
                }
            }
            c.mountValid = c.mountValid && found == 1;
        }
        return c;
    }
    void validate(const Container &s, const Container &c, const Binding &b)
    {
        iface(b.scope);
        id(b.sourceId);
        id(b.collectorId);
        if (s.id != b.sourceId || s.name != "/" + b.scope || !s.running || s.pid <= 0 || s.startedAt.empty()
            || c.id != b.collectorId || c.name != "/" + collectorName(b.scope) || c.image != image
            || c.label != b.scope || c.network != "container:" + b.sourceId || !c.mountValid)
            throw Failure("publication identity");
    }
    void publicationPreflight(Adapter &a, const std::string &scope, const std::string &root)
    {
        iface(scope);
        Binding seed { scope, std::string(64, 'a'), std::string(64, 'b') };
        auto source = get(a, scope, seed, root, true);
        id(source.id);
        if (source.name != "/" + scope || !source.running || source.pid <= 0 || source.startedAt.empty())
            throw Failure("source ownership");
        auto names = a.run({ "ps", "-a", "--format", "{{.Names}}" });
        if (names.code || names.output.size() > 1024 * 1024)
            throw Failure("collector inventory");
        std::istringstream rows(names.output);
        std::string name;
        bool found = false;
        while (std::getline(rows, name))
            if (name == collectorName(scope)) found = true;
        if (!found) return;
        auto collector = get(a, collectorName(scope), seed, root, true);
        Binding bound { scope, source.id, collector.id };
        validate(source, collector, bound);
        if (!collector.scopeEnvironment)
            throw Failure("collector scope environment");
        if (collector.nativeProcess && (!collector.running || collector.pid <= 0))
            throw Failure("previous native collector not running");
        auto original = epoch(a, source);
        if (collector.running && (collector.pid <= 0 || a.netns(collector) != original.second || !a.listener(collector)))
            throw Failure("previous collector process");
        auto freshSource = get(a, source.id, bound, root, true), freshCollector = get(a, collector.id, bound, root, true);
        validate(freshSource, freshCollector, bound);
        if (!freshCollector.scopeEnvironment || epoch(a, freshSource) != original
            || freshCollector.running != collector.running || freshCollector.pid != collector.pid
            || freshCollector.startedAt != collector.startedAt || freshCollector.nativeSha256 != collector.nativeSha256
            || (collector.running && a.netns(freshCollector) != original.second))
            throw Failure("publication epoch drift");
    }
    void reconcile(Adapter &a, const Binding &b, const std::string &root)
    {
        iface(b.scope);
        id(b.sourceId);
        id(b.collectorId);
        auto source = get(a, b.sourceId, b, root), collector = get(a, b.collectorId, b, root);
        validate(source, collector, b);
        auto original = epoch(a, source);
        if (a.netns(collector) != original.second) {
            checked(a, { "restart", b.collectorId });
            collector = get(a, b.collectorId, b, root);
        }
        auto fresh = get(a, b.sourceId, b, root);
        validate(fresh, collector, b);
        if (epoch(a, fresh) != original || a.netns(collector) != original.second)
            throw Failure("namespace drift");
        // Host proc evidence is read only for the already publication-bound collector PID.
        for (int attempt = 0;; ++attempt) {
            if (a.listener(collector))
                break;
            if (attempt == 9)
                throw Failure("collector listener");
            a.pause();
        }
        auto afterProbeSource = get(a, b.sourceId, b, root), afterProbeCollector = get(a, b.collectorId, b, root);
        validate(afterProbeSource, afterProbeCollector, b);
        if (epoch(a, afterProbeSource) != original || a.netns(afterProbeCollector) != original.second
            || afterProbeCollector.pid != collector.pid || afterProbeCollector.startedAt != collector.startedAt)
            throw Failure("listener epoch drift");
        Args rule = { "PREROUTING", "-i",    iface(b.scope), "-d",       "172.29.172.251/32", "-p",   "tcp",
                      "--dport",    "17866", "-j",           "REDIRECT", "--to-ports",        "17866" };
        auto cmd = [&](const char *op) {
            Args v = { "exec", b.sourceId, "iptables", "-t", "nat", op };
            v.insert(v.end(), rule.begin(), rule.end());
            return v;
        };
        const int before = a.run(cmd("-C")).code;
        if (before == 1) {
            if (epoch(a, get(a, b.sourceId, b, root)) != original)
                throw Failure("source epoch");
            checked(a, cmd("-A"));
        } else if (before != 0)
            throw Failure("rule check");
        try {
            checked(a, cmd("-C"));
            auto finalSource = get(a, b.sourceId, b, root), finalCollector = get(a, b.collectorId, b, root);
            validate(finalSource, finalCollector, b);
            if (epoch(a, finalSource) != original || a.netns(finalCollector) != original.second
                || finalCollector.pid != collector.pid || finalCollector.startedAt != collector.startedAt)
                throw Failure("final namespace drift");
        } catch (...) {
            if (before == 1) {
                try {
                    auto observed = get(a, b.sourceId, b, root);
                    if (observed.id == b.sourceId && epoch(a, observed) == original)
                        checked(a, cmd("-D"));
                } catch (...) {
                }
            }
            throw;
        }
    }
}
