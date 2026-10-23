#include "automatic_plan.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
using namespace amnezia::awgMigration;
namespace fs = std::filesystem;
namespace
{
    void check(bool b)
    {
        if (!b)
            throw std::runtime_error("unit check failed");
    }
    void error(const std::function<void()> &f, const std::string &code)
    {
        try {
            f();
        } catch (const PlannerError &e) {
            check(e.code() == code);
            return;
        }
        throw std::runtime_error("expected refusal");
    }
    struct Temp
    {
        fs::path root;
        Temp()
        {
            char x[] = "/tmp/awg-plan-unit-XXXXXX";
            auto *p = mkdtemp(x);
            check(p);
            root = p;
        }
        ~Temp()
        {
            fs::remove_all(root);
        }
        void journal(const std::string &generation, const std::string &body)
        {
            auto d = root / "amnezia-awg2" / generation;
            fs::create_directories(d);
            std::ofstream(d / "transaction.json") << body;
        }
    };
    const char *sourceDigest = "41cf6794ba4200b839c53531555f0f3998df4cbb01a4d5cb0b94e3ca5e23947d";
    std::string ready(const std::string &host = "vpn.example", const std::string &image = "pinned", unsigned port = 51822)
    {
        return "{\"phase\":\"ready\",\"request\":{\"host\":\"" + host + "\",\"image\":\"" + image + "\",\"port\":"
                + std::to_string(port) + ",\"generation\":1},\"sourceDigest\":\"" + sourceDigest + "\"}";
    }
    std::string imageJson(bool descriptor = false)
    {
        std::string manifest = std::string(TrustedImage).substr(std::string(TrustedImage).find('@') + 1);
        return "[{\"Id\":\"" + (descriptor ? manifest : TrustedImageId) + "\",\"Descriptor\":{\"digest\":\"" + manifest
                + "\"},\"RepoDigests\":[\"" + TrustedImage + "\"],\"Os\":\"linux\",\"Architecture\":\"amd64\"}]";
    }
    struct Fake : ProcessRunner
    {
        std::vector<ProcessArgs> calls;
        std::string host = "{\"OSType\":\"linux\",\"Architecture\":\"x86_64\"}", image = imageJson(),
                    version = TrustedReportedVersion,
                    hashed = std::string(TrustedBinarySha256) + "  /usr/bin/amneziawg-go", tools = "ready";
        int inspection = 0;
        bool cacheMissing = false;
        std::function<void(const ProcessArgs &)> hook;
        std::string run(const ProcessArgs &a) override
        {
            calls.push_back(a);
            if (hook)
                hook(a);
            if (a.size() > 1 && a[1] == "info")
                return host;
            if (a.size() > 2 && a[1] == "image") {
                if (cacheMissing && ++inspection == 1)
                    throw ProcessFailure(ProcessFailureKind::Exit);
                return image;
            }
            if (a.size() > 1 && a[1] == "pull")
                return {};
            if (std::find(a.begin(), a.end(), "--version") != a.end())
                return version;
            if (std::find(a.begin(), a.end(), "sha256sum") != a.end())
                return hashed;
            if (std::find(a.begin(), a.end(), "sh") != a.end())
                return tools;
            throw ProcessFailure(ProcessFailureKind::Other);
        }
    };
    struct Inventory : ProcessRunner
    {
        std::vector<ProcessArgs> calls;
        std::string ss = "UNCONN 0 0 0.0.0.0:51821 0.0.0.0:*\nudp UNCONN 0 0 [::]:51822 [::]:*\n",
                    ids = "aaaaaaaaaaaa\n",
                    json = "[{\"NetworkSettings\":{\"Ports\":{\"51823/udp\":[{\"HostPort\":\"51823\"}],\"51824/"
                           "tcp\":[{\"HostPort\":\"51824\"}]}}}]";
        std::string run(const ProcessArgs &a) override
        {
            calls.push_back(a);
            if (a[0] == "ss")
                return ss;
            if (a[1] == "ps")
                return ids;
            return json;
        }
    };
    struct Probe : PortProbe
    {
        int opened = 0, closed = 0, bound = 0, v6 = 0;
        int failAt = 0;
        struct Lease : PortLease
        {
            Probe &p;
            explicit Lease(Probe &p) : p(p)
            {
            }
            ~Lease()
            {
                ++p.closed;
            }
            void ipv6Only() override
            {
                ++p.v6;
            }
            void bind(const std::string &a, unsigned port) override
            {
                check((a == "0.0.0.0" || a == "::") && port == 51822);
                if (++p.bound == p.failAt)
                    throw std::runtime_error("private bind error");
            }
        };
        std::unique_ptr<PortLease> open(UdpFamily) override
        {
            ++opened;
            return std::make_unique<Lease>(*this);
        }
    };
}
int main()
{
    int n = 0;
    auto test = [&](auto f) {
        f();
        ++n;
    };
    test([] {
        Inventory r;
        auto p = occupiedUdpPorts(r);
        check(p == UdpPorts({ 51821, 51822, 51823 }));
        check(selectUdpPort(p, 51824) == 51825);
    });
    test([] {
        Inventory r;
        r.ids = "";
        auto p = occupiedUdpPorts(r);
        check(r.calls.size() == 2 && p.size() == 2);
    });
    test([] {
        Inventory r;
        r.ss = "malformed\n";
        error([&] { occupiedUdpPorts(r); }, "udp_inventory_unavailable");
    });
    test([] {
        Inventory r;
        r.ids = "--privileged";
        error([&] { occupiedUdpPorts(r); }, "udp_inventory_unavailable");
        check(r.calls.size() == 2);
    });
    test([] {
        Inventory r;
        r.json = "[{\"NetworkSettings\":{\"Ports\":{\"51823/udp\":[{\"HostPort\":true}]}}}]";
        error([&] { occupiedUdpPorts(r); }, "udp_inventory_unavailable");
    });
    test([] {
        UdpPorts p;
        for (unsigned x = 51821; x <= 65535; ++x)
            p.insert(x);
        error([&] { selectUdpPort(p, 51820); }, "migration_udp_port_unavailable");
    });
    test([] {
        Temp t;
        auto p = automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, { 51821 });
        check(p.port == 51822 && p.generation == 1);
    });
    test([] {
        Temp t;
        for (auto host : { "2001:db8::1", "", "bad name", "x;whoami" })
            error([&] { automaticPlan(t.root, "amnezia-awg2", host, "pinned", "source", 51820, {}); },
                  "migration_endpoint_unsupported");
    });
    test([] {
        Temp t;
        t.journal("1", ready());
        auto p = automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, { 51822 });
        check(p.port == 51822 && p.generation == 1);
    });
    test([] {
        for (auto name : { "01", "0", "9007199254740992" }) {
            Temp t;
            t.journal(name, ready());
            error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}); },
                  "migration_journal_conflict");
        }
        for (auto value : { "true", "0", "1.0", "\"1\"", "9007199254740992" }) {
            Temp t;
            auto body = ready();
            const auto key = body.find("\"generation\":1");
            body.replace(key, std::string("\"generation\":1").size(), std::string("\"generation\":") + value);
            t.journal("1", body);
            error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}); },
                  "migration_journal_conflict");
        }
    });
    test([] {
        Temp t;
        t.journal("2", ready());
        error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}); },
              "migration_journal_conflict");
    });
    test([] {
        Temp t;
        t.journal("1", ready());
        error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "changed", 51820, {}); },
              "migration_ready_drift");
    });
    test([] {
        Temp t;
        t.journal("1", "{\"phase\":\"creating\"}");
        check(automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}).generation == 1);
    });
    test([] {
        Temp t;
        t.journal("2", "{\"phase\":\"creating\"}");
        error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}); },
              "migration_journal_conflict");
    });
    test([] {
        Temp t;
        t.journal("1", ready("changed"));
        t.journal("2", ready());
        error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}); },
              "migration_journal_conflict");
    });
    test([] {
        Temp t;
        fs::create_directories(t.root / "amnezia-awg2/1");
        error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}); },
              "migration_journal_conflict");
    });
    test([] {
        Temp t;
        t.journal("1", ready());
        fs::create_directory_symlink(t.root / "amnezia-awg2/1", t.root / "amnezia-awg2/2");
        error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}); },
              "migration_journal_conflict");
    });
    test([] {
        Temp t;
        fs::create_directories(t.root / "amnezia-awg2/1");
        check(mkfifo((t.root / "amnezia-awg2/1/transaction.json").c_str(), 0600) == 0);
        error([&] { automaticPlan(t.root, "amnezia-awg2", "vpn.example", "pinned", "source", 51820, {}); },
              "migration_journal_conflict");
    });
    test([] {
        Probe p;
        verifyAutomaticPort(51822, p);
        check(p.opened == 2 && p.closed == 2 && p.bound == 2 && p.v6 == 1);
    });
    test([] {
        Probe p;
        p.failAt = 2;
        error([&] { verifyAutomaticPort(51822, p); }, "migration_udp_port_unavailable");
        check(p.opened == 2 && p.closed == 2);
    });
    test([] {
        Fake r;
        check(resolveTrustedImage(r) == TrustedImage);
        for (auto &a : r.calls)
            if (a[1] == "run") {
                auto prefix = trustedSandboxArgs();
                check(a.size() > prefix.size() && std::equal(prefix.begin(), prefix.end(), a.begin()));
                check(std::find(a.begin(), a.end(), "-v") == a.end()
                      && std::find(a.begin(), a.end(), "--device") == a.end());
            }
    });
    test([] {
        Fake r;
        r.image = imageJson(true);
        check(resolveTrustedImage(r) == TrustedImage);
    });
    test([] {
        Fake r;
        r.host = "{\"OSType\":\"linux\",\"Architecture\":\"aarch64\"}";
        error([&] { resolveTrustedImage(r); }, "unsupported_server_architecture");
        check(r.calls.size() == 1);
    });
    test([] {
        Fake r;
        r.cacheMissing = true;
        check(resolveTrustedImage(r) == TrustedImage);
        check(std::any_of(r.calls.begin(), r.calls.end(), [](auto &a) { return a[1] == "pull"; }));
    });
    test([] {
        for (auto kind : { ProcessFailureKind::Exit, ProcessFailureKind::Timeout, ProcessFailureKind::Os }) {
            Fake r;
            r.cacheMissing = true;
            r.hook = [&](auto &a) {
                if (a[1] == "pull")
                    throw ProcessFailure(kind);
            };
            error([&] { resolveTrustedImage(r); }, "image_fetch_unavailable");
        }
    });
    test([] {
        Fake r;
        r.cacheMissing = true;
        r.hook = [](auto &a) {
            if (a[1] == "pull")
                throw ProcessFailure(ProcessFailureKind::Other);
        };
        error([&] { resolveTrustedImage(r); }, "trusted_image_unavailable");
    });
    test([] {
        Fake r;
        r.hook = [](auto &a) {
            if (a[1] == "run")
                throw ProcessFailure(ProcessFailureKind::Timeout);
        };
        error([&] { resolveTrustedImage(r); }, "trusted_image_unavailable");
    });
    test([] {
        Fake r;
        r.version = "amneziawg-go 3.1";
        error([&] { resolveTrustedImage(r); }, "trusted_image_unavailable");
    });
    test([] {
        Fake r;
        r.hashed = "wrong";
        error([&] { resolveTrustedImage(r); }, "trusted_image_unavailable");
    });
    test([] {
        Fake r;
        r.tools = "ready\n";
        error([&] { resolveTrustedImage(r); }, "trusted_image_unavailable");
    });
    test([] {
        auto j = plannerJson("{\"RepoDigests\":\"prefix arbitrary text\",\"Id\":\"x\"}");
        check(!trustedImageIdentity(j.get()));
    });
    test([] {
        for (const auto *raw : {"{\"phase\":\"creating\",\"phase\":\"ready\"}",
                               "{\"phase\":1,\"ph\\u0061se\":2}",
                               "{\"request\":{\"port\":60000,\"port\":51822}}",
                               "{\"x\":NaN}", "{\"x\":Infinity}", "{\"x\":-Infinity}",
                               "{\"x\":1}{}", "{\"x\":\"\\u0000\"}"})
            error([&] { plannerJson(raw); }, "invalid_json");
        std::string invalidUtf8 = "{\"ignored\":\"";
        invalidUtf8.push_back(static_cast<char>(0xff));
        invalidUtf8 += "\"}";
        error([&] { plannerJson(invalidUtf8); }, "invalid_json");
        const std::string deep = std::string(40, '[') + "0" + std::string(40, ']');
        error([&] { plannerJson(deep); }, "invalid_json");
        error([&] { plannerJson("{\"x\":1}", 6); }, "invalid_json");
        check(plannerJson(" {\"first\":{\"x\":1},\"second\":{\"x\":2},\"unicode\":\"\\u0430\"} \n") != nullptr);
    });
    test([] {
        auto literal = plannerJson(R"({"opaque":"literal\\u0000","key\\u0000":"value"})");
        auto *value = json_object_object_get(literal.get(), "opaque");
        check(value && std::string(json_object_get_string(value)) == "literal\\u0000");
        check(plannerJson(R"({"opaque":"\u005cu0000","key\u005cu0000":"value"})") != nullptr);
        for (const auto *raw : {R"({"key\u0000":"value"})", R"({"key":"value\u0000"})"})
            error([&] { plannerJson(raw); }, "invalid_json");
        std::string rawNul = "{\"key\":\"value";
        rawNul.push_back('\0');
        rawNul += "\"}";
        error([&] { plannerJson(rawNul); }, "invalid_json");
    });
    // Generated from a complete local Python chr.isspace scan (29 codepoints).
    for (const auto &space : std::vector<std::string>{
            "\x09",
            "\x0a",
            "\x0b",
            "\x0c",
            "\x0d",
            "\x1c",
            "\x1d",
            "\x1e",
            "\x1f",
            "\x20",
            "\xc2\x85",
            "\xc2\xa0",
            "\xe1\x9a\x80",
            "\xe2\x80\x80",
            "\xe2\x80\x81",
            "\xe2\x80\x82",
            "\xe2\x80\x83",
            "\xe2\x80\x84",
            "\xe2\x80\x85",
            "\xe2\x80\x86",
            "\xe2\x80\x87",
            "\xe2\x80\x88",
            "\xe2\x80\x89",
            "\xe2\x80\x8a",
            "\xe2\x80\xa8",
            "\xe2\x80\xa9",
            "\xe2\x80\xaf",
            "\xe2\x81\x9f",
            "\xe3\x80\x80"}) {
        test([&] {
            Fake hash, version, tools;
            hash.hashed = space + hash.hashed + space;
            version.version = space + version.version + space;
            tools.tools = space + tools.tools + space;
            check(resolveTrustedImage(hash) == TrustedImage);
            check(resolveTrustedImage(version) == TrustedImage);
            // The tool readiness token intentionally has no strip operation.
            error([&] { resolveTrustedImage(tools); }, "trusted_image_unavailable");
        });
    }
    for (const auto &invalid : std::vector<std::string>{
            "\xff", "\x80", "\xc0\xaf", "\xe2\x82", "\xed\xa0\x80", "\xf4\x90\x80\x80"}) {
        test([&] {
            for (bool suffix : {false, true}) {
                Fake hash, version, tools;
                hash.hashed = suffix ? hash.hashed + invalid : invalid + hash.hashed;
                version.version = suffix ? version.version + invalid : invalid + version.version;
                tools.tools = suffix ? tools.tools + invalid : invalid + tools.tools;
                error([&] { resolveTrustedImage(hash); }, "trusted_image_unavailable");
                error([&] { resolveTrustedImage(version); }, "trusted_image_unavailable");
                error([&] { resolveTrustedImage(tools); }, "trusted_image_unavailable");
            }
        });
    }
    test([] {
        Fake hash, version;
        hash.hashed = "\xe3\x80\x80\xc2\xa0";
        version.version = hash.hashed;
        error([&] { resolveTrustedImage(hash); }, "trusted_image_unavailable");
        error([&] { resolveTrustedImage(version); }, "trusted_image_unavailable");
    });
    test([] {
        Fake hash, version;
        hash.hashed = std::string("\xe2\x80\x8b") + hash.hashed;
        version.version = std::string("\xe2\x80\x8b") + version.version;
        error([&] { resolveTrustedImage(hash); }, "trusted_image_unavailable");
        error([&] { resolveTrustedImage(version); }, "trusted_image_unavailable");
    });
    std::cout << "plannerCases=" << n << " passed=true liveProcesses=0 udpBindings=0\n";
}
