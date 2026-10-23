#include "route.hpp"
#include "../../../core/utils/constants/protocolConstants.h"
#include <cassert>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace collector_route;
namespace fs = std::filesystem;
namespace
{
    const std::string sid(64, 'a'), cid(64, 'b');
    const Binding bind { "amnezia-awg2", sid, cid };
    const std::string publishedName = std::string(amnezia::protocols::clientLogs::tunnelContainerName) + "-" + bind.scope;
    const std::string image =
            "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df";
    std::string source(const std::string &epoch = "epoch1")
    {
        return "[{\"Id\":\"" + sid
                + "\",\"Name\":\"/amnezia-awg2\",\"State\":{\"Running\":true,\"Pid\":11,\"StartedAt\":\"" + epoch
                + "\"}}]";
    }
    std::string collector(const std::string &root = "/opt/amnezia/client-logs")
    {
        return "[{\"Id\":\""
                + cid + "\",\"Name\":\"/" + publishedName + "\",\"State\":{\"Running\":true,\"Pid\":12},\"Config\":{\"Image\":\""
                + image + "\",\"Entrypoint\":[\"python\"],\"Cmd\":[\"/data/collector.py\"],\"Labels\":{\"org.amnezia.client-logs.route\":\"amnezia-awg2\"}},\"HostConfig\":{\"NetworkMode\":\"container:"
                + sid + "\"},\"Mounts\":[{\"Destination\":\"/data\",\"Source\":\"" + root + "\",\"RW\":true}]}]";
    }
    void replace(std::string &s, const std::string &a, const std::string &b)
    {
        auto p = s.find(a);
        assert(p != std::string::npos);
        s.replace(p, a.size(), b);
    }
    struct Fake : Adapter
    {
        std::string s = source(), c = collector(), ns = "net:1", cns = "net:1";
        std::vector<Args> calls;
        bool present = true;
        int checks = 0, probeFailures = 0;
        std::function<void(const Args &)> hook;
        Result run(const Args &a) override
        {
            calls.push_back(a);
            if (hook)
                hook(a);
            if (a[0] == "ps") return { 0, publishedName + "\n" };
            if (a[0] == "inspect")
                return { 0, a[1] == sid || a[1] == bind.scope ? s : c };
            if (a[0] == "restart") {
                assert(a[1] == cid);
                cns = ns;
                return { 0, "" };
            }
            if (a.size() > 2 && a[2] == "python")
                return { probeFailures-- > 0 ? 1 : 0, "" };
            if (a.size() > 5 && a[5] == "-C") {
                ++checks;
                return { present ? 0 : 1, "" };
            }
            if (a.size() > 5 && a[5] == "-A") {
                present = true;
                return { 0, "" };
            }
            if (a.size() > 5 && a[5] == "-D") {
                present = false;
                return { 0, "" };
            }
            throw Failure("unplanned fake command");
        }
        std::string netns(const Container &v) override
        {
            return v.id == sid ? ns : cns;
        }
        bool listener(const Container &) override
        {
            return probeFailures-- > 0 ? false : true;
        }
        void pause() override
        {
        }
        bool has(const std::string &v) const
        {
            for (auto &a : calls)
                for (auto &s : a)
                    if (s == v)
                        return true;
            return false;
        }
    };
    void refuses(const std::function<void()> &f)
    {
        bool rejected = false;
        try {
            f();
        } catch (const std::exception &) {
            rejected = true;
        }
        assert(rejected);
    }
    struct Temp
    {
        fs::path root;
        Temp()
        {
            char x[] = "/tmp/amnezia-route-unit-XXXXXX";
            auto *p = mkdtemp(x);
            assert(p);
            root = p;
            assert(chmod(root.c_str(), 0700) == 0);
        }
        ~Temp()
        {
            fs::remove_all(root);
        }
        void put(const std::string &n, const std::string &v, int mode = 0600)
        {
            std::ofstream(root / n) << v;
            chmod((root / n).c_str(), mode);
        }
    };
}
int main()
{
    {
        Fake f;
        replace(f.c, "\"Labels\":", "\"Env\":[\"AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2\"],\"Labels\":");
        publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs");
        for (const auto &call : f.calls) assert(call[0] == "inspect" || call[0] == "ps");
        const auto valid = f.c;
        const std::string legacyLabels = "\"Labels\":{\"org.amnezia.client-logs.route\":\"amnezia-awg2\"}";
        for (const auto &labelField : Args { "\"Labels\":null", "\"Unrelated\":null" }) {
            f.c = valid;
            replace(f.c, legacyLabels, labelField);
            publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs");
        }
        f.c = valid;

        replace(f.c, "\"org.amnezia.client-logs.route\":\"amnezia-awg2\"", "");
        publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs");
        replace(f.c, "\"Running\":true", "\"Running\":false");
        replace(f.c, "\"Pid\":12", "\"Pid\":0");
        publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs");
        f.c = valid;

        for (const auto &change : std::vector<std::pair<std::string, std::string>> {
            { image, "unowned:image" }, { "container:" + sid, "container:other" },
            { "\"RW\":true", "\"RW\":false" }, { "/data/collector.py", "/data/other.py" },
            { "\"org.amnezia.client-logs.route\":\"amnezia-awg2\"", "\"org.amnezia.client-logs.route\":\"other\"" }
        }) {
            f.c = valid;
            replace(f.c, change.first, change.second);
            refuses([&] { publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs"); });
        }
        f.c = valid;
        replace(f.c, "\"Env\":[\"AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2\"]", "\"Env\":[]");
        refuses([&] { publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs"); });
        f.c = valid;
        replace(f.c, "\"Env\":[\"AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2\"]", "\"Env\":[\"AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2\",\"AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2\"]");
        refuses([&] { publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs"); });
        f.c = valid;
        f.hook = [&](const Args &call) { if (call[0] == "inspect" && call[1] == sid) f.s = source("changed"); };
        refuses([&] { publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs"); });
        f.hook = {};
        f.s = source();
        f.hook = [&](const Args &call) { if (call[0] == "inspect" && call[1] == cid) replace(f.c, "\"Pid\":12", "\"Pid\":13"); };
        refuses([&] { publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs"); });
        f.hook = {};
        f.c = valid;
        replace(f.c, "\"Entrypoint\":[\"python\"]", "\"Entrypoint\":[\"/data/amnezia-client-logs-collector\"]");
        replace(f.c, "\"Cmd\":[\"/data/collector.py\"]", "\"Cmd\":[\"--root\",\"/data\"]");
        replace(f.c, "\"Labels\":{", "\"Labels\":{\"org.amnezia.client-logs.native-sha256\":\"" + std::string(64, 'c') + "\",");
        publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs");
        replace(f.c, "\"Running\":true", "\"Running\":false");
        refuses([&] { publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs"); });
        f.c = valid;
        f.probeFailures = 1;
        refuses([&] { publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs"); });
        replace(f.c, "AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2", "AMNEZIA_CLIENT_LOGS_SCOPE=other");
        refuses([&] { publicationPreflight(f, bind.scope, "/opt/amnezia/client-logs"); });
    }

    int n = 0;
    auto test = [&](auto f) {
        f();
        ++n;
    };
    test([] {
        for (const auto &scope : Args { "amnezia-awg2", "amnezia-awg", "amnezia-wireguard", "amnezia-openvpn" })
            assert(collectorName(scope) == std::string(amnezia::protocols::clientLogs::tunnelContainerName) + "-" + scope);
        Temp t;
        Fake f;
        f.c = collector(t.root.string());
        f.hook = [](const Args &call) {
            if (call[0] == "inspect" && call[1] != sid && call[1] != cid && call[1] != bind.scope)
                assert(call[1] == publishedName);
        };
        cli(f, { bind.scope, "--bind" }, t.root.string(), geteuid());
        assert(f.has(publishedName));
        std::ifstream stored(t.root / "route-amnezia-awg2.json");
        const std::string bytes((std::istreambuf_iterator<char>(stored)), std::istreambuf_iterator<char>());
        assert(binding(bytes).collectorId == cid);
    });
    test([] {
        Fake f;
        replace(f.c, publishedName, "amnezia-client-logs-" + bind.scope);
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("-A") && !f.has("restart"));
    });
    test([] { assert(binding(canonical(bind)).sourceId == sid); });
    test([] {
        for (auto s :
             std::vector<std::string> { "{}", "[]", "null", "{\"schema\":true}", "{} trailing", std::string(4097, 'x') })
            refuses([&] { binding(s); });
    });
    test([] {
        auto s = canonical(bind);
        replace(s, "\"schema\": 1", "\"schema\": true");
        refuses([&] { binding(s); });
    });
    test([] {
        auto s = canonical(bind);
        replace(s, "\"schema\": 1", "\"schema\": 1.0");
        refuses([&] { binding(s); });
    });
    test([] {
        auto s = canonical(bind);
        replace(s, "amnezia-awg2", "x; reboot");
        refuses([&] { binding(s); });
    });
    test([] {
        auto s = canonical(bind);
        s.insert(s.size() - 1, ",\"extra\":1");
        refuses([&] { binding(s); });
    });
    test([] {
        Fake f;
        reconcile(f, bind);
        assert(!f.has("restart") && !f.has("-A") && !f.has("-D") && !f.has("python"));
    });
    test([] {
        Fake f;
        f.cns = "old";
        f.present = false;
        reconcile(f, bind);
        assert(f.has("restart") && f.has("-A") && !f.has("-D"));
        for (auto &a : f.calls)
            if (a[0] == "restart")
                assert(a[1] == cid);
    });
    test([] {
        Fake f;
        replace(f.c, "\"amnezia-awg2\"", "\"foreign\"");
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("restart") && !f.has("exec"));
    });
    test([] {
        Fake f;
        replace(f.c, "container:" + sid, "container:" + cid);
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("restart") && !f.has("exec"));
    });
    test([] {
        Fake f;
        replace(f.c, "\"RW\":true", "\"RW\":1");
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("restart"));
    });
    test([] {
        Fake f;
        replace(f.c, "/opt/amnezia/client-logs", "/foreign");
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("restart"));
    });
    test([] {
        Fake f;
        replace(f.s, sid, std::string(64, 'c'));
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("exec"));
    });
    test([] {
        Fake f;
        replace(f.s, "\"Pid\":11", "\"Pid\":true");
        refuses([&] { reconcile(f, bind); });
    });
    test([] {
        Fake f;
        f.probeFailures = 10;
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("-C") && !f.has("-A"));
    });
    test([] {
        Fake f;
        f.present = false;
        f.hook = [&](const Args &a) {
            if (a.size() > 5 && a[5] == "-A")
                f.ns = "new";
        };
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("-D"));
    });
    test([] {
        Fake f;
        f.present = false;
        f.hook = [&](const Args &a) {
            if (a.size() > 5 && a[5] == "-A")
                replace(f.c, "\"RW\":true", "\"RW\":false");
        };
        refuses([&] { reconcile(f, bind); });
        assert(f.has("-A") && f.has("-D"));
    });
    test([] {
        Temp t;
        Fake f;
        f.c = collector(t.root.string());
        cli(f, { bind.scope, "--bind" }, t.root.string(), geteuid());
        assert(fs::exists(t.root / "route-amnezia-awg2.json"));
        std::ifstream file(t.root / "route-amnezia-awg2.json");
        std::string body((std::istreambuf_iterator<char>(file)), { });
        assert(binding(body).collectorId == cid);
    });
    test([] {
        Temp t;
        t.put("route-amnezia-awg2.json", canonical(bind));
        Fake f;
        f.c = collector(t.root.string());
        cli(f, { bind.scope }, t.root.string(), geteuid());
        assert(!f.has("restart"));
    });
    test([] {
        Temp t;
        t.put("foreign", canonical(bind));
        fs::create_symlink(t.root / "foreign", t.root / "route-amnezia-awg2.json");
        Fake f;
        refuses([&] { cli(f, { bind.scope }, t.root.string(), geteuid()); });
        assert(f.calls.empty());
    });
    test([] {
        Temp t;
        t.put("route-amnezia-awg2.json", canonical(bind), 0644);
        Fake f;
        refuses([&] { cli(f, { bind.scope }, t.root.string(), geteuid()); });
        assert(f.calls.empty());
    });
    test([] {
        Temp t;
        t.put("route-amnezia-awg2.tmp", "foreign");
        Fake f;
        f.c = collector(t.root.string());
        refuses([&] { cli(f, { bind.scope, "--bind" }, t.root.string(), geteuid()); });
        std::ifstream file(t.root / "route-amnezia-awg2.tmp");
        std::string x;
        file >> x;
        assert(x == "foreign");
    });
    test([] {
        Temp t;
        t.put("route-amnezia-awg2.lock", "");
        int fd = open((t.root / "route-amnezia-awg2.lock").c_str(), O_RDWR);
        assert(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
        Fake f;
        refuses([&] { cli(f, { bind.scope }, t.root.string(), geteuid()); });
        assert(f.calls.empty());
        close(fd);
    });
    test([] {
        Temp t;
        fs::create_directories(t.root / "11/ns");
        fs::create_symlink("net:[fixture-owned]", t.root / "11/ns/net");
        PosixAdapter a(t.root.string());
        Container c;
        c.running = true;
        c.pid = 11;
        assert(a.netns(c) == "net:[fixture-owned]");
    });
    test([] {
        Temp t;
        fs::create_directories(t.root / "12/fd");
        fs::create_directories(t.root / "12/net");
        std::string command = "python";
        command += '\0';
        command += "/data/collector.py";
        command += '\0';
        std::ofstream(t.root / "12/cmdline", std::ios::binary).write(command.data(), command.size());
        fs::create_symlink("socket:[91]", t.root / "12/fd/4");
        std::ofstream(t.root / "12/net/tcp") << "header\n0: 00000000:45CA 00000000:0000 0A 0 0 0 0 0 91\n";
        PosixAdapter a(t.root.string());
        Container c;
        c.running = true;
        c.pid = 12;
        assert(a.listener(c));
        std::ofstream(t.root / "12/net/tcp") << "header\n0: 0100007F:45CA 0 0A 0 0 0 0 0 91\n";
        assert(!a.listener(c));
    });
    test([] {
        auto x = canonical(bind);
        x.insert(x.size() - 1, ",\"schema\":true");
        refuses([&] { binding(x); });
    });
    test([] {
        std::string x = canonical(bind);
        x.insert(1, std::string(1, char(0xff)));
        refuses([&] { binding(x); });
    });
    test([] {
        Fake f;
        f.present = false;
        int inspected = 0;
        f.hook = [&](const Args &a) {
            if (a[0] == "inspect" && a[1] == cid && ++inspected == 2)
                replace(f.c, "\"Pid\":12", "\"Pid\":13");
        };
        refuses([&] { reconcile(f, bind); });
        assert(!f.has("-A"));
    });
    test([] {
        Temp t;
        Fake f;
        chmod(t.root.c_str(), 0755);
        refuses([&] { cli(f, { bind.scope }, t.root.string(), geteuid()); });
        assert(f.calls.empty());
    });
    test([] {
        Temp t;
        t.put("route-amnezia-awg2.json", std::string(4097, 'x'));
        Fake f;
        refuses([&] { cli(f, { bind.scope }, t.root.string(), geteuid()); });
        assert(f.calls.empty());
    });
    test([] {
        Temp t;
        fs::create_directories(t.root / "12/fd");
        fs::create_directories(t.root / "12/net");
        std::string cmd = "python";
        cmd += '\0';
        cmd += "/foreign/data/collector.py.fake";
        cmd += '\0';
        std::ofstream(t.root / "12/cmdline", std::ios::binary).write(cmd.data(), cmd.size());
        PosixAdapter a(t.root.string());
        Container c;
        c.running = true;
        c.pid = 12;
        assert(!a.listener(c));
    });
    test([] {
        auto x = canonical(bind);
        replace(x, "schema", "schema\\u0000alias");
        refuses([&] { binding(x); });
    });
    test([] {
        Fake f;
        f.present = false;
        int inspected = 0;
        f.hook = [&](const Args &a) {
            if (a[0] == "inspect" && a[1] == cid && ++inspected == 3)
                replace(f.c, "\"Pid\":12", "\"Pid\":13");
        };
        refuses([&] { reconcile(f, bind); });
        assert(f.has("-A") && f.has("-D"));
    });
    test([] {
        Fake f;
        f.present = false;
        int inspected = 0;
        replace(f.c, "\"Pid\":12", "\"Pid\":12,\"StartedAt\":\"collectorEpoch1\"");
        f.hook = [&](const Args &a) {
            if (a[0] == "inspect" && a[1] == cid && ++inspected == 3)
                replace(f.c, "collectorEpoch1", "collectorEpoch2");
        };
        refuses([&] { reconcile(f, bind); });
        assert(f.has("-A") && f.has("-D"));
    });
    test([] {
        Fake f;
        f.present = false;
        f.hook = [&](const Args &a) {
            if (a.size() > 5 && a[5] == "-A") {
                f.present = true;
                throw Failure("uncertain Docker add acknowledgement");
            }
        };
        refuses([&] { reconcile(f, bind); });
        assert(f.has("-A") && !f.has("-D"));
    });
    test([] {
        Temp t;
        Binding other = bind;
        other.scope = "amnezia-wireguard";
        t.put("route-amnezia-awg2.json", canonical(other));
        Fake f;
        refuses([&] { cli(f, { bind.scope }, t.root.string(), geteuid()); });
        assert(f.calls.empty());
    });
    test([] {
        Temp t;
        assert(mkfifo((t.root / "route-amnezia-awg2.json").c_str(), 0600) == 0);
        auto child = fork();
        assert(child >= 0);
        if (child == 0) {
            alarm(2);
            Fake f;
            try {
                cli(f, { bind.scope }, t.root.string(), geteuid());
            } catch (const Failure &) {
                _exit(f.calls.empty() ? 0 : 2);
            }
            _exit(3);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    });
    test([] {
        auto document = collector();
        replace(document, "\"Entrypoint\":[\"python\"]", "\"Entrypoint\":[\"other\"]");
        refuses([&] { inspectDocument(document, bind.scope, "/opt/amnezia/client-logs"); });
    });
    test([] {
        auto document = collector();
        replace(document, "\"Entrypoint\":[\"python\"],\"Cmd\":[\"/data/collector.py\"]",
                "\"Entrypoint\":[\"/data/amnezia-client-logs-collector\"],\"Cmd\":[\"--root\",\"/data\"]");
        replace(document, "\"Labels\":{", "\"Labels\":{\"org.amnezia.client-logs.native-sha256\":\"" + std::string(64, 'c') + "\",");
        auto native = inspectDocument(document, bind.scope, "/opt/amnezia/client-logs");
        assert(native.nativeProcess && native.nativeSha256 == std::string(64, 'c'));
        validate(inspectDocument(source(), bind.scope, "/opt/amnezia/client-logs"), native, bind);
        replace(document, std::string(64, 'c'), "invalid");
        refuses([&] { inspectDocument(document, bind.scope, "/opt/amnezia/client-logs"); });
    });
    test([] {
        Temp t;
        fs::create_directories(t.root / "12/fd");
        fs::create_directories(t.root / "12/net");
        const std::string command = std::string("/data/amnezia-client-logs-collector") + '\0' + "--root" + '\0' + "/data" + '\0';
        std::ofstream(t.root / "12/cmdline", std::ios::binary).write(command.data(), command.size());
        std::ofstream(t.root / "12/exe", std::ios::binary) << "abc";
        fs::create_symlink("socket:[91]", t.root / "12/fd/4");
        std::ofstream(t.root / "12/net/tcp") << "header\n0: 00000000:45CA 0 0A 0 0 0 0 0 91\n";
        PosixAdapter a(t.root.string());
        Container c;
        c.running = true; c.pid = 12; c.nativeProcess = true;
        c.nativeSha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert(a.listener(c));
        std::ofstream(t.root / "12/exe", std::ios::binary) << "abd";
        assert(!a.listener(c));
        std::ofstream(t.root / "12/exe", std::ios::binary) << "abc";
        std::ofstream(t.root / "12/cmdline", std::ios::binary) << "/data/amnezia-client-logs-collector";
        assert(!a.listener(c));
    });
    std::cout << "ownedFixtureTests=" << n << " passed=true liveDockerCommands=0\n";
}
