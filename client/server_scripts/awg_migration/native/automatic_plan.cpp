#include "automatic_plan.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <climits>
#include <fcntl.h>
#include <iomanip>
#include <openssl/evp.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
namespace amnezia::awgMigration
{
    namespace
    {
        json_object *member(json_object *p, const char *k, json_type type)
        {
            json_object *v = nullptr;
            if (!p || json_object_get_type(p) != json_type_object || !json_object_object_get_ex(p, k, &v) || !v
                || json_object_get_type(v) != type)
                throw PlannerError("migration_journal_conflict");
            return v;
        }
        std::string text(json_object *p, const char *k)
        {
            auto *v = member(p, k, json_type_string);
            return { json_object_get_string(v), std::size_t(json_object_get_string_len(v)) };
        }
        unsigned number(std::string_view s)
        {
            unsigned v {};
            auto result = std::from_chars(s.data(), s.data() + s.size(), v);
            if (s.empty() || result.ec != std::errc {} || result.ptr != s.data() + s.size() || v > 65535)
                throw PlannerError("udp_inventory_unavailable");
            return v;
        }
        std::vector<std::string> words(const std::string &s)
        {
            std::istringstream stream(s);
            std::vector<std::string> v;
            std::string x;
            while (stream >> x)
                v.push_back(x);
            return v;
        }
        std::string output(ProcessRunner &r, const ProcessArgs &a)
        {
            auto s = r.run(a);
            const bool ascii = a[0] == "ss" || (a.size() > 1 && a[1] == "ps");
            if (ascii && !std::all_of(s.begin(), s.end(), [](unsigned char c) {
                    return (c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t';
                }))
                throw PlannerError("udp_inventory_unavailable");
            if (s.size() > 1024 * 1024)
                throw PlannerError("udp_inventory_unavailable");
            return s;
        }
        std::string hash(std::string_view raw)
        {
            std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
            unsigned count = 0;
            if (EVP_Digest(raw.data(), raw.size(), digest.data(), &count, EVP_sha256(), nullptr) != 1 || count != 32)
                throw PlannerError("migration_journal_conflict");
            std::ostringstream s;
            s << std::hex << std::setfill('0');
            for (unsigned i = 0; i < count; ++i)
                s << std::setw(2) << unsigned(digest[i]);
            return s.str();
        }
        bool sameJournal(const struct stat &a, const struct stat &b)
        {
            return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode
                && a.st_size == b.st_size && a.st_mtim.tv_sec == b.st_mtim.tv_sec
                && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec && a.st_ctim.tv_sec == b.st_ctim.tv_sec
                && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
        }
        std::string readJournal(const std::filesystem::path &p)
        {
            struct stat beforePath {};
            if (lstat(p.c_str(), &beforePath) || !S_ISREG(beforePath.st_mode)
                || beforePath.st_size > 1024 * 1024)
                throw PlannerError("migration_journal_conflict");
            int fd = open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (fd < 0)
                throw PlannerError("migration_journal_conflict");
            struct Close
            {
                int n;
                ~Close()
                {
                    close(n);
                }
            } guard { fd };
            struct stat before {};
            if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size > 1024 * 1024
                || !sameJournal(beforePath, before))
                throw PlannerError("migration_journal_conflict");
            std::string s;
            char buffer[8192];
            for (;;) {
                auto n = read(fd, buffer, sizeof buffer);
                if (n < 0 && errno == EINTR)
                    continue;
                if (n < 0)
                    throw PlannerError("migration_journal_conflict");
                if (!n)
                    break;
                s.append(buffer, std::size_t(n));
                if (s.size() > 1024 * 1024)
                    throw PlannerError("migration_journal_conflict");
            }
            struct stat after {}, afterPath {};
            if (fstat(fd, &after) || lstat(p.c_str(), &afterPath)
                || !sameJournal(before, after) || !sameJournal(after, afterPath)
                || after.st_size < 0 || static_cast<std::uintmax_t>(after.st_size) != s.size())
                throw PlannerError("migration_journal_conflict");
            return s;
        }
        std::uint64_t generation(std::string_view s)
        {
            std::uint64_t v {};
            auto result = std::from_chars(s.data(), s.data() + s.size(), v);
            if (result.ec != std::errc {} || result.ptr != s.data() + s.size() || v < 1
                || v > 9007199254740991ULL || std::to_string(v) != s)
                throw PlannerError("migration_journal_conflict");
            return v;
        }
        void endpoint(const std::string &host)
        {
            if (host.empty() || host.size() > 253 || !std::all_of(host.begin(), host.end(), [](unsigned char c) {
                    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.'
                            || c == '-';
                }))
                throw PlannerError("migration_endpoint_unsupported");
        }
    }
    UdpPorts occupiedUdpPorts(ProcessRunner &r)
    {
        try {
            UdpPorts ports;
            std::istringstream lines(output(r, { "ss", "-H", "-uan" }));
            std::string line;
            while (std::getline(lines, line)) {
                auto v = words(line);
                if (v.size() < 5)
                    throw PlannerError("udp_inventory_unavailable");
                const auto &endpoint = v[(v[0] == "udp" || v[0] == "udp6") ? 4 : 3];
                auto colon = endpoint.rfind(':');
                if (colon == std::string::npos)
                    throw PlannerError("udp_inventory_unavailable");
                auto port = endpoint.substr(colon + 1);
                if (port == "*")
                    continue;
                ports.insert(number(port));
            }
            auto ids = words(output(r, { "docker", "ps", "-q" }));
            if (ids.empty())
                return ports;
            if (ids.size() > 4096)
                throw PlannerError("udp_inventory_unavailable");
            for (auto &id : ids)
                if (id.size() < 12 || id.size() > 64 || !std::all_of(id.begin(), id.end(), [](unsigned char c) {
                        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                    }))
                    throw PlannerError("udp_inventory_unavailable");
            ProcessArgs a = { "docker", "inspect" };
            a.insert(a.end(), ids.begin(), ids.end());
            auto j = plannerJson(output(r, a));
            if (json_object_get_type(j.get()) != json_type_array || json_object_array_length(j.get()) != ids.size())
                throw PlannerError("udp_inventory_unavailable");
            for (std::size_t i = 0; i < json_object_array_length(j.get()); ++i) {
                auto *c = json_object_array_get_idx(j.get(), i);
                if (!c || json_object_get_type(c) != json_type_object)
                    throw PlannerError("udp_inventory_unavailable");
                json_object *network = nullptr;
                if (!json_object_object_get_ex(c, "NetworkSettings", &network))
                    continue;
                if (!network || json_object_get_type(network) != json_type_object)
                    throw PlannerError("udp_inventory_unavailable");
                json_object *p = nullptr;
                if (!json_object_object_get_ex(network, "Ports", &p) || !p)
                    continue;
                if (json_object_get_type(p) != json_type_object)
                    throw PlannerError("udp_inventory_unavailable");
                json_object_object_foreach(p, key, bindings)
                {
                    std::string protocol = key;
                    if (protocol.size() < 4 || protocol.substr(protocol.size() - 4) != "/udp")
                        continue;
                    if (!bindings)
                        continue;
                    if (json_object_get_type(bindings) != json_type_array)
                        throw PlannerError("udp_inventory_unavailable");
                    for (std::size_t k = 0; k < json_object_array_length(bindings); ++k) {
                        auto *b = json_object_array_get_idx(bindings, k);
                        ports.insert(number(text(b, "HostPort")));
                    }
                }
            }
            return ports;
        } catch (...) {
            throw PlannerError("udp_inventory_unavailable");
        }
    }
    unsigned selectUdpPort(const UdpPorts &occupied, unsigned sourcePort)
    {
        for (unsigned p = 51821; p <= 65535; ++p)
            if (p != sourcePort && !occupied.count(p))
                return p;
        throw PlannerError("migration_udp_port_unavailable");
    }
    AutomaticRequest automaticPlan(const std::filesystem::path &root, const std::string &source,
                                   const std::string &host, const std::string &image, std::string_view raw,
                                   unsigned sourcePort, const UdpPorts &occupied)
    {
        endpoint(host);
        if (source != "amnezia-awg" && source != "amnezia-awg2")
            throw PlannerError("migration_journal_conflict");
        try {
            auto scope = root / source;
            std::vector<std::filesystem::path> existing;
            if (std::filesystem::is_symlink(root) || std::filesystem::is_symlink(scope))
                throw PlannerError("migration_journal_conflict");
            if (std::filesystem::exists(scope)) {
                if (!std::filesystem::is_directory(scope))
                    throw PlannerError("migration_journal_conflict");
                for (auto &entry : std::filesystem::directory_iterator(scope)) {
                    if (entry.is_symlink())
                        throw PlannerError("migration_journal_conflict");
                    auto name = entry.path().filename().string();
                    if (entry.is_directory() && !name.empty()
                        && std::all_of(name.begin(), name.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) {
                        generation(name);
                        existing.push_back(entry.path());
                    }
                }
            }
            std::sort(existing.begin(), existing.end(), [](const auto &a, const auto &b) {
                return generation(a.filename().string()) < generation(b.filename().string());
            });
            std::vector<PlannerJson> ready;
            std::vector<std::uint64_t> readyGenerations;
            for (auto &dir : existing) {
                auto j = plannerJson(readJournal(dir / "transaction.json"));
                if (text(j.get(), "phase") == "ready") {
                    ready.push_back(std::move(j));
                    readyGenerations.push_back(generation(dir.filename().string()));
                }
            }
            if (ready.size() > 1)
                throw PlannerError("migration_journal_conflict");
            if (ready.size() == 1) {
                auto *j = ready.front().get();
                auto *request = member(j, "request", json_type_object);
                if (text(request, "image") != image || text(request, "host") != host
                    || text(j, "sourceDigest") != hash(raw))
                    throw PlannerError("migration_ready_drift");
                auto port = json_object_get_int64(member(request, "port", json_type_int));
                auto gen = json_object_get_int64(member(request, "generation", json_type_int));
                if (port < 1024 || port > 65535 || gen < 1 || gen > 9007199254740991LL
                    || json_object_object_length(request) != 4 || std::uint64_t(gen) != readyGenerations.front())
                    throw PlannerError("migration_journal_conflict");
                return { host, image, unsigned(port), std::uint64_t(gen) };
            }
            if (existing.size() > 1 || (existing.size() == 1 && existing.front().filename() != "1"))
                throw PlannerError("migration_journal_conflict");
            return { host, image, selectUdpPort(occupied, sourcePort), 1 };
        } catch (const PlannerError &e) {
            if (std::string_view(e.code()) == "migration_ready_drift"
                || std::string_view(e.code()) == "migration_udp_port_unavailable")
                throw;
            throw PlannerError("migration_journal_conflict");
        } catch (...) {
            throw PlannerError("migration_journal_conflict");
        }
    }
    std::string automaticRequestJson(const AutomaticRequest &r)
    {
        PlannerJson j(json_object_new_object());
        json_object_object_add(j.get(), "host", json_object_new_string_len(r.host.data(), int(r.host.size())));
        json_object_object_add(j.get(), "image", json_object_new_string_len(r.image.data(), int(r.image.size())));
        json_object_object_add(j.get(), "port", json_object_new_int64(r.port));
        json_object_object_add(j.get(), "generation", json_object_new_int64(std::int64_t(r.generation)));
        return json_object_to_json_string_ext(j.get(), JSON_C_TO_STRING_PLAIN);
    }
    void verifyAutomaticPort(unsigned port, PortProbe &probe)
    {
        if (port > 65535)
            throw PlannerError("migration_udp_port_unavailable");
        std::vector<std::unique_ptr<PortLease>> leases;
        try {
            for (auto family : { UdpFamily::V4, UdpFamily::V6 }) {
                auto lease = probe.open(family);
                if (!lease)
                    throw PlannerError("migration_udp_port_unavailable");
                leases.push_back(std::move(lease));
                if (family == UdpFamily::V6)
                    leases.back()->ipv6Only();
                leases.back()->bind(family == UdpFamily::V4 ? "0.0.0.0" : "::", port);
            }
        } catch (...) {
            throw PlannerError("migration_udp_port_unavailable");
        }
    }
}
