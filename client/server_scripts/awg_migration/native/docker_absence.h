#pragma once
#include "bounded_docker.h"
#include <algorithm>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace amnezia::awgMigration {
// stderr is intentionally discarded by the bounded process transport. A
// failed inspect alone is therefore not evidence of absence: daemon/permission
// errors have the same exit class. Use a successful complete read-only inventory
// and validate every row before emitting the journal's private absence marker.
template<class Runner>
bool verifiedDockerInspectAbsence(const std::vector<std::string>& argv, Runner run)
{
    if (argv.size() != 3 || argv[0] != "docker" || argv[1] != "inspect"
        || !std::regex_match(argv[2], std::regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"))) return false;
    const auto raw = run(std::vector<std::string>{"docker","ps","-a","--no-trunc","--format","{{.ID}}\t{{.Names}}"});
    if (raw.size() > 1024u * 1024u || raw.find('\0') != std::string::npos
        || (!raw.empty() && raw.back() != '\n')) throw BoundedDockerError();
    std::set<std::string> ids, names;
    bool found = false;
    std::size_t at = 0;
    while (at < raw.size()) {
        const auto end = raw.find('\n', at), tab = raw.find('\t', at);
        if (tab == std::string::npos || tab >= end) throw BoundedDockerError();
        const auto id = raw.substr(at, tab - at), name = raw.substr(tab + 1, end - tab - 1);
        if (id.size() != 64 || !std::all_of(id.begin(),id.end(),[](char ch){return (ch>='0'&&ch<='9')||(ch>='a'&&ch<='f');})
            || !std::regex_match(name,std::regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"))
            || !ids.insert(id).second || !names.insert(name).second) throw BoundedDockerError();
        if (argv[2] == id || argv[2] == name) found = true;
        at = end + 1;
    }
    return !found;
}
} // namespace amnezia::awgMigration
