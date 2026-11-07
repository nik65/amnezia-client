#include "prepare_entry.h"
#include <json-c/json.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace amnezia::awgMigration::prepareEntry {
namespace {
struct JsonDelete { void operator()(json_object *v) const noexcept { if (v) json_object_put(v); } };
using Json = std::unique_ptr<json_object, JsonDelete>;

bool unsignedValue(const char *text, unsigned long long &value) {
    if (!text || !*text || *text == '-') return false;
    char *end = nullptr;
    errno = 0;
    value = std::strtoull(text, &end, 10);
    return errno == 0 && end && *end == '\0';
}

std::string print(const Parsed &parsed, const prepare::Outcome &outcome) {
    Json root(json_object_new_object());
    json_object_object_add(root.get(), "prepared", json_object_new_boolean(outcome.prepared));
    json_object_object_add(root.get(), "preflight", json_object_new_boolean(outcome.preflight));
    json_object_object_add(root.get(), "eligible", json_object_new_boolean(outcome.eligible));
    json_object_object_add(root.get(), "cleaned", json_object_new_boolean(outcome.cleaned));
    if (!outcome.failure.empty()) {
        json_object_object_add(root.get(), "failure", json_object_new_string(outcome.failure.c_str()));
        // Existing automatic UI/retry consumers use Python's public reason key.
        json_object_object_add(root.get(), "reason", json_object_new_string(outcome.failure.c_str()));
    }
    if (!outcome.requestJson.empty())
        json_object_object_add(root.get(), "request",
            json_tokener_parse(outcome.requestJson.c_str()));
    if (!outcome.receiptJson.empty())
        json_object_object_add(root.get(), "receipt", json_object_new_string(outcome.receiptJson.c_str()));
    json_object *phases = json_object_new_array();
    for (const auto &phase : outcome.phases)
        json_object_array_add(phases, json_object_new_string(phase.c_str()));
    json_object_object_add(root.get(), "phases", phases);
    if (!parsed.request.source.empty())
        json_object_object_add(root.get(), "source", json_object_new_string(parsed.request.source.c_str()));
    return json_object_to_json_string_ext(root.get(), JSON_C_TO_STRING_PLAIN);
}
} // namespace

Parsed parseArgv(int argc, char **argv) {
    Parsed parsed;
    std::set<std::string> seen;
    auto need = [&](int &index) -> const char * {
        if (index + 1 >= argc) { parsed.error = "missing option value"; return nullptr; }
        return argv[++index];
    };
    for (int i = 1; i < argc; ++i) {
        const std::string option = argv[i];
        if (option == "--help" || option == "-h") { parsed.help = true; continue; }
        if (option != "--source" && option != "--image" && option != "--host" && option != "--port"
            && option != "--generation" && option != "--automatic" && option != "--preflight"
            && option != "--native-feed" && option != "--native-feed-sha256"
            && option != "--native-collector" && option != "--native-collector-sha256"
            && option != "--native-control") {
            parsed.error = "unsupported option";
            return parsed;
        }
        if (!seen.insert(option).second) { parsed.error = "duplicate option"; return parsed; }
        if (option == "--automatic") { parsed.request.automatic = true; continue; }
        if (option == "--preflight") { parsed.request.preflight = true; continue; }
        if (option == "--native-control") { parsed.request.nativeControl = true; continue; }
        const char *value = need(i);
        if (!value) return parsed;
        if (option == "--source") parsed.request.source = value;
        else if (option == "--image") parsed.request.image = value;
        else if (option == "--host") parsed.request.host = value;
        else if (option == "--native-feed") parsed.nativeFeed = value;
        else if (option == "--native-feed-sha256") parsed.request.nativeFeedSha256 = value;
        else if (option == "--native-collector") parsed.nativeCollector = value;
        else if (option == "--native-collector-sha256") parsed.request.nativeCollectorSha256 = value;
        else {
            unsigned long long number = 0;
            if (!unsignedValue(value, number)) { parsed.error = "invalid number"; return parsed; }
            if (option == "--port") parsed.request.port = static_cast<unsigned>(number);
            else parsed.request.generation = number;
        }
    }
    if (parsed.help) { parsed.valid = true; return parsed; }
    if (parsed.request.source.empty() || parsed.request.host.empty()) {
        parsed.error = "source and host required";
        return parsed;
    }
    if (parsed.nativeFeed.empty() != parsed.request.nativeFeedSha256.empty()) {
        parsed.error = "native feed path and digest must be supplied together";
        return parsed;
    }
    if (parsed.nativeCollector.empty() != parsed.request.nativeCollectorSha256.empty()) {
        parsed.error = "native collector path and digest must be supplied together";
        return parsed;
    }
    if (!parsed.nativeCollector.empty() && !parsed.request.nativeControl) {
        parsed.error = "--native-collector requires --native-control";
        return parsed;
    }
    if (parsed.request.nativeControl && (parsed.request.nativeFeedSha256.empty() ||
                                         parsed.request.nativeCollectorSha256.empty())) {
        parsed.error = "--native-control requires --native-feed/--native-feed-sha256"
                       " and --native-collector/--native-collector-sha256";
        return parsed;
    }
    parsed.valid = true;
    return parsed;
}

int run(const Parsed &parsed, const std::filesystem::path &root,
        prepare::ObservationPort &observation, prepare::EffectPort &effects,
        prepare::AutomaticPlannerPort *automatic) {
    if (!parsed.valid) {
        std::cout << "{\"error\":\"usage\",\"detail\":\"" << parsed.error << "\"}\n";
        return 2;
    }
    if (!root.is_absolute()) {
        std::cout << "{\"error\":\"usage\",\"detail\":\"absolute migration root required\"}\n";
        return 2;
    }
    if (parsed.help) {
        std::cout << "usage: awg-native-prepare --source amnezia-awg|amnezia-awg2 --host HOST"
                     " --image IMAGE@sha256:DIGEST --port PORT --generation N"
                     " [--automatic] [--preflight] [--native-control]"
                     " [--native-feed PATH --native-feed-sha256 DIGEST]"
                     " [--native-collector PATH --native-collector-sha256 DIGEST]\n";
        return 0;
    }
    const prepare::Outcome outcome = prepare::run(root, parsed.request, observation, effects, automatic);
    std::cout << print(parsed, outcome) << '\n';
    if (outcome.preflight) return outcome.eligible ? 0 : 23;
    return outcome.prepared ? 0 : 23;
}
} // namespace amnezia::awgMigration::prepareEntry
