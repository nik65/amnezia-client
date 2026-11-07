// S1 sequencer: phase-ordered parity with prepare.prepare().
// No OS boundary is crossed here; EffectPort/ObservationPort are injected.
#include "prepare_sequencer.h"
#include "config_generation.h"
#include "transaction_journal.h"
#include "trusted_image.h"
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <regex>
#include <set>
#include <sstream>

namespace amnezia::awgMigration::prepare {
namespace {
using Json = std::shared_ptr<json_object>;
Json take(json_object *raw) { return Json(raw, json_object_put); }
std::string hex(const unsigned char *bytes, std::size_t size) {
    std::ostringstream out;
    for (std::size_t i = 0; i < size; ++i)
        out << std::hex << std::setfill('0') << std::setw(2) << unsigned(bytes[i]);
    return out.str();
}
std::string sha256(const std::string &bytes) {
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest, &length, EVP_sha256(), nullptr) != 1)
        throw PrepareError("migration_preparation_failed");
    return hex(digest, length);
}
std::string base64Decode(const std::string &value) {
    if (value.empty() || value.size() % 4 != 0) throw PrepareError("server key");
    std::size_t padding = 0;
    for (auto it = value.rbegin(); it != value.rend() && *it == '='; ++it) ++padding;
    if (padding > 2) throw PrepareError("server key");
    std::string out((value.size() * 3) / 4, '\0');
    const int length = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(out.data()),
        reinterpret_cast<const unsigned char *>(value.data()), static_cast<int>(value.size()));
    if (length < 0 || static_cast<std::size_t>(length) < padding) throw PrepareError("server key");
    out.resize(static_cast<std::size_t>(length) - padding);
    return out;
}
std::string base64Encode(const unsigned char *data, std::size_t size) {
    std::string out(4 * ((size + 2) / 3), '\0');
    const int length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data, static_cast<int>(size));
    if (length < 0) throw PrepareError("server key");
    out.resize(static_cast<std::size_t>(length));
    return out;
}
std::string serverPublicKey(const std::string &rawConfig) {
    const ReadyConfig config = parseConfig(rawConfig);
    const auto key = config.Interface.find("PrivateKey");
    if (key == config.Interface.end()) throw PrepareError("server key");
    const std::string privateBytes = base64Decode(key->second);
    if (privateBytes.size() != 32) throw PrepareError("server key");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
            reinterpret_cast<const unsigned char *>(privateBytes.data()), privateBytes.size()),
        EVP_PKEY_free);
    unsigned char publicBytes[32]; std::size_t publicSize = sizeof(publicBytes);
    if (!pkey || EVP_PKEY_get_raw_public_key(pkey.get(), publicBytes, &publicSize) != 1 || publicSize != 32)
        throw PrepareError("server key");
    return base64Encode(publicBytes, publicSize);
}
std::vector<std::string> splitSlash(const std::string &address) {
    const auto slash = address.find('/');
    return {address.substr(0, slash), slash == std::string::npos ? "32" : address.substr(slash + 1)};
}
std::string mappingJson(const ReadyConfig &config, const std::string &scope) {
    json_object *mapping = json_object_new_object();
    if (!mapping) throw PrepareError("native_generation_rejected");
    Json owned = take(mapping);
    for (const auto &peer : config.Peers) {
        const auto keyIt = peer.find("PublicKey"), allowedIt = peer.find("AllowedIPs");
        if (keyIt == peer.end() || allowedIt == peer.end()) throw PrepareError("native_generation_rejected");
        const auto parts = splitSlash(allowedIt->second);
        json_object *item = json_object_new_object();
        json_object_object_add(item, "sourceIp", json_object_new_string(parts[0].c_str()));
        json_object_object_add(item, "targetIp", json_object_new_string(parts[0].c_str()));
        json_object_object_add(item, "clientAddress", json_object_new_string(allowedIt->second.c_str()));
        json_object_object_add(item, "clientId", json_object_new_string(
            sha256(scope + "\t" + keyIt->second).c_str()));
        json_object_object_add(mapping, keyIt->second.c_str(), item);
    }
    return json_object_to_json_string_ext(mapping, JSON_C_TO_STRING_PLAIN);
}
std::string fieldsJson(const ConfigFields &fields) {
    json_object *object = json_object_new_object();
    Json owned = take(object);
    for (const auto &[key, value] : fields)
        json_object_object_add(object, key.c_str(), json_object_new_string(value.c_str()));
    return json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
}
std::string bindingJson(const std::map<std::string, policy::Fields> &binding) {
    json_object *object = json_object_new_object();
    Json owned = take(object);
    for (const auto &[name, role] : binding) {
        json_object *item = json_object_new_object();
        json_object_object_add(item, "networkId",
            json_object_new_string(role.count("networkId") ? role.at("networkId").c_str() : ""));
        json_object_object_add(item, "interface",
            json_object_new_string(role.count("interface") ? role.at("interface").c_str() : ""));
        json_object_object_add(item, "default",
            json_object_new_boolean(role.count("default") && role.at("default") == "1"));
        json_object_object_add(object, name.c_str(), item);
    }
    return json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
}
std::string startupScript(bool automatic, const policy::Snapshot &snapshot,
                          const std::string &address, unsigned port, const std::string &ownership,
                          const std::string &iface) {
    const std::string startup = automatic
        ? "test \"$(sha256sum /usr/bin/amneziawg-go | cut -d \" \" -f 1)\" = "
          "6d96502ebd9ed6f9d17bdecd637cba7502c9960fed1b6922b3882784417a036d\n"
          "/usr/bin/amneziawg-go -f awg0 >/dev/null 2>&1 &\nengine=$!\n"
          "printf \"%s\\n\" \"$engine\" > /migration/engine.pid\n"
          "trap \"kill $engine 2>/dev/null || true\" EXIT INT TERM\nattempt=0\n"
          "while ! awg show awg0 >/dev/null 2>&1; do\n  kill -0 \"$engine\"\n"
          "  attempt=$((attempt + 1))\n  test \"$attempt\" -lt 20\n  sleep 1\ndone\n"
          "awg setconf awg0 /migration/awg0.native.conf\nip address add " + address + " dev awg0\n"
          "ip link set dev awg0 mtu " + std::to_string(snapshot.mtu) + " up\n"
        : "awg-quick up /migration/awg0.conf\n";
    return "#!/bin/sh\nset -eu\n"
        "attempt=0\nwhile ! test -f /migration/network-approved; do\n  attempt=$((attempt + 1))\n"
        "  test \"$attempt\" -lt 60\n  sleep 1\ndone\n" + startup + policy::firewallScript(snapshot) +
        "iptables -I INPUT 1 -p tcp --dport 18082 -m comment --comment " + ownership + " -j REJECT\n"
        "iptables -I INPUT 1 -i " + iface + " -p tcp --dport 18082 -m comment --comment " +
        ownership + " -j ACCEPT\n"
        "iptables -t nat -A PREROUTING -i " + iface +
        " -d 172.29.172.251/32 -p tcp --dport 18082 -m comment --comment " + ownership +
        " -j REDIRECT --to-ports " + std::to_string(port) + "\n" +
        (automatic ? "while :; do kill -0 \"$engine\"; " : "while :; do ") +
        "awg show awg0 latest-handshakes > /migration/handshakes.tsv.tmp; "
        "mv /migration/handshakes.tsv.tmp /migration/handshakes.tsv; sleep 2; done\n";
}
std::string journalInitial(const Request &request, const SourceObservation &observation,
                           const std::string &owner, const std::string &target,
                           const std::string &sourceDigest) {
    json_object *root = json_object_new_object();
    Json owned = take(root);
    json_object_object_add(root, "owner", json_object_new_string(owner.c_str()));
    json_object_object_add(root, "phase", json_object_new_string("preparing"));
    json_object_object_add(root, "containers", json_object_new_object());
    json_object_object_add(root, "source", json_object_new_string(request.source.c_str()));
    json_object_object_add(root, "sourceId", json_object_new_string(observation.sourceId.c_str()));
    json_object_object_add(root, "sourceIface", json_object_new_string(observation.sourceIface.c_str()));
    json_object_object_add(root, "sourceRules", json_object_new_boolean(0));
    json_object_object_add(root, "sourceDigest", json_object_new_string(sourceDigest.c_str()));
    if (!request.nativeFeedSha256.empty())
        json_object_object_add(root, "nativeFeedSha256", json_object_new_string(request.nativeFeedSha256.c_str()));
    json_object_object_add(root, "target", json_object_new_string(target.c_str()));
    json_object_object_add(root, "sourceEpoch", json_object_new_string(observation.startedAt.c_str()));
    json_object *entry = json_object_new_object();
    json_object_object_add(entry, "image", json_object_new_string(request.image.c_str()));
    json_object_object_add(entry, "host", json_object_new_string(request.host.c_str()));
    json_object_object_add(entry, "port", json_object_new_int64(request.port));
    json_object_object_add(entry, "generation", json_object_new_int64(static_cast<std::int64_t>(request.generation)));
    json_object_object_add(root, "request", entry);
    return json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
}
std::string requestJson(const Request &request) {
    json_object *root = json_object_new_object();
    Json owned = take(root);
    json_object_object_add(root, "image", json_object_new_string(request.image.c_str()));
    json_object_object_add(root, "host", json_object_new_string(request.host.c_str()));
    json_object_object_add(root, "port", json_object_new_int64(request.port));
    json_object_object_add(root, "generation",
        json_object_new_int64(static_cast<std::int64_t>(request.generation)));
    return json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
}
std::vector<std::string> namesOf(const std::filesystem::path &sourceRoot) {
    std::vector<std::string> generations;
    std::error_code error;
    if (!std::filesystem::is_directory(sourceRoot, error)) return generations;
    for (const auto &entry : std::filesystem::directory_iterator(sourceRoot, error)) {
        const auto name = entry.path().filename().string();
        if (entry.is_directory(error) && !name.empty() &&
            std::all_of(name.begin(), name.end(), [](unsigned char c) { return std::isdigit(c); }))
            generations.push_back(name);
    }
    std::sort(generations.begin(), generations.end(),
              [](const std::string &a, const std::string &b) {
                  return a.size() == b.size() ? a < b : a.size() < b.size();
              });
    return generations;
}
}  // namespace

Outcome run(const std::filesystem::path &root, const Request &requestInput, ObservationPort &observation,
            EffectPort &effects, AutomaticPlannerPort *automatic) {
    Request request = requestInput;
    Outcome outcome;
    auto phase = [&](const std::string &name) { outcome.phases.push_back(name); };
    static const std::regex imagePattern(R"([a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64})");
    static const std::regex hostPattern(R"([A-Za-z0-9.-]{1,253})");
    static const std::regex digestPattern(R"([a-f0-9]{64})");
    std::filesystem::path directory;
    std::unique_ptr<TransactionJournal> journal;
    bool mutationStarted = false;
    bool committed = false;
    try {
        phase("validate");
        if (request.source != "amnezia-awg" && request.source != "amnezia-awg2")
            throw PrepareError("administrator/source required");
        if (!std::regex_match(request.host, hostPattern)) throw PrepareError("request");
        // Automatic requests intentionally carry no image/port/generation; those
        // are derived from the observed source below and then pass the identical
        // gates as an explicit request.
        if (!request.automatic && !std::regex_match(request.image, imagePattern))
            throw PrepareError("AWG3 immutable image required");
        if (!request.automatic && (request.port < 1024 || request.port > 65535 ||
            request.generation < 1 || request.generation > 9007199254740991ULL))
            throw PrepareError("request");
        if (!request.nativeFeedSha256.empty() && !std::regex_match(request.nativeFeedSha256, digestPattern))
            throw PrepareError("native_feed_invalid");
        if (!request.nativeCollectorSha256.empty() &&
            !std::regex_match(request.nativeCollectorSha256, digestPattern))
            throw PrepareError("native_collector_invalid");
        if (request.nativeControl &&
            (request.nativeFeedSha256.empty() || request.nativeCollectorSha256.empty()))
            throw PrepareError("native_control_rejected");
        if (!request.nativeCollectorSha256.empty() && !request.nativeControl)
            throw PrepareError("native_control_rejected");
        if (request.automatic && !request.preflight && !automatic)
            throw PrepareError("native_automatic_rejected");
        // Capture all selected executable payloads once, before any preflight
        // observation or mutation. A missing/wrong/unsafe feed or collector
        // therefore leaves no signer, generation, journal or container behind.
        effects.capturePayloads(request.nativeFeedSha256, request.nativeCollectorSha256);

        SourceObservation observed;
        bool observedReady = false;
        if (request.automatic && !request.preflight) {
            phase("automatic-plan");
            phase("observe");
            observed = observation.observe(request);
            observedReady = true;
            Request planned = request;
            try {
                automatic->planAutomatic(root, request, observed, planned);
            } catch (const PlannerError &error) {
                throw PrepareError(error.code());
            }
            request = planned;
            phase("validate-selected");
            if (!std::regex_match(request.image, imagePattern))
                throw PrepareError("AWG3 immutable image required");
            if (request.port < 1024 || request.port > 65535 || request.generation < 1 ||
                request.generation > 9007199254740991ULL)
                throw PrepareError("request");
            outcome.requestJson = requestJson(request);
        }
        if (!observedReady) {
            phase("observe");
            observed = observation.observe(request);
        }
        const ReadyConfig source = parseConfig(observed.rawConfig);
        const std::string iface = request.source == "amnezia-awg" ? "wg0" : "awg0";
        if (observed.sourceIface != iface) throw PrepareError("unsupported_source_network_topology");
        if (request.preflight) {
            phase("preflight");
            // Read-only eligibility gates, matching the original preflight
            // contract. Nothing is recovered, created, pulled or removed here.
            if (observed.sourceId.size() != 64 || observed.startedAt.empty())
                throw PrepareError("migration_preparation_failed");
            if (observed.networkBinding.empty() || observed.networkOptions.empty())
                throw PrepareError("unsupported_source_network_topology");
            if (!observed.epoch) throw PrepareError("managed_client_policy_not_ready");
            if (observed.snapshot.mtu <= 0) throw PrepareError("unsupported_mtu");
            const auto sourceRoot = root / request.source;
            std::error_code preflightError;
            if (std::filesystem::is_directory(sourceRoot, preflightError)) {
                for (const auto &entry : std::filesystem::directory_iterator(sourceRoot, preflightError)) {
                    std::filesystem::path transaction;
                    if (entry.path().filename() == "transaction.json") transaction = entry.path();
                    else if (std::filesystem::is_directory(entry.path()))
                        transaction = entry.path() / "transaction.json";
                    if (!transaction.empty() && std::filesystem::exists(transaction)
                        && !request.nativeFeedSha256.empty())
                        throw PrepareError("native_feed_existing_generation_requires_maintenance");
                }
            }
            outcome.preflight = true;
            outcome.eligible = true;
            return outcome;
        }
        if (request.automatic && (observed.sourceId.size() != 64 || observed.startedAt.empty() ||
            observed.networkBinding.empty() || !observed.epoch))
            throw PrepareError("unsupported_source_network_topology");

        phase("layout");
        const auto sourceRoot = root / request.source;
        if (std::filesystem::exists(sourceRoot)) {
            for (const auto &entry : std::filesystem::directory_iterator(sourceRoot)) {
                if (entry.path().filename() == "transaction.json")
                    throw PrepareError("native_feed_existing_generation_requires_maintenance");
                if (std::filesystem::is_directory(entry.path()) &&
                    std::filesystem::exists(entry.path() / "transaction.json"))
                    throw PrepareError("native_feed_existing_generation_requires_maintenance");
            }
        }
        directory = sourceRoot / std::to_string(request.generation);
        const auto generations = namesOf(sourceRoot);
        if (!generations.empty() && std::stoull(generations.back()) >= request.generation)
            throw PrepareError("generation must increase");
        if (std::filesystem::exists(directory)) throw PrepareError("generation already exists; never overwrite");
        const std::string target = request.source + "-migration-" + std::to_string(request.generation);
        for (const std::string &name : {target, target + "-control", target + "-source-control",
                                        target + "-logs", target + "-feeds"})
            if (observation.componentExists(name)) throw PrepareError("container name collision");
        if (observation.sourceControlBound()) throw PrepareError("source control port already bound");

        phase("journal");
        std::error_code error;
        std::filesystem::create_directories(directory, error);
        if (error) throw PrepareError("migration_preparation_failed");
        std::filesystem::permissions(directory, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace, error);
        if (error) throw PrepareError("migration_preparation_failed");
        unsigned char ownerBytes[16];
        if (RAND_priv_bytes(ownerBytes, sizeof(ownerBytes)) != 1) throw PrepareError("migration_preparation_failed");
        const std::string ownership = hex(ownerBytes, sizeof(ownerBytes));
        const std::string sourceDigest = sha256(observed.rawConfig);
        journal = std::make_unique<TransactionJournal>(directory,
            [&](const std::vector<std::string> &argv) {
                const CommandResult result = effects.command(argv);
                return amnezia::awgMigration::CommandResult{result.status, result.output, result.error};
            },
            journalInitial(request, observed, ownership, target, sourceDigest));
        mutationStarted = true;

        phase("signing");
        const std::string publicKey = effects.signingPublicKey(directory);
        const std::string serverKey = serverPublicKey(observed.rawConfig);
        phase("generation");
        phase("generation-config");
        const GeneratedConfig generated = generateConfig(observed.rawConfig, request.port,
                                                         static_cast<unsigned>(observed.snapshot.mtu));
        if (generated.interface.at("PrivateKey") != source.Interface.at("PrivateKey") ||
            generated.interface.at("Address") != source.Interface.at("Address"))
            throw PrepareError("native_generation_rejected");
        phase("generation-write");
        effects.write(directory / "awg0.conf", generated.config, 0600);
        if (request.automatic) effects.write(directory / "awg0.native.conf", generated.nativeConfig, 0600);
        effects.installNativeFeed(directory, request.nativeFeedSha256);
        phase("generation-startup");
        effects.write(directory / "start.sh", startupScript(request.automatic, observed.snapshot,
            std::string(source.Interface.at("Address")), request.port, ownership, iface), 0600);

        phase("target");
        if (!request.automatic) effects.command({"docker", "pull", request.image});
        const CommandResult image = effects.command({"docker", "image", "inspect", "--format", "{{.Id}}", request.image});
        if (image.status != 0 || image.output.empty()) throw PrepareError("migration_preparation_failed");
        journal->plan(target, image.output);
        if (request.automatic) {
            phase("port-check");
            effects.verifyAutomaticPort(request.port);
        }
        CommandResult created = effects.command({"docker", "create", "--name", target,
            "--label", "amnezia.migration.scope=" + request.source,
            "--label", "amnezia.migration.owner=" + ownership,
            "--label", "amnezia.migration.generation=" + std::to_string(request.generation),
            "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
            "--sysctl", "net.ipv4.ip_forward=1", "--restart", "unless-stopped",
            "--log-driver", "none", "-p", std::to_string(request.port) + ":" + std::to_string(request.port) + "/udp",
            "-v", directory.string() + ":/migration:rw", "--network", "bridge",
            "--entrypoint", "sh", request.image, "/migration/start.sh"});
        if (created.status != 0) throw PrepareError("migration_preparation_failed");
        journal->record(target);
        if (observation.binding(target) != observed.networkBinding)
            throw PrepareError("unsupported_source_network_topology");
        effects.command({"docker", "start", target});
        if (observation.binding(request.source) != observed.networkBinding ||
            observation.binding(target) != observed.networkBinding)
            throw PrepareError("unsupported_source_network_topology");
        effects.write(directory / "network-approved", "{\"approved\":true}", 0600);

        phase("ready-attest");
        const auto targetConfig = generated.config;
        const std::vector<std::string> targetLines = {targetConfig};
        if (!effects.ready(observed, targetLines, serverKey, request.automatic).ready)
            throw PrepareError("migration_ready_drift");
        const policy::Snapshot targetPolicy = observation.targetSnapshot(target, parseConfig(targetConfig), "awg0", {ownership});
        if (targetPolicy.mtu != observed.snapshot.mtu || targetPolicy.filter != observed.snapshot.filter ||
            targetPolicy.nat != observed.snapshot.nat || targetPolicy.routes != observed.snapshot.routes ||
            targetPolicy.egress != observed.snapshot.egress || targetPolicy.dockerDns != observed.snapshot.dockerDns)
            throw PrepareError("effective_namespace_policy_or_mtu_changed");
        if (observation.binding(request.source) != observed.networkBinding ||
            observation.binding(target) != observed.networkBinding)
            throw PrepareError("unsupported_source_network_topology");
        const std::string mapping = mappingJson(parseConfig(targetConfig), request.source);
        json_object *state = json_object_new_object();
        Json stateOwned = take(state);
        json_object_object_add(state, "networkBinding", json_tokener_parse(bindingJson(observed.networkBinding).c_str()));
        json_object_object_add(state, "schema", json_object_new_int(1));
        json_object_object_add(state, "serverPublicKey", json_object_new_string(serverKey.c_str()));
        json_object_object_add(state, "containerId", json_object_new_string(request.source.c_str()));
        json_object_object_add(state, "generation", json_object_new_int64(static_cast<std::int64_t>(request.generation)));
        json_object_object_add(state, "expiresAt", json_object_new_int64(static_cast<std::int64_t>(std::time(nullptr)) + 30 * 86400));
        json_object_object_add(state, "signingPublicKey", json_object_new_string(publicKey.c_str()));
        json_object_object_add(state, "endpoint", json_object_new_string((request.host + ":" + std::to_string(request.port)).c_str()));
        json_object_object_add(state, "parameters", json_tokener_parse(fieldsJson(generated.parameters).c_str()));
        json_object_object_add(state, "peers", json_tokener_parse(mapping.c_str()));
        json_object_object_add(state, "challengeAddress", json_object_new_string("172.29.172.251"));
        json_object_object_add(state, "challengePort", json_object_new_int(18082));
        json_object_object_add(state, "targetContainer", json_object_new_string(target.c_str()));
        effects.write(directory / "ready.json", json_object_to_json_string_ext(state, JSON_C_TO_STRING_PLAIN), 0600);

        phase("feeds");
        std::vector<std::string> feedPorts;
        for (const auto &rule : observed.snapshot.nat)
            for (const auto *port : {"17864", "17865"})
                if (rule.find(std::string("--dport ") + port + " ") != std::string::npos &&
                    std::find(feedPorts.begin(), feedPorts.end(), port) == feedPorts.end())
                    feedPorts.emplace_back(port);
        std::sort(feedPorts.begin(), feedPorts.end());
        for (const auto &port : feedPorts)
            if (!observed.expectedFeedSha.count(port)) throw PrepareError("target_client_feed_readiness_failed");
        if (!feedPorts.empty()) {
            std::string requestedPorts;
            for (const auto &port : feedPorts) {
                if (!requestedPorts.empty()) requestedPorts += ',';
                requestedPorts += port;
            }
            const std::string feedImage = "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df";
            const CommandResult feedImageId = effects.command({"docker", "image", "inspect", "--format", "{{.Id}}", feedImage});
            if (feedImageId.status != 0 || feedImageId.output.empty())
                throw PrepareError("target_client_feed_readiness_failed");
            journal->plan(target + "-feeds", feedImageId.output);
            const CommandResult started = effects.command({"docker", "run", "-d", "--name", target + "-feeds", "--log-driver", "none",
                "--restart", "unless-stopped", "--label", "amnezia.migration.owner=" + ownership,
                "--network", "container:" + target, "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "-e", "AMNEZIA_FEED_PORTS=" + requestedPorts, "-v", directory.string() + "/awg-feed:/app/awg-feed:ro",
                "-v", "/opt/amnezia/server-routing-rules:/routing:ro",
                "-v", "/opt/amnezia/client-updates:/updates:ro",
                "--entrypoint", "/app/awg-feed", feedImage, "--serve"});
            if (started.status != 0) throw PrepareError("target_client_feed_readiness_failed");
            journal->record(target + "-feeds");
        }
        for (const auto &port : feedPorts) {
            CommandResult checked = effects.command({"docker", "exec", target + "-feeds", "/app/awg-feed",
                "--check-feed", port == "17864" ? "routing" : "updates", port, observed.expectedFeedSha.at(port)});
            if (checked.status != 0) throw PrepareError("target_client_feed_readiness_failed");
        }
        phase("logs");
        if (request.nativeControl) {
            // Native log collector cutover: the exact captured static ELF is
            // staged in a private executable image context below this
            // generation; only that context is mounted as /app. User log data
            // stays at /data and no Python collector or fallback is run.
            const std::filesystem::path collectorContext =
                effects.stageNativeCollector(directory, request.nativeCollectorSha256);
            if (collectorContext.empty()) throw PrepareError("native_collector_rejected");
            const std::string collectorImage = target + "-logs-image";
            const CommandResult collectorBuild =
                effects.command({"docker", "build", "-t", collectorImage, collectorContext.string()});
            if (collectorBuild.status != 0) throw PrepareError("native_collector_rejected");
            const CommandResult collectorImageId =
                effects.command({"docker", "image", "inspect", "--format", "{{.Id}}", collectorImage});
            if (collectorImageId.status != 0 || collectorImageId.output.empty())
                throw PrepareError("native_collector_rejected");
            journal->plan(target + "-logs", collectorImageId.output);
            const CommandResult started = effects.command({"docker", "run", "-d", "--name", target + "-logs",
                "--log-driver", "none", "--restart", "unless-stopped",
                "--label", "amnezia.migration.owner=" + ownership,
                "--network", "container:" + target, "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "-e", "AMNEZIA_CLIENT_LOGS_BOOTSTRAP=1",
                "-e", "AMNEZIA_CLIENT_LOGS_SCOPE=" + request.source,
                "-v", collectorContext.string() + ":/app:ro",
                "-v", "/opt/amnezia/client-logs:/data:rw",
                "--entrypoint", "/app/amnezia-client-logs-collector", collectorImage,
                "--root", "/data", "--bind", "0.0.0.0", "--port", "17866",
                "--upload-path", "/logs", "--bootstrap-path", "/bootstrap"});
            if (started.status != 0) throw PrepareError("native_collector_rejected");
            journal->record(target + "-logs");
        } else {
            // Legacy mode is intentionally byte-for-byte unchanged.
            const std::string logImage = "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df";
            const CommandResult logImageId = effects.command({"docker", "image", "inspect", "--format", "{{.Id}}", logImage});
            journal->plan(target + "-logs", logImageId.output);
            effects.command({"docker", "run", "-d", "--name", target + "-logs", "--log-driver", "none",
                "--restart", "unless-stopped", "--label", "amnezia.migration.owner=" + ownership,
                "--network", "container:" + target, "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "-e", "AMNEZIA_CLIENT_LOGS_BOOTSTRAP=1",
                "-e", "AMNEZIA_CLIENT_LOGS_SCOPE=" + request.source, "-v", "/opt/amnezia/client-logs:/data:rw",
                "--entrypoint", "python", logImage, "/data/collector.py"});
            journal->record(target + "-logs");
        }

        phase("controls");
        const std::string controlImage = target + "-control-image";
        if (!request.nativeControl) {
            // Legacy native-feed generation: its PID1 remains Python. This
            // producer is intentionally unchanged and remains fail-closed.
            effects.command({"docker", "build", "-t", controlImage, directory.string() + "-build"});
            const CommandResult controlImageId = effects.command({"docker", "image", "inspect", "--format", "{{.Id}}", controlImage});
            journal->plan(target + "-control", controlImageId.output);
            effects.command({"docker", "run", "-d", "--name", target + "-control", "--log-driver", "none",
                "--restart", "unless-stopped", "--label", "amnezia.migration.owner=" + ownership,
                "--network", "container:" + target, "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "-v", directory.string() + ":/migration:rw",
                "-v", "/opt/amnezia/client-logs:/logs:ro", "--entrypoint", "python",
                controlImage, "/migration/target.py"});
            journal->record(target + "-control");
            journal->plan(target + "-source-control", controlImageId.output);
            throw PrepareError("native_control_pid1_boundary");
        }

        // Explicit native-control-http-v1 producer. The staged image contains
        // only the Dockerfile and the exact captured /app/awg-feed bytes; no
        // VPN/signing/receipt material enters the build context. The expected
        // digest is the authenticated operator value, never a receipt field.
        const std::filesystem::path controlContext = effects.stageNativeControl(directory, request.nativeFeedSha256);
        const CommandResult controlBuild = effects.command({"docker", "build", "-t", controlImage, controlContext.string()});
        if (controlBuild.status != 0) throw PrepareError("native_control_rejected");
        const CommandResult controlImageId = effects.command({"docker", "image", "inspect", "--format", "{{.Id}}", controlImage});
        if (controlImageId.status != 0 || controlImageId.output.empty())
            throw PrepareError("native_control_rejected");
        const auto controlEnvironment = [&](const std::string &role) {
            return std::vector<std::string>{"-e", "AMNEZIA_CONTROL_NATIVE_SHA256=" + request.nativeFeedSha256,
                "-e", "AMNEZIA_MIGRATION_ROLE=" + role, "-e", "AMNEZIA_MIGRATION_SCOPE=" + request.source};
        };
        const auto startControl = [&](const std::string &name, const std::string &role,
                                      const std::string &network) {
            std::vector<std::string> argv = {"docker", "run", "-d", "--name", name, "--log-driver", "none",
                "--restart", "unless-stopped", "--label", "amnezia.migration.owner=" + ownership,
                "--network", "container:" + network, "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true"};
            const auto environment = controlEnvironment(role);
            argv.insert(argv.end(), environment.begin(), environment.end());
            argv.insert(argv.end(), {"-v", directory.string() + ":/migration:rw",
                "-v", "/opt/amnezia/client-logs:/logs:ro", "--entrypoint", "/app/awg-feed",
                controlImage, "--control-pid1"});
            return effects.command(argv);
        };
        const auto attestControl = [&](const std::string &name, const std::string &role) {
            CommandResult result;
            for (unsigned attempt = 0; attempt < 10; ++attempt) {
                result = effects.command({"docker", "exec", name, "/app/awg-feed",
                    "--verify-control-live", role, request.nativeFeedSha256,
                    "/migration/control-loaded-" + role + ".json"});
                if (result.status == 0) return;
                effects.pause(1000);
            }
            throw PrepareError("native_control_rejected");
        };

        journal->plan(target + "-control", controlImageId.output);
        if (startControl(target + "-control", "target", target).status != 0)
            throw PrepareError("native_control_rejected");
        journal->record(target + "-control");
        attestControl(target + "-control", "target");
        // Real policy-epoch readiness through the captured native feed CLI,
        // matching prepare.py check_collector_policy_epoch. The epoch is the
        // observed policy value, never a receipt/request field.
        if (observed.epoch) {
            const CommandResult epochCheck = effects.command({"docker", "exec", target + "-control",
                "/app/awg-feed", "--check-policy-epoch",
                std::to_string(observed.epoch->revision), observed.epoch->contentSha256});
            if (epochCheck.status != 0 || !epochCheck.output.empty())
                throw PrepareError("client_policy_feed_epoch_changed");
        }

        // Source rules are owned by this generation before the source helper
        // exists; the journal records sourceRules=true first so an interrupted
        // activation is always removable by cleanup.
        journal->activateSourceRules();
        journal->plan(target + "-source-control", controlImageId.output);
        if (startControl(target + "-source-control", "source", request.source).status != 0)
            throw PrepareError("native_control_rejected");
        journal->record(target + "-source-control");
        attestControl(target + "-source-control", "source");

        const std::string receipt = [&] {
            json_object *root = json_object_new_object();
            Json owned = take(root);
            json_object_object_add(root, "prepared", json_object_new_boolean(1));
            json_object_object_add(root, "generation", json_object_new_int64(static_cast<std::int64_t>(request.generation)));
            json_object_object_add(root, "peerCount", json_object_new_int(static_cast<int>(source.Peers.size())));
            json_object_object_add(root, "serverPublicKey", json_object_new_string(serverKey.c_str()));
            json_object_object_add(root, "signingPublicKey", json_object_new_string(publicKey.c_str()));
            json_object_object_add(root, "legacyRetained", json_object_new_boolean(1));
            return std::string(json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN));
        }();
        json_object *native = json_object_new_object();
        Json nativeOwned = take(native);
        json_object_object_add(native, "variant", json_object_new_string("native-control-http-v1"));
        json_object_object_add(native, "protocol", json_object_new_string("control-http-v1"));
        json_object_object_add(native, "authority", json_object_new_string("authenticated-operator-sha256"));
        json_object_object_add(native, "sha256", json_object_new_string(request.nativeFeedSha256.c_str()));
        json_object_object_add(native, "image", json_object_new_string(controlImageId.output.c_str()));
        json_object_object_add(native, "verifier", json_object_new_string("--verify-control-live"));
        json_object_object_add(native, "roles", json_tokener_parse("[\"target\",\"source\"]"));
        journal->finalizeNativeControl(receipt,
            json_object_to_json_string_ext(native, JSON_C_TO_STRING_PLAIN));
        outcome.prepared = true;
        outcome.eligible = true;
        outcome.receiptJson = receipt;
        committed = true;
    } catch (const PrepareError &error) {
        outcome.failure = error.what();
    } catch (const std::exception &) {
        outcome.failure = "migration_preparation_failed";
    }
    try {
        if (!mutationStarted || committed) {
            phase("finalization");
            return outcome;
        }
        if (journal) journal->cleanup();
        std::error_code ignored;
        if (!directory.empty()) std::filesystem::remove_all(directory, ignored);
        // remove_all reports permission/IO failure only through the error code.
        // Never claim cleanup while the generation directory still exists.
        std::error_code residueError;
        const bool residue = static_cast<bool>(ignored) ||
            (!directory.empty() && std::filesystem::exists(directory, residueError)) ||
            static_cast<bool>(residueError);
        outcome.cleaned = !residue;
        if (!outcome.cleaned && outcome.failure.empty()) outcome.failure = "cleanup_failed";
    } catch (const std::exception &) {
        outcome.cleaned = false;
        if (outcome.failure.empty()) outcome.failure = "cleanup_failed";
    }
    phase("finalization");
    return outcome;
}
}  // namespace amnezia::awgMigration::prepare
