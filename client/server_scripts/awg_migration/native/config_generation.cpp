#include "config_generation.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t configLimit = 1024 * 1024;
struct Secret {
    GenerationEntropy bytes{};
    ~Secret() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
void append(std::string &output, const std::string &value) {
    if (value.size() > configLimit - output.size()) throw GenerationError();
    output += value;
}
std::string serialize(const ConfigFields &interface, const std::vector<ConfigFields> &peers, bool native) {
    std::string result = "[Interface]\n";
    const auto fields = [&](const ConfigFields &values, bool header) {
        for (const auto &entry : values) {
            if (native && header && (entry.first == "Address" || entry.first == "MTU")) continue;
            append(result, entry.first);
            append(result, " = ");
            append(result, entry.second);
            append(result, "\n");
        }
    };
    fields(interface, true);
    for (const auto &peer : peers) {
        append(result, "\n[Peer]\n");
        fields(peer, false);
    }
    return result;
}
}
GeneratedConfig generateConfig(std::string_view raw, unsigned port, unsigned mtu,
                               const GenerationRandom &random) {
    if (raw.size() > configLimit || port < 1024 || port > 65535 || mtu < 576 || mtu > 9000 || !random)
        throw GenerationError();
    ReadyConfig source;
    try { source = parseConfig(raw); }
    catch (...) { throw GenerationError(); }
    Secret entropy;
    if (!random(entropy.bytes)) throw GenerationError();
    std::array<unsigned char, 45> encoded{};
    if (EVP_EncodeBlock(encoded.data(), entropy.bytes.data(), static_cast<int>(entropy.bytes.size())) != 44)
        throw GenerationError();
    GeneratedConfig generated;
    generated.parameters = {
        {"Jc", "4"}, {"Jmin", "10"}, {"Jmax", "50"},
        {"S1", "16"}, {"S2", "16"}, {"S3", "16"}, {"S4", "16"},
        {"H1", "1"}, {"H2", "2"}, {"H3", "3"}, {"H4", "4"},
        {"HeaderProtectionKey", std::string(reinterpret_cast<const char *>(encoded.data()), 44)},
        {"ContentPaddingAddition", "0"}, {"RekeyAfterTime", "120"}, {"RekeyTimeout", "5"},
        {"RejectAfterTime", "180"}, {"KeepaliveTimeout", "10"},
        {"MaxHandshakeAttempts", "20"}, {"RandomTrailers", "0"}, {"DisableCookies", "0"}
    };
    generated.interface = generated.parameters;
    generated.interface.emplace("PrivateKey", source.Interface.at("PrivateKey"));
    generated.interface.emplace("Address", source.Interface.at("Address"));
    generated.interface.emplace("ListenPort", std::to_string(port));
    generated.interface.emplace("MTU", std::to_string(mtu));
    generated.config = serialize(generated.interface, source.Peers, false);
    generated.nativeConfig = serialize(generated.interface, source.Peers, true);
    return generated;
}
GeneratedConfig generateConfig(std::string_view source, unsigned port, unsigned mtu) {
    return generateConfig(source, port, mtu, [](GenerationEntropy &bytes) {
        return RAND_priv_bytes(bytes.data(), static_cast<int>(bytes.size())) == 1;
    });
}
}
