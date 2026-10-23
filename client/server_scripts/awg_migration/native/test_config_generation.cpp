#include "config_generation.h"
#include "config_generation_runtime.h"
#include <cassert>
#include <iostream>

using namespace amnezia::awgMigration;
namespace {
unsigned checks = 0;
void check(bool result) { ++checks; assert(result); }
const std::string source = "[Interface]\nPrivateKey = " + std::string(43, 'A')
    + "=\nAddress = 10.0.0.1/24\nListenPort = 55555\nMTU = 1280\nPostUp = owned-unused\n"
      "DNS = owned-unused\nSaveConfig = true\nI1 = owned-unused\n"
      "[Peer]\nPublicKey = " + std::string(43, 'B') + "=\nPresharedKey = " + std::string(43, 'C')
    + "=\nAllowedIPs = 10.0.0.2/32\nPersistentKeepalive = " + std::string("one\0two", 7)
    + "\n[Peer]\nPublicKey = " + std::string(43, 'D') + "=\nAllowedIPs = 10.0.0.3/32\n";
template<class Function> void rejected(Function f) {
    ++checks;
    try { f(); assert(false); }
    catch (const GenerationError &error) { assert(std::string(error.what()) == "native_generation_rejected"); }
}
}
int main() {
    unsigned calls = 0;
    const GenerationRandom random = [&](GenerationEntropy &bytes) { ++calls; bytes.fill('c'); return true; };
    const auto generated = generateConfig(source, 51821, 1420, random);
    check(calls == 1);
    check(generated.parameters.size() == 20 && generated.interface.size() == 24);
    check(generated.parameters.at("HeaderProtectionKey") == "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=");
    check(generated.parameters.at("Jc") == "4");
    check(generated.parameters.at("Jmin") == "10");
    check(generated.parameters.at("Jmax") == "50");
    for (const auto *key : {"S1", "S2", "S3", "S4"}) check(generated.parameters.at(key) == "16");
    for (unsigned n = 1; n <= 4; ++n) check(generated.parameters.at("H" + std::to_string(n)) == std::to_string(n));
    for (const auto &entry : ConfigFields{{"ContentPaddingAddition", "0"}, {"RekeyAfterTime", "120"},
            {"RekeyTimeout", "5"}, {"RejectAfterTime", "180"}, {"KeepaliveTimeout", "10"},
            {"MaxHandshakeAttempts", "20"}, {"RandomTrailers", "0"}, {"DisableCookies", "0"}})
        check(generated.parameters.at(entry.first) == entry.second);
    const auto parsed = parseConfig(generated.config);
    const auto original = parseConfig(source);
    check(parsed.Peers == original.Peers);
    check(parsed.Interface == generated.interface);
    check(generated.interface.at("PrivateKey") == original.Interface.at("PrivateKey"));
    check(generated.interface.at("Address") == original.Interface.at("Address"));
    check(generated.interface.at("ListenPort") == "51821" && generated.interface.at("MTU") == "1420");
    for (const auto *discarded : {"PostUp", "DNS", "SaveConfig", "I1"}) check(!generated.interface.count(discarded));
    check(generated.nativeConfig.find("\nAddress = ") == std::string::npos);
    check(generated.nativeConfig.find("\nMTU = ") == std::string::npos);
    check(generated.nativeConfig.find(std::string("one\0two", 7)) != std::string::npos);
    check(generated.nativeConfig.find("PublicKey = " + std::string(43, 'B'))
        < generated.nativeConfig.find("PublicKey = " + std::string(43, 'D')));
    for (const auto port : {0U, 1023U, 65536U, ~0U}) rejected([&] { generateConfig(source, port, 1420, random); });
    for (const auto mtu : {0U, 575U, 9001U, ~0U}) rejected([&] { generateConfig(source, 51821, mtu, random); });
    rejected([&] { generateConfig(source, 51821, 1420, GenerationRandom{}); });
    rejected([&] { generateConfig(source, 51821, 1420, [](GenerationEntropy &) { return false; }); });
    rejected([&] { generateConfig("bad source", 51821, 1420, random); });
    rejected([&] { generateConfig(std::string(1024 * 1024 + 1, 'a'), 51821, 1420, random); });
    // Source fits the parser cap, but the new target defaults increase its size.
    const auto shortSource = source.substr(0, source.find("one"));
    const auto large = shortSource + std::string(1024 * 1024 - shortSource.size() - 1, 'x') + '\n';
    check(large.size() == 1024 * 1024);
    rejected([&] { generateConfig(large, 51821, 1420, random); });
    // These valid production calls exercise OpenSSL entropy only: no sockets/files/processes.
    const auto first = generateConfig(source, 1024, 576);
    const auto second = generateConfig(source, 65535, 9000);
    check(first.parameters.at("HeaderProtectionKey").size() == 44);
    check(first.parameters.at("HeaderProtectionKey") != second.parameters.at("HeaderProtectionKey"));
    check(first.interface.at("ListenPort") == "1024" && second.interface.at("MTU") == "9000");
    for (const auto &request : {std::string("{}"), std::string("{\"source\":\"x\",\"port\":1024,\"mtu\":576,\"port\":1025}"),
            std::string("{\"source\":\"x\",\"port\":true,\"mtu\":576}"),
            std::string("{\"source\":\"x\",\"port\":1024.0,\"mtu\":576}"),
            std::string("{\"source\":\"x\",\"port\":1024,\"mtu\":576} trailing")})
        rejected([&] { generationRuntimeRequest(request); });
    std::cout << "config generation checks: " << checks << '\n';
}
