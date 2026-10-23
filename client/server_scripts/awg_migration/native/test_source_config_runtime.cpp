#include "source_config_runtime.h"
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <json-c/json.h>
#include <memory>
#include <unistd.h>

using namespace amnezia::awgMigration;
namespace {
using Args = std::vector<std::string>;
const std::string identity(64,'a');
unsigned cases = 0;
int unexpectedExecMarker = -1;
void check(bool value) { if (!value) throw std::runtime_error("source config assertion"); }
std::string config() {
    return "[Interface]\nPrivateKey="+std::string(43,'A')+"=\nAddress=10.0.0.1/24\nListenPort=51820\n"
        "[Peer]\nPublicKey="+std::string(43,'B')+"=\nAllowedIPs=10.0.0.2/32\n";
}
void rejects(const std::function<void()> &call) {
    try { call(); }
    catch (const SourceConfigRuntimeError &error) { check(std::string(error.what()) == "native_source_config_rejected"); ++cases; return; }
    throw std::runtime_error("expected private source config rejection");
}
struct Scripted {
    std::vector<Args> expected;
    std::vector<std::string> output;
    std::vector<Args> calls;
    unsigned failAt{};
    explicit Scripted(const std::string &source = "amnezia-awg", std::string raw = config()) {
        const Args inspect{"docker","inspect","--format","{{.Id}}",source};
        expected = {inspect,{"docker","exec",identity,"cat",source == "amnezia-awg" ? "/opt/amnezia/awg/wg0.conf" : "/opt/amnezia/awg/awg0.conf"},inspect};
        output = {identity+'\n',std::move(raw),identity+'\n'};
    }
    SourceConfigRunner runner() {
        return [this](const Args &args) {
            const auto at = calls.size(); calls.push_back(args);
            if (failAt && calls.size() == failAt) throw std::runtime_error("owned private backend message");
            if (at >= expected.size() || args != expected[at]) throw std::runtime_error("unexpected fixed fake argv");
            return output[at];
        };
    }
};
std::string request(const std::string &source) { return "{\"op\":\"read\",\"source\":\""+source+"\"}"; }
std::string resultRaw(const std::string &output) {
    std::unique_ptr<json_object,decltype(&json_object_put)> root(json_tokener_parse(output.c_str()),json_object_put);
    check(root && json_object_is_type(root.get(),json_type_object) && json_object_object_length(root.get()) == 1);
    json_object *result = nullptr, *value = nullptr;
    check(json_object_object_get_ex(root.get(),"result",&result) && result && json_object_is_type(result,json_type_object)
        && json_object_object_length(result) == 1 && json_object_object_get_ex(result,"raw",&value) && value
        && json_object_is_type(value,json_type_string));
    return {json_object_get_string(value),static_cast<std::size_t>(json_object_get_string_len(value))};
}
void validRaw(std::string raw, const std::string &source = "amnezia-awg") {
    Scripted fake(source,raw);
    const auto output = sourceConfigRuntimeRequest(request(source),fake.runner());
    check(resultRaw(output) == raw && fake.calls == fake.expected && output.size() <= 8*1024*1024); ++cases;
}
}
// Test-only guard: an allowlist regression must never execute a real Docker binary.
extern "C" int execve(const char *, char *const[], char *const[]) noexcept {
    if (unexpectedExecMarker >= 0) {
        const char marker = 'x';
        if (::write(unexpectedExecMarker,&marker,1) != 1) _exit(116);
    }
    _exit(115);
}
int main() {
    int execTrace[2]; check(::pipe2(execTrace,O_CLOEXEC | O_NONBLOCK) == 0); unexpectedExecMarker = execTrace[1];
    {
        Scripted fake;
        check(sourceConfigRuntimeRequest("{\"op\":\"capability\"}",fake.runner()) == "{\"result\":{\"sourceConfigVersion\":1}}");
        check(fake.calls.empty()); ++cases;
        check(sourceConfigRuntimeRequest("{\"op\":\"capability\"}") == "{\"result\":{\"sourceConfigVersion\":1}}"); ++cases;
    }
    {
        Scripted fake; std::string raw = "{\"op\":\"capability\"}"; raw.resize(8192,' ');
        check(sourceConfigRuntimeRequest(raw,fake.runner()) == "{\"result\":{\"sourceConfigVersion\":1}}" && fake.calls.empty()); ++cases;
        raw.push_back(' '); rejects([&] { sourceConfigRuntimeRequest(raw,fake.runner()); }); check(fake.calls.empty());
    }
    validRaw(config()); validRaw(config(),"amnezia-awg2");
    for (const auto &opaque : {std::string(u8"данные😀"),std::string("left\0right",10),std::string("quoted\"\\path"),std::string("\x01middle\x02")}) {
        auto raw = config(); raw.insert(raw.find("[Peer]"),"PostUp="+opaque+'\n'); validRaw(raw);
    }
    {
        auto raw = config(); raw.insert(raw.find("[Peer]"),"PostUp=\x01\n");
        const auto at = raw.find('\x01'); raw.replace(at,1,std::string(1024*1024-raw.size()+1,'\x01'));
        check(raw.size() == 1024*1024);
        Scripted fake("amnezia-awg",raw); const auto output = sourceConfigRuntimeRequest(request("amnezia-awg"),fake.runner());
        check(output.size() > 1024*1024 && output.size() < 8*1024*1024 && resultRaw(output) == raw && fake.calls.size() == 3); ++cases;
    }
    for (unsigned variant = 0;variant < 3;++variant) {
        Scripted fake;
        if (variant == 0) fake.output[0] = identity;
        if (variant == 1) fake.output[2] = identity;
        if (variant == 2) fake.output[0] = fake.output[2] = identity;
        check(resultRaw(sourceConfigRuntimeRequest(request("amnezia-awg"),fake.runner())) == config()); ++cases;
    }
    for (const auto &badId : {std::string(),std::string(63,'a'),std::string(65,'a'),std::string(64,'A'),identity+"\r\n",identity+"\n\n",identity+" ","\n"+identity,std::string(129,'a'),std::string(1,static_cast<char>(0xff))}) {
        for (const auto at : {0u,2u}) {
            Scripted fake; fake.output[at] = badId;
            rejects([&] { sourceConfigRuntimeRequest(request("amnezia-awg"),fake.runner()); });
            check(fake.calls.size() == at+1);
        }
    }
    { Scripted fake; fake.output[2] = std::string(64,'b')+'\n';
      rejects([&] { sourceConfigRuntimeRequest(request("amnezia-awg"),fake.runner()); }); check(fake.calls.size() == 3); }
    for (const auto &raw : {std::string(),std::string("owned private text"),std::string(1,static_cast<char>(0xff)),std::string(1024*1024+1,'x'),
        std::string("[Interface]\nPrivateKey=private-fixture\n"),config()+"[Interface]\n"}) {
        Scripted fake("amnezia-awg",raw);
        rejects([&] { sourceConfigRuntimeRequest(request("amnezia-awg"),fake.runner()); }); check(fake.calls.size() == 2);
    }
    for (unsigned at = 1;at <= 3;++at) {
        Scripted fake; fake.failAt = at;
        rejects([&] { sourceConfigRuntimeRequest(request("amnezia-awg"),fake.runner()); }); check(fake.calls.size() == at);
    }
    for (const auto &source : {"", "owned-id", "amnezia-awg-migration-1", "/amnezia-awg", "amnezia-awg;private", "amnezia-awg2-extra", "AMNEZIA-AWG"}) {
        Scripted fake; rejects([&] { sourceConfigRuntimeRequest(request(source),fake.runner()); }); check(fake.calls.empty());
    }
    for (const auto &raw : {"", "{}", "[]", "null", "{\"op\":true}", "{\"op\":\"unknown\"}",
        "{\"op\":\"read\",\"source\":true}", "{\"op\":\"read\",\"source\":\"amnezia-awg\\u0000suffix\"}",
        "{\"op\":\"read\",\"source\":\"amnezia-awg\",\"path\":\"private-fixture\"}",
        "{\"op\":\"capability\",\"source\":\"amnezia-awg\"}",
        "{\"op\":\"read\",\"source\":\"amnezia-awg\",\"source\":\"amnezia-awg2\"}",
        "{\"op\":\"capability\",\"ignored\":NaN}","{\"op\":\"capability\",\"ignored\":Infinity}"}) {
        Scripted fake; rejects([&] { sourceConfigRuntimeRequest(raw,fake.runner()); }); check(fake.calls.empty());
    }
    for (const auto &raw : {std::string(8193,' '),std::string("{\"op\":\"capabil")+static_cast<char>(0xff)+"ity\"}"}) {
        Scripted fake; rejects([&] { sourceConfigRuntimeRequest(raw,fake.runner()); }); check(fake.calls.empty());
    }
    for (const auto &args : std::vector<Args>{{},{"docker","stop",identity},{"docker","inspect","--format","{{.Id}}",identity},
        {"docker","inspect","--format","{{json .}}","amnezia-awg"},
        {"docker","exec","amnezia-awg","cat","/opt/amnezia/awg/wg0.conf"},
        {"docker","exec",identity,"cat","/etc/shadow"},{"docker","exec",identity,"sh","-c","cat private-fixture"}}) {
        rejects([&] { productionSourceConfigRunner()(args); });
        char marker = 0; check(::read(execTrace[0],&marker,1) < 0 && errno == EAGAIN);
    }
    ::close(execTrace[0]); ::close(execTrace[1]); unexpectedExecMarker = -1;
    std::cout << cases << " source config cases PASS; private scripted data and rejected production argv only\n";
}
