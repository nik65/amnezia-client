#include "source_config_runtime.h"
#include "bounded_docker.h"
#include "ready_config.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <iostream>
#include <json-c/json.h>
#include <memory>
#include <poll.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <set>
#include <unistd.h>

namespace amnezia::awgMigration {
namespace {
constexpr std::size_t inputLimit = 8*1024, rawLimit = 1024*1024, outputLimit = 8*1024*1024;
constexpr const char *idFormat = "{{.Id}}";
constexpr const char *awgConfig = "/opt/amnezia/awg/wg0.conf", *awg2Config = "/opt/amnezia/awg/awg0.conf";
[[noreturn]] void reject() { throw SourceConfigRuntimeError(); }
struct JsonDelete { void operator()(json_object *value) const noexcept { if (value) json_object_put(value); } };
using Json = std::unique_ptr<json_object,JsonDelete>;
struct UniqueKeys : rapidjson::BaseReaderHandler<rapidjson::UTF8<>,UniqueKeys> {
    struct Frame { bool object; std::set<std::string> keys; };
    std::vector<Frame> stack;
    bool StartObject() { if (stack.size() >= 32) return false; stack.push_back({true,{}}); return true; }
    bool StartArray() { if (stack.size() >= 32) return false; stack.push_back({false,{}}); return true; }
    bool EndObject(rapidjson::SizeType) { if (stack.empty() || !stack.back().object) return false; stack.pop_back(); return true; }
    bool EndArray(rapidjson::SizeType) { if (stack.empty() || stack.back().object) return false; stack.pop_back(); return true; }
    bool Key(const char *data, rapidjson::SizeType size, bool) {
        if (stack.empty() || !stack.back().object) return false;
        std::string key(data,size);
        return key.find('\0') == std::string::npos && stack.back().keys.insert(std::move(key)).second;
    }
};
Json parse(const std::string &raw) {
    if (raw.empty() || raw.size() > inputLimit || raw.find('\0') != std::string::npos) reject();
    rapidjson::MemoryStream stream(raw.data(),raw.size());
    rapidjson::Reader reader;
    UniqueKeys keys;
    if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream,keys)
        || !keys.stack.empty() || stream.Tell() != raw.size()) reject();
    auto tok = std::unique_ptr<json_tokener,decltype(&json_tokener_free)>(json_tokener_new_ex(32),json_tokener_free);
    if (!tok) reject();
    json_tokener_set_flags(tok.get(),JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    Json result(json_tokener_parse_ex(tok.get(),raw.data(),static_cast<int>(raw.size())));
    if (!result || json_tokener_get_error(tok.get()) != json_tokener_success || !json_object_is_type(result.get(),json_type_object)) reject();
    return result;
}
void exact(json_object *input, std::set<std::string> keys) {
    json_object_object_foreach(input,key,value) { (void)value; if (!keys.erase(key)) reject(); }
    if (!keys.empty()) reject();
}
std::string text(json_object *input, const char *key) {
    json_object *value = nullptr;
    if (!json_object_object_get_ex(input,key,&value) || !value || !json_object_is_type(value,json_type_string)) reject();
    std::string result(json_object_get_string(value),static_cast<std::size_t>(json_object_get_string_len(value)));
    if (result.find('\0') != std::string::npos) reject();
    return result;
}
bool sourceName(const std::string &value) { return value == "amnezia-awg" || value == "amnezia-awg2"; }
bool id(const std::string &value) {
    return value.size() == 64 && std::all_of(value.begin(),value.end(),[](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
std::size_t commandLimit(const std::vector<std::string> &args) {
    if (args.size() == 5 && args[0] == "docker" && args[1] == "inspect" && args[2] == "--format"
        && args[3] == idFormat && sourceName(args[4])) return 128;
    if (args.size() == 5 && args[0] == "docker" && args[1] == "exec" && id(args[2]) && args[3] == "cat"
        && (args[4] == awgConfig || args[4] == awg2Config)) return rawLimit;
    reject();
}
std::string capture(const SourceConfigRunner &runner, const std::vector<std::string> &args) {
    const auto limit = commandLimit(args);
    auto output = runner(args);
    if (output.size() > limit) reject();
    return output;
}
std::string capturedId(const std::string &raw) {
    std::string value = raw;
    if (value.size() == 65 && value.back() == '\n') value.pop_back();
    if (!id(value)) reject();
    return value;
}
std::string readConfig(const std::string &source, const SourceConfigRunner &runner) {
    if (!sourceName(source)) reject();
    const std::vector<std::string> inspect{"docker","inspect","--format",idFormat,source};
    const auto identity = capturedId(capture(runner,inspect));
    auto raw = capture(runner,{"docker","exec",identity,"cat",source == "amnezia-awg" ? awgConfig : awg2Config});
    // Parse immediately: invalid encoding/config does not cause another observation.
    static_cast<void>(parseConfig(raw));
    if (capturedId(capture(runner,inspect)) != identity) reject();
    return raw;
}
std::string readInput() {
    std::string raw;
    const auto deadline = std::chrono::steady_clock::now()+std::chrono::seconds(5);
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
        if (left <= 0) reject();
        pollfd fd{STDIN_FILENO,POLLIN,0};
        const auto ready = ::poll(&fd,1,static_cast<int>(left));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || (fd.revents & (POLLNVAL | POLLERR))) reject();
        std::array<char,1024> data{};
        const auto count = ::read(STDIN_FILENO,data.data(),data.size());
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) reject();
        if (!count) return raw;
        raw.append(data.data(),static_cast<std::size_t>(count));
        if (raw.size() > inputLimit) reject();
    }
}
}
std::string sourceConfigRuntimeRequest(const std::string &raw, const SourceConfigRunner &runner) {
    try {
        auto input = parse(raw);
        const auto op = text(input.get(),"op");
        Json value(json_object_new_object());
        if (op == "capability") {
            exact(input.get(),{"op"});
            json_object_object_add(value.get(),"sourceConfigVersion",json_object_new_int(1));
        } else if (op == "read") {
            exact(input.get(),{"op","source"});
            const auto source = text(input.get(),"source");
            const auto config = readConfig(source,runner);
            json_object_object_add(value.get(),"raw",json_object_new_string_len(config.data(),static_cast<int>(config.size())));
        } else reject();
        Json result(json_object_new_object());
        json_object_object_add(result.get(),"result",value.release());
        std::string output = json_object_to_json_string_ext(result.get(),JSON_C_TO_STRING_PLAIN);
        if (output.size() > outputLimit) reject();
        return output;
    } catch (...) { reject(); }
}
SourceConfigRunner productionSourceConfigRunner() {
    return [](const std::vector<std::string> &args) {
        try { return runBoundedDocker(args,commandLimit(args)); }
        catch (...) { reject(); }
    };
}
std::string sourceConfigRuntimeRequest(const std::string &raw) {
    return sourceConfigRuntimeRequest(raw,productionSourceConfigRunner());
}
int sourceConfigJsonMain(const SourceConfigRunner &runner) {
    try {
        std::cout << sourceConfigRuntimeRequest(readInput(),runner) << '\n';
        return 0;
    } catch (...) {
        std::cout << "{\"error\":\"native_source_config_rejected\"}\n";
        return 2;
    }
}
int sourceConfigJsonMain() { return sourceConfigJsonMain(productionSourceConfigRunner()); }
}
