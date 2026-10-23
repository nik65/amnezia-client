// Test-only executable: exact owned response map and intercepted execve.
#include "network_topology_runtime.h"
#include "source_config_runtime.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

using namespace amnezia::awgMigration;
namespace {
struct Response { std::vector<std::string> args; std::string output; int status{}; unsigned delayMs{}, callIndex{}; };
std::vector<Response> responses;
[[noreturn]] void invalid() { throw NetworkTopologyError(); }
json_object *member(json_object *root, const char *key, json_type type) {
    json_object *value = nullptr;
    if (!root || !json_object_is_type(root,json_type_object) || !json_object_object_get_ex(root,key,&value)
        || !value || !json_object_is_type(value,type)) invalid();
    return value;
}
std::string string(json_object *value, std::size_t limit) {
    if (!value || !json_object_is_type(value,json_type_string)) invalid();
    std::string result(json_object_get_string(value),static_cast<std::size_t>(json_object_get_string_len(value)));
    if (result.size() > limit) invalid();
    return result;
}
unsigned number(json_object *root, const char *key, unsigned maximum) {
    json_object *value = nullptr;
    if (!json_object_object_get_ex(root,key,&value)) return 0;
    if (!value || !json_object_is_type(value,json_type_int)) invalid();
    const auto result = json_object_get_int64(value);
    if (result < 0 || result > maximum) invalid();
    return static_cast<unsigned>(result);
}
std::string readOwnedFixture() {
    const int fd = ::open("network-observer-fixture.json",O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) invalid();
    struct Close { int fd; ~Close() { ::close(fd); } } close{fd};
    struct stat before{}, after{};
    if (::fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_uid != ::geteuid()
        || before.st_nlink != 1 || before.st_size < 0 || before.st_size > 8*1024*1024) invalid();
    std::string raw;
    for (;;) {
        char buffer[8192]; const auto size = ::read(fd,buffer,sizeof buffer);
        if (size < 0 && errno == EINTR) continue;
        if (size < 0) invalid();
        if (!size) break;
        raw.append(buffer,static_cast<std::size_t>(size));
        if (raw.size() > 8*1024*1024) invalid();
    }
    if (::fstat(fd,&after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || before.st_ctim.tv_sec != after.st_ctim.tv_sec
        || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec || raw.size() != static_cast<std::size_t>(after.st_size)) invalid();
    return raw;
}
unsigned hexDigit(unsigned char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    invalid();
}
void load() {
    auto root = topologyDetail::parse(readOwnedFixture(),8*1024*1024);
    auto *items = member(root.get(),"responses",json_type_array);
    if (json_object_object_length(root.get()) != 1 || json_object_array_length(items) > 32) invalid();
    for (std::size_t i = 0;i < json_object_array_length(items);++i) {
        auto *item = json_object_array_get_idx(items,i);
        auto *args = member(item,"args",json_type_array);
        if (!json_object_array_length(args) || json_object_array_length(args) > 32) invalid();
        Response response;
        for (std::size_t k = 0;k < json_object_array_length(args);++k) {
            auto arg = string(json_object_array_get_idx(args,k),1024);
            if (arg.find('\0') != std::string::npos) invalid();
            response.args.push_back(std::move(arg));
        }
        json_object *output = nullptr, *hex = nullptr;
        const bool hasOutput = json_object_object_get_ex(item,"output",&output), hasHex = json_object_object_get_ex(item,"outputHex",&hex);
        if (hasOutput && hasHex) invalid();
        if (hasOutput) response.output = string(output,2*1024*1024);
        if (hasHex) {
            const auto encoded = string(hex,4*1024*1024);
            if (encoded.size() % 2) invalid();
            for (std::size_t k = 0;k < encoded.size();k += 2)
                response.output.push_back(static_cast<char>(16*hexDigit(encoded[k])+hexDigit(encoded[k+1])));
        }
        response.status = static_cast<int>(number(item,"status",255)); response.delayMs = number(item,"delayMs",10000);
        response.callIndex = number(item,"callIndex",32);
        json_object *ordinal = nullptr;
        if (json_object_object_get_ex(item,"callIndex",&ordinal) && !response.callIndex) invalid();
        json_object_object_foreach(item,key,value) {
            (void)value;
            const std::string name(key);
            if (name != "args" && name != "output" && name != "outputHex" && name != "status" && name != "delayMs" && name != "callIndex") invalid();
        }
        for (const auto &previous : responses) if (previous.args == response.args
            && (!previous.callIndex || !response.callIndex || previous.callIndex == response.callIndex)) invalid();
        responses.push_back(std::move(response));
    }
}
bool writeAll(int fd, const std::string &value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto count = ::write(fd,value.data()+offset,value.size()-offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return true;
}
unsigned trace(const std::vector<std::string> &args) {
    topologyDetail::Json row(json_object_new_array());
    for (const auto &arg : args) json_object_array_add(row.get(),json_object_new_string(arg.c_str()));
    const std::string output = std::string(json_object_to_json_string_ext(row.get(),JSON_C_TO_STRING_PLAIN))+'\n';
    const int fd = ::open("network-observer-trace.jsonl",O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,0600);
    if (fd < 0) _exit(112);
    struct stat info{};
    if (::fstat(fd,&info) || !S_ISREG(info.st_mode) || info.st_uid != ::geteuid() || info.st_nlink != 1
        || info.st_size < 0 || info.st_size > 65536) _exit(112);
    unsigned index = 1; std::size_t used = 0;
    for (;;) {
        char data[8192]; const auto count = ::read(fd,data,sizeof data);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) _exit(112);
        if (!count) break;
        used += static_cast<std::size_t>(count); if (used > 65536) _exit(112);
        for (ssize_t i = 0;i < count;++i) if (data[i] == '\n') ++index;
    }
    if (index > 32 || !writeAll(fd,output)) _exit(112);
    ::close(fd);
    return index;
}
}
extern "C" int execve(const char *path, char *const argv[], char *const[]) noexcept {
    try {
        if (std::strcmp(path,"/usr/bin/docker")) _exit(110);
        std::vector<std::string> args;
        for (std::size_t i = 0;argv[i];++i) {
            if (i >= 32) _exit(110);
            args.emplace_back(argv[i]);
        }
        if (args.empty() || args.front() != "/usr/bin/docker") _exit(110);
        args.front() = "docker";
        const auto callIndex = trace(args);
        for (const auto &response : responses) {
            if (response.args != args || (response.callIndex && response.callIndex != callIndex)) continue;
            timespec remaining{static_cast<time_t>(response.delayMs/1000),static_cast<long>(response.delayMs%1000)*1000000};
            while (::nanosleep(&remaining,&remaining) < 0 && errno == EINTR) {}
            if (!writeAll(STDOUT_FILENO,response.output)) _exit(112);
            _exit(response.status);
        }
        _exit(110);
    } catch (...) { _exit(111); }
}
int main(int argc, char **argv) {
    if (argc != 2 || (std::string(argv[1]) != "--network-json" && std::string(argv[1]) != "--source-config-json")) return 2;
    try { load(); return std::string(argv[1]) == "--network-json" ? networkTopologyJsonMain() : sourceConfigJsonMain(); }
    catch (...) { return 2; }
}
