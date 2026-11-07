// Actual production pool admission + HTTP policy. Every socket/proc/process
// boundary is the unchanged concurrency fixture's fake syscall ABI BEFORE entry.
#define main original_concurrency_fixture_main_not_executed
#define __wrap_accept4 original_fixture_accept4
#define __wrap_read original_fixture_read
#include "test_control_concurrency.cpp"
#undef __wrap_read
#undef __wrap_accept4
#undef main
#include <arpa/inet.h>

static std::atomic<int> refusedReads{0};
extern "C" int __wrap_accept4(int listener, struct sockaddr* peer, socklen_t* size, int flags) {
    const int fd = original_fixture_accept4(listener, peer, size, flags);
    if (fd == 99 && peer) {
        auto* value = reinterpret_cast<sockaddr_in*>(peer);
        ::inet_pton(AF_INET, "192.0.2.3", &value->sin_addr);
    }
    return fd;
}
extern "C" ssize_t __wrap_read(int fd, void* data, size_t size) {
    if (fd == 99) ++refusedReads;
    return original_fixture_read(fd, data, size);
}

int main(int argc, char** argv) {
    int failures = 0;
    FakeCapture capture;
    const auto elf = elfFixture(); capture.add(capture.nextFd, elf);
    FakeSink sink;
    auto transport = makePosixPoolTransport(18082);
    int dispatches = 0;
    ControlHooks hooks;
    hooks.allowPeer = [](const std::string& peer) { return peer == "127.0.0.1"; };
    hooks.dispatch = [&](const std::string&, const std::filesystem::path&) {
        ++dispatches; return std::string("{\"result\":{\"handled\":false,\"status\":403,\"body\":\"\",\"authenticate\":false}}");
    };
    ControlPid1Deps deps{capture, sink, *transport, [] { return std::string("12345"); }, hooks};
    ControlPid1Config config{"/app/awg-feed", "/migration", sha(elf), "target", "amnezia-awg"};
    { std::lock_guard<std::mutex> lock(g_ioMutex); g_acceptQueue.push_back(99); g_requests[99] = requestFor("/migration/v1/unknown"); }
    int runResult = -1;
    std::thread server([&] { runResult = controlPid1Run(config, deps); });
    const bool closed = waitForIo([] { return closeCount(99) == 1; }, 2000);
    transport->requestStop(); server.join(); transport.reset();
    const bool early = closed && !sentOn(99) && refusedReads == 0 && dispatches == 0 && runResult == 0;
    std::cout << "unmapped-peer closed=" << closed << " bytes-read=" << refusedReads << " response=" << sentOn(99)
              << " dispatched=" << dispatches << " expected=close-before-read-and-slot\n";
    if (!early) ++failures;
    ControlConfig policy{"fixture-unused", "target", "amnezia-awg"};
    const std::vector<std::pair<std::string,int>> cases = {
        {"GET / HTTP/1.1\r\nHost: control\r\n\r\n",501},
        {"POST /outside HTTP/1.1\r\nHost: control\r\n\r\n",404},
        {requestFor("/migration/v1/unknown"),403},
        {"POST /migration/v1/unknown HTTP/1.1\r\nHost: control\r\n\r\n",403}
    };
    for (std::size_t i=0;i<cases.size();++i) {
        const auto result = handleControlRequest(policy,hooks,cases[i].first,"127.0.0.1");
        std::cout << "http-policy case=" << i << " actual=" << result.status << " expected=" << cases[i].second << '\n';
        if (result.status != cases[i].second) ++failures;
    }
    if (g_unexpected || closeCount(listenerFd) != 1) ++failures;
    if (failures) return 1;
    if (argc==2 && std::string(argv[1])=="--fail-work") return 23;
    return 0;
}
