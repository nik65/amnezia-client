#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <hvsocket.h>
#include <objbase.h>
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace {

constexpr wchar_t kSshServiceGuid[] = L"{5f2f2a1e-9c3a-4fa9-8f4d-31e9960d7c31}";
constexpr wchar_t kHttpServiceGuid[] = L"{6f3bdc8b-7b21-4df1-a3f5-6e4aaecf8f42}";
constexpr uint16_t kSshPort = 22222;
constexpr uint16_t kHttpPort = 17865;
constexpr uint16_t kGuestSshPort = 22222;
constexpr uint16_t kGuestHttpPort = 17865;
constexpr DWORD kPollMs = 250;
constexpr DWORD kConnectionDeadlineMs = 15 * 60 * 1000;

struct Channel { const wchar_t *name; const wchar_t *serviceGuid; uint16_t hostPort; uint16_t guestPort; };
constexpr Channel kSshChannel{L"ssh", kSshServiceGuid, kSshPort, kGuestSshPort};
constexpr Channel kHttpChannel{L"http", kHttpServiceGuid, kHttpPort, kGuestHttpPort};
static_assert(kSshPort == kGuestSshPort);
static_assert(kHttpPort == kGuestHttpPort);

struct Options {
    std::wstring mode, channel, vmId, runId, caseId, ownershipFile, receiptFile, helperSha256, stopEventName;
    DWORD parentPid = 0;
    std::uint64_t parentStart = 0;
    DWORD selfTestDelayMs = 0;
};
struct RelayContext {
    std::atomic_bool cancelled{false};
    std::atomic_bool failed{false};
    std::mutex socketsMutex;
    std::mutex listenerMutex;
    std::set<SOCKET> sockets;
    SOCKET listener = INVALID_SOCKET;
    HANDLE stopEvent = nullptr;
};

const Channel *channelFor(const std::wstring &name) {
    if (name == L"ssh") return &kSshChannel;
    if (name == L"http") return &kHttpChannel;
    return nullptr;
}
bool validLeaseId(const std::wstring &value)
{
    return !value.empty() && value.size() <= 96 && std::all_of(value.begin(), value.end(), [](wchar_t character) {
        return (character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z')
            || (character >= L'0' && character <= L'9') || character == L'.' || character == L'_' || character == L'-';
    });
}
bool parseGuid(const std::wstring &text, GUID &guid) { return CLSIDFromString(text.c_str(), &guid) == S_OK; }
bool isForbiddenVmId(const GUID &guid) {
    const GUID empty{};
    return IsEqualGUID(guid, empty) || IsEqualGUID(guid, HV_GUID_ZERO)
        || IsEqualGUID(guid, HV_GUID_WILDCARD) || IsEqualGUID(guid, HV_GUID_BROADCAST)
        || IsEqualGUID(guid, HV_GUID_CHILDREN) || IsEqualGUID(guid, HV_GUID_LOOPBACK)
        || IsEqualGUID(guid, HV_GUID_PARENT);
}
void closeSocket(SOCKET socketHandle) { if (socketHandle != INVALID_SOCKET) { shutdown(socketHandle, SD_BOTH); closesocket(socketHandle); } }
void addSocket(RelayContext &context, SOCKET socketHandle) { std::lock_guard lock(context.socketsMutex); context.sockets.insert(socketHandle); }
void removeSocket(RelayContext &context, SOCKET socketHandle) { std::lock_guard lock(context.socketsMutex); context.sockets.erase(socketHandle); }
SOCKET detachListener(RelayContext &context)
{
    std::lock_guard lock(context.listenerMutex);
    const SOCKET listener = context.listener;
    context.listener = INVALID_SOCKET;
    return listener;
}

void cancel(RelayContext &context) {
    context.cancelled.store(true);
    if (context.stopEvent) SetEvent(context.stopEvent);
    closeSocket(detachListener(context));
    std::lock_guard lock(context.socketsMutex);
    for (SOCKET socketHandle : context.sockets) shutdown(socketHandle, SD_BOTH);
}

std::wstring expectedStopEventName(const std::wstring &runId, const std::wstring &caseId)
{
    return L"Local\\AmneziaReleaseLabRelayStop_" + runId + L"_" + caseId;
}

HANDLE openStopEvent(const Options &options)
{
    HANDLE event = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, options.stopEventName.c_str());
    if (!event) throw std::runtime_error("relay owned stop event is unavailable");
    return event;
}

std::map<std::wstring, std::wstring> readLease(const std::wstring &path)
{
    std::wifstream input(path);
    if (!input) throw std::runtime_error("relay ownership file is not readable");
    std::map<std::wstring, std::wstring> values;
    std::wstring line;
    while (std::getline(input, line)) {
        const std::size_t separator = line.find(L'=');
        if (separator == std::wstring::npos || separator == 0) throw std::runtime_error("relay ownership line is malformed");
        if (!values.emplace(line.substr(0, separator), line.substr(separator + 1)).second) throw std::runtime_error("relay ownership key is duplicated");
    }
    return values;
}

std::uint64_t toUnsigned(const std::wstring &value, const char *label)
{
    try {
        if (value.empty()) throw std::runtime_error("empty value");
        std::uint64_t parsed = 0;
        for (const wchar_t character : value) {
            if (character < L'0' || character > L'9') throw std::runtime_error("non-decimal value");
            const std::uint64_t digit = static_cast<std::uint64_t>(character - L'0');
            if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10) throw std::runtime_error("overflow");
            parsed = parsed * 10 + digit;
        }
        return parsed;
    } catch (...) { throw std::runtime_error(std::string(label) + " is invalid"); }
}

std::uint64_t processStartTime(DWORD pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) throw std::runtime_error("parent process start time is unavailable");
    FILETIME creation{}, exitTime{}, kernel{}, user{};
    const BOOL read = GetProcessTimes(process, &creation, &exitTime, &kernel, &user);
    CloseHandle(process);
    if (!read) throw std::runtime_error("parent process start time read failed");
    ULARGE_INTEGER value{};
    value.LowPart = creation.dwLowDateTime;
    value.HighPart = creation.dwHighDateTime;
    return value.QuadPart;
}

std::wstring sha256File(const std::wstring &path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("relay executable hash input is unavailable");
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD resultLength = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0
        || BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                             reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0) != 0) {
        CloseHandle(file); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); throw std::runtime_error("relay hash provider unavailable");
    }
    std::vector<UCHAR> object(objectLength);
    std::array<UCHAR, 32> digest{};
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) != 0) {
        CloseHandle(file); BCryptCloseAlgorithmProvider(algorithm, 0); throw std::runtime_error("relay hash initialization failed");
    }
    std::array<UCHAR, 64 * 1024> buffer{};
    DWORD read = 0;
    bool ok = true;
    do {
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) { ok = false; break; }
        if (read && BCryptHashData(hash, buffer.data(), read, 0) != 0) { ok = false; break; }
    } while (read != 0);
    if (ok && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) ok = false;
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); CloseHandle(file);
    if (!ok) throw std::runtime_error("relay executable hash failed");
    static constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring result;
    for (UCHAR byte : digest) { result.push_back(digits[byte >> 4]); result.push_back(digits[byte & 0xf]); }
    return result;
}

HANDLE openVerifiedParent(DWORD parentPid, std::uint64_t expectedStart)
{
    HANDLE parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!parent) throw std::runtime_error("relay parent process is unavailable");
    FILETIME creation{}, exitTime{}, kernel{}, user{};
    ULARGE_INTEGER actual{};
    if (!GetProcessTimes(parent, &creation, &exitTime, &kernel, &user)) { CloseHandle(parent); throw std::runtime_error("relay parent start time read failed"); }
    actual.LowPart = creation.dwLowDateTime; actual.HighPart = creation.dwHighDateTime;
    if (actual.QuadPart != expectedStart) { CloseHandle(parent); throw std::runtime_error("relay parent start time does not match ownership lease"); }
    return parent;
}

std::thread watchParent(RelayContext &context, HANDLE parent)
{
    return std::thread([&context, parent] {
        HANDLE waits[2] = {parent, context.stopEvent};
        const DWORD count = context.stopEvent ? 2 : 1;
        const DWORD result = WaitForMultipleObjects(count, waits, FALSE, INFINITE);
        if (result == WAIT_OBJECT_0 || result == WAIT_FAILED) { context.failed.store(true); cancel(context); }
    });
}

std::thread watchStop(RelayContext &context, HANDLE stopEvent)
{
    return std::thread([&context, stopEvent] {
        const DWORD result = WaitForSingleObject(stopEvent, INFINITE);
        if (result == WAIT_FAILED) { context.failed.store(true); cancel(context); }
        else if (!context.cancelled.load()) cancel(context);
    });
}

void writeReceipt(const Options &options, const Channel &channel)
{
    const std::wstring temporary = options.receiptFile + L".tmp." + std::to_wstring(GetCurrentProcessId());
    std::wofstream receipt(temporary, std::ios::trunc);
    if (!receipt) throw std::runtime_error("relay receipt is not writable");
    receipt << L"schema=1\nmode=" << options.mode << L"\nchannel=" << channel.name
            << L"\nrun_id=" << options.runId << L"\ncase_id=" << options.caseId
            << L"\nvm_id=" << options.vmId << L"\nservice_guid=" << channel.serviceGuid
            << L"\nrelay_pid=" << GetCurrentProcessId() << L"\nrelay_start=" << processStartTime(GetCurrentProcessId())
            << L"\nparent_pid=" << options.parentPid << L"\nparent_start=" << options.parentStart
            << L"\nhelper_sha256=" << options.helperSha256 << L"\nstop_event=" << options.stopEventName << L"\nstate=running\n";
    receipt.flush();
    if (!receipt) { receipt.close(); DeleteFileW(temporary.c_str()); throw std::runtime_error("relay receipt write failed"); }
    receipt.close();
    if (!MoveFileExW(temporary.c_str(), options.receiptFile.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str()); throw std::runtime_error("relay receipt publish failed");
    }
}
void finishReceipt(const Options &options, bool failed)
{
    std::wofstream receipt(options.receiptFile, std::ios::app);
    if (!receipt) throw std::runtime_error("relay terminal receipt is not writable");
    receipt << L"state=" << (failed ? L"failed" : L"stopped") << L"\n";
    receipt.flush();
    if (!receipt) throw std::runtime_error("relay terminal receipt write failed");
}
SOCKADDR_HV hypervAddress(const GUID &vmId, const wchar_t *serviceGuid) {
    GUID service{};
    if (!parseGuid(serviceGuid, service)) throw std::runtime_error("fixed service GUID is invalid");
    SOCKADDR_HV address{}; address.Family = AF_HYPERV; address.VmId = vmId; address.ServiceId = service; return address;
}
SOCKET makeHypervSocket() {
    SOCKET socketHandle = ::socket(AF_HYPERV, SOCK_STREAM, HV_PROTOCOL_RAW);
    if (socketHandle == INVALID_SOCKET) throw std::runtime_error("AF_HYPERV socket creation failed");
    return socketHandle;
}
SOCKET makeLoopbackListener(uint16_t port) {
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) throw std::runtime_error("loopback listener creation failed");
    BOOL exclusive = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char *>(&exclusive), sizeof(exclusive));
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
    u_long nonBlocking = 1; ioctlsocket(listener, FIONBIO, &nonBlocking);
    if (::bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == SOCKET_ERROR || ::listen(listener, 1) == SOCKET_ERROR) { closeSocket(listener); throw std::runtime_error("loopback listener bind/listen failed"); }
    return listener;
}
void setNonBlocking(SOCKET socketHandle)
{
    u_long nonBlocking = 1;
    if (ioctlsocket(socketHandle, FIONBIO, &nonBlocking) != 0) throw std::runtime_error("relay socket nonblocking mode failed");
}

SOCKET connectWithDeadline(RelayContext *context, SOCKET socketHandle, const sockaddr *address, int addressLength, const char *errorLabel, DWORD injectedSetupDelayMs = 0)
{
    if (injectedSetupDelayMs) {
        const ULONGLONG setupDeadline = GetTickCount64() + injectedSetupDelayMs;
        while (!context || !context->cancelled.load()) { if (GetTickCount64() >= setupDeadline) break; Sleep(kPollMs); }
    }
    if (context && context->cancelled.load()) { closeSocket(socketHandle); throw std::runtime_error(std::string(errorLabel) + " cancelled"); }
    setNonBlocking(socketHandle);
    if (::connect(socketHandle, address, addressLength) == 0) return socketHandle;
    const int connectError = WSAGetLastError();
    if (connectError != WSAEWOULDBLOCK && connectError != WSAEINPROGRESS && connectError != WSAEALREADY) {
        closeSocket(socketHandle); throw std::runtime_error(errorLabel);
    }
    const ULONGLONG deadline = GetTickCount64() + kConnectionDeadlineMs;
    while (context == nullptr || !context->cancelled.load()) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) { closeSocket(socketHandle); throw std::runtime_error(std::string(errorLabel) + " timeout"); }
        const DWORD remaining = static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, kPollMs));
        fd_set writeSet; FD_ZERO(&writeSet); FD_SET(socketHandle, &writeSet);
        fd_set errorSet; FD_ZERO(&errorSet); FD_SET(socketHandle, &errorSet);
        timeval timeout{0, static_cast<long>(remaining) * 1000};
        const int ready = select(0, nullptr, &writeSet, &errorSet, &timeout);
        if (ready == SOCKET_ERROR) { closeSocket(socketHandle); throw std::runtime_error(std::string(errorLabel) + " select failed"); }
        if (ready == 0) continue;
        int socketError = 0; int errorLength = sizeof(socketError);
        if (getsockopt(socketHandle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&socketError), &errorLength) == SOCKET_ERROR || socketError != 0) {
            closeSocket(socketHandle); throw std::runtime_error(errorLabel);
        }
        return socketHandle;
    }
    closeSocket(socketHandle);
    throw std::runtime_error(std::string(errorLabel) + " cancelled");
}

SOCKET connectLoopback(RelayContext *context, uint16_t port) {
    SOCKET socketHandle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketHandle == INVALID_SOCKET) throw std::runtime_error("loopback socket creation failed");
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
    return connectWithDeadline(context, socketHandle, reinterpret_cast<const sockaddr *>(&address), sizeof(address), "fixed loopback target connection failed");
}
SOCKET connectParent(RelayContext &context, const Channel &channel) {
    SOCKET socketHandle = makeHypervSocket();
    const SOCKADDR_HV address = hypervAddress(HV_GUID_PARENT, channel.serviceGuid);
    return connectWithDeadline(&context, socketHandle, reinterpret_cast<const sockaddr *>(&address), sizeof(address), "AF_HYPERV parent connection failed");
}
void pump(RelayContext &context, SOCKET source, SOCKET destination, DWORD deadlineMs = kConnectionDeadlineMs) {
    setNonBlocking(source); setNonBlocking(destination);
    const ULONGLONG deadline = GetTickCount64() + deadlineMs;
    std::array<char, 64 * 1024> buffer{};
    while (!context.cancelled.load()) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) { context.failed.store(true); cancel(context); return; }
        const DWORD remaining = static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, kPollMs));
        fd_set readSet; FD_ZERO(&readSet); FD_SET(source, &readSet); timeval timeout{0, static_cast<long>(remaining) * 1000};
        const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR) { if (!context.cancelled.load()) { context.failed.store(true); cancel(context); } return; }
        if (ready == 0) continue;
        const int received = recv(source, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (received == 0) break;
        if (received < 0) { if (!context.cancelled.load()) { context.failed.store(true); cancel(context); } return; }
        int offset = 0;
        while (offset < received && !context.cancelled.load()) {
            const ULONGLONG sendNow = GetTickCount64();
            if (sendNow >= deadline) { context.failed.store(true); cancel(context); return; }
            const DWORD sendRemaining = static_cast<DWORD>(std::min<ULONGLONG>(deadline - sendNow, kPollMs));
            fd_set writeSet; FD_ZERO(&writeSet); FD_SET(destination, &writeSet); timeval sendTimeout{0, static_cast<long>(sendRemaining) * 1000};
            const int writable = select(0, nullptr, &writeSet, nullptr, &sendTimeout);
            if (writable == SOCKET_ERROR) { if (!context.cancelled.load()) { context.failed.store(true); cancel(context); } return; }
            if (writable == 0) continue;
            const int sent = send(destination, buffer.data() + offset, received - offset, 0);
            if (sent <= 0) { if (!context.cancelled.load()) { context.failed.store(true); cancel(context); } return; }
            offset += sent;
        }
    }
    shutdown(destination, SD_SEND);
}
SOCKET currentListener(RelayContext &context) { std::lock_guard lock(context.listenerMutex); return context.listener; }
void relayPair(RelayContext &context, SOCKET left, SOCKET right) {
    RelayContext pairContext;
    addSocket(context, left); addSocket(context, right);
    addSocket(pairContext, left); addSocket(pairContext, right);
    std::thread leftToRight(pump, std::ref(pairContext), left, right, kConnectionDeadlineMs); std::thread rightToLeft(pump, std::ref(pairContext), right, left, kConnectionDeadlineMs);
    leftToRight.join(); rightToLeft.join(); removeSocket(pairContext, left); removeSocket(pairContext, right); removeSocket(context, left); removeSocket(context, right); closeSocket(left); closeSocket(right);
}

void cleanupRelay(RelayContext &context, HANDLE &parent, HANDLE &stopEvent, std::thread &parentWatcher, std::thread &stopWatcher)
{
    cancel(context);
    if (parentWatcher.joinable()) parentWatcher.join();
    if (stopWatcher.joinable()) stopWatcher.join();
    closeSocket(detachListener(context));
    if (parent) { CloseHandle(parent); parent = nullptr; }
    if (stopEvent) { CloseHandle(stopEvent); stopEvent = nullptr; context.stopEvent = nullptr; }
}

int loopbackDaemon(const Options &options, const Channel &channel, bool selfTestMode)
{
    RelayContext context;
    HANDLE parent = nullptr; HANDLE stopEvent = nullptr;
    std::thread parentWatcher; std::thread stopWatcher;
    try {
        parent = openVerifiedParent(options.parentPid, options.parentStart);
        stopEvent = openStopEvent(options); context.stopEvent = stopEvent;
        // Self-tests must never claim the production relay ports: the lab may
        // exercise them concurrently. The daemon only needs an ephemeral
        // listener for its accept/close probe.
        context.listener = makeLoopbackListener(selfTestMode ? 0 : channel.guestPort);
        if (options.selfTestDelayMs) Sleep(options.selfTestDelayMs);
        writeReceipt(options, channel);
        parentWatcher = watchParent(context, parent);
        stopWatcher = watchStop(context, stopEvent);
        while (!context.cancelled.load()) {
            const SOCKET listener = currentListener(context); if (listener == INVALID_SOCKET) break;
            fd_set readSet; FD_ZERO(&readSet); FD_SET(listener, &readSet); timeval timeout{0, static_cast<long>(kPollMs) * 1000};
            const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR) { context.failed.store(true); break; }
            if (ready == 0) continue;
            SOCKET accepted = accept(listener, nullptr, nullptr);
            if (accepted == INVALID_SOCKET) { if (context.cancelled.load() || WSAGetLastError() == WSAEWOULDBLOCK) continue; context.failed.store(true); break; }
            closeSocket(accepted);
        }
        cleanupRelay(context, parent, stopEvent, parentWatcher, stopWatcher);
        bool failed = context.failed.load();
        try { finishReceipt(options, failed); } catch (const std::exception &error) { std::wcerr << error.what() << L'\n'; failed = true; }
        return failed ? 70 : 0;
    } catch (...) {
        cleanupRelay(context, parent, stopEvent, parentWatcher, stopWatcher);
        throw;
    }
}

int hostRelay(const Options &options, const Channel &channel, const GUID &childVmId) {
    if (isForbiddenVmId(childVmId)) throw std::runtime_error("host relay requires exact child VM ID");
    RelayContext context; HANDLE parent = nullptr; HANDLE stopEvent = nullptr;
    std::thread parentWatcher; std::thread stopWatcher;
    try {
        parent = openVerifiedParent(options.parentPid, options.parentStart);
        stopEvent = openStopEvent(options); context.stopEvent = stopEvent;
        context.listener = makeHypervSocket(); u_long nonBlocking = 1; ioctlsocket(context.listener, FIONBIO, &nonBlocking); const SOCKADDR_HV address = hypervAddress(childVmId, channel.serviceGuid);
        if (::bind(context.listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == SOCKET_ERROR || ::listen(context.listener, 1) == SOCKET_ERROR) throw std::runtime_error("AF_HYPERV host relay bind/listen failed");
        writeReceipt(options, channel);
        parentWatcher = watchParent(context, parent);
        stopWatcher = watchStop(context, stopEvent);
        while (!context.cancelled.load()) {
            const SOCKET listener = currentListener(context); if (listener == INVALID_SOCKET) break;
            fd_set readSet; FD_ZERO(&readSet); FD_SET(listener, &readSet); timeval timeout{0, static_cast<long>(kPollMs) * 1000}; const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR) { context.failed.store(true); break; } if (ready == 0) continue;
            SOCKET accepted = accept(listener, nullptr, nullptr); if (accepted == INVALID_SOCKET) { if (context.cancelled.load() || WSAGetLastError() == WSAEWOULDBLOCK) continue; context.failed.store(true); break; }
            try { relayPair(context, accepted, connectLoopback(&context, channel.hostPort)); } catch (...) { if (!context.cancelled.load()) context.failed.store(true); cancel(context); closeSocket(accepted); }
        }
        cleanupRelay(context, parent, stopEvent, parentWatcher, stopWatcher);
        bool failed = context.failed.load();
        try { finishReceipt(options, failed); } catch (const std::exception &error) { std::wcerr << error.what() << L'\n'; failed = true; }
        return failed ? 70 : 0;
    } catch (...) {
        cleanupRelay(context, parent, stopEvent, parentWatcher, stopWatcher);
        throw;
    }
}
int guestProxy(const Options &options, const Channel &channel) {
    RelayContext context; HANDLE parent = nullptr; HANDLE stopEvent = nullptr;
    std::thread parentWatcher; std::thread stopWatcher;
    try {
        parent = openVerifiedParent(options.parentPid, options.parentStart);
        stopEvent = openStopEvent(options); context.stopEvent = stopEvent;
        context.listener = makeLoopbackListener(channel.guestPort);
        writeReceipt(options, channel);
        parentWatcher = watchParent(context, parent);
        stopWatcher = watchStop(context, stopEvent);
        while (!context.cancelled.load()) {
            const SOCKET listener = currentListener(context); if (listener == INVALID_SOCKET) break;
            fd_set readSet; FD_ZERO(&readSet); FD_SET(listener, &readSet); timeval timeout{0, static_cast<long>(kPollMs) * 1000}; const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR) { context.failed.store(true); break; } if (ready == 0) continue;
            SOCKET accepted = accept(listener, nullptr, nullptr); if (accepted == INVALID_SOCKET) { if (context.cancelled.load() || WSAGetLastError() == WSAEWOULDBLOCK) continue; context.failed.store(true); break; }
            try { relayPair(context, accepted, connectParent(context, channel)); } catch (...) { if (!context.cancelled.load()) context.failed.store(true); cancel(context); closeSocket(accepted); }
        }
        cleanupRelay(context, parent, stopEvent, parentWatcher, stopWatcher);
        bool failed = context.failed.load();
        try { finishReceipt(options, failed); } catch (const std::exception &error) { std::wcerr << error.what() << L'\n'; failed = true; }
        return failed ? 70 : 0;
    } catch (...) {
        cleanupRelay(context, parent, stopEvent, parentWatcher, stopWatcher);
        throw;
    }
}
int selfTest() {
    GUID ssh{}; GUID http{}; if (!parseGuid(kSshServiceGuid, ssh) || !parseGuid(kHttpServiceGuid, http) || IsEqualGUID(ssh, http) || isForbiddenVmId(ssh)) return 2;
    if (!channelFor(L"ssh") || !channelFor(L"http") || channelFor(L"tcp") != nullptr) return 3;
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 4;
    int result = 0;
    try {
        const auto portOf = [](SOCKET listener) {
            sockaddr_in address{}; int length = sizeof(address);
            if (getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) == SOCKET_ERROR) throw std::runtime_error("self-test getsockname failed");
            return ntohs(address.sin_port);
        };
        SOCKET leftListener = makeLoopbackListener(0); SOCKET rightListener = makeLoopbackListener(0);
        SOCKET leftClient = connectLoopback(nullptr, portOf(leftListener)); SOCKET leftServer = accept(leftListener, nullptr, nullptr);
        SOCKET rightClient = connectLoopback(nullptr, portOf(rightListener)); SOCKET rightServer = accept(rightListener, nullptr, nullptr);
        u_long blocking = 0; ioctlsocket(leftClient, FIONBIO, &blocking); ioctlsocket(rightClient, FIONBIO, &blocking);
        closeSocket(leftListener); closeSocket(rightListener);
        RelayContext context;
        std::thread transfer(pump, std::ref(context), leftServer, rightServer, kConnectionDeadlineMs);
        std::vector<char> payload(1024 * 1024, 'A');
        std::vector<char> receivedPayload(payload.size());
        std::atomic_bool readerOk{true};
        std::thread reader([&] {
            std::size_t receivedTotal = 0;
            while (receivedTotal < receivedPayload.size()) {
                const int received = recv(rightClient, receivedPayload.data() + receivedTotal, static_cast<int>(receivedPayload.size() - receivedTotal), 0);
                if (received <= 0) { readerOk.store(false); return; }
                receivedTotal += static_cast<std::size_t>(received);
            }
        });
        for (std::size_t offset = 0; offset < payload.size();) {
            const int sent = send(leftClient, payload.data() + offset, static_cast<int>(std::min<std::size_t>(65536, payload.size() - offset)), 0);
            if (sent <= 0) { readerOk.store(false); break; }
            offset += static_cast<std::size_t>(sent);
        }
        shutdown(leftClient, SD_SEND);
        reader.join();
        cancel(context); transfer.join();
        if (!readerOk.load() || receivedPayload != payload) {
            std::wcerr << L"readerOk=" << (readerOk.load() ? 1 : 0) << L" failed=" << (context.failed.load() ? 1 : 0) << L'\n';
            throw std::runtime_error("self-test loopback transfer failed");
        }
        closeSocket(leftClient); closeSocket(rightClient);

        const auto makePair = [](SOCKET &client, SOCKET &server) {
            SOCKET listener = makeLoopbackListener(0);
            sockaddr_in address{}; int length = sizeof(address);
            if (getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) == SOCKET_ERROR) { closeSocket(listener); throw std::runtime_error("self-test pair address failed"); }
            client = connectLoopback(nullptr, ntohs(address.sin_port));
            server = accept(listener, nullptr, nullptr); closeSocket(listener);
            if (server == INVALID_SOCKET) { closeSocket(client); throw std::runtime_error("self-test pair accept failed"); }
            u_long blockingMode = 0; ioctlsocket(client, FIONBIO, &blockingMode);
        };

        // An idle peer must terminate at the short injected deadline and mark
        // the relay failed; this exercises the actual pump deadline path.
        {
            SOCKET sourceClient = INVALID_SOCKET, sourceServer = INVALID_SOCKET;
            SOCKET destinationClient = INVALID_SOCKET, destinationServer = INVALID_SOCKET;
            makePair(sourceClient, sourceServer); makePair(destinationClient, destinationServer);
            RelayContext timeoutContext;
            std::thread timeoutPump(pump, std::ref(timeoutContext), sourceServer, destinationServer, 250);
            timeoutPump.join();
            if (!timeoutContext.failed.load()) throw std::runtime_error("self-test idle timeout was not failed");
            closeSocket(sourceClient); closeSocket(destinationClient); closeSocket(sourceServer); closeSocket(destinationServer);
        }

        // Cancellation must wake the pump without turning an intentional stop
        // into a transport failure.
        {
            SOCKET sourceClient = INVALID_SOCKET, sourceServer = INVALID_SOCKET;
            SOCKET destinationClient = INVALID_SOCKET, destinationServer = INVALID_SOCKET;
            makePair(sourceClient, sourceServer); makePair(destinationClient, destinationServer);
            RelayContext cancelContext;
            std::thread cancelPump(pump, std::ref(cancelContext), sourceServer, destinationServer, 3000);
            Sleep(50); cancel(cancelContext); cancelPump.join();
            if (cancelContext.failed.load()) throw std::runtime_error("self-test cancellation became failed");
            closeSocket(sourceClient); closeSocket(destinationClient); closeSocket(sourceServer); closeSocket(destinationServer);
        }

        // Resetting the destination peer must be reported as a failed send and
        // must not leave a blocking send behind the bounded pump deadline.
        {
            SOCKET sourceClient = INVALID_SOCKET, sourceServer = INVALID_SOCKET;
            SOCKET destinationClient = INVALID_SOCKET, destinationServer = INVALID_SOCKET;
            makePair(sourceClient, sourceServer); makePair(destinationClient, destinationServer);
            linger reset{1, 0}; setsockopt(destinationClient, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char *>(&reset), sizeof(reset));
            closeSocket(destinationClient);
            RelayContext resetContext;
            std::thread resetPump(pump, std::ref(resetContext), sourceServer, destinationServer, 2000);
            std::vector<char> resetPayload(256 * 1024, 'R');
            for (std::size_t offset = 0; offset < resetPayload.size(); offset += 64 * 1024) {
                const int sent = send(sourceClient, resetPayload.data() + offset, static_cast<int>(std::min<std::size_t>(64 * 1024, resetPayload.size() - offset)), 0);
                if (sent <= 0) break;
            }
            shutdown(sourceClient, SD_SEND);
            resetPump.join();
            if (!resetContext.failed.load()) throw std::runtime_error("self-test reset was not failed");
            closeSocket(sourceClient); closeSocket(sourceServer); closeSocket(destinationServer);
        }

        // A cancellation that races the connect setup must remain an
        // intentional stop, rather than becoming a transport failure.
        {
            RelayContext connectCancelContext;
            SOCKET socketHandle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(1);
            bool cancelled = false;
            std::thread connectThread([&] {
                try { connectWithDeadline(&connectCancelContext, socketHandle, reinterpret_cast<const sockaddr *>(&address), sizeof(address), "self-test connect", 500); }
                catch (const std::exception &error) { cancelled = std::string(error.what()).find("cancelled") != std::string::npos; }
            });
            Sleep(50); connectCancelContext.cancelled.store(true); connectThread.join();
            if (!cancelled) throw std::runtime_error("self-test connect cancellation was not preserved");
        }
    } catch (const std::exception &error) {
        std::wcerr << L"self-test: " << error.what() << L'\n';
        result = 5;
    } catch (...) {
        result = 5;
    }
    WSACleanup();
    return result;
}
std::wstring argument(const std::vector<std::wstring> &args, const wchar_t *name) { for (std::size_t index = 0; index + 1 < args.size(); ++index) if (args[index] == name) return args[index + 1]; return {}; }
}
int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && std::wstring(argv[1]) == L"--self-test") return selfTest();
    std::vector<std::wstring> args; for (int index = 1; index < argc; ++index) args.emplace_back(argv[index]);
    const std::set<std::wstring> allowed = {L"--mode", L"--channel", L"--vm-id", L"--run-id", L"--case-id", L"--ownership-file", L"--receipt-path", L"--helper-sha256", L"--parent-pid", L"--parent-start", L"--stop-event-name", L"--self-test-daemon", L"--self-test-daemon-delay"}; std::set<std::wstring> seen;
    bool loopbackDaemonMode = false;
    for (std::size_t index = 0; index < args.size(); ++index) {
        if (args[index] == L"--self-test-daemon") { if (!seen.insert(args[index]).second) return 64; loopbackDaemonMode = true; continue; }
        if (allowed.count(args[index]) == 0 || index + 1 >= args.size() || !seen.insert(args[index]).second) return 64; ++index;
    }
    Options options; options.mode = argument(args, L"--mode"); options.channel = argument(args, L"--channel"); options.vmId = argument(args, L"--vm-id"); options.runId = argument(args, L"--run-id"); options.caseId = argument(args, L"--case-id"); options.ownershipFile = argument(args, L"--ownership-file"); options.receiptFile = argument(args, L"--receipt-path"); options.helperSha256 = argument(args, L"--helper-sha256"); options.stopEventName = argument(args, L"--stop-event-name");
    const std::wstring parentPidText = argument(args, L"--parent-pid"); const std::wstring parentStartText = argument(args, L"--parent-start");
    if (options.mode != L"host" && options.mode != L"guest") return 64; const Channel *channel = channelFor(options.channel); GUID vmId{};
    if (channel == nullptr || !validLeaseId(options.runId) || !validLeaseId(options.caseId) || options.ownershipFile.empty() || options.receiptFile.empty() || options.helperSha256.size() != 64 || options.stopEventName != expectedStopEventName(options.runId, options.caseId) || parentPidText.empty() || parentStartText.empty() || !parseGuid(options.vmId, vmId)) return 64;
    std::uint64_t parentPidValue = 0;
    try { parentPidValue = toUnsigned(parentPidText, "parent pid"); }
    catch (const std::exception &) { return 64; }
    if (parentPidValue == 0 || parentPidValue > static_cast<std::uint64_t>(MAXDWORD)) return 64;
    options.parentPid = static_cast<DWORD>(parentPidValue);
    try { options.parentStart = toUnsigned(parentStartText, "parent start"); }
    catch (const std::exception &) { return 64; }
    const std::wstring delayText = argument(args, L"--self-test-daemon-delay");
    if (!delayText.empty()) { try { const std::uint64_t delay = toUnsigned(delayText, "self-test daemon delay"); if (delay > 120000) return 64; options.selfTestDelayMs = static_cast<DWORD>(delay); } catch (const std::exception &) { return 64; } }
    try {
        const auto lease = readLease(options.ownershipFile);
        for (const wchar_t *key : {L"run_id", L"case_id", L"vm_id", L"helper_sha256", L"parent_pid", L"parent_start", L"stop_event", L"state"}) if (lease.count(key) == 0) return 64;
        if (lease.at(L"run_id") != options.runId || lease.at(L"case_id") != options.caseId || lease.at(L"vm_id") != options.vmId || lease.at(L"helper_sha256") != options.helperSha256 || lease.at(L"stop_event") != options.stopEventName || lease.at(L"state") != L"relay-authorized" || toUnsigned(lease.at(L"parent_pid"), "lease parent pid") != options.parentPid || toUnsigned(lease.at(L"parent_start"), "lease parent start") != options.parentStart) return 64;
    } catch (const std::exception &) { return 64; }
    wchar_t modulePath[MAX_PATH]{};
    const DWORD moduleLength = GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
    if (moduleLength == 0 || moduleLength >= std::size(modulePath) || sha256File(modulePath) != options.helperSha256) return 64;
    WSADATA winsock{}; if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 69;
    try { const int result = loopbackDaemonMode ? loopbackDaemon(options, *channel, true) : (options.mode == L"host" ? hostRelay(options, *channel, vmId) : guestProxy(options, *channel)); WSACleanup(); return result; } catch (const std::exception &error) { std::wcerr << error.what() << L'\n'; std::wofstream failure(options.receiptFile + L".error", std::ios::trunc); if (failure) failure << error.what() << L'\n'; WSACleanup(); return 70; }
}
