#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace {

constexpr DWORD kPollMs = 100;
constexpr DWORD kReceiptDrainMs = 5000;

struct Options {
    std::wstring relayExe, mode, channel, vmId, runId, caseId, ownershipFile, receiptFile, helperSha256;
    DWORD readyTimeoutMs = 15000;
    bool loopbackTest = false;
    bool parentLossTest = false;
    bool delayedReadyTest = false;
};

std::wstring valueOf(const std::vector<std::wstring> &args, const wchar_t *name)
{
    for (std::size_t index = 0; index + 1 < args.size(); ++index) if (args[index] == name) return args[index + 1];
    return {};
}

bool validId(const std::wstring &value)
{
    return !value.empty() && value.size() <= 96 && std::all_of(value.begin(), value.end(), [](wchar_t character) {
        return (character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z')
            || (character >= L'0' && character <= L'9') || character == L'.' || character == L'_' || character == L'-';
    });
}

bool parseTimeout(const std::wstring &value, DWORD &parsed)
{
    if (value.empty()) return false;
    std::uint64_t number = 0;
    for (wchar_t character : value) {
        if (character < L'0' || character > L'9') return false;
        const std::uint64_t digit = static_cast<std::uint64_t>(character - L'0');
        if (number > (120000 - digit) / 10) return false;
        number = number * 10 + digit;
    }
    if (number == 0) return false;
    parsed = static_cast<DWORD>(number); return true;
}

std::wstring stopEventName(const Options &options)
{
    return L"Local\\AmneziaReleaseLabRelayStop_" + options.runId + L"_" + options.caseId;
}

std::uint64_t processStartTime(DWORD pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) throw std::runtime_error("supervisor process start time is unavailable");
    FILETIME creation{}, exitTime{}, kernel{}, user{};
    const BOOL read = GetProcessTimes(process, &creation, &exitTime, &kernel, &user);
    CloseHandle(process);
    if (!read) throw std::runtime_error("supervisor process start time read failed");
    ULARGE_INTEGER value{}; value.LowPart = creation.dwLowDateTime; value.HighPart = creation.dwHighDateTime;
    return value.QuadPart;
}

std::wstring sha256File(const std::wstring &path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("supervisor helper hash input is unavailable");
    BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr; DWORD objectLength = 0; DWORD resultLength = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0
        || BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0) != 0) {
        CloseHandle(file); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); throw std::runtime_error("supervisor hash provider unavailable");
    }
    std::vector<UCHAR> object(objectLength); std::array<UCHAR, 32> digest{};
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) != 0) {
        CloseHandle(file); BCryptCloseAlgorithmProvider(algorithm, 0); throw std::runtime_error("supervisor hash initialization failed");
    }
    std::array<UCHAR, 64 * 1024> buffer{}; DWORD read = 0; bool ok = true;
    do {
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) { ok = false; break; }
        if (read && BCryptHashData(hash, buffer.data(), read, 0) != 0) { ok = false; break; }
    } while (read != 0);
    if (ok && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) ok = false;
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); CloseHandle(file);
    if (!ok) throw std::runtime_error("supervisor helper hash failed");
    static constexpr wchar_t digits[] = L"0123456789abcdef"; std::wstring result;
    for (UCHAR byte : digest) { result.push_back(digits[byte >> 4]); result.push_back(digits[byte & 0xf]); }
    return result;
}

std::map<std::wstring, std::wstring> readMap(const std::wstring &path)
{
    std::wifstream input(path); if (!input) throw std::runtime_error("supervisor metadata is unreadable");
    std::map<std::wstring, std::wstring> values; std::wstring line;
    while (std::getline(input, line)) {
        const std::size_t separator = line.find(L'=');
        if (separator == std::wstring::npos || separator == 0 || !values.emplace(line.substr(0, separator), line.substr(separator + 1)).second) throw std::runtime_error("supervisor metadata is malformed");
    }
    return values;
}

std::map<std::wstring, std::wstring> readReceipt(const std::wstring &path)
{
    std::wifstream input(path); if (!input) throw std::runtime_error("supervisor receipt is unreadable");
    std::map<std::wstring, std::wstring> values; std::wstring line;
    while (std::getline(input, line)) {
        const std::size_t separator = line.find(L'=');
        if (separator == std::wstring::npos || separator == 0) throw std::runtime_error("supervisor receipt is malformed");
        const std::wstring key = line.substr(0, separator);
        const std::wstring value = line.substr(separator + 1);
        if (key == L"state") values[key] = value;
        else if (!values.emplace(key, value).second) throw std::runtime_error("supervisor receipt key is duplicated");
    }
    return values;
}

void atomicWrite(const std::wstring &path, const std::wstring &content)
{
    const std::wstring temporary = path + L".tmp." + std::to_wstring(GetCurrentProcessId());
    std::wofstream output(temporary, std::ios::trunc);
    if (!output) throw std::runtime_error("supervisor metadata is not writable");
    output << content; output.flush();
    if (!output) { output.close(); DeleteFileW(temporary.c_str()); throw std::runtime_error("supervisor metadata write failed"); }
    output.close();
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { DeleteFileW(temporary.c_str()); throw std::runtime_error("supervisor metadata publish failed"); }
}

void writeLease(const Options &options, std::uint64_t parentStart)
{
    if (GetFileAttributesW(options.ownershipFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
        const auto existing = readMap(options.ownershipFile);
        for (const wchar_t *key : {L"run_id", L"case_id", L"vm_id", L"helper_sha256"}) if (existing.count(key) == 0) throw std::runtime_error("existing ownership lease is incomplete");
        if (existing.at(L"run_id") != options.runId || existing.at(L"case_id") != options.caseId || existing.at(L"vm_id") != options.vmId || existing.at(L"helper_sha256") != options.helperSha256) throw std::runtime_error("existing ownership lease belongs to another run");
    }
    std::wstring content = L"schema=1\nrun_id=" + options.runId + L"\ncase_id=" + options.caseId + L"\nvm_id=" + options.vmId
        + L"\nhelper_sha256=" + options.helperSha256 + L"\nparent_pid=" + std::to_wstring(GetCurrentProcessId())
        + L"\nparent_start=" + std::to_wstring(parentStart) + L"\nstop_event=" + stopEventName(options) + L"\nstate=relay-authorized\n";
    atomicWrite(options.ownershipFile, content);
}

void quarantineReceipt(const Options &options)
{
    if (GetFileAttributesW(options.receiptFile.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    const auto existing = readReceipt(options.receiptFile);
    if (existing.count(L"run_id") == 0 || existing.at(L"run_id") != options.runId || existing.count(L"case_id") == 0 || existing.at(L"case_id") != options.caseId) throw std::runtime_error("existing receipt is not owned by this run");
    const std::wstring quarantine = options.receiptFile + L".preexisting." + std::to_wstring(GetCurrentProcessId());
    if (!MoveFileExW(options.receiptFile.c_str(), quarantine.c_str(), MOVEFILE_WRITE_THROUGH)) throw std::runtime_error("preexisting receipt cannot be quarantined");
}

std::wstring quoteArg(const std::wstring &value)
{
    if (value.find(L'"') != std::wstring::npos) throw std::runtime_error("supervisor argument contains a quote");
    return L"\"" + value + L"\"";
}

bool receiptReady(const Options &options, std::wstring *state = nullptr)
{
    try {
        const auto receipt = readReceipt(options.receiptFile);
        if (receipt.at(L"run_id") != options.runId || receipt.at(L"case_id") != options.caseId || receipt.at(L"vm_id") != options.vmId || receipt.at(L"stop_event") != stopEventName(options)) return false;
        if (state) *state = receipt.at(L"state");
        return true;
    } catch (...) { return false; }
}

HANDLE createKillOnCloseJob()
{
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) throw std::runtime_error("supervisor job creation failed");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { CloseHandle(job); throw std::runtime_error("supervisor job policy failed"); }
    return job;
}

bool waitAndReap(HANDLE process, HANDLE &job, DWORD firstWaitMs)
{
    if (WaitForSingleObject(process, firstWaitMs) == WAIT_OBJECT_0) return true;
    TerminateProcess(process, 70);
    if (WaitForSingleObject(process, kReceiptDrainMs) == WAIT_OBJECT_0) return true;
    if (job) { CloseHandle(job); job = nullptr; }
    return WaitForSingleObject(process, kReceiptDrainMs) == WAIT_OBJECT_0;
}

int runSupervisor(const Options &options)
{
    const std::uint64_t parentStart = processStartTime(GetCurrentProcessId());
    if (sha256File(options.relayExe) != options.helperSha256) throw std::runtime_error("relay helper hash does not match frozen bytes");
    writeLease(options, parentStart); quarantineReceipt(options);
    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, stopEventName(options).c_str());
    if (!stopEvent) throw std::runtime_error("owned stop event creation failed");
    // The deterministic event is shared only by the exact same run/case, so
    // the SSH and HTTP supervisors can be stopped atomically. A different
    // run/case has a different name and cannot collide with this lease.

    std::wstring command = quoteArg(options.relayExe) + L" --mode " + quoteArg(options.mode) + L" --channel " + quoteArg(options.channel)
        + L" --vm-id " + quoteArg(options.vmId) + L" --run-id " + quoteArg(options.runId) + L" --case-id " + quoteArg(options.caseId)
        + L" --ownership-file " + quoteArg(options.ownershipFile) + L" --receipt-path " + quoteArg(options.receiptFile)
        + L" --helper-sha256 " + quoteArg(options.helperSha256) + L" --parent-pid " + std::to_wstring(GetCurrentProcessId())
        + L" --parent-start " + std::to_wstring(parentStart) + L" --stop-event-name " + quoteArg(stopEventName(options));
    if (options.loopbackTest) command += L" --self-test-daemon";
    if (options.delayedReadyTest) command += L" --self-test-daemon-delay 1000";
    HANDLE job = options.parentLossTest ? nullptr : createKillOnCloseJob();
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
    std::vector<wchar_t> commandLine(command.begin(), command.end()); commandLine.push_back(L'\0');
    if (!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &process)) { if (job) CloseHandle(job); CloseHandle(stopEvent); throw std::runtime_error("relay process creation failed"); }
    if (job && (!AssignProcessToJobObject(job, process.hProcess) || ResumeThread(process.hThread) == static_cast<DWORD>(-1))) {
        TerminateProcess(process.hProcess, 70); WaitForSingleObject(process.hProcess, kReceiptDrainMs); CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job); CloseHandle(stopEvent); throw std::runtime_error("relay process job assignment failed");
    }
    if (!job && ResumeThread(process.hThread) == static_cast<DWORD>(-1)) { TerminateProcess(process.hProcess, 70); WaitForSingleObject(process.hProcess, kReceiptDrainMs); CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(stopEvent); throw std::runtime_error("relay process resume failed"); }
    CloseHandle(process.hThread);

    bool ready = false; const ULONGLONG readyDeadline = GetTickCount64() + options.readyTimeoutMs;
    while (GetTickCount64() < readyDeadline) {
        if (receiptReady(options)) { ready = true; break; }
        if (WaitForSingleObject(process.hProcess, kPollMs) == WAIT_OBJECT_0) break;
    }
    if (!ready) { DWORD notReadyExit = STILL_ACTIVE; GetExitCodeProcess(process.hProcess, &notReadyExit); std::wofstream diagnostic(options.receiptFile + L".supervisor-error", std::ios::trunc); if (diagnostic) diagnostic << L"child_exit=" << notReadyExit << L"\n"; SetEvent(stopEvent); const bool reaped = waitAndReap(process.hProcess, job, kReceiptDrainMs); if (reaped && job) CloseHandle(job); CloseHandle(process.hProcess); CloseHandle(stopEvent); return 70; }

    if (options.parentLossTest) {
        Sleep(1000);
        CloseHandle(process.hProcess);
        // The child owns the verified process handle and must publish failed
        // before its parent-loss watcher exits it.
        ExitProcess(0);
    }

    auto invalidStop = std::make_shared<std::atomic_bool>(false);
    std::thread stopReader([stopEvent, invalidStop] {
        std::wstring line;
        if (std::getline(std::wcin, line)) {
            if (!line.empty() && line != L"stop") invalidStop->store(true);
            SetEvent(stopEvent);
        }
    });
    DWORD childExit = STILL_ACTIVE;
    while (WaitForSingleObject(process.hProcess, kPollMs) != WAIT_OBJECT_0) {}
    GetExitCodeProcess(process.hProcess, &childExit);
    SetEvent(stopEvent);
    stopReader.detach();
    std::wstring state; bool terminal = false; const ULONGLONG terminalDeadline = GetTickCount64() + kReceiptDrainMs;
    while (GetTickCount64() < terminalDeadline) {
        terminal = receiptReady(options, &state) && (state == L"stopped" || state == L"failed");
        if (terminal) break;
        Sleep(50);
    }
    CloseHandle(process.hProcess);
    if (job) CloseHandle(job);
    // The detached reader owns no stack references; the process exit closes
    // the named event after the child has drained. This keeps stop signaling
    // safe even when stdin is closed concurrently with child shutdown.
    return (!invalidStop->load() && terminal && state == L"stopped") ? 0 : 70;
}

int signalStop(const std::wstring &runId, const std::wstring &caseId, const std::wstring &ownershipFile)
{
    if (!validId(runId) || !validId(caseId)) return 64;
    const auto lease = readMap(ownershipFile);
    const std::wstring expected = L"Local\\AmneziaReleaseLabRelayStop_" + runId + L"_" + caseId;
    if (lease.count(L"run_id") == 0 || lease.at(L"run_id") != runId || lease.count(L"case_id") == 0 || lease.at(L"case_id") != caseId || lease.count(L"stop_event") == 0 || lease.at(L"stop_event") != expected || lease.count(L"state") == 0 || lease.at(L"state") != L"relay-authorized") return 64;
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, expected.c_str());
    if (!event) return 70;
    const BOOL signaled = SetEvent(event); CloseHandle(event);
    return signaled ? 0 : 70;
}

} // namespace

int wmain(int argc, wchar_t **argv)
{
    std::vector<std::wstring> args; for (int index = 1; index < argc; ++index) args.emplace_back(argv[index]);
    const std::set<std::wstring> allowed = {L"--relay-exe", L"--mode", L"--channel", L"--vm-id", L"--run-id", L"--case-id", L"--ownership-file", L"--receipt-path", L"--helper-sha256", L"--ready-timeout-ms", L"--loopback-self-test", L"--self-test-parent-loss", L"--self-test-delayed-ready", L"--stop"};
    std::set<std::wstring> seen; bool loopbackTest = false; bool parentLossTest = false; bool delayedReadyTest = false; bool stopOnly = false;
    for (std::size_t index = 0; index < args.size(); ++index) {
        if (args[index] == L"--loopback-self-test") { if (!seen.insert(args[index]).second) return 64; loopbackTest = true; continue; }
        if (args[index] == L"--self-test-parent-loss") { if (!seen.insert(args[index]).second) return 64; parentLossTest = true; continue; }
        if (args[index] == L"--self-test-delayed-ready") { if (!seen.insert(args[index]).second) return 64; delayedReadyTest = true; continue; }
        if (args[index] == L"--stop") { if (!seen.insert(args[index]).second) return 64; stopOnly = true; continue; }
        if (allowed.count(args[index]) == 0 || index + 1 >= args.size() || !seen.insert(args[index]).second) return 64; ++index;
    }
    Options options; options.relayExe = valueOf(args, L"--relay-exe"); options.mode = valueOf(args, L"--mode"); options.channel = valueOf(args, L"--channel"); options.vmId = valueOf(args, L"--vm-id"); options.runId = valueOf(args, L"--run-id"); options.caseId = valueOf(args, L"--case-id"); options.ownershipFile = valueOf(args, L"--ownership-file"); options.receiptFile = valueOf(args, L"--receipt-path"); options.helperSha256 = valueOf(args, L"--helper-sha256"); options.loopbackTest = loopbackTest; options.parentLossTest = parentLossTest; options.delayedReadyTest = delayedReadyTest;
    if (stopOnly) {
        if (args.size() != 7 || valueOf(args, L"--run-id").empty() || valueOf(args, L"--case-id").empty() || valueOf(args, L"--ownership-file").empty()) return 64;
        try { return signalStop(options.runId, options.caseId, options.ownershipFile); } catch (...) { return 70; }
    }
    const std::wstring timeout = valueOf(args, L"--ready-timeout-ms");
    if (!timeout.empty() && !parseTimeout(timeout, options.readyTimeoutMs)) return 64;
    if (options.relayExe.empty() || (options.mode != L"host" && options.mode != L"guest") || (options.channel != L"ssh" && options.channel != L"http") || options.vmId.empty() || !validId(options.runId) || !validId(options.caseId) || options.ownershipFile.empty() || options.receiptFile.empty() || options.helperSha256.size() != 64) return 64;
    try { return runSupervisor(options); } catch (const std::exception &error) { std::wcerr << error.what() << L'\n'; return 70; }
}
