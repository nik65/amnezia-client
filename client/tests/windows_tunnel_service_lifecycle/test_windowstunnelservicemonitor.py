"""Compile the real Windows monitor method with inert SCM, timer and signal mocks."""
from pathlib import Path
import argparse, hashlib, json, subprocess

def function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 0
    for i in range(brace, len(source)):
        depth += (source[i] == '{') - (source[i] == '}')
        if not depth:
            return source[start:i+1]
    raise ValueError('unterminated method: ' + signature)

FIXTURE = r'''
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#define emit
using SC_HANDLE = void*;
struct SERVICE_STATUS { unsigned dwCurrentState = 0; };
constexpr unsigned SERVICE_RUNNING = 4;
constexpr unsigned WINDOWS_TUNNEL_MONITOR_TIMEOUT_MSEC = 2000;
int nowMs = 0;
int queries = 0;
int diagnostics = 0;
std::function<bool(SERVICE_STATUS*)> query;
bool QueryServiceStatus(SC_HANDLE, SERVICE_STATUS* status) {
  ++queries;
  return query(status);
}
struct Sink {
  template<class T> Sink& operator<<(const T&) { return *this; }
};
struct Logger {
  Sink error() { ++diagnostics; return {}; }
  Sink debug() { ++diagnostics; return {}; }
} logger;
namespace WindowsUtils { void windowsLog(const char*) { ++diagnostics; } }
struct Timer {
  bool active = false;
  int intervalMs = 0;
  bool isActive() const { return active; }
  int interval() const { return intervalMs; }
  void setInterval(int value) { intervalMs = value; }
  void start(int value) { intervalMs = value; active = true; }
  void stop() { active = false; }
};
struct Guard { void dismiss() {} };
class WindowsTunnelService {
 public:
  Timer m_timer;
  void* m_service = nullptr;
  int failures = 0;
  int nextTickMs = 0;
  std::vector<int> intervalsAtEmission;
  std::vector<int> failureTimes;
  std::function<void()> callback;
  void timeout();
  void backendFailure() {
    ++failures;
    intervalsAtEmission.push_back(m_timer.interval());
    failureTimes.push_back(nowMs);
    // Qt retains the connection during emission; snapshot the inert callback too.
    const auto onFailure = callback;
    if (onFailure) onFailure();
  }
  bool startOwned() {
    Guard guard;
    void* service = reinterpret_cast<void*>(1);
    @@START_SUCCESS@@
  }
  void stop() { m_timer.stop(); }
  void arm() { startOwned(); nextTickMs = nowMs + m_timer.interval(); }
  void advanceTo(int targetMs) {
    while (m_timer.isActive() && nextTickMs <= targetMs) {
      nowMs = nextTickMs;
      timeout();
      nextTickMs = nowMs + m_timer.interval();
    }
    nowMs = targetMs;
  }
};
@@TIMEOUT@@
int failedChecks = 0;
void check(bool ok, const std::string& label) {
  if (!ok) { ++failedChecks; std::cerr << "FAIL " << label << '\n'; }
}
void reset() {
  nowMs = queries = diagnostics = 0;
  query = [](SERVICE_STATUS* status) { status->dwCurrentState = 1; return true; };
}
int main() {
  reset();
  {
    WindowsTunnelService service;
    service.arm();
    service.advanceTo(600000);
    check(service.failures == 12, "persistent failure uses bounded 5/15/60 second retries");
    check(diagnostics == 12, "persistent failure diagnostics are bounded");
    check(!service.failureTimes.empty() && service.failureTimes.front() == 2000,
          "first observed failure is immediate");
    check(!service.intervalsAtEmission.empty() && service.intervalsAtEmission.front() == 5000,
          "backoff is set before synchronous failure callback");
    check(service.m_timer.isActive(), "persistent failure remains eligible for cleanup retry");
  }
  reset();
  {
    WindowsTunnelService service;
    bool ownershipRetained = true;
    bool killSwitchRetained = true;
    int cleanupAttempts = 0;
    service.callback = [&] {
      ++cleanupAttempts;
      if (nowMs >= 60000) { ownershipRetained = false; service.stop(); }
    };
    service.arm();
    service.advanceTo(59000);
    check(ownershipRetained && killSwitchRetained, "failed cleanup retains ownership and kill switch");
    check(service.m_timer.isActive(), "cleanup quarantine does not strand future retry");
    service.advanceTo(90000);
    check(!ownershipRetained && cleanupAttempts == 4, "cleanup retries after quarantine clears");
    check(!service.m_timer.isActive(), "successful callback stop is not undone after emit");
  }
  reset();
  {
    query = [](SERVICE_STATUS* status) {
      status->dwCurrentState = nowMs >= 20000 && nowMs <= 40000 ? SERVICE_RUNNING : 1;
      return true;
    };
    WindowsTunnelService service;
    service.arm();
    service.advanceTo(24000);
    check(service.failures == 2 && service.m_timer.interval() == 2000,
          "observed recovery rearms normal two second monitoring");
    service.advanceTo(42000);
    check(service.failures == 3 && service.m_timer.interval() == 5000,
          "new failure after recovery starts a fresh retry episode");
  }
  reset();
  {
    query = [](SERVICE_STATUS*) { return false; };
    WindowsTunnelService service;
    service.arm(); service.advanceTo(23000);
    check(service.failures == 3 && diagnostics == 3, "unknown SCM status remains failure with bounded retry");
  }
  reset();
  {
    WindowsTunnelService service;
    service.arm(); service.m_service = nullptr; service.advanceTo(23000);
    check(service.failures == 3 && queries == 0, "missing owned handle remains failure with bounded retry");
  }
  reset();
  {
    WindowsTunnelService service;
    service.arm(); service.stop(); service.timeout();
    check(service.failures == 0 && queries == 0, "stale timeout after explicit stop is inert");
  }
  reset();
  {
    WindowsTunnelService service;
    service.arm(); service.advanceTo(22000);
    service.stop(); service.arm();
    check(service.m_timer.interval() == 2000, "actual successful start resets prior failure backoff");
    service.advanceTo(24000);
    check(service.m_timer.interval() == 5000 && service.failures == 4,
          "explicit retry receives its own first failure notification");
  }
  reset();
  {
    WindowsTunnelService service;
    service.callback = [&] { service.stop(); service.arm(); };
    service.arm(); service.advanceTo(2000);
    check(service.m_timer.interval() == 2000 && service.m_timer.isActive(),
          "synchronous restart is not overwritten after emit");
  }
  reset();
  {
    query = [](SERVICE_STATUS* status) { status->dwCurrentState = SERVICE_RUNNING; return true; };
    WindowsTunnelService service;
    service.arm(); service.advanceTo(200000);
    check(queries == 100 && service.failures == 0 && diagnostics == 0,
          "healthy service is checked at unchanged cadence without false failure");
  }
  reset();
  {
    auto* service = new WindowsTunnelService;
    service->callback = [&] { delete service; service = nullptr; };
    service->arm(); nowMs = 2000; service->timeout();
    check(service == nullptr, "synchronous receiver may delete service");
  }
  std::cout << "monitor scenarios=10 failedChecks=" << failedChecks << '\n';
  return failedChecks ? 1 : 0;
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cxx', default='c++')
    parser.add_argument('--emit-only', action='store_true')
    args = parser.parse_args()
    raw = args.source.read_bytes()
    source = raw.decode('utf8')
    timeout = function(source, 'void WindowsTunnelService::timeout()')
    start = function(source, 'bool WindowsTunnelService::start(')
    success = function(start, 'if (lifecycle.started)')
    success = success[success.index('{')+1:success.rindex('}')]
    fixture = FIXTURE.replace('@@TIMEOUT@@', timeout).replace('@@START_SUCCESS@@', success)
    args.out.mkdir(parents=True, exist_ok=True)
    cpp = (args.out / 'monitor_fixture.cpp').resolve()
    cpp.write_text(fixture, encoding='utf8')
    if args.emit_only:
        print('Generated mocked monitor fixture from ' + str(args.source))
        return 0
    is_msvc = Path(args.cxx).name.lower() in ('cl', 'cl.exe')
    exe = (args.out / ('monitor_fixture.exe' if is_msvc else 'monitor_fixture')).resolve()
    if is_msvc:
        command = [args.cxx, '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/UNDEBUG',
                   str(cpp), '/Fe:' + str(exe), '/Fo:' + str((args.out / 'monitor_fixture.obj').resolve())]
    else:
        command = [args.cxx, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                   '-UNDEBUG', str(cpp), '-o', str(exe)]
    compiled = subprocess.run(command, capture_output=True, cwd=args.out)
    (args.out / 'compile.log').write_bytes(compiled.stdout + compiled.stderr)
    tested = subprocess.run([str(exe)], capture_output=True, cwd=args.out) if compiled.returncode == 0 else None
    if tested is not None:
        (args.out / 'test.log').write_bytes(tested.stdout + tested.stderr)
    receipt = dict(source=str(args.source), sourceSha256=hashlib.sha256(raw).hexdigest(),
                   fixtureSha256=hashlib.sha256(cpp.read_bytes()).hexdigest(),
                   compilerCommand=command, compileExit=compiled.returncode,
                   testExit=tested.returncode if tested else None,
                   productionSourceUnchanged=args.source.read_bytes()==raw,
                   appBuild=False, nativeServiceAccess=False,
                   status='PASS' if tested is not None and tested.returncode == 0 else 'FAIL')
    (args.out / 'RESULT.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf8')
    print(json.dumps(receipt, indent=2))
    if compiled.returncode:
        print((compiled.stdout+compiled.stderr).decode(errors='replace'))
    elif tested is not None:
        print((tested.stdout+tested.stderr).decode(errors='replace'))
    return 0 if receipt['status'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
