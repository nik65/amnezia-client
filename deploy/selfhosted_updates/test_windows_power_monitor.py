"""Compile the production initializer with inert Win32 API doubles."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class WindowsPowerMonitorTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("wsl.exe") or shutil.which("g++"), "C++ compiler is required")
    def test_wlan_failures_do_not_disable_power_notifications(self):
        source = (ROOT / "client/platforms/windows/windowsnetworkwatcher.cpp").read_text()
        body = source[source.index("void WindowsNetworkWatcher::initialize()"):
                      source.index("// static", source.index("void WindowsNetworkWatcher::initialize()"))]
        harness = r'''
#include <cassert>
#include <cstddef>
using DWORD = unsigned long; using LONG_PTR = long long; using HWND = void*;
using WLAN_NOTIFICATION_CALLBACK = void(*)(); using LPVOID = void*;
constexpr DWORD ERROR_SUCCESS=0, ERROR_ACCESS_DENIED=5, WLAN_NOTIFICATION_SOURCE_MSM=16;
constexpr int GWLP_USERDATA=0; HWND HWND_MESSAGE=nullptr;
int opened=0, registered=0, windows=0, userData=0, warnings=0, errors=0;
DWORD openCode=0, registrationCode=0; bool windowFails=false;
struct Stream { template<class T> Stream& operator<<(T const&) { return *this; } };
struct Logger { Stream debug(){return{};} Stream warning(){warnings++;return{};}
                Stream error(){errors++;return{};} } logger;
namespace WindowsUtils { int getErrorMessage(DWORD){return 0;} }
struct WNDCLASS { void(*lpfnWndProc)(); void* hInstance; const wchar_t* lpszClassName; int cbWndExtra; };
DWORD WlanOpenHandle(int,void*,DWORD*,void** p){opened++;*p=nullptr;return openCode;}
DWORD WlanRegisterNotification(void*,DWORD,bool,WLAN_NOTIFICATION_CALLBACK,void*,void*,DWORD*){
    registered++;return registrationCode;}
void* GetModuleHandle(void*){return nullptr;} bool RegisterClass(WNDCLASS*){return true;}
HWND CreateWindowEx(int,const wchar_t*,const wchar_t*,int,int,int,int,int,HWND,void*,void*,void*){
    windows++;return windowFails?nullptr:reinterpret_cast<void*>(1);}
void SetWindowLongPtr(HWND,int,LONG_PTR){userData++;}
class WindowsNetworkWatcher { public: void* m_wlanHandle=nullptr;
    static void PowerWndProcCallback(){} static void wlanCallback(){} void initialize(); };
'''
        harness += body + r'''
int main(){
    for (int scenario=0; scenario<5; scenario++) {
        opened=registered=windows=userData=warnings=errors=0;
        openCode=scenario==0?6:0; registrationCode=scenario==1?5:scenario==2?6:0;
        windowFails=scenario==4;
        WindowsNetworkWatcher watcher; watcher.initialize();
        assert(opened==1); assert(registered==(scenario==0?0:1));
        assert(windows==1); assert(userData==(windowFails?0:1));
        assert(warnings==(scenario==1?1:0));
        assert(errors==((scenario==0||scenario==2)?1:0));
    }
}
'''
        # Run only a compiler and isolated test binary, never an Amnezia product.
        with tempfile.TemporaryDirectory(prefix="amnezia-power-unit-") as directory:
            path = pathlib.Path(directory) / "test.cpp"
            path.write_text(harness)
            prefix = []
            native = str(path)
            if not shutil.which("g++"):
                prefix = ["wsl.exe", "-e"]
                native = subprocess.check_output(prefix + ["wslpath", "-a", str(path)], text=True).strip()
            subprocess.run(prefix + ["g++", "-std=c++17", native, "-o", native + ".test"], check=True)
            subprocess.run(prefix + [native + ".test"], check=True)


if __name__ == "__main__":
    unittest.main()
