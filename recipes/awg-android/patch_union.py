"""Install the reviewed union overlay into the pinned upstream build source.

Exact anchors reject upstream drift. No module cache or installed binary is edited.
"""
from pathlib import Path
import shutil


def install_union(source: Path, overlay: Path):
    api_path = source / "api-android.go"
    text = api_path.read_text(encoding="utf-8")
    if "func turnOn(" in text:
        raise RuntimeError("AWG source already patched; use a fresh build source")

    def change(before, after):
        nonlocal text
        if text.count(before) != 1:
            raise RuntimeError(f"AWG union upstream anchor mismatch: {before[:70]!r}")
        text = text.replace(before, after)

    change('"strings"', '"strings"\n\t"sync"')
    change("uapi   net.Listener", "uapi   net.Listener\n\tunionCallbacks uintptr")
    change("var tunnelHandles map[int32]TunnelHandle", "var tunnelHandles map[int32]TunnelHandle\nvar tunnelHandlesMu sync.RWMutex")
    change("func awgTurnOn(interfaceName string, tunFd int32, settings string) int32 {",
           "func awgTurnOn(interfaceName string, tunFd int32, settings string) int32 {\n"
           "\treturn turnOn(interfaceName, tunFd, settings, 0, \"\")\n}\n\n"
           "func turnOn(interfaceName string, tunFd int32, settings string, callbacks uintptr, policy string) int32 {\n"
           "\ttunnelHandlesMu.Lock()\n\tdefer tunnelHandlesMu.Unlock()")
    change("device := device.NewDevice(tun, conn.NewStdNetBind(), logger)",
           "var bind conn.Bind = conn.NewStdNetBind()\n\tif callbacks != 0 {\n"
           "\t\ttun, bind, err = newUnionBackend(tun, bind, callbacks, policy)\n"
           "\t\tif err != nil { tun.Close(); logger.Errorf(\"Union backend initialization failed\"); return -1 }\n\t}\n"
           "\tdevice := device.NewDevice(tun, bind, logger)")
    change('unix.Close(int(tunFd))\n\t\tlogger.Errorf("IpcSet: %v", err)',
           'device.Close()\n\t\tlogger.Errorf("IpcSet: %v", err)')
    # UAPIOpen can fail on Android; neither later error path may dereference nil.
    if text.count("\t\tuapiFile.Close()\n\t\tdevice.Close()") != 2:
        raise RuntimeError("AWG UAPI cleanup anchor mismatch")
    text = text.replace("\t\tuapiFile.Close()\n\t\tdevice.Close()",
                        "\t\tif uapi != nil { uapi.Close() }\n\t\tdevice.Close()")
    change("TunnelHandle{device: device, uapi: uapi}", "TunnelHandle{device: device, uapi: uapi, unionCallbacks: callbacks}")
    change("func awgTurnOff(tunnelHandle int32) {", "func awgTurnOff(tunnelHandle int32) {\n\ttunnelHandlesMu.Lock()")
    change("if !ok {\n\t\treturn\n\t}\n\tdelete(tunnelHandles, tunnelHandle)",
           "if !ok { tunnelHandlesMu.Unlock(); return }\n\tdelete(tunnelHandles, tunnelHandle)\n\ttunnelHandlesMu.Unlock()")
    change("\thandle.device.Close()\n}", "\thandle.device.Close()\n\tif handle.unionCallbacks != 0 { releaseUnionBridge(handle.unionCallbacks) }\n}")
    for signature in ("func awgGetSocketV4(tunnelHandle int32) int32 {",
                      "func awgGetSocketV6(tunnelHandle int32) int32 {",
                      "func awgGetConfig(tunnelHandle int32) *C.char {"):
        change(signature, signature + "\n\ttunnelHandlesMu.RLock()\n\tdefer tunnelHandlesMu.RUnlock()")
    api_path.write_text(text, encoding="utf-8", newline="\n")
    for file in overlay.iterdir():
        destination = source / file.name
        if file.is_dir():
            shutil.copytree(file, destination, dirs_exist_ok=True)
        else:
            shutil.copy2(file, destination)


if __name__ == "__main__":
    import sys
    install_union(Path(sys.argv[1]), Path(__file__).with_name("union"))
