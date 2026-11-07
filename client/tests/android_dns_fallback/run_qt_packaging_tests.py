"""Exercise the real Qt deployer with the pinned Android PIE component.

Builds a tiny ARM64 Qt deployment fixture and runs androiddeployqt --aux-mode.
No APK, Android app, emulator, device, ADB or native DNSTT process is started.
An optional --module permits a preserved pre-fix admission module for RED runs.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import xml.etree.ElementTree as ET


parser = argparse.ArgumentParser()
for name in ("component", "qt-host", "qt-android", "sdk", "ndk", "output"):
    parser.add_argument("--" + name, type=Path, required=True)
repo = Path(__file__).resolve().parents[3]
parser.add_argument("--module", type=Path, default=repo / "client/cmake/dns_transport.cmake")
templates = parser.add_mutually_exclusive_group()
templates.add_argument("--library-template", type=Path, default=repo / "client/android/res/values/libs.xml")
templates.add_argument("--qt-default-template", action="store_true")
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
if (out / "result.json").exists():
    raise SystemExit("Use a new output directory to preserve prior evidence")
component = args.component.resolve()
manifest = json.loads(component.with_name("dnstt-manifest.json").read_text(encoding="utf-8-sig"))
source = out / "source"
source.mkdir(exist_ok=True)
build = out / "build"
target = "DnsttDeploymentProbe"
commands = []
library_template = None if args.qt_default_template else args.library_template.resolve()


def cmake_path(path):
    return path.resolve().as_posix().replace('"', '\\"')


def run(label, command):
    with (out / (label + ".log")).open("w", encoding="utf-8") as log:
        result = subprocess.run(list(map(str, command)), stdout=log, stderr=subprocess.STDOUT, timeout=120)
    commands.append({"stage": label, "argv": list(map(str, command)), "exitCode": result.returncode})
    if result.returncode:
        raise AssertionError(f"{label} failed with exit {result.returncode}; see its log")


receipt = {
    "kind": "actual-Qt-deployment-fixture",
    "startedUtc": datetime.now(timezone.utc).isoformat(),
    "harnessSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "admissionModuleSha256": hashlib.sha256(args.module.read_bytes()).hexdigest(),
    "componentSha256": hashlib.sha256(component.read_bytes()).hexdigest(),
    "manifestSha256": hashlib.sha256(component.with_name("dnstt-manifest.json").read_bytes()).hexdigest(),
    "deployerSha256": hashlib.sha256((args.qt_host / "bin/androiddeployqt").read_bytes()).hexdigest(),
    "libraryTemplate": str(library_template) if library_template else "Qt standard template",
    "libraryTemplateSha256": hashlib.sha256(library_template.read_bytes()).hexdigest() if library_template else None,
    "APKOrDeviceAcceptance": False,
    "commands": commands,
}
try:
    template_property = ""
    if library_template:
        package_source = source / "package-source"
        (package_source / "res/values").mkdir(parents=True)
        shutil.copy2(library_template, package_source / "res/values/libs.xml")
        template_property = (f"set_target_properties({target} PROPERTIES QT_ANDROID_PACKAGE_SOURCE_DIR "
                             f'"{cmake_path(package_source)}")\n')
    (source / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.25)\n"
        f"project({target} LANGUAGES CXX)\n"
        "find_package(Qt6 REQUIRED COMPONENTS Core Gui)\n"
        f"qt_add_executable({target} main.cpp)\n"
        f"target_link_libraries({target} PRIVATE Qt6::Core Qt6::Gui)\n"
        f'set(AMNEZIA_DNSTT_ANDROID_CLIENT "{cmake_path(component)}" CACHE FILEPATH "")\n'
        f'include("{cmake_path(args.module)}")\n'
        f"amnezia_bundle_android_dns_transport({target})\n" + template_property,
        encoding="utf-8",
    )
    (source / "main.cpp").write_text(
        "#include <QGuiApplication>\n"
        "int main(int argc,char **argv) { QGuiApplication app(argc,argv); return 0; }\n",
        encoding="utf-8",
    )
    cmake = shutil.which("cmake")
    if not cmake:
        raise AssertionError("CMake must be available")
    run("configure", [cmake, "-S", source, "-B", build, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Debug",
        "-DCMAKE_TOOLCHAIN_FILE=" + cmake_path(args.qt_android / "lib/cmake/Qt6/qt.toolchain.cmake"),
        "-DQT_HOST_PATH=" + cmake_path(args.qt_host), "-DANDROID_SDK_ROOT=" + cmake_path(args.sdk),
        "-DANDROID_NDK_ROOT=" + cmake_path(args.ndk), "-DCMAKE_ANDROID_NDK=" + cmake_path(args.ndk),
        "-DANDROID_PLATFORM=android-28", "-DANDROID_ABI=arm64-v8a", "-DQT_ANDROID_BUILD_ALL_ABIS=FALSE"])
    run("build", [cmake, "--build", build, "--target", target, "--parallel", "1"])
    deployment = build / ("android-" + target + "-deployment-settings.json")
    package = build / "android-build"
    native_dir = package / "libs/arm64-v8a"
    native_dir.mkdir(parents=True, exist_ok=True)
    # The normal Qt APK prepare target performs this copy before androiddeployqt.
    shutil.copy2(build / ("lib" + target + "_arm64-v8a.so"), native_dir)
    run("deploy", [args.qt_host / "bin/androiddeployqt", "--input", deployment, "--output", package,
                   "--aux-mode", "--android-platform", "android-36"])
    if library_template:
        # Qt aux-mode skips copyAndroidSources(). Mirror its one template copy,
        # then run the real updater without restoring Qt's standard template.
        shutil.copy2(library_template, package / "res/values/libs.xml")
        run("deploy-product-template", [args.qt_host / "bin/androiddeployqt", "--input", deployment,
            "--output", package, "--aux-mode", "--no-build", "--android-platform", "android-36"])
    payload = native_dir / "libdnstt.so"
    if not payload.is_file() or hashlib.sha256(payload.read_bytes()).hexdigest() != manifest["sha256"]:
        raise AssertionError("Qt deployment must retain the exact admitted DNSTT bytes")
    if not payload.stat().st_mode & stat.S_IXUSR:
        raise AssertionError("Deployed native DNSTT payload lost executable permission")
    arrays = ET.parse(package / "res/values/libs.xml").getroot().findall("array")
    startup_arrays = {"bundled_libs", "qt_libs", "load_local_libs"}
    if not startup_arrays.issubset({array.attrib.get("name") for array in arrays}):
        raise AssertionError("Qt deployment must generate every startup library list")
    settings = json.loads(deployment.read_text())
    autoload_entries = [item.text for array in arrays if array.attrib.get("name") in startup_arrays
                        for item in array.findall("item") if "dnstt" in (item.text or "").lower()]
    extra_jni = "libdnstt.so" in settings.get("android-extra-libs", "")
    receipt.update(payloadBytes=payload.stat().st_size, deployedSha256=hashlib.sha256(payload.read_bytes()).hexdigest(),
                   startupLoadEntries=autoload_entries, classifiedAsExtraJni=extra_jni)
    if autoload_entries:
        raise AssertionError("DNSTT PIE must not enter Qt's startup System.load list")
    if extra_jni:
        raise AssertionError("DNSTT is executable data, not an extra JNI library")
    receipt["passed"] = True
except Exception as error:
    receipt.update(passed=False, error=str(error))
    raise
finally:
    receipt["finishedUtc"] = datetime.now(timezone.utc).isoformat()
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

print("Actual Qt deployment: exact executable bytes retained; excluded from all startup load lists PASS")
