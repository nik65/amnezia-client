"""Run extracted Android stop/bind consumers without Android, a device or native VPN.

Dependencies come exclusively from a pre-existing Gradle cache. Optional source
overrides reproduce an immutable old consumer without modifying the checkout.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
parser.add_argument("--cache", type=Path, default=Path.home()/".gradle/caches/modules-2/files-2.1")
parser.add_argument("--java", default=shutil.which("java"))
parser.add_argument("--activity-source", type=Path)
parser.add_argument("--service-source", type=Path)
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
activity = args.activity_source or ROOT/"client/android/src/org/amnezia/vpn/AmneziaActivity.kt"
service = args.service_source or ROOT/"client/android/src/org/amnezia/vpn/AmneziaVpnService.kt"
subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("generate_fixture.py")), str(ROOT), str(out), str(activity), str(service)], check=True)

def jar(group, name, version):
    hits = list((args.cache/group/name/version).glob("*/*.jar"))
    if len(hits) != 1:
        raise RuntimeError(f"Expected one cached jar: {group}/{name}/{version}; got {len(hits)}")
    return hits[0]

stdlib = jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.1.0")
annotations = jar("org.jetbrains", "annotations", "23.0.0")
coroutines = jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.6.4")
compiler = [jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.1.0"), stdlib,
            jar("org.jetbrains.kotlin", "kotlin-script-runtime", "2.1.0"),
            jar("org.jetbrains.kotlin", "kotlin-reflect", "1.6.10"),
            jar("org.jetbrains.intellij.deps", "trove4j", "1.0.20200330"), annotations, coroutines]
runtime = os.pathsep.join(map(str, [stdlib, annotations, coroutines]))
real = [ROOT/"client/android/protocolApi/src/main/kotlin/NativeSessionBinding.kt",
        ROOT/"client/android/src/org/amnezia/vpn/IpcMessage.kt",
        ROOT/"client/android/src/org/amnezia/vpn/IpcMessenger.kt"]
sources = real + [out/name for name in ["AndroidOs.kt", "Log.kt", "PendingStopFixture.kt"]]
target = out/"pending-stop.jar"
receipt = {"inputs": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [activity, service]+sources},
           "cached_tools": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in compiler},
           "native_effects": "inert; no cleanup confirmation or absence receipt is produced"}
for p in [ROOT/"client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt",
          ROOT/"client/android/src/org/amnezia/vpn/DnsFallbackProtocol.kt"]:
    receipt["inputs"][str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
receipt["native_effects"] = "inert; active-handle cleanup is never confirmed; pristine receipt comes only from actual guard/backend retirement"
for p, digest in json.loads((out/"extracted-inputs.json").read_text(encoding="utf-8")).items():
    if receipt["inputs"][p] != digest:
        raise RuntimeError(f"Source changed during fixture extraction: {p}")
commands = [("compile", [args.java, "-cp", os.pathsep.join(map(str, compiler)),
                         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect",
                         "-classpath", runtime, "-d", str(target)]+list(map(str, sources))),
            ("test", [args.java, "-cp", str(target)+os.pathsep+runtime, "PendingStopFixtureKt"])]
for name, command in commands:
    with (out/(name+".log")).open("w", encoding="utf-8") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=90)
    receipt[name+"_exit"] = result.returncode
    if target.exists():
        receipt["test_jar_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    (out/"receipt.json").write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8")
    print(name, result.returncode, flush=True)
    if result.returncode:
        sys.exit(result.returncode)
for p, digest in receipt["inputs"].items():
    if hashlib.sha256(Path(p).read_bytes()).hexdigest() != digest:
        raise RuntimeError(f"Input changed during compilation/execution: {p}")
receipt["inputs_stable"] = True
(out/"receipt.json").write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8")
