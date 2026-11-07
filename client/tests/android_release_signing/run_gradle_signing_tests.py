"""Inspect the real staged Android Gradle DSL without signing or building APKs."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess


KEYS = ("QT_ANDROID_KEYSTORE_PATH", "QT_ANDROID_KEYSTORE_STORE_PASS",
        "QT_ANDROID_KEYSTORE_ALIAS", "QT_ANDROID_KEYSTORE_KEY_PASS")
ERROR = "Release signing requires QT_ANDROID_KEYSTORE_PATH, QT_ANDROID_KEYSTORE_STORE_PASS and QT_ANDROID_KEYSTORE_ALIAS together"


def binding(path):
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--gradle-user-home", required=True, type=Path)
    args = parser.parse_args()
    project = args.project.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixture = out / "inert identity with spaces"
    fixture.mkdir()
    keystore = fixture / "metadata-only.keystore"
    keystore.write_bytes(b"Not a keystore; configuration inspection only.\n")
    init = out / "inspect-signing.gradle"
    init.write_text('''import groovy.json.JsonOutput
gradle.projectsEvaluated {
    if (gradle.rootProject.projectDir.canonicalPath != System.getenv('AMNEZIA_SIGNING_PROJECT')) return
    def android = gradle.rootProject.extensions.getByName('android')
    def release = android.buildTypes.getByName('release')
    def signing = release.signingConfig
    def env = System.getenv()
    println('AMNEZIA_SIGNING_DSL=' + JsonOutput.toJson([
        configured: signing != null,
        mandatoryValuesPreserved: signing == null ? null :
            signing.storeFile == new File(env.QT_ANDROID_KEYSTORE_PATH) &&
            signing.storePassword == env.QT_ANDROID_KEYSTORE_STORE_PASS &&
            signing.keyAlias == env.QT_ANDROID_KEYSTORE_ALIAS,
        keyPasswordPreserved: signing == null ? null :
            signing.keyPassword == (env.QT_ANDROID_KEYSTORE_KEY_PASS ?: env.QT_ANDROID_KEYSTORE_STORE_PASS),
        debuggable: release.debuggable,
        jniDebuggable: release.jniDebuggable,
        minifyEnabled: release.minifyEnabled,
        shrinkResources: release.shrinkResources
    ]))
}
''', encoding="utf-8")
    env = os.environ.copy()
    for name in (*KEYS, "CODEX_PC_SSH_KEY_B64", "SELFHOSTED_UPDATE_PRIVATE_KEY_PATH"):
        env.pop(name, None)
    env.update(JAVA_HOME=str(args.java_home.resolve()),
               PATH=str(args.java_home.resolve() / "bin") + os.pathsep + env["PATH"],
               GRADLE_USER_HOME=str(args.gradle_user_home.resolve()),
               AMNEZIA_SIGNING_PROJECT=str(project))
    mandatory = {KEYS[0]: str(keystore), KEYS[1]: " store password with spaces ",
                 KEYS[2]: " alias with spaces "}
    cases = (("none", {}, False), ("partial", {KEYS[0]: str(keystore)}, None),
             ("complete-fallback", mandatory, True),
             ("explicit-key-password", {**mandatory, KEYS[3]: " key password with spaces "}, True))
    results = []
    try:
        for name, values, configured in cases:
            case = out / name
            case.mkdir()
            command = [str(project / "gradlew"), "--offline", "--no-daemon",
                       "--console=plain", "-q", "--init-script", str(init), "help"]
            started = datetime.datetime.now(datetime.timezone.utc).isoformat()
            process = subprocess.run(command, cwd=project, env={**env, **values},
                                     capture_output=True, timeout=180)
            (case / "stdout").write_bytes(process.stdout)
            (case / "stderr").write_bytes(process.stderr)
            text = process.stdout.decode(errors="replace")
            errors = process.stderr.decode(errors="replace")
            result = {"case": name, "startedUtc": started,
                      "finishedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "command": command, "nativeExit": process.returncode,
                      "inertSigningVariableNames": sorted(values)}
            results.append(result)
            if configured is None:
                require(process.returncode != 0 and ERROR in text + errors, text + errors)
                require("AMNEZIA_SIGNING_DSL=" not in text, "Partial inputs reached configured DSL")
                result["partialInputsRejectedBeforeTasks"] = True
            else:
                require(process.returncode == 0, text + errors)
                lines = [line.split("=", 1)[1] for line in text.splitlines()
                         if line.startswith("AMNEZIA_SIGNING_DSL=")]
                require(len(lines) == 1, text)
                dsl = json.loads(lines[0])
                require(dsl["configured"] is configured, dsl)
                require(dsl["debuggable"] is False and dsl["jniDebuggable"] is False, dsl)
                if configured:
                    require(dsl["mandatoryValuesPreserved"] and dsl["keyPasswordPreserved"], dsl)
                result["effectiveReleaseDsl"] = dsl
            result["passed"] = True
    finally:
        receipt = {"scope": "Actual staged Gradle DSL; inert inputs only; no APK build/signing",
                   "subject": binding(project / "build.gradle.kts"),
                   "harness": binding(Path(__file__).resolve()), "cases": results,
                   "passed": len(results) == 4 and all(case.get("passed") for case in results),
                   "apkBuilds": 0, "signingOperations": 0}
        (out / "RESULT.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": receipt["passed"], "cases": len(results),
                      "result": str(out / "RESULT.json")}))


if __name__ == "__main__":
    main()
