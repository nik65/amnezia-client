"""Negative acquisition boundaries; fake transports never grant acceptance."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from deploy.release_lab import android_real_device_acquisition as acquisition


class AndroidAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.adb = self.root/"adb.exe"
        self.apk = self.root/"candidate.apk"
        self.manifest = self.root/"manifest.json"
        for path in (self.adb, self.apk, self.manifest):
            path.write_bytes(b"exact managed bytes")
        self.candidate = acquisition.file_record(self.apk)
        self.manifest_record = acquisition.file_record(self.manifest)
        self.boot = "123e4567-e89b-12d3-a456-426614174000"
        self.package_path = "/data/app/~~fixture/org.amnezia.vpn-fixture/base.apk"
        self.package = "  userId=10426\n  versionCode=2200 minSdk=28 targetSdk=36\n  versionName=5.0.3.14\n"
        self.calls = []
        self.challenge_count = 0
        self.responses = {}
        self.post_command = None
        self.mutate_after_log = False
        self.process_changed = False
        self.vpn_changed = False

    def transport(self, argv, **kwargs):
        self.assertEqual(argv[:3], [str(self.adb), "-s", "e87861c7"])
        self.assertGreater(kwargs["timeout"], 0)
        self.assertGreater(kwargs["max_output"], 0)
        args = argv[3:]
        self.calls.append(args)
        if tuple(args) in self.responses:
            result = self.responses[tuple(args)]
            return subprocess.CompletedProcess(argv, result[0], result[1], result[2])
        if args == ["get-state"]: text = "device"
        elif args == ["get-serialno"]: text = "e87861c7"
        elif args[0] == "shell" and args[1].startswith("printf '"):
            nonce = args[1].split("'")[1].split("\\")[0]
            self.challenge_count += 1
            text = f"{nonce}\n{self.boot}\n2000\n1792664000"
        elif args[:2] == ["shell", "getprop"]:
            text = {"ro.kernel.qemu": "0", "ro.boot.qemu": "", "ro.hardware": "qcom",
                    "ro.product.manufacturer": "Xiaomi", "ro.product.model": "22081212UG",
                    "ro.build.fingerprint": "Xiaomi/ditingp_ru/diting:15/fixture/release-keys",
                    "ro.build.version.release": "15", "ro.build.version.sdk": "35"}[args[2]]
        elif args == ["shell", "dumpsys", "package", acquisition.PACKAGE]: text = self.package
        elif args == ["shell", "pm", "list", "packages", "-U", "--user", "current", acquisition.PACKAGE]:
            text = "package:org.amnezia.vpn uid:10426"
        elif args == ["shell", "pm", "path", acquisition.PACKAGE]: text = "package:"+self.package_path
        elif args[:2] == ["shell", "sha256sum"]: text = self.candidate["sha256"]+"  "+self.package_path
        elif args[:4] == ["shell", "stat", "-c", "%s"]: text = str(self.candidate["size"])
        elif args == ["shell", "ps", "-A", "-o", "UID,PID,NAME"]:
            text = "UID PID NAME\n10426 100 org.amnezia.vpn\n10426 200 org.amnezia.vpn:amneziaAwgService"
        elif args[:2] == ["shell", "cat"]:
            pid = int(args[2].split("/")[2])
            ticks = "101" if self.process_changed and any(a[0] == "logcat" for a in self.calls) else "100"
            text = str(pid)+" (process) S "+" ".join(["0"]*18+[ticks]+["0"]*5)
        elif args == ["shell", "dumpsys", "connectivity"]:
            network = "2" if self.vpn_changed and any(a[0] == "logcat" for a in self.calls) else "1"
            text = "NetworkAgentInfo{network{"+network+"} ni{VPN CONNECTED extra:} InterfaceName: tun0 Transports: VPN Capabilities: INTERNET&VALIDATED OwnerUid: 10426}"
        elif args[0] == "logcat":
            if "--uid=10426" not in args:
                self.assertIn("--pid="+str(100 if len([a for a in self.calls if a[0] == "logcat"]) == 1 else 200), args)
            text = "1792664000.100 100 100 I fixture: exact record bytes\n"
            if self.mutate_after_log: self.apk.write_bytes(b"changed bytes")
        else: self.fail("unexpected command: "+repr(args))
        if self.post_command: text = self.post_command(args, text)
        return subprocess.CompletedProcess(argv, 0, (text+"\n").encode(), b"")

    def acquire(self, **kwargs):
        self.calls = []
        self.challenge_count = 0
        with patch.object(acquisition, "PINNED_ADB", self.adb), \
                patch.object(acquisition, "_bounded_process", side_effect=self.transport):
            return acquisition.acquire_android_device(run_id=kwargs.get("run_id", "phone-capture"),
                serial=kwargs.get("serial", "e87861c7"), candidate=kwargs.get("candidate", self.candidate),
                manifest=self.manifest_record, version="5.0.3.14", version_code=kwargs.get("version_code", 2200))

    def test_capture_preserves_original_bytes_and_no_acceptance(self):
        value = self.acquire()
        self.assertEqual(value["state"], "acquired-not-accepted")
        self.assertNotIn("passed", value)
        self.assertNotIn("signature", value)
        self.assertEqual(value["capture"]["size"], len(value["raw_capture"]))
        self.assertEqual(base64.b64decode(value["capture"]["bytes_b64"]), value["raw_capture"])
        records = json.loads(value["raw_capture"])
        logs = [r for r in records if r["label"].startswith("logcat:")]
        self.assertEqual(len(logs), 2)
        self.assertTrue(all(b"exact record bytes" in base64.b64decode(r["stdout_b64"]) for r in logs))
        self.assertEqual(value["installed_before"], value["installed_after"])
        self.assertTrue(value["vpn_observations"][0]["validated"])

    def test_each_capture_has_fresh_256_bit_challenge(self):
        first = self.acquire()["challenge"]
        second = self.acquire()["challenge"]
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, second)

    def test_transport_commands_are_read_only_fixed_list(self):
        self.acquire()
        self.assertFalse(any(word in {"install", "uninstall", "push", "input", "am", "reboot", "su"}
                             for args in self.calls for word in args))
        self.assertEqual(self.challenge_count, 2)

    def test_emulator_serial_rejected_before_transport(self):
        with self.assertRaises(acquisition.AndroidAcquisitionError): self.acquire(serial="emulator-5554")
        self.assertFalse(self.calls)

    def test_emulator_metadata_rejected(self):
        self.responses[("shell", "getprop", "ro.kernel.qemu")] = (0, b"1\n", b"")
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "emulator"): self.acquire()

    def test_challenge_replay_rejected(self):
        self.post_command = lambda args, text: "0"*64+"\n"+"\n".join(text.splitlines()[1:]) if len(args)>1 and args[1].startswith("printf '") else text
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "challenge"): self.acquire()

    def test_root_shell_is_rejected(self):
        self.post_command = lambda args, text: text.replace("\n2000\n", "\n0\n") if len(args)>1 and args[1].startswith("printf '") else text
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "shell UID"): self.acquire()

    def test_wrong_installed_hash_rejected(self):
        self.responses[("shell", "sha256sum", self.package_path)] = (0, ("0"*64+"  "+self.package_path).encode(), b"")
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "candidate bytes"): self.acquire()

    def test_wrong_installed_version_rejected(self):
        self.package = self.package.replace("2200", "2199")
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "candidate bytes"): self.acquire()

    def test_android15_app_id_and_active_user_uid(self):
        self.package = self.package.replace("userId=", "appId=")
        self.assertEqual(self.acquire()["installed_after"]["uid"], 10426)

    def test_wrong_active_user_uid_rejected(self):
        self.responses[("shell", "pm", "list", "packages", "-U", "--user", "current", acquisition.PACKAGE)] = (0, b"package:org.amnezia.vpn uid:10500", b"")
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "app ID"): self.acquire()

    def test_vpn_transport_over_wifi_is_detected(self):
        self.post_command = lambda args, text: text.replace("Transports: VPN", "Transports: WIFI|VPN")
        self.assertTrue(self.acquire()["vpn_observations"][0]["connected"])

    def test_split_or_unsafe_installed_paths_rejected(self):
        for text in ("package:/data/app/a/../bad/base.apk", "package:"+self.package_path+"\npackage:/data/app/split.apk"):
            self.responses[("shell", "pm", "path", acquisition.PACKAGE)] = (0, text.encode(), b"")
            with self.subTest(text=text), self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "APK path"):
                self.acquire()

    def test_source_mutation_during_capture_rejected(self):
        self.mutate_after_log = True
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "artifact bytes changed"): self.acquire()

    def test_manifest_mutation_during_capture_rejected(self):
        def mutate(args, text):
            if args[0] == "logcat": self.manifest.write_bytes(b"changed manifest")
            return text
        self.post_command = mutate
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "artifact bytes changed"): self.acquire()

    def test_adb_executable_mutation_during_capture_rejected(self):
        def mutate(args, text):
            if args[0] == "logcat": self.adb.write_bytes(b"changed transport")
            return text
        self.post_command = mutate
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "ADB executable changed"): self.acquire()

    def test_different_serial_transport_rejected(self):
        self.responses[("get-serialno",)] = (0, b"other-device\n", b"")
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "transport not ready"): self.acquire()

    def test_pid_reuse_during_capture_rejected(self):
        self.process_changed = True
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "binding changed"): self.acquire()

    def test_vpn_network_change_during_capture_rejected(self):
        self.vpn_changed = True
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "binding changed"): self.acquire()

    def test_device_boot_change_rejected(self):
        def boot_change(args, text):
            if len(args)>1 and args[1].startswith("printf '") and self.challenge_count > 1:
                return text.replace(self.boot, "123e4567-e89b-12d3-a456-426614174001")
            return text
        self.post_command = boot_change
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "binding changed"): self.acquire()

    def test_transport_error_and_boolean_returncode_rejected(self):
        for code in (1, True):
            self.responses[("get-state",)] = (code, b"device\n", b"denied")
            with self.subTest(code=code), self.assertRaises(acquisition.AndroidAcquisitionError): self.acquire()

    def test_boolean_size_or_version_code_rejected(self):
        with self.assertRaises(acquisition.AndroidAcquisitionError): self.acquire(candidate={**self.candidate, "size": True})
        with self.assertRaises(acquisition.AndroidAcquisitionError): self.acquire(version_code=True)

    def test_per_command_and_aggregate_output_limits(self):
        with patch.object(acquisition, "MAX_OUTPUT", 4), self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "response bounds"):
            self.acquire()
        with patch.object(acquisition, "MAX_CAPTURE_OUTPUT", 20), self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "aggregate"):
            self.acquire()


class BoundedTransportTests(unittest.TestCase):
    def run_child(self, program, *, limit=16384, timeout=2, input_bytes=None):
        children = []
        real_popen = subprocess.Popen
        def capture(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child
        try:
            with patch.object(acquisition.subprocess, "Popen", side_effect=capture):
                return acquisition._bounded_process([sys.executable, "-c", program],
                                                    timeout=timeout, max_output=limit, input_bytes=input_bytes)
        finally:
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll(), "only owned test client must be reaped")

    def test_preserve_exact_stdout_and_stderr(self):
        result = self.run_child("import os;os.write(1,b'exact\\x00bytes');os.write(2,b'stderr')")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"exact\x00bytes")
        self.assertEqual(result.stderr, b"stderr")

    def test_stream_overflow_stops_early_without_accumulating_stream(self):
        started = time.monotonic()
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "output limit"):
            self.run_child("import os\nwhile True: os.write(1,b'x'*4096)", limit=8192)
        self.assertLess(time.monotonic()-started, 3)

    def test_combined_stdout_stderr_share_budget(self):
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "output limit"):
            self.run_child("import os;os.write(1,b'a'*8192);os.write(2,b'b'*8192)", limit=16383)

    def test_timeout_stops_only_owned_client(self):
        started = time.monotonic()
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "deadline"):
            self.run_child("import time;time.sleep(10)", timeout=0.1)
        self.assertLess(time.monotonic()-started, 3)

    def test_bounded_input_preserves_exact_bytes(self):
        payload = b"readonly script\x00\n" * 1000
        result = self.run_child("import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())", input_bytes=payload, limit=65536)
        self.assertEqual(result.stdout, payload)

    def test_stdin_not_reading_does_not_block_deadline(self):
        with self.assertRaisesRegex(acquisition.AndroidAcquisitionError, "deadline"):
            self.run_child("import time;time.sleep(10)", input_bytes=b"x"*65536, timeout=0.1)


if __name__ == "__main__": unittest.main()
