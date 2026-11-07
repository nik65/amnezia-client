"""Compare retained ownership behavior and verify stronger native cleanup.

No live Docker, network, VPN, host-rule or product-service mutation is available.
Generated cleanup shell is executed only with private inert iptables fixtures.
Control-maintenance recipe activation and listener probing are separate ports.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROBE = Path(sys.argv.pop(1)).resolve()
spec = importlib.util.spec_from_file_location("legacy_journal", Path(__file__).resolve().parents[1] / "journal.py")
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
OWNER = "a" * 32
SOURCE_ID, TARGET_ID, HELPER_ID = "1" * 64, "2" * 64, "3" * 64
IMAGE = "sha256:" + "b" * 64
TARGET = "amnezia-awg-migration-1"


def initial():
    return dict(owner=OWNER, phase="preparing", source="amnezia-awg",
                sourceId=SOURCE_ID, sourceIface="wg0", sourceRules=False,
                sourceDigest=hashlib.sha256(b"source-config").hexdigest(),
                sourceEpoch="epoch1", targetEpoch="epoch1", target=TARGET,
                containers={}, request=dict(image="pinned-image", host="vpn.example",
                                            port=18082, generation=1))


def observed(name, identity, running=True, owner=OWNER, epoch="epoch1"):
    return dict(Id=identity, Name="/" + name, Image=IMAGE,
                Config=dict(Labels={"amnezia.migration.owner": owner}),
                State=dict(Running=running, StartedAt=epoch))


class Parity(unittest.TestCase):
    def compare(self, scenario):
        with tempfile.TemporaryDirectory(prefix="awg-journal-parity-") as root:
            root = Path(root)
            py_dir, native_dir = [root / runtime / "amnezia-awg" / "1" for runtime in ("python", "native")]
            for directory in (py_dir, native_dir):
                directory.mkdir(parents=True, mode=0o700)
                directory.parent.chmod(0o700)
                directory.parent.parent.chmod(0o700)
            commands = []
            inspections = copy.deepcopy(scenario["inspections"])

            def run(*args):
                commands.append(list(args))
                if args[:2] == ("docker", "inspect"):
                    item = inspections.get(args[2])
                    if item is None:
                        raise subprocess.CalledProcessError(1, args, stderr=b"No such object")
                    return json.dumps([item]).encode()
                if args[:2] == ("docker", "rm"):
                    for key in list(inspections):
                        if key == args[-1] or inspections[key].get("Id") == args[-1]:
                            inspections.pop(key)
                return b""

            journal = legacy.Journal(py_dir, run, copy.deepcopy(scenario["initial"]))
            rejected = False
            try:
                for operation in scenario["operations"]:
                    op = operation["op"]
                    if op == "plan":
                        journal.plan(operation["name"], operation["image"])
                    elif op == "record":
                        journal.record(operation["name"])
                    elif op == "save":
                        journal.save(operation["phase"])
                    elif op == "cleanup":
                        journal.cleanup()
                    elif op == "recoverReady":
                        journal.recover_ready()
            except ValueError:
                rejected = True
            result = subprocess.run([str(PROBE), str(native_dir)],
                                    input=json.dumps(scenario), text=True,
                                    capture_output=True, check=True, timeout=10)
            actual = json.loads(result.stdout)
            self.assertEqual(actual["rejected"], rejected)
            self.assertEqual(actual["snapshot"], journal.value)
            # Native recovery additionally preflights all owned containers and
            # source before the first mutation. Compare mutating command order,
            # and prove each one addresses an immutable ID, never a name.
            mutations = lambda items: [args for args in items if args[1] != "inspect"]
            self.assertEqual(mutations(actual["commands"]), mutations(commands))
            for args in mutations(actual["commands"]):
                self.assertIn(args[3] if args[1] == "rm" else args[2], (SOURCE_ID, TARGET_ID, HELPER_ID))

    def test_plan_record_cleanup(self):
        self.compare(dict(initial=initial(), inspections={TARGET: observed(TARGET, TARGET_ID), TARGET_ID: observed(TARGET, TARGET_ID)},
                          operations=[dict(op="plan", name=TARGET, image=IMAGE), dict(op="record", name=TARGET), dict(op="cleanup")]))

    def test_creation_interrupted_before_record(self):
        self.compare(dict(initial=initial(), inspections={TARGET: observed(TARGET, TARGET_ID)},
                          operations=[dict(op="plan", name=TARGET, image=IMAGE), dict(op="cleanup")]))

    def test_creation_never_happened(self):
        self.compare(dict(initial=initial(), inspections={},
                          operations=[dict(op="plan", name=TARGET, image=IMAGE), dict(op="cleanup")]))

    def test_foreign_ownership_refused(self):
        self.compare(dict(initial=initial(), inspections={TARGET: observed(TARGET, TARGET_ID, owner="c" * 32)},
                          operations=[dict(op="plan", name=TARGET, image=IMAGE), dict(op="record", name=TARGET)]))

    def test_immutable_image_refused(self):
        item = observed(TARGET, TARGET_ID)
        item["Image"] = "sha256:" + "c" * 64
        self.compare(dict(initial=initial(), inspections={TARGET: item},
                          operations=[dict(op="plan", name=TARGET, image=IMAGE), dict(op="record", name=TARGET)]))

    def test_ready_recovery_stable_parent(self):
        value = initial()
        value.update(phase="ready", containers={TARGET: dict(image=IMAGE, id=TARGET_ID)})
        self.compare(dict(initial=value, inspections={TARGET_ID: observed(TARGET, TARGET_ID), SOURCE_ID: observed("amnezia-awg", SOURCE_ID)}, operations=[dict(op="recoverReady")]))

    def test_ready_recovery_stopped_target(self):
        value = initial()
        value.update(phase="ready", containers={TARGET: dict(image=IMAGE, id=TARGET_ID)})
        self.compare(dict(initial=value, inspections={TARGET_ID: observed(TARGET, TARGET_ID, running=False), SOURCE_ID: observed("amnezia-awg", SOURCE_ID)}, operations=[dict(op="recoverReady")]))

    def cleanup_rule_probe(self, root, forced_status=None):
        directory = root / "native" / "amnezia-awg" / "1"
        directory.mkdir(parents=True, mode=0o700)
        directory.parent.chmod(0o700)
        directory.parent.parent.chmod(0o700)
        value = initial()
        value["sourceRules"] = True
        scenario = dict(initial=value, inspections={SOURCE_ID: observed("amnezia-awg", SOURCE_ID)},
                        operations=[dict(op="cleanup")])
        if forced_status is not None:
            scenario["forcedShellStatus"] = forced_status
        result = subprocess.run([str(PROBE), str(directory)], input=json.dumps(scenario), text=True,
                                capture_output=True, check=True, timeout=10)
        return json.loads(result.stdout)

    def test_owned_rule_cleanup_requires_native_proof_and_retires_flag(self):
        # Intentional stronger native behavior than legacy's `-D ... || true`:
        # never compare the known false-success shell or retained true flag.
        with tempfile.TemporaryDirectory(prefix="awg-rules-proof-") as temporary:
            result = self.cleanup_rule_probe(Path(temporary))
            self.assertFalse(result["rejected"])
            self.assertFalse(result["snapshot"]["sourceRules"])
            self.assertEqual(result["snapshot"]["phase"], "aborted")
            scripts = [args[-1] for args in result["commands"] if args[1] == "exec"]
            self.assertEqual(len(scripts), 3)
            for script in scripts:
                self.assertTrue(script.startswith("set -eu; if iptables "))
                self.assertNotIn("|| true", script)
                self.assertEqual(script.count("iptables "), 3)
                self.assertEqual(script.count("--comment " + OWNER), 3)
        with tempfile.TemporaryDirectory(prefix="awg-rules-error-") as temporary:
            result = self.cleanup_rule_probe(Path(temporary), forced_status=13)
            self.assertTrue(result["rejected"])
            self.assertTrue(result["snapshot"]["sourceRules"])
            self.assertNotEqual(result["snapshot"]["phase"], "aborted")

    def test_actual_cleanup_shell_with_private_inert_iptables(self):
        with tempfile.TemporaryDirectory(prefix="awg-rules-shell-") as temporary:
            root = Path(temporary)
            result = self.cleanup_rule_probe(root)
            scripts = [args[-1] for args in result["commands"] if args[1] == "exec"]
            tool = root / "iptables"
            tool.write_text(r'''#!/bin/sh
set -eu
case "$*" in *"-t nat"*) key=nat;; *"-j REJECT"*) key=reject;; *"-j ACCEPT"*) key=accept;; *) exit 99;; esac
if [ "$1" = "-t" ]; then shift 2; fi
operation=$1
state="$IPT_ROOT/$key"
read -r count < "$state"
if [ "$operation" = "-C" ]; then
  if [ "${IPT_CHECK_ERROR:-0}" -ne 0 ]; then exit "$IPT_CHECK_ERROR"; fi
  if [ "$count" -gt 0 ]; then exit 0; else exit 1; fi
elif [ "$operation" = "-D" ]; then
  if [ "${IPT_DELETE_ERROR:-0}" -ne 0 ]; then exit "$IPT_DELETE_ERROR"; fi
  if [ "${IPT_STICKY:-0}" -eq 0 ]; then count=$((count-1)); fi
  printf '%s\n' "$count" > "$state"
  exit 0
fi
exit 98
''', encoding="utf-8")
            tool.chmod(0o755)
            cases = (("absent", 0, {}, 0), ("present", 1, {}, 0),
                     ("check-error", 1, {"IPT_CHECK_ERROR": "2"}, 2),
                     ("delete-error", 1, {"IPT_DELETE_ERROR": "13"}, 13),
                     ("still-present", 1, {"IPT_STICKY": "1"}, 1),
                     ("duplicate", 2, {}, 1))
            for name, count, changes, expected in cases:
                with self.subTest(case=name):
                    for key in ("nat", "reject", "accept"):
                        (root / key).write_text(str(count) + "\n", encoding="ascii")
                    # PATH has only the inert fixture. The real host iptables
                    # cannot be found even if a shell script regresses.
                    env = {"PATH": str(root), "IPT_ROOT": str(root), **changes}
                    for script in scripts:
                        actual = subprocess.run(["/bin/sh", "-c", script], env=env,
                                                capture_output=True, text=True, timeout=5)
                        self.assertEqual(actual.returncode, expected, actual.stderr)


if __name__ == "__main__":
    unittest.main()
