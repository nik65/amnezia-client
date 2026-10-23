"""Compare the native ownership core with Python journal.py using fake Docker.

No live Docker, network, VPN, service or process mutation is available here.
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

            def run(*args):
                commands.append(list(args))
                if args[:2] == ("docker", "inspect"):
                    item = scenario["inspections"].get(args[2])
                    if item is None:
                        raise subprocess.CalledProcessError(1, args, stderr=b"No such object")
                    return json.dumps([item]).encode()
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

    def test_owned_rule_cleanup(self):
        value = initial()
        value["sourceRules"] = True
        self.compare(dict(initial=value, inspections={SOURCE_ID: observed("amnezia-awg", SOURCE_ID)}, operations=[dict(op="cleanup")]))


if __name__ == "__main__":
    unittest.main()
