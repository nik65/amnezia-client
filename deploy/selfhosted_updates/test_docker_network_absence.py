"""Inert regression for Docker network absence classification.

Only the exact query_network_field function is executed, with as_root replaced
by a byte-preserving response fixture. No installer, Docker, guest, publication,
service, or network operation is launched. The leading empty stdout line was
observed before Docker's daemon error in the real owned Linux bootstrap.
"""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

SCRIPT = Path(__file__).with_name("install_server_update_host.sh")
SHELL = shutil.which("dash") if os.name == "posix" else None
TARGET = "amnezia-dns-net"
DAEMON_MISSING = f"Error response from daemon: network {TARGET} not found"


@unittest.skipUnless(SHELL, "POSIX dash required for the inert shell function")
class DockerNetworkAbsenceTests(unittest.TestCase):
    def query(self, output, code=1):
        source = SCRIPT.read_text(encoding="utf-8")
        begin = source.index("\nquery_network_field() {")
        end = source.index("\nquery_network_id() {", begin)
        function = source[begin:end]
        harness = (
            "set -u\n"
            'die() { printf "%s\\n" "$1" >&2; exit 2; }\n'
            'as_root() { printf "%s" "$QUERY_RESPONSE"; return "$QUERY_CODE"; }\n'
            + function
            + '\nquery_network_field "amnezia-dns-net" "{{.Id}}" "network ID"\n'
            + 'status=$?\nprintf "status=%s\\nvalue=%s\\n" "$status" "$NETWORK_QUERY_VALUE"\nexit "$status"\n'
        )
        return subprocess.run(
            [SHELL, "-c", harness], capture_output=True, text=True, timeout=5,
            env={"PATH": "/usr/bin:/bin", "QUERY_RESPONSE": output, "QUERY_CODE": str(code)},
        )

    def test_observed_daemon_absence_with_empty_stdout_line(self):
        result = self.query("\n" + DAEMON_MISSING + "\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "status=1\nvalue=\n")

    def test_daemon_absence_without_empty_stdout(self):
        result = self.query(DAEMON_MISSING)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_legacy_absence_is_preserved(self):
        for label in ("network", "object"):
            with self.subTest(label=label):
                result = self.query(f"\nError: No such {label}: {TARGET}\n")
                self.assertEqual(result.returncode, 1, result.stderr)

    def test_another_network_is_not_absence_of_requested_network(self):
        result = self.query("\nError response from daemon: network another-network not found\n")
        self.assertEqual(result.returncode, 2)

    def test_additional_permission_error_is_not_hidden(self):
        result = self.query("\n" + DAEMON_MISSING + "\npermission denied\n")
        self.assertEqual(result.returncode, 2)

    def test_permission_denied_stays_fatal(self):
        result = self.query("permission denied while connecting to Docker socket")
        self.assertEqual(result.returncode, 2)

    def test_unexpected_daemon_response_stays_fatal(self):
        result = self.query("Error response from daemon: internal server error")
        self.assertEqual(result.returncode, 2)

    def test_success_value_is_byte_preserved(self):
        identity = "a" * 64
        result = self.query(identity + "\n", code=0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"status=0\nvalue={identity}\n")


if __name__ == "__main__":
    unittest.main()
