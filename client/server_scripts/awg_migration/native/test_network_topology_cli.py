"""Private pure-data CLI limits; no Docker, socket, installer or service calls."""
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

BINARY = sys.argv.pop(1)
ERROR = {'error': 'unsupported_source_network_topology'}
CONTAINER = '[{"NetworkSettings":{"Networks":{"bridge":{}}}}]'
FRAME = 8 * 1024 ** 2
OBSERVATION = 1024 ** 2


def request(container=CONTAINER):
    return json.dumps({'op': 'networks', 'container': container}, separators=(',', ':')).encode()


class NetworkTopologyCli(unittest.TestCase):
    def invoke(self, raw, success=False):
        process = subprocess.run([BINARY, '--network-json'], input=raw,
                                 capture_output=True, timeout=12)
        self.assertEqual(process.stderr, b'')
        self.assertLessEqual(len(process.stdout), 16 * 1024 + 1)
        self.assertEqual(process.returncode, 0 if success else 2)
        self.assertEqual(json.loads(process.stdout), {'result': ['bridge']} if success else ERROR)

    def test_valid_discovery_and_private_errors(self):
        self.invoke(request(), True)
        for raw in (b'{}', b'[]', b'null', b'{"op":"unknown","private":"private-topology-marker"}',
                    b'{"op":"networks","container":true}', b'{"op":"networks","op":"networks"}',
                    b'{"op":"networks","container":"[]","x":NaN}', b'{"ignored":"\xff"}'):
            with self.subTest(input_sha_kind=len(raw)):
                self.invoke(raw)

    def test_actual_frame_cap_and_overflow(self):
        raw = request()
        self.invoke(raw + b' ' * (FRAME - len(raw)), True)
        self.invoke(raw + b' ' * (FRAME + 1 - len(raw)))

    def test_actual_observation_cap_and_overflow(self):
        self.invoke(request(CONTAINER + ' ' * (OBSERVATION - len(CONTAINER))), True)
        self.invoke(request(CONTAINER + ' ' * (OBSERVATION + 1 - len(CONTAINER))))

    def test_recognized_mode_requires_eof_within_five_seconds(self):
        started = time.monotonic()
        process = subprocess.Popen([BINARY, '--network-json'], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(request())
            process.stdin.flush()
            # Keep stdin open: a complete JSON value alone must not bypass EOF
            # or leave the private helper waiting indefinitely.
            process.wait(timeout=8)
            elapsed = time.monotonic() - started
            self.assertEqual(process.returncode, 2)
            self.assertEqual(process.stderr.read(), b'')
            self.assertEqual(json.loads(process.stdout.read()), ERROR)
            self.assertGreaterEqual(elapsed, 4.5)
            self.assertLess(elapsed, 8)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


if __name__ == '__main__':
    if not Path(BINARY).is_file():
        raise SystemExit('standalone helper is required')
    unittest.main()
