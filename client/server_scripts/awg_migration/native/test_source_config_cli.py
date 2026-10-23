"""Private framing tests; fixture interposes every execve, never real Docker."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
REQUEST = b'{"op":"capability"}'
SUCCESS = {'result': {'sourceConfigVersion': 1}}
ERROR = {'error': 'native_source_config_rejected'}


class SourceConfigCli(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-source-config-cli-')
        self.directory = Path(self.temporary.name)
        (self.directory / 'network-observer-fixture.json').write_text('{"responses":[]}', encoding='utf8')

    def tearDown(self):
        self.temporary.cleanup()

    def no_commands(self):
        self.assertFalse((self.directory / 'network-observer-trace.jsonl').exists())

    def invoke(self, raw, success=False):
        result = subprocess.run([BINARY, '--source-config-json'], input=raw,
                                cwd=self.directory, capture_output=True, timeout=9)
        self.assertEqual(result.returncode, 0 if success else 2)
        self.assertEqual(result.stderr, b'')
        self.assertLessEqual(len(result.stdout), 128)
        self.assertEqual(json.loads(result.stdout), SUCCESS if success else ERROR)
        self.no_commands()

    def test_exact_actual_input_cap_and_overflow(self):
        self.invoke(REQUEST + b' ' * (8192 - len(REQUEST)), True)
        self.invoke(REQUEST + b' ' * (8193 - len(REQUEST)))

    def test_invalid_private_protocol_is_fixed_and_effect_free(self):
        for raw in (b'', b'[]', b'null', b'{"op":"capability","op":"capability"}',
                    b'{"op":"capability","private":"private-source-marker"}',
                    b'{"op":"capability","source":"amnezia-awg"}', b'{"op":"\xff"}',
                    b'{"op":"read","source":"foreign"}',
                    b'{"op":"read","source":"amnezia-awg","path":"private-source-marker"}'):
            with self.subTest(length=len(raw)):
                self.invoke(raw)

    def test_complete_json_still_requires_eof_within_five_seconds(self):
        begin = time.monotonic()
        process = subprocess.Popen([BINARY, '--source-config-json'], cwd=self.directory,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(REQUEST)
            process.stdin.flush()
            process.wait(timeout=8)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(process.stderr.read(), b'')
            self.assertEqual(json.loads(process.stdout.read()), ERROR)
            self.assertGreaterEqual(time.monotonic() - begin, 4.5)
            self.assertLess(time.monotonic() - begin, 8)
            self.no_commands()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


if __name__ == '__main__':
    unittest.main()
