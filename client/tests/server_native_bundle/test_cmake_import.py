"""Exercise CMake import with data-only synthetic ELF fixtures, never executable code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--build-dir', type=Path, required=True, help='Directory for receipts and logs')
    parser.add_argument('--cmake', default='cmake')
    args = parser.parse_args()
    evidence = args.build_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    module = args.repo.resolve() / 'client/cmake/serverNativeBundle.cmake'
    if not module.is_file():
        parser.error('repository does not contain the CMake importer')
    results = []
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
    # System temporary storage intentionally keeps Unix FIFO fixtures off filesystems
    # such as Windows-mounted WSL drives that do not support named pipes.
    with tempfile.TemporaryDirectory(prefix='amnezia-native-import-') as temporary:
        out = Path(temporary)
        root = out / 'bundle & space'
        (root / 'x86_64').mkdir(parents=True)
        binary = bytearray(120)
        binary[:9] = b'\x7fELF\x02\x01\x01\x00\x00'
        struct.pack_into('<HHIQQQIHHHHHH', binary, 16, 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        struct.pack_into('<IIQQQQQQ', binary, 64, 1, 5, 0, 0x400000, 0, 120, 120, 4096)
        exe = root / 'x86_64/collector'
        row = dict(architecture='x86_64', path='x86_64/collector', role='collector',
                   sha256=hashlib.sha256(binary).hexdigest(), size=len(binary))
        good = dict(binaries=[row], schema=1)
        script = out / 'test.cmake'
        script.write_text('cmake_minimum_required(VERSION 3.21)\ninclude([=[' + module.as_posix()
                          + ']=])\namnezia_import_server_native_bundle(result)\n', encoding='utf-8')

        def check(name, expected=False, bundle=root):
            command = [args.cmake]
            if bundle is not None:
                command.append('-DAMNEZIA_SERVER_NATIVE_BUNDLE_DIR=' + str(bundle))
            process = subprocess.run(command + ['-P', str(script)], cwd=out,
                                     capture_output=True, text=True, timeout=10)
            (evidence / (name + '.log')).write_text(process.stdout + process.stderr, encoding='utf-8')
            passed = (process.returncode == 0) == expected
            results.append(dict(name=name, expected=expected, exit=process.returncode, passed=passed))
            if not passed:
                raise AssertionError(name + ': ' + process.stdout + process.stderr)

        def run(name, manifest, data=binary, expected=False, bundle=root):
            exe.write_bytes(data)
            (root / 'manifest.json').write_text(manifest, encoding='utf-8')
            check(name, expected, bundle)

        run('valid', canonical(good), expected=True)
        run('valid-lf', canonical(good) + '\n', expected=True)
        assert '&amp;' in (out / 'serverNativeBundle.qrc').read_text(encoding='utf-8')
        run('unknown', canonical(dict(good, extra=1)))
        run('duplicate-key', canonical(good).replace('"schema":1', '"schema":1,"schema":1'))
        run('duplicate-identity', canonical(dict(binaries=[row, row], schema=1)))
        for name, changed in [('bad-size', dict(row, size=121)),
                              ('hash', dict(row, sha256='0' * 64)),
                              ('path', dict(row, path='../collector'))]:
            run(name, canonical(dict(binaries=[changed], schema=1)))
        mutations = [('dynamic', 64, '<I', 2), ('interpreter', 64, '<I', 3),
                     ('machine', 18, '<H', 183), ('entry', 24, '<Q', 0x500000),
                     ('bounds', 96, '<Q', 121), ('table', 32, '<Q', 1000),
                     ('load-overflow', 80, '<Q', 0x7fffffffffffffff),
                     ('page-incongruent', 80, '<Q', 0x400001),
                     ('alignment-nonpower', 112, '<Q', 3),
                     ('alignment-incongruent', 112, '<Q', 0x800000)]
        for name, offset, fmt, value in mutations:
            bad = bytearray(binary)
            struct.pack_into(fmt, bad, offset, value)
            changed = dict(row, sha256=hashlib.sha256(bad).hexdigest())
            run(name, canonical(dict(binaries=[changed], schema=1)), bad)
        bad = bytearray(binary)
        struct.pack_into('<H', bad, 18, 183)
        struct.pack_into('<Q', bad, 80, 0x401000)
        struct.pack_into('<Q', bad, 24, 0x401000)
        (root / 'aarch64').mkdir()
        (root / 'aarch64/collector').write_bytes(bad)
        changed = dict(row, architecture='aarch64', path='aarch64/collector',
                       sha256=hashlib.sha256(bad).hexdigest())
        run('arm-page-incongruent', canonical(dict(binaries=[changed], schema=1)))
        run('relative', canonical(good), bundle=Path('relative'))
        if os.name != 'nt':
            exe.unlink()
            os.mkfifo(exe)
            check('fifo')
            exe.unlink()
            target = root / 'target'
            target.write_bytes(binary)
            exe.symlink_to(target)
            check('symlink-file')
            exe.unlink()
            target.unlink()
            linked = out / 'linked-root'
            linked.symlink_to(root, target_is_directory=True)
            exe.write_bytes(binary)
            check('symlink-root', bundle=linked)
            linked.unlink()
        run('optional-absent', canonical(good), expected=True, bundle=None)
    receipt = dict(results=results, app_build=False,
                   source_sha256=hashlib.sha256(module.read_bytes()).hexdigest())
    (evidence / 'RECEIPT.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(f'CMake native bundle import: {len(results)} cases passed; no application built')


if __name__ == '__main__':
    main()
