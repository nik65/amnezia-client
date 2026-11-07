"""Drive the existing Linux GUI evidence helper in an owned guest only.

The driver archives pixels and live window identity. A root visual review is
still required; no screenshot statistic or driver return value grants PASS.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import zlib

PROFILE = 'linux-x64-gui'
HELPER = 'deploy/release_lab/guest_helpers/linux_gui_window_evidence.py'
MAX_PIXELS = 8192 * 8192
MAX_PPM_BYTES = MAX_PIXELS * 3 + 4096


class LinuxGuiDriverError(RuntimeError):
    pass


def ppm_to_png(data: bytes) -> bytes:
    """Convert bounded QMP P6 screenshots without external imaging packages."""
    if not isinstance(data, bytes) or len(data) > MAX_PPM_BYTES:
        raise LinuxGuiDriverError('screenshot bounds')
    position = 0
    def token():
        nonlocal position
        while position < len(data):
            if data[position:position+1] in b' \t\r\n':
                position += 1
            elif data[position:position+1] == b'#':
                end = data.find(b'\n', position)
                if end < 0: raise LinuxGuiDriverError('unterminated PPM comment')
                position = end + 1
            else: break
        start = position
        while position < len(data) and data[position:position+1] not in b' \t\r\n':
            position += 1
            if position-start > 16: raise LinuxGuiDriverError('PPM token bounds')
        return data[start:position]
    try:
        magic = token(); width = int(token()); height = int(token()); maximum = int(token())
    except ValueError as error:
        raise LinuxGuiDriverError('invalid PPM header') from error
    if magic != b'P6' or maximum != 255 or width <= 0 or height <= 0 or width * height > MAX_PIXELS:
        raise LinuxGuiDriverError('unsupported PPM geometry')
    if position >= len(data) or data[position:position+1] not in b' \t\r\n':
        raise LinuxGuiDriverError('missing PPM raster separator')
    position += 1
    if data[position-1:position+1] == b'\r\n': position += 1
    raster = data[position:]
    if len(raster) != width * height * 3:
        raise LinuxGuiDriverError('PPM raster size mismatch')
    def chunk(kind, value):
        return struct.pack('>I', len(value)) + kind + value + struct.pack('>I', zlib.crc32(kind + value) & 0xffffffff)
    compressor = zlib.compressobj()
    compressed = []
    stride = width * 3
    for row in range(height):
        compressed.append(compressor.compress(b'\0' + raster[row*stride:(row+1)*stride]))
    compressed.append(compressor.flush())
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', b''.join(compressed)) + chunk(b'IEND', b''))


def _write_new(path: Path, data: bytes):
    if path.is_symlink() or path.exists(): raise LinuxGuiDriverError('immutable archive already exists')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(data); output.flush(); os.fsync(output.fileno())


class LinuxGuiDriver:
    def __init__(self, controller, run_id: str, expected_binary_sha256: str):
        from .lab import LabController, QgaClient, ensure_owned_child
        if type(controller) is not LabController or controller.dry_run or controller.test_mode:
            raise LinuxGuiDriverError('live production controller required')
        controller.assert_mutation_context()
        if controller._mutation_lock_depth <= 0 or controller._mutation_lock_fd is None:
            raise LinuxGuiDriverError('active mutation session required')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', run_id) or not re.fullmatch(r'[0-9a-f]{64}', expected_binary_sha256):
            raise LinuxGuiDriverError('invalid run/binary binding')
        self.controller, self.run_id, self.binary_sha = controller, run_id, expected_binary_sha256
        self.nonce = secrets.token_hex(24)
        self.run = copy.deepcopy(controller.get_run(run_id))
        self.artifact = self.run['artifacts']['linux-x64']
        self.helper = self.run['semantic_helper_records'][HELPER]
        self.binding = copy.deepcopy(controller.owned_vm(run_id, PROFILE))
        self.qga = QgaClient(Path(self.binding['qga_socket']))
        self.guest_root = f'/run/amnezia-release-lab/{run_id}/{PROFILE}'
        self.script = self.guest_root + '/window-evidence-helper.py'
        self.archive = ensure_owned_child(controller.root, controller.root/'exports'/run_id/PROFILE/('visual-'+self.nonce), 'GUI visual archive')
        if self.archive.exists(): raise LinuxGuiDriverError('visual archive already exists')
        self.archive.mkdir(mode=0o700,parents=True)
        self.launch = self.collect = None
        self._fence()

    def _fence(self):
        self.controller.assert_mutation_context()
        if self.controller._mutation_lock_depth <= 0 or self.controller._mutation_lock_fd is None:
            raise LinuxGuiDriverError('active mutation session required')
        if self.controller.get_run(self.run_id) != self.run or self.controller.owned_vm(self.run_id, PROFILE) != self.binding:
            raise LinuxGuiDriverError('run or live guest identity changed')
        for item in (self.artifact, self.helper):
            path = Path(item['path'])
            if path.is_symlink() or not path.is_file() or path.stat().st_size != item['size']:
                raise LinuxGuiDriverError('planned GUI/helper file changed')
            with path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if digest != item['sha256']: raise LinuxGuiDriverError('planned GUI/helper bytes changed')

    def _execute(self, action):
        self._fence()
        args = [self.script, action, '--run-id', self.run_id, '--profile', PROFILE,
                '--attempt-nonce', self.nonce, '--evidence-dir', self.guest_root,
                '--expected-version', self.run['candidate_version'], '--expected-binary-sha256', self.binary_sha,
                '--artifact-sha256', self.artifact['sha256'], '--helper-sha256', self.helper['sha256']]
        if getattr(self.controller,'linux_acceleration',None)=='tcg':
            try:from . import tcg_mode, lab
            except ImportError as error:raise LinuxGuiDriverError('verified execution-copy TCG adapter unavailable') from error
            plan=tcg_mode.load(self.controller,self.run,lab.repo_root())
            if not isinstance(plan,dict) or plan.get('acceleration')!='tcg' or PROFILE not in plan.get('profiles',{}):
                raise LinuxGuiDriverError('reviewed TCG renderer plan required')
            args += ['--renderer-policy','softpipe']
        if action == 'collect': args += ['--screenshot-ack', self.guest_root+'/screenshot-archive-ack.json']
        try:
            response = self.qga.guest_exec_wait('/usr/bin/python3', args, timeout=120)
        except BaseException as primary:
            if action=='launch':self._capture_launch_failure(args,primary)
            raise
        self._fence()
        if not isinstance(response,dict) or type(response.get('exitcode')) is not int or response['exitcode'] != 0:
            raise LinuxGuiDriverError('GUI helper operation failed')
        try: value = json.loads(response['stdout'])
        except (ValueError, KeyError, TypeError) as error: raise LinuxGuiDriverError('GUI helper returned no JSON') from error
        if (value.get('schema') != 'amnezia.release-lab.linux-gui-window.v1' or value.get('phase') != action
                or value.get('origin') != 'qga' or value.get('injected') is not False
                or value.get('run_id') != self.run_id or value.get('profile') != PROFILE or value.get('attempt_nonce') != self.nonce):
            raise LinuxGuiDriverError('GUI helper evidence binding differs')
        _write_new(self.archive/(action+'.json'), response['stdout'].encode())
        return value

    def _capture_launch_failure(self, original_args, primary):
        """Read fixed owned attempt before canonical VM reset, even if archived."""
        try:
            self._fence()  # Lost ownership means no diagnostic guest command.
            args=list(original_args);args[1]='diagnose'
            response=self.qga.guest_exec_wait('/usr/bin/python3',args,timeout=20)
            self._fence()
            if type(response.get('exitcode'))is not int or response['exitcode']!=0:raise LinuxGuiDriverError('private launch diagnostics failed')
            raw=response['stdout'].encode()
            if len(raw)>512000:raise LinuxGuiDriverError('private launch diagnostic bounds')
            value=json.loads(raw)
            if (value.get('schema')!='amnezia.release-lab.linux-gui-window.v1' or value.get('phase')!='diagnose'
                    or value.get('diagnosticOnly')is not True or value.get('origin')!='qga' or value.get('injected')is not False
                    or value.get('run_id')!=self.run_id or value.get('profile')!=PROFILE or value.get('attempt_nonce')!=self.nonce):
                raise LinuxGuiDriverError('private launch diagnostic identity differs')
            _write_new(self.archive/'launch-failure.private.json',raw)
        except BaseException as diagnostic_error:
            primary.add_note('bounded private GUI launch capture: '+type(diagnostic_error).__name__)

    def stage_and_launch(self):
        if self.launch is not None: raise LinuxGuiDriverError('launch already performed')
        self._fence()
        # The canonical runner created this run/profile directory and marker.
        self.qga.write_file(self.script, Path(self.helper['path']).read_bytes())
        self.launch = self._execute('launch')
        return copy.deepcopy(self.launch)

    def capture_and_collect(self):
        from .lab import QmpClient
        if self.launch is None or self.collect is not None: raise LinuxGuiDriverError('GUI capture order conflict')
        self._execute('unlocked')
        self._fence(); ppm = self.archive/'screen.ppm'
        if ppm.exists() or ppm.is_symlink(): raise LinuxGuiDriverError('screenshot target exists')
        result = QmpClient(Path(self.binding['qmp_socket'])).request('screendump', {'filename':str(ppm)})
        self._fence()
        if 'return' not in result or not ppm.is_file() or ppm.is_symlink() or ppm.stat().st_size > MAX_PPM_BYTES:
            raise LinuxGuiDriverError('QMP screenshot failed or exceeded bounds')
        png = ppm_to_png(ppm.read_bytes()); target = self.archive/'screen.png'; _write_new(target, png)
        if len(png) <= 1024: raise LinuxGuiDriverError('screenshot lacks canonical archive size')
        record = {'path':str(target), 'sha256':hashlib.sha256(png).hexdigest(), 'size':len(png), 'kind':'linux-gui-window'}
        launch = self.launch
        ack = {'schema':'amnezia.release-lab.controller-screenshot-ack.v1', 'controller_created':True,
               'run_id':self.run_id, 'profile':PROFILE, 'attempt_nonce':self.nonce,
               'guest_marker':launch['guest_marker'], 'pid':launch['process']['pid'], 'start_ticks':launch['process']['start_ticks'],
               'window_id':launch['window']['id'], 'artifact_sha256':self.artifact['sha256'], 'helper_sha256':self.helper['sha256'],
               'expected_version':self.run['candidate_version'], 'expected_binary_sha256':self.binary_sha,
               'screenshot_sha256':record['sha256'], 'screenshot_size':record['size'], 'archive_record':record,
               'final_gate_revalidation_required':True}
        self.qga.write_file(self.guest_root+'/screenshot-archive-ack.json', (json.dumps(ack,sort_keys=True)+'\n').encode())
        self.collect = self._execute('collect')
        return copy.deepcopy(self.collect)

    def cleanup(self):
        if self.launch is None: raise LinuxGuiDriverError('no owned GUI launch to clean')
        return self._execute('cleanup')
