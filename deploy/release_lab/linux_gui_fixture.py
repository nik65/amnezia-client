"""Fixed softpipe and desktop-readiness fixture in a canonical owned guest.

No public callback or PASS import; original GUI/runtime/visual gates follow.
"""
import base64
import copy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time

from .linux_desktop_readiness import DesktopReadinessTracker
from .linux_gui_driver import MAX_PPM_BYTES, ppm_to_png, _write_new

PROFILE = 'linux-x64-gui'
PREFIX = 'deploy/release_lab/'
XRES_PACKAGE = 'dist/release-lab-fixtures/gui-xres-noble-amd64-20261023/libxres1_1.2.1-1build1_amd64.deb'
XRES_PACKAGE_SHA256 = 'e47d216187d3ef658ff087e3ecada2cf46b199ad28106e55ff00412cd6c55dbd'
SOURCES = (PREFIX+'linux_gui_fixture.py', PREFIX+'linux_desktop_readiness.py',
           PREFIX+'guest_helpers/linux_gui_softpipe_setup.py',
           PREFIX+'guest_helpers/linux_gui_readiness_probe.py',
           PREFIX+'guest_helpers/linux_gui_xres_probe.py',
           PREFIX+'guest_helpers/linux_gui_xres_dependency.py',
           PREFIX+'guest_helpers/linux_gui_continuous.py', XRES_PACKAGE)

FIXTURE_BINDING = r'''
import os,sys,re,stat,json
run,profile,nonce,phase=sys.argv[1:5]
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}',run) or profile!='linux-x64-gui' or not re.fullmatch('[0-9a-f]{48}',nonce) or phase not in ('setup','observe','capture'):
 raise RuntimeError('invalid fixed fixture binding')
root='/run/amnezia-release-lab-fixture-'+nonce
expected=json.dumps({'run_id':run,'profile':profile,'nonce':nonce},sort_keys=True).encode()
if phase=='setup':
 os.mkdir(root,0o700)
d=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 s=os.fstat(d)
 if s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o700:raise RuntimeError('private fixture directory identity differs')
 if phase=='setup':
  f=os.open('marker',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
  with os.fdopen(f,'wb') as stream:stream.write(expected);stream.flush();os.fsync(stream.fileno())
 f=os.open('marker',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
 try:
  s=os.fstat(f)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size!=len(expected) or os.read(f,4096)!=expected:raise RuntimeError('private fixture marker differs')
 finally:os.close(f)
finally:os.close(d)
if phase=='observe':
 f=os.open('/tmp/amnezia-release-lab-marker',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(f)
  expected_run=('amnezia-release-lab:'+run+':'+profile).encode()
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_size!=len(expected_run) or os.read(f,4096)!=expected_run:raise RuntimeError('canonical run/profile marker differs')
 finally:os.close(f)
sys.argv=[sys.argv[0]]+sys.argv[5:]
'''

SETUP_OUTER_TIMEOUT = 150  # Inner limits total 122s + 28s scheduling/I/O margin.
PHASE_CAPTURE = r'''
import base64,hashlib
d=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 f=os.open('setup-phases.jsonl',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
 try:
  before=os.fstat(f)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or stat.S_IMODE(before.st_mode)!=0o600:raise RuntimeError('private phase file identity differs')
  data=os.read(f,262144);after=os.fstat(f)
  print(json.dumps({'schema':'linux-gui-setup-phase-snapshot-v1','body_base64':base64.b64encode(data).decode(),'captured_size':len(data),'captured_sha256':hashlib.sha256(data).hexdigest(),'size_before':before.st_size,'size_after':after.st_size,'truncated':after.st_size>len(data),'stable_read':before.st_size==after.st_size==len(data),'setup_completion_not_implied':True}))
 finally:os.close(f)
finally:os.close(d)
'''


class LinuxGuiFixtureError(RuntimeError):
    pass


def offline_profile_record(run):
    """Bind the offline boot adjustment to the canonical planned GUI profile."""
    expected = Path(__file__).resolve().parent/'profiles'/f'{PROFILE}.json'
    record = run.get('profile_records', {}).get(PROFILE)
    if type(record) is not dict:
        raise LinuxGuiFixtureError('planned GUI profile source missing')
    path = Path(record.get('path', ''))
    if path.is_symlink() or path.resolve() != expected or not path.is_file() or path.stat().st_size != record.get('size') or hashlib.sha256(path.read_bytes()).hexdigest() != record.get('sha256'):
        raise LinuxGuiFixtureError('planned GUI profile source changed')
    profile = json.loads(path.read_bytes())
    if profile.get('id') != PROFILE or profile.get('backend') != 'qemu-linux' or profile.get('nic') != 'none':
        raise LinuxGuiFixtureError('offline boot adjustment requires canonical NIC none')
    return record


class LinuxGuiFixture:
    def __init__(self, controller, run_id):
        from .lab import LabController, QgaClient, ensure_owned_child
        if type(controller) is not LabController or controller.dry_run or controller.test_mode:
            raise LinuxGuiFixtureError('canonical live controller required')
        controller.assert_mutation_context()
        if controller._mutation_lock_depth <= 0 or controller._mutation_lock_fd is None:
            raise LinuxGuiFixtureError('active mutation lock required')
        self.controller, self.run_id = controller, run_id
        self.nonce = secrets.token_hex(24)
        self.run = copy.deepcopy(controller.get_run(run_id))
        offline_profile_record(self.run)
        self.binding = copy.deepcopy(controller.owned_vm(run_id, PROFILE))
        records = self.run.get('semantic_helper_records', {})
        if any(name not in records for name in SOURCES):
            raise LinuxGuiFixtureError('fixed GUI fixture source closure missing')
        self.records = {name: records[name] for name in SOURCES}
        self.archive = ensure_owned_child(controller.root, controller.root/'exports'/run_id/PROFILE/('desktop-'+secrets.token_hex(24)), 'GUI fixture archive')
        self.qga = QgaClient(Path(self.binding['qga_socket']))
        self._setup_done = False
        self._ready_done = False
        self.telemetry_gaps = []
        self._fence()
        self.archive.mkdir(mode=0o700, parents=True, exist_ok=False)

    def _fence(self):
        self.controller.assert_mutation_context()
        if self.controller._mutation_lock_depth <= 0 or self.controller._mutation_lock_fd is None:
            raise LinuxGuiFixtureError('active mutation lock required')
        if self.controller.get_run(self.run_id) != self.run or self.controller.owned_vm(self.run_id, PROFILE) != self.binding:
            raise LinuxGuiFixtureError('planned run or live guest identity changed')
        offline_profile_record(self.run)
        for name, record in self.records.items():
            path = Path(record['path'])
            expected = Path(__file__).resolve().parents[2]/name
            if path.resolve() != expected or path.is_symlink() or not path.is_file() or path.stat().st_size != record['size'] or hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
                raise LinuxGuiFixtureError('planned fixture source changed')

    def _source(self, name):
        record = self.records[PREFIX+'guest_helpers/'+name]
        data = Path(record['path']).read_bytes()
        if len(data) != record['size'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise LinuxGuiFixtureError('executed helper bytes differ from plan')
        return data.decode('utf-8-sig')

    def _execute(self, name, args=(), *, label):
        self._fence()
        phase = 'setup' if name == 'linux_gui_softpipe_setup.py' else 'observe'
        program = FIXTURE_BINDING+'\n'+self._source(name)
        if phase == 'setup':
            # _fence verified the plan-bound canonical NIC-none source above.
            args = ('--planned-nic-none', *args)
        try:
            result = self.qga.guest_exec_wait('/usr/bin/python3', ['-c', program, self.run_id, PROFILE, self.nonce, phase, *args], timeout=SETUP_OUTER_TIMEOUT if phase == 'setup' else 105 if name == 'linux_gui_xres_dependency.py' else 45)
        except BaseException as error:
            if phase == 'setup':
                try:
                    self._fence()
                    self._capture_setup_phases('setup-failure-phases')
                    self._fence()
                except BaseException as capture_error:
                    error.add_note('Private GUI setup phase capture unavailable: '+type(capture_error).__name__)
            raise
        self._fence()
        if type(result.get('exitcode')) is not int or result['exitcode'] != 0:
            raise LinuxGuiFixtureError('fixed guest helper failed')
        raw = result['stdout'].encode()
        if len(raw) > 950000:
            raise LinuxGuiFixtureError('guest fixture output exceeded bounds')
        _write_new(self.archive/(label+'.json'), raw)
        if phase == 'setup':
            # Optional diagnostic I/O cannot undo real successful setup. Live
            # ownership/source fences remain mandatory outside this catch.
            self._fence()
            try:
                self._capture_setup_phases('setup-complete-phases')
            except Exception as capture_error:
                gap = {'phase':'setup', 'operation':'private-phase-telemetry', 'error_type':type(capture_error).__name__}
                self.telemetry_gaps = getattr(self,'telemetry_gaps',[]) + [gap]
                try:
                    _write_new(self.archive/'setup-phase-telemetry-gap.json',json.dumps(gap,sort_keys=True).encode())
                except Exception as archive_error:
                    gap['gap_archive_error_type'] = type(archive_error).__name__
            self._fence()
        return json.loads(raw)

    def _capture_setup_phases(self, label):
        result = self.qga.guest_exec_wait('/usr/bin/python3', ['-c',FIXTURE_BINDING+'\n'+PHASE_CAPTURE,self.run_id,PROFILE,self.nonce,'capture'], timeout=10)
        if type(result.get('exitcode')) is not int or result['exitcode'] != 0:
            raise LinuxGuiFixtureError('private setup phase capture failed')
        raw = result['stdout'].encode()
        if len(raw)>400000:
            raise LinuxGuiFixtureError('private setup phase capture exceeds bounds')
        _write_new(self.archive/(label+'.json'),raw)
        value = json.loads(raw)
        if value.get('schema') != 'linux-gui-setup-phase-snapshot-v1' or value.get('setup_completion_not_implied') is not True:
            raise LinuxGuiFixtureError('private setup phase snapshot schema differs')
        data = base64.b64decode(value['body_base64'],validate=True)
        if len(data)>262144 or len(data)!=value.get('captured_size') or hashlib.sha256(data).hexdigest()!=value.get('captured_sha256'):
            raise LinuxGuiFixtureError('private setup phase snapshot bytes differ')
        _write_new(self.archive/(label+'.jsonl'),data)

    def configure_before_login(self):
        if self._setup_done:
            raise LinuxGuiFixtureError('fixture configuration already performed')
        result = self._execute('linux_gui_softpipe_setup.py', label='softpipe-configuration')
        if result.get('GL_RENDERER') != 'softpipe' or result.get('setting') != 'GALLIUM_DRIVER=softpipe' or result.get('otherExperimentSettingsChanged') is not False:
            raise LinuxGuiFixtureError('softpipe fixture readback differs')
        boot = result.get('offlineNetworkBoot')
        if type(boot) is not dict or boot.get('plannedNIC') != 'none' or boot.get('interfaces') != ['lo'] or boot.get('runtimeOnly') is not True or boot.get('unit') != 'systemd-networkd-wait-online.service' or boot.get('readback', {}).get('Job') != '' or boot.get('readback', {}).get('LoadState') != 'masked' or boot.get('readback', {}).get('ActiveState') != 'inactive':
            raise LinuxGuiFixtureError('offline boot proof/readback differs')
        self._setup_done = True
        return result

    def ensure_xres_dependency_after_probe(self):
        if not self._setup_done or self._ready_done:
            raise LinuxGuiFixtureError('dependency fixture ordering differs')
        self.run = copy.deepcopy(self.controller.get_run(self.run_id))
        steps = self.run['profiles'][PROFILE].get('steps', [])
        if len(steps) != 1 or steps[0].get('id') != 'probe' or steps[0].get('passed') is not True:
            raise LinuxGuiFixtureError('XRes dependency requires canonical probe only')
        self._fence()
        package = Path(self.records[XRES_PACKAGE]['path']).read_bytes()
        if len(package) != 6778 or hashlib.sha256(package).hexdigest() != XRES_PACKAGE_SHA256:
            raise LinuxGuiFixtureError('fixed XRes package identity differs')
        arguments = [base64.b64encode(package).decode(),
                     base64.b64encode(self._source('linux_gui_readiness_probe.py').encode()).decode(),
                     base64.b64encode(self._source('linux_gui_xres_probe.py').encode()).decode()]
        result = self._execute('linux_gui_xres_dependency.py', arguments, label='xres-dependency')
        if result.get('schema') != 'linux-gui-xres-dependency-v1' or result.get('verified') is not True or result.get('overlayOnly') is not True or result.get('packageSHA256') != XRES_PACKAGE_SHA256:
            raise LinuxGuiFixtureError('actual XRes dependency proof missing')
        return result

    def _continuous_remaining(self):
        deadline=getattr(self,'_diagnostic_deadline',None) or getattr(self,'_continuous_deadline',None)
        if deadline is None:return 10.0
        remaining=deadline-time.monotonic()
        if remaining<=0:raise LinuxGuiFixtureError('bounded continuous transaction deadline exceeded')
        return remaining

    def _live_fence(self):
        """Fresh live ownership between full entry/exit closure validations."""
        from .lab import QmpClient
        self.controller.assert_mutation_context()
        if self.controller._mutation_lock_depth <= 0 or self.controller._mutation_lock_fd is None:
            raise LinuxGuiFixtureError('mutation lock lost')
        state = json.loads((self.controller.root/'state.json').read_bytes())
        if state['runs'].get(self.run_id) != self.run:
            raise LinuxGuiFixtureError('run changed inside continuous transaction')
        vm = self.binding
        proc = Path('/proc')/str(vm['pid'])
        command = (proc/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        expected = vm['argv']
        if (proc.stat().st_uid != os.getuid() or Path(command[0]).name != Path(expected[0]).name
                or command[1:] != expected[1:] or
                (proc/'stat').read_text().rsplit(') ',1)[1].split()[19] != str(vm['proc_start_time'])):
            raise LinuxGuiFixtureError('live VM PID/start/UID/argv changed')
        directory = self.controller.root/'runs'/self.run_id/PROFILE
        for key,name in (('qmp_socket','qmp.sock'),('qga_socket','qga.sock')):
            path=Path(vm[key]);info=path.lstat()
            if path != directory/name or path.is_symlink() or not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid():
                raise LinuxGuiFixtureError('live VM socket changed')
            identity=(info.st_dev,info.st_ino)
            previous=getattr(self,'_socket_identities',{}).get(key)
            if previous is not None and previous!=identity:raise LinuxGuiFixtureError('live socket inode changed')
            if not hasattr(self,'_socket_identities'):self._socket_identities={}
            self._socket_identities[key]=identity
        marker=directory/'.owned-overlay.json'
        expected_marker={'run_id':self.run_id,'profile':PROFILE,'overlay':str(directory/'overlay.qcow2')}
        if self.run.get('execution_plan_sha256'):expected_marker['execution_plan_sha256']=self.run['execution_plan_sha256']
        if marker.is_symlink() or json.loads(marker.read_bytes())!=expected_marker:
            raise LinuxGuiFixtureError('live overlay marker changed')
        for name,record in self.records.items():
            path=Path(record['path'])
            if path.is_symlink() or path.stat().st_size!=record['size'] or hashlib.sha256(path.read_bytes()).hexdigest()!=record['sha256']:
                raise LinuxGuiFixtureError('continuous source changed')
        qmp=QmpClient(Path(vm['qmp_socket']),timeout=min(5,self._continuous_remaining()))
        status=qmp.request('query-status');uid=qmp.request('query-uuid')
        if status.get('return',{}).get('running') is not True or uid.get('return',{}).get('UUID')!=vm['uuid']:
            raise LinuxGuiFixtureError('live QMP UUID/status differs')

    def _continuous_control(self, operation, payload=None):
        self._continuous_remaining()
        self._live_fence()
        program=FIXTURE_BINDING+'\n'+self._source('linux_gui_continuous.py')
        result=self.qga.guest_exec_wait('/usr/bin/python3',['-c',program,self.run_id,PROFILE,self.nonce,'observe','control',operation,json.dumps(payload or {})],timeout=min(10,self._continuous_remaining()))
        self._live_fence()
        data=result['stdout'].encode()
        if len(data)>95000:raise LinuxGuiFixtureError('continuous control output bounds')
        value=json.loads(data)
        if operation=='status' and not value.get('pending'):
            if value.get('worker',{}).get('pid')!=self._resident_pid or value.get('run')!=self.run_id or value.get('nonce')!=self.nonce:
                raise LinuxGuiFixtureError('continuous worker handshake differs')
        return value

    def continuous_alive(self):
        if not getattr(self,'_resident_pid',None):return
        # Legitimate collect/visual transitions update only the canonical run.
        self.run=copy.deepcopy(self.controller.get_run(self.run_id))
        if self.controller.owned_vm(self.run_id,PROFILE)!=self.binding:raise LinuxGuiFixtureError('GUI ownership changed')
        self._fence()
        return self.inhibitor_alive()

    def inhibitor_alive(self):
        if not getattr(self,'_resident_pid',None):return
        state=self._continuous_control('status')
        if state.get('phase')!='sealed':raise LinuxGuiFixtureError('continuous inhibitor lease not alive')
        return state

    def close(self):
        if not getattr(self,'_resident_pid',None):return
        self._continuous_deadline=self._diagnostic_deadline=None
        self.run=copy.deepcopy(self.controller.get_run(self.run_id))
        self._fence()  # Lost ownership means no guest stop/kill commands.
        self._continuous_control('stop')
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            self._live_fence()
            reply=getattr(self,'_resident_exit',None) or self.qga.request('guest-exec-status',{'pid':self._resident_pid})
            payload=reply.get('return',{})
            if payload.get('exited') is True:
                _write_new(self.archive/'continuous-worker-exit.json',json.dumps(reply).encode())
                if payload.get('exitcode')!=0:raise LinuxGuiFixtureError('continuous worker cleanup failed')
                self._resident_pid=None
                self._fence()
                return
            time.sleep(.2)
        raise LinuxGuiFixtureError('owned continuous worker did not reap')

    def _capture_continuous_failure(self, primary):
        if not getattr(self,'_resident_pid',None):return
        self._continuous_deadline=None
        self._diagnostic_deadline=time.monotonic()+20
        data=bytearray();state=None;total=None
        try:
            self._live_fence()  # Never send even a diagnostic/stop after ownership loss.
            self._continuous_control('stop')
            while self._continuous_remaining()>0:
                self._live_fence()
                reply=self.qga.request('guest-exec-status',{'pid':self._resident_pid})
                if reply.get('return',{}).get('exited') is True:
                    self._resident_exit=reply
                    _write_new(self.archive/'continuous-failure-exit.json',json.dumps(reply).encode())
                    break
                time.sleep(.1)
            state=self._continuous_control('status')
            _write_new(self.archive/'continuous-failure-state.json',json.dumps(state).encode())
            total=state.get('rawSize',0)
            if type(total)is not int or not 0<=total<=16*1024*1024:raise LinuxGuiFixtureError('failure raw archive bounds')
            while len(data)<total:
                self._continuous_remaining()
                part=self._continuous_control('archive',{'offset':len(data)})
                chunk=base64.b64decode(part['data'],validate=True)
                if part['offset']!=len(data) or part['size']!=total or not 0<len(chunk)<=32768 or len(data)+len(chunk)>total:raise LinuxGuiFixtureError('failure archive chunk differs')
                data.extend(chunk)
        except BaseException as capture_error:
            primary.add_note('bounded continuous failure capture: '+type(capture_error).__name__)
        finally:
            self._diagnostic_deadline=None
            try:
                _write_new(self.archive/'continuous-failure-raw.partial.jsonl',bytes(data))
                _write_new(self.archive/'continuous-failure-capture.json',json.dumps({'diagnosticOnly':True,'capturedSize':len(data),'expectedSize':total,'sha256':hashlib.sha256(data).hexdigest(),'partial':total is None or len(data)!=total}).encode())
            except BaseException as archive_error:primary.add_note('private continuous failure write: '+type(archive_error).__name__)

    def wait_after_steps(self):
        try:return self._wait_after_steps_continuous()
        except BaseException as primary:
            self._capture_continuous_failure(primary)
            raise

    def _wait_after_steps_continuous(self):
        from .lab import QmpClient
        if not self._setup_done or self._ready_done:raise LinuxGuiFixtureError('fixture ordering differs')
        self.run=copy.deepcopy(self.controller.get_run(self.run_id))
        steps=self.run['profiles'][PROFILE].get('steps',[])
        if tuple(s.get('id') for s in steps)!=('probe','reinstall','update','service-health') or any(s.get('passed') is not True for s in steps):
            raise LinuxGuiFixtureError('canonical GUI matrix is incomplete')
        self._fence()
        program=FIXTURE_BINDING+'\n'+self._source('linux_gui_continuous.py')
        sources=[base64.b64encode(self._source(n).encode()).decode() for n in ('linux_gui_readiness_probe.py','linux_gui_xres_probe.py')]
        self._live_fence()
        start=self.qga.guest_exec('/usr/bin/python3',['-c',program,self.run_id,PROFILE,self.nonce,'observe','worker',*sources])
        self._resident_pid=start['pid'];self._live_fence()
        deadline=time.monotonic()+300;self._continuous_deadline=deadline;woken=False;capture=None
        while time.monotonic()<deadline:
            state=self._continuous_control('status')
            if state.get('phase')=='failed':
                _write_new(self.archive/'continuous-failure.json',json.dumps(state).encode())
                raise LinuxGuiFixtureError('continuous guest sampler failed')
            level=(state.get('latestDPMS') or state.get('displayBefore',{}).get('dpms',{})).get('level')
            if level is not None and level!=0 and not woken:
                self._live_fence()
                reply=QmpClient(Path(self.binding['qmp_socket'])).request('send-key',{'keys':[{'type':'qcode','data':'shift'}],'hold-time':80})
                self._live_fence()
                if not isinstance(reply.get('return'),dict) or 'error' in reply:raise LinuxGuiFixtureError('owned display wake failed')
                woken=True
                _write_new(self.archive/'continuous-wake.json',json.dumps({'diagnosticOnly':True,'dpmsBefore':level,'qmpResponse':reply}).encode())
            if state.get('dwellSpanMs',0)>=30000 and state.get('phase')=='sampling' and capture is None:
                bracket=self._continuous_control('clock')
                ppm=self.archive/'continuous-desktop.ppm'
                self._live_fence()
                reply=QmpClient(Path(self.binding['qmp_socket'])).request('screendump',{'filename':str(ppm)})
                self._live_fence()
                if 'error' in reply or not isinstance(reply.get('return'),dict) or ppm.is_symlink() or not ppm.is_file() or not 0<ppm.stat().st_size<=MAX_PPM_BYTES:
                    raise LinuxGuiFixtureError('continuous QMP capture failed')
                os.chmod(ppm,0o600);png=ppm_to_png(ppm.read_bytes());target=self.archive/'continuous-desktop.png';_write_new(target,png)
                capture=self._continuous_control('capture',{**bracket,'sha256':hashlib.sha256(png).hexdigest(),'size':len(png)})
                capture['path']=str(target)
                _write_new(self.archive/'continuous-capture-bracket.json',json.dumps(capture).encode())
            if state.get('phase')=='sealed':
                if capture is None or state.get('capture',{}).get('sha256')!=capture['sha256']:raise LinuxGuiFixtureError('sealed capture changed')
                data=bytearray();total=state.get('rawSize')
                if type(total)is not int or not 0<total<=16*1024*1024:raise LinuxGuiFixtureError('continuous archive bounds')
                while len(data)<total:
                    self._continuous_remaining()
                    part=self._continuous_control('archive',{'offset':len(data)})
                    chunk=base64.b64decode(part['data'],validate=True)
                    if part['offset']!=len(data) or part['size']!=total or not 0<len(chunk)<=32768 or len(data)+len(chunk)>total:raise LinuxGuiFixtureError('continuous archive chunk differs')
                    data.extend(chunk)
                _write_new(self.archive/'continuous-raw.jsonl',bytes(data))
                rows=[json.loads(line) for line in data.splitlines()]
                observations=[r['observation'] for r in rows if type(r.get('observation'))is dict and r.get('xres',{}).get('dpms',{}).get('level')==0]
                if observations!=state.get('observations') or len(observations)<2:raise LinuxGuiFixtureError('continuous actual observations differ')
                tracker=DesktopReadinessTracker()
                for row in rows[:-1]:
                    observed=row.get('observation')
                    if type(observed)is dict and row.get('xres',{}).get('dpms',{}).get('level')==0:tracker.observe_nonvisual(observed)
                    else:tracker.break_continuity()
                final=copy.deepcopy(observations[-1])
                if final['boot_id']!=capture['bootID'] or not capture['beforeMs']<=capture['afterMs']<=final['monotonic_ms'] or final['monotonic_ms']-capture['beforeMs']>10000:
                    raise LinuxGuiFixtureError('actual postcapture freshness differs')
                final['pixels']={'path':capture['path'],'sha256':capture['sha256'],'size':capture['size'],'captured_monotonic_ms':capture['afterMs'],'diagnosticOnly':True}
                decision=tracker.observe(final)
                _write_new(self.archive/'continuous-decision.json',json.dumps(asdict(decision)).encode())
                if not decision.ready_for_root_visual_review:raise LinuxGuiFixtureError('actual continuous readiness rejected')
                self._fence()
                alive=self._continuous_control('status')
                if alive.get('phase')!='sealed':raise LinuxGuiFixtureError('identity changed after full closure validation')
                self._ready_done=True
                self._continuous_deadline=None
                return {'diagnosticOnly':True,'decision':asdict(decision),'archive':str(self.archive),'captureBracket':capture,'source_records':list(self.records.values()),'telemetry_gaps':self.telemetry_gaps}
            time.sleep(.3)
        raise LinuxGuiFixtureError('bounded desktop readiness deadline exceeded')
