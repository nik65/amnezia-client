"""Staged fixed guest helper; never run on the workstation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

PHASE_LIMITS = {'sessions':5, 'user-manager':5, 'egl':30,
                'daemon-reload':15, 'environment':5, 'start-graphical':45,
                'display-manager':5, 'package':5, 'offline-network':5,
                'offline-network-readback':2}
SETUP_OUTER_TIMEOUT = 150
PHASE_OUTPUT_LIMIT = 8192


class PhaseJournal:
    def __init__(self, directory):
        self.directory = os.open(directory, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        info = os.fstat(self.directory)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(self.directory)
            raise RuntimeError('private phase directory differs')
        try:
            self.fd = os.open('setup-phases.jsonl', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
        except BaseException:
            os.close(self.directory)
            raise

    def record(self, phase, state, **fields):
        value = {'phase':phase, 'state':state, 'monotonic_ns':time.monotonic_ns(), **fields}
        data = (json.dumps(value, sort_keys=True)+'\n').encode()
        view = memoryview(data)
        while view:
            count = os.write(self.fd, view)
            if count <= 0:
                raise RuntimeError('short private phase write')
            view = view[count:]
        os.fsync(self.fd)

    def close(self):
        os.close(self.fd)
        os.close(self.directory)


def output_record(value):
    if value is None:
        data = b''
    else:
        data = value.encode() if isinstance(value, str) else bytes(value)
    return {'base64':base64.b64encode(data[:PHASE_OUTPUT_LIMIT]).decode(),
            'original_size':len(data), 'sha256':hashlib.sha256(data).hexdigest(),
            'truncated':len(data)>PHASE_OUTPUT_LIMIT}


def run_phase(journal, name, args, *, check=True):
    limit = PHASE_LIMITS[name]
    journal.record(name, 'begin', timeout_seconds=limit)
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=check, timeout=limit)
    except BaseException as error:
        journal.record(name, 'failed', error_type=type(error).__name__,
                       stdout=output_record(getattr(error, 'stdout', None)),
                       stderr=output_record(getattr(error, 'stderr', None)))
        raise
    journal.record(name, 'complete', exit_code=result.returncode,
                   stdout=output_record(result.stdout), stderr=output_record(result.stderr))
    return result.stdout


def offline_interfaces(*, planned_nic_none):
    if planned_nic_none is not True:
        raise RuntimeError('offline boot adjustment requires planned NIC none')
    interfaces = sorted(path.name for path in Path('/sys/class/net').iterdir())
    if interfaces != ['lo']:
        raise RuntimeError('offline boot adjustment refused: non-loopback interface present')
    return interfaces


def offline_boot(journal, *, planned_nic_none):
    interfaces = offline_interfaces(planned_nic_none=planned_nic_none)
    journal.record('offline-network-proof', 'complete', planned_nic='none', interfaces=interfaces)
    # Sealed NIC-none guests cannot satisfy wait-online. Mask only this runtime
    # unit in the disposable overlay; do not change network configuration/routes.
    run_phase(journal,'offline-network',['systemctl','mask','--runtime','--now','systemd-networkd-wait-online.service'])
    raw = run_phase(journal,'offline-network-readback',['systemctl','show','systemd-networkd-wait-online.service','-pLoadState','-pActiveState','-pSubState','-pJob'])
    properties = dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
    if properties.get('LoadState') != 'masked' or properties.get('ActiveState') != 'inactive' or properties.get('Job') != '':
        raise RuntimeError('offline wait-online unit/job did not unblock')
    return {'plannedNIC':'none', 'interfaces':interfaces, 'runtimeOnly':True,
            'unit':'systemd-networkd-wait-online.service', 'readback':properties}


def setup(nonce, egl_source, *, planned_nic_none=False):
    if sum(PHASE_LIMITS.values()) + 20 >= SETUP_OUTER_TIMEOUT:
        raise RuntimeError('aggregate fixture deadline contract invalid')
    offline_interfaces(planned_nic_none=planned_nic_none)
    journal = PhaseJournal('/run/amnezia-release-lab-fixture-'+nonce)
    try:
        if run_phase(journal, 'sessions', ['loginctl','list-sessions','--no-legend']).strip():
            raise RuntimeError('session already exists; no configuration applied')
        state = run_phase(journal, 'user-manager', ['systemctl','show','user@1000.service','-pActiveState','--value']).strip()
        if state not in ('inactive','unknown'):
            raise RuntimeError('user manager already active')
        egl = json.loads(run_phase(journal, 'egl', ['/usr/bin/python3','-c',egl_source]))
        if egl.get('GL_RENDERER') != 'softpipe':
            raise RuntimeError('softpipe EGL renderer differs')
        journal.record('drop-in', 'begin')
        root = Path('/run/systemd/system/user@1000.service.d')
        if root.exists() or root.is_symlink():
            raise RuntimeError('guest user-manager drop-in already exists')
        root.mkdir(mode=0o700)
        path = root/'90-release-lab-softpipe.conf'
        data = b'[Service]\nEnvironment=GALLIUM_DRIVER=softpipe\n'
        descriptor = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        journal.record('drop-in', 'complete', sha256=hashlib.sha256(data).hexdigest())
        run_phase(journal,'daemon-reload',['systemctl','daemon-reload'])
        readback = run_phase(journal,'environment',['systemctl','show','user@1000.service','-pEnvironment'])
        if 'GALLIUM_DRIVER=softpipe' not in readback:
            raise RuntimeError('guest softpipe environment differs')
        # Unblock already queued boot jobs only AFTER the user-manager softpipe
        # drop-in is loaded and read back, so autologin cannot race onto llvmpipe.
        boot = offline_boot(journal, planned_nic_none=planned_nic_none)
        run_phase(journal,'start-graphical',['systemctl','start','amnezia-lab-gui.service'])
        if run_phase(journal,'display-manager',['systemctl','is-active','display-manager.service']).strip() != 'active':
            raise RuntimeError('guest display manager inactive')
        package = run_phase(journal,'package',['dpkg-query','-W','libgl1-mesa-dri'],check=False)
        journal.record('setup', 'complete')
        return {'setting':'GALLIUM_DRIVER=softpipe', 'GL_RENDERER':egl['GL_RENDERER'],
                'GL_VERSION':egl['GL_VERSION'], 'config':str(path),
                'eglVersion':egl['eglVersion'], 'package':package,
                'scope':'disposable guest lab graphical user manager before first login',
                'configSHA256':hashlib.sha256(data).hexdigest(), 'readback':readback,
                'offlineNetworkBoot':boot,
                'otherExperimentSettingsChanged':False}
    except BaseException as error:
        journal.record('setup', 'failed', error_type=type(error).__name__)
        raise
    finally:
        journal.close()


EGL_PROGRAM = "import ctypes as c,os,json\nos.environ['GALLIUM_DRIVER']='softpipe'\ne=c.CDLL('libEGL.so.1');e.eglGetProcAddress.argtypes=[c.c_char_p];e.eglGetProcAddress.restype=c.c_void_p\nget=c.CFUNCTYPE(c.c_void_p,c.c_uint,c.c_void_p,c.POINTER(c.c_int))(e.eglGetProcAddress(b'eglGetPlatformDisplayEXT'));d=get(0x31DD,None,None);assert d\nfor name,args,ret in [('eglInitialize',[c.c_void_p,c.POINTER(c.c_int),c.POINTER(c.c_int)],c.c_uint),('eglBindAPI',[c.c_uint],c.c_uint),('eglChooseConfig',[c.c_void_p,c.POINTER(c.c_int),c.POINTER(c.c_void_p),c.c_int,c.POINTER(c.c_int)],c.c_uint),('eglCreatePbufferSurface',[c.c_void_p,c.c_void_p,c.POINTER(c.c_int)],c.c_void_p),('eglCreateContext',[c.c_void_p,c.c_void_p,c.c_void_p,c.POINTER(c.c_int)],c.c_void_p),('eglMakeCurrent',[c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p],c.c_uint)]:f=getattr(e,name);f.argtypes=args;f.restype=ret\nmajor,minor=c.c_int(),c.c_int();assert e.eglInitialize(d,c.byref(major),c.byref(minor));assert e.eglBindAPI(0x30A2)\na=(c.c_int*7)(0x3033,1,0x3040,8,0x3024,8,0x3038);cfg=c.c_void_p();n=c.c_int();assert e.eglChooseConfig(d,a,c.byref(cfg),1,c.byref(n)) and n.value>0\npa=(c.c_int*5)(0x3057,1,0x3056,1,0x3038);s=e.eglCreatePbufferSurface(d,cfg,pa);ca=(c.c_int*1)(0x3038);ctx=e.eglCreateContext(d,cfg,None,ca);assert s and ctx and e.eglMakeCurrent(d,s,s,ctx)\ng=c.CDLL('libGL.so.1');g.glGetString.argtypes=[c.c_uint];g.glGetString.restype=c.c_char_p;renderer=g.glGetString(0x1F01).decode();version=g.glGetString(0x1F02).decode();assert renderer=='softpipe',renderer\n\nprint(json.dumps({'GL_RENDERER':renderer,'GL_VERSION':version,'eglVersion':[major.value,minor.value]}))\n"

if __name__ == '__main__':
    # The controller supplies fixed hash-bound EGL source, not an operator hook.
    if sys.argv[1:] != ['--planned-nic-none']:
        raise RuntimeError('canonical offline profile proof missing')
    print(json.dumps(setup(nonce, EGL_PROGRAM, planned_nic_none=True)))
