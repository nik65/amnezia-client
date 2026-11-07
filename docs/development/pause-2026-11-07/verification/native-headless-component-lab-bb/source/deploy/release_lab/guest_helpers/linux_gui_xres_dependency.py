"""Fixed Ubuntu package repair inside a nonce-bound disposable GUI guest only."""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import subprocess
import selectors
import signal

PACKAGE_SHA256 = 'e47d216187d3ef658ff087e3ecada2cf46b199ad28106e55ff00412cd6c55dbd'
PACKAGE_SIZE = 6778
PACKAGE_VERSION = '2:1.2.1-1build1'
LIBRARY_SHA256 = 'c2aefa4bf373492430f48aec108c5ead95e1dc757d52968775e905e23a2ad56c'
LIBRARY = '/usr/lib/x86_64-linux-gnu/libXRes.so.1.0.0'
LOADER_QUERY = r'''
import ctypes,ctypes.util,hashlib,json,os,stat
value={'findLibrary':ctypes.util.find_library('XRes'),'soname':'libXRes.so.1','cdllLoaded':False}
try:
 library=ctypes.CDLL('libXRes.so.1');value['cdllLoaded']=True
 path='/usr/lib/x86_64-linux-gnu/libXRes.so.1.0.0'
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>65536:raise RuntimeError('unsafe XRes runtime file')
  data=os.read(fd,65537);value['fileSHA256']=hashlib.sha256(data).hexdigest()
 finally:os.close(fd)
 value['mappedPaths']=sorted(set(line.split()[-1] for line in open('/proc/self/maps') if 'libXRes.so' in line))
except (OSError,RuntimeError) as error:value['errorType']=type(error).__name__
print(json.dumps(value))
'''

def secure_canonical_marker(expected):
    """Replace the QGA-created writable inode; never chmod an existing inode."""
    parent=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    old=new=temporary=None
    created_directory=False
    name='amnezia-release-lab-marker'
    try:
        info=os.fstat(parent)
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o1777:raise RuntimeError('canonical marker parent differs')
        old=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        original=os.fstat(old)
        def valid(fd,mode=None):
            value=os.fstat(fd)
            os.lseek(fd,0,os.SEEK_SET)
            if (not stat.S_ISREG(value.st_mode) or value.st_uid!=0 or value.st_nlink!=1
                    or value.st_size!=len(expected) or (mode is not None and stat.S_IMODE(value.st_mode)!=mode)
                    or os.read(fd,4096)!=expected):raise RuntimeError('canonical GUI marker differs')
            return value
        valid(old)
        evidence={'beforeMode':oct(stat.S_IMODE(original.st_mode)),'beforeUID':original.st_uid,
                  'beforeNlink':original.st_nlink,'beforeInode':original.st_ino,'replaced':False}
        if stat.S_IMODE(original.st_mode)==0o600:
            evidence.update(afterMode='0o600',afterInode=original.st_ino)
            return evidence
        temporary='.amnezia-marker-'+os.urandom(24).hex()
        os.mkdir(temporary,0o700,dir_fd=parent)
        created_directory=True
        new=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        directory=os.fstat(new)
        if directory.st_uid!=0 or stat.S_IMODE(directory.st_mode)!=0o700:raise RuntimeError('marker staging directory differs')
        fresh=os.open('marker',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=new)
        try:
            if os.write(fresh,expected)!=len(expected):raise RuntimeError('short canonical marker write')
            os.fsync(fresh);created=valid(fresh,0o600)
            current=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if (current.st_dev,current.st_ino)!=(original.st_dev,original.st_ino):raise RuntimeError('canonical marker changed before replacement')
            valid(old)
            os.replace('marker',name,src_dir_fd=new,dst_dir_fd=parent)
            os.fsync(parent)
            current=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if (current.st_dev,current.st_ino)!=(created.st_dev,created.st_ino):raise RuntimeError('canonical marker changed after replacement')
            valid(fresh,0o600)
            evidence.update(afterMode='0o600',afterInode=created.st_ino,replaced=True)
            return evidence
        finally:os.close(fresh)
    finally:
        if old is not None:os.close(old)
        if new is not None:
            try:os.unlink('marker',dir_fd=new)
            except FileNotFoundError:pass
            os.close(new)
        if created_directory:os.rmdir(temporary,dir_fd=parent)
        os.close(parent)


def context(run, profile, nonce, marker_evidence=None):
    if os.geteuid()!=0 or profile!='linux-x64-gui' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}',run) or not re.fullmatch('[0-9a-f]{48}',nonce):
        raise RuntimeError('owned GUI dependency context required')
    fd=os.open('/run/amnezia-release-lab-fixture-'+nonce,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise RuntimeError('private fixture owner/mode differs')
        for name,expected,parent in [('marker',json.dumps({'run_id':run,'profile':profile,'nonce':nonce},sort_keys=True).encode(),fd),('/tmp/amnezia-release-lab-marker',('amnezia-release-lab:'+run+':'+profile).encode(),None)]:
            if parent is None:
                evidence=secure_canonical_marker(expected)
                if marker_evidence is not None:marker_evidence.update(evidence)
            marker=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            try:
                m=os.fstat(marker)
                if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_nlink!=1 or m.st_size!=len(expected) or stat.S_IMODE(m.st_mode)!=0o600 or os.read(marker,4096)!=expected:raise RuntimeError('canonical GUI marker differs')
            finally:os.close(marker)
        return fd
    except BaseException:
        os.close(fd)
        raise

def install_attempt(argv,timeout):
    """Bounded actual child output; never terminates the package-lock holder."""
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={**os.environ,'LC_ALL':'C'})
    selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()};end=time.monotonic()+timeout
    value={'exitcode':None,'timeout':False,'overflow':False}
    try:
        for name,stream in (('stdout',child.stdout),('stderr',child.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        while selector.get_map():
            left=end-time.monotonic()
            if left<=0:value['timeout']=True;break
            for key,_ in selector.select(min(.1,left)):
                data=os.read(key.fileobj.fileno(),8192)
                if not data:selector.unregister(key.fileobj);continue
                room=8192-sum(map(len,buffers.values()));buffers[key.data].extend(data[:max(0,room)])
                if len(data)>room:value['overflow']=True;break
            if value['overflow']:break
        if value['timeout'] or value['overflow']:
            if child.poll() is None:os.killpg(child.pid,signal.SIGTERM)
        try:value['exitcode']=child.wait(timeout=max(.01,min(1,end-time.monotonic())))
        except subprocess.TimeoutExpired:
            value['timeout']=True
            if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
            value['exitcode']=child.wait(timeout=1)
        return {**value,**{k:bytes(v) for k,v in buffers.items()}}
    finally:
        if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=1)
        selector.close();child.stdout.close();child.stderr.close()


def lock_holder(pid):
    result={'reportedPID':pid,'diagnosticOnly':True,'gaps':[]}
    try:parent=os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    except OSError as error:result['gaps'].append(type(error).__name__);return result
    try:
        def read(name,limit):
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            try:return os.read(fd,limit+1)
            finally:os.close(fd)
        before=read('stat',4096);closing=before.rfind(b') ')
        start=int(before[closing+2:].split()[19])
        command=read('cmdline',1024)
        result.update(start_ticks=start,uid=os.fstat(parent).st_uid,cmdline_base64=base64.b64encode(command[:1024]).decode(),cmdlineTruncated=len(command)>1024)
        after=read('stat',4096)
        if after[after.rfind(b') ')+2:].split()[19]!=str(start).encode():raise RuntimeError('holder process changed')
        result['identityObserved']=True
    except (OSError,ValueError,IndexError,RuntimeError) as error:result['gaps'].append(type(error).__name__)
    finally:os.close(parent)
    return result


def install_with_lock_retry(argv,deadline,report,ownership):
    # The previous single install had30s. Retries share that same30s slice
    # AND the existing dependency90s deadline; no timeout enlargement.
    end=min(deadline,time.monotonic()+30)
    report['packageInstallAttempts']=[]
    for number in range(1,33):
        ownership()
        remaining=end-time.monotonic()
        if remaining<=0:raise RuntimeError('bounded dpkg lock/install budget exhausted')
        raw=install_attempt(argv,remaining)
        record={'attempt':number,**{k:raw[k] for k in ('exitcode','timeout','overflow')},
                'stdout_base64':base64.b64encode(raw['stdout']).decode(),'stderr_base64':base64.b64encode(raw['stderr']).decode()}
        report['packageInstallAttempts'].append(record)
        if raw['timeout'] or raw['overflow']:raise RuntimeError('bounded dpkg install output/deadline failure')
        if raw['exitcode']==0:return raw['stdout']
        match=re.match(rb'dpkg: error: dpkg frontend lock was locked by another process with pid ([1-9][0-9]*)\n',raw['stderr'])
        if raw['exitcode']!=2 or raw['stdout'] or not match:raise RuntimeError('dpkg install failed without retryable frontend lock')
        record['lockHolder']=lock_holder(int(match[1]))
        left=end-time.monotonic()
        if left<=0:raise RuntimeError('bounded dpkg lock/install budget exhausted')
        time.sleep(min(1,left))
    raise RuntimeError('bounded dpkg lock attempt count exhausted')



def configure_session_policy(execute,prefix,deadline,report=None):
    """Fixed lab session only, nonce/context checked by execute before each call."""
    def text(argv):return execute(argv).decode().strip()
    candidates=[]
    for row in text(['loginctl','list-sessions','--no-legend']).splitlines():
        columns=row.split()
        if len(columns)<3 or columns[2]!='lab':continue
        sid=columns[0]
        if not re.fullmatch(r'[a-zA-Z0-9]+',sid):raise RuntimeError('unsafe owned session identifier')
        props={k:text(['loginctl','show-session',sid,'-p'+k,'--value']) for k in ('Type','Active','State','Class','User')}
        if props=={'Type':'x11','Active':'yes','State':'active','Class':'user','User':'1000'}:candidates.append(sid)
    if len(candidates)!=1:raise RuntimeError('unique active owned X11 session required for idle policy')
    sid=candidates[0]
    def locked():
        props={k:text(['loginctl','show-session',sid,'-p'+k,'--value']) for k in ('Type','Active','State','Class','User')}
        if props!={'Type':'x11','Active':'yes','State':'active','Class':'user','User':'1000'}:raise RuntimeError('owned idle session identity changed')
        hint=text(['loginctl','show-session',sid,'-pLockedHint','--value'])
        active=text(prefix+['gdbus','call','--session','--dest','org.gnome.Shell.ScreenShield','--object-path','/org/gnome/ScreenSaver','--method','org.gnome.ScreenSaver.GetActive'])
        if hint not in ('yes','no') or active not in ('(true,)','(false,)'):raise RuntimeError('session lock readback invalid')
        return {'lockedHint':hint,'screenSaverActive':active}
    if report is None:report={}
    report.update({'sessionId':sid,'before':locked(),'policy':[]})
    for schema,key,value in [('org.gnome.desktop.session','idle-delay','uint32 0'),('org.gnome.desktop.screensaver','lock-enabled','false')]:
        if text(prefix+['gsettings','writable',schema,key])!='true':raise RuntimeError('owned idle setting not writable')
        old=text(prefix+['gsettings','get',schema,key])
        execute(prefix+['gsettings','set',schema,key,value])
        actual=text(prefix+['gsettings','get',schema,key])
        if actual!=value:raise RuntimeError('owned idle policy readback differs')
        report['policy'].append({'schema':schema,'key':key,'before':old,'after':actual})
    if report['before']!={'lockedHint':'no','screenSaverActive':'(false,)'}:
        execute(['loginctl','unlock-session',sid])
        report['unlockRequested']=True
    else:report['unlockRequested']=False
    for unused in range(10):
        report['after']=locked()
        if report['after']=={'lockedHint':'no','screenSaverActive':'(false,)'}:break
        left=deadline-time.monotonic()
        if left<=0:raise RuntimeError('owned session unlock budget exhausted')
        time.sleep(min(.2,left))
    else:raise RuntimeError('owned session remains locked after policy')
    return report


def ensure_dependency(run,profile,nonce,encoded,readiness_source,xres_source):
    # Validate bytes before any subprocess/package operation; no network/apt.
    package=base64.b64decode(encoded,validate=True)
    if len(package)!=PACKAGE_SIZE or hashlib.sha256(package).hexdigest()!=PACKAGE_SHA256:
        raise RuntimeError('fixed Ubuntu XRes package hash/size differs')
    report={'schema':'linux-gui-xres-dependency-v1','overlayOnly':True,'packageSHA256':PACKAGE_SHA256,'packageVersion':PACKAGE_VERSION,'librarySHA256':LIBRARY_SHA256}
    scope={'__name__':'fixed-bounded-observation-library'}
    exec(readiness_source,scope)
    report['canonicalMarker']={}
    try:directory=context(run,profile,nonce,report['canonicalMarker'])
    except BaseException as error:
        report['errorType']=type(error).__name__;report['errorStage']='owned-marker-context'
        print(json.dumps(report),flush=True)
        raise
    deadline=time.monotonic()+90
    def execute(args,timeout=8,allow_codes=(0,)):
        check=context(run,profile,nonce);os.close(check)
        remaining=deadline-time.monotonic()
        if remaining<=0:raise RuntimeError('XRes dependency90s budget exhausted')
        return scope['command'](args,limit=8192,timeout=min(timeout,remaining),allow_codes=allow_codes)
    def loader():return json.loads(execute(['/usr/bin/python3','-c',LOADER_QUERY]))
    def package_status():return execute(['dpkg-query','-W','-f=${Status}\t${Version}\t${Architecture}','libxres1'],allow_codes=(0,1)).decode().strip()
    def valid(value):
        return (value.get('findLibrary')=='libXRes.so.1' and value.get('cdllLoaded') is True
                and value.get('fileSHA256')==LIBRARY_SHA256 and value.get('mappedPaths')==[LIBRARY])
    try:
        report['packageBefore']=package_status();report['loaderBefore']=loader()
        if report['packageBefore'] not in ('','install ok installed\t'+PACKAGE_VERSION+'\tamd64'):
            raise RuntimeError('unexpected pre-existing XRes package version/status')
        if not valid(report['loaderBefore']):
            # Fixed bytes, private openat fd, verified after write before dpkg.
            fd=os.open('libxres1.deb',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as stream:stream.write(package);stream.flush();os.fsync(stream.fileno())
            fd=os.open('libxres1.deb',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            try:
                info=os.fstat(fd)
                if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=PACKAGE_SIZE or hashlib.sha256(os.read(fd,PACKAGE_SIZE+1)).hexdigest()!=PACKAGE_SHA256:
                    raise RuntimeError('private XRes package changed before install')
            finally:os.close(fd)
            report['packageInstallOutput']=install_with_lock_retry(['dpkg','--install','/run/amnezia-release-lab-fixture-'+nonce+'/libxres1.deb'],deadline,report,lambda:os.close(context(run,profile,nonce))).decode()
            report['installedExactPackage']=True
        else:report['installedExactPackage']=False
        report['packageAfter']=package_status();report['loaderAfter']=loader()
        if report['packageAfter']!='install ok installed\t'+PACKAGE_VERSION+'\tamd64' or not valid(report['loaderAfter']):
            raise RuntimeError('XRes package/loader/SONAME/hash postcondition differs')
        # Require the actual existing XRes query to identify this owned GNOME.
        pids=execute(['pgrep','-u','1000','-x','gnome-shell']).split()
        if len(pids)!=1:raise RuntimeError('unique GNOME process unavailable after dependency')
        before,env=scope['process_identity'](int(pids[0]))
        if before['uid']!=1000 or before['exe']!='/usr/bin/gnome-shell' or env.get(b'GALLIUM_DRIVER')!=b'softpipe':raise RuntimeError('owned GNOME identity differs')
        display=env[b'DISPLAY'].decode();auth=env[b'XAUTHORITY'].decode()
        if not re.fullmatch(r':[0-9]+(?:\.[0-9]+)?',display) or not auth.startswith('/run/user/1000/'):raise RuntimeError('owned display escaped')
        prefix=['runuser','-u','lab','--','env','XDG_RUNTIME_DIR=/run/user/1000','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus','DISPLAY='+display,'XAUTHORITY='+auth]
        report['sessionPolicy']={}
        configure_session_policy(execute,prefix,deadline,report['sessionPolicy'])
        report['xresAfter']=json.loads(execute(prefix+['/usr/bin/python3','-c',xres_source]))
        after,_=scope['process_identity'](before['pid'])
        if not scope['shell_identity_stable'](before,after) or report['xresAfter'].get('identityGap') or report['xresAfter'].get('localPID')!=before['pid']:
            raise RuntimeError('actual XRes GNOME PID proof missing')
        report['gnome']=after;report['verified']=True
        return report
    except BaseException as error:
        report['errorType']=type(error).__name__
        print(json.dumps(report),flush=True)
        raise
    finally:os.close(directory)

if __name__=='__main__':
    encoded,support64,xres64=sys.argv[1:]
    print(json.dumps(ensure_dependency(run,profile,nonce,encoded,base64.b64decode(support64,validate=True).decode(),base64.b64decode(xres64,validate=True).decode())),flush=True)
