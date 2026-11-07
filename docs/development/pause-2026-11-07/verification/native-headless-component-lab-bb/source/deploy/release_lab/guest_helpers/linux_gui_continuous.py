"""Fixed nonce-owned sampler/inhibitor. No caller supplied health or process ID."""
import ast,base64,hashlib,json,os,re,signal,stat,subprocess,sys,time
from pathlib import Path
MAX_RAW=16*1024*1024
LEASE=35*60
SAMPLE_BUDGET=180

def tick():return int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)
def identity(pid):
 p=Path('/proc')/str(pid);s=(p/'stat').read_text();return {'pid':pid,'start':s[s.rfind(')')+2:].split()[19],'uid':p.stat().st_uid}
def private():
 d=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  s=os.fstat(d)
  if s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o700:raise RuntimeError('private sampler directory changed')
  f=os.open('marker',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
  try:
   s=os.fstat(f)
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or os.read(f,4096)!=json.dumps({'run_id':run,'profile':profile,'nonce':nonce},sort_keys=True).encode():raise RuntimeError('sampler nonce changed')
  finally:os.close(f)
  return d
 except BaseException:os.close(d);raise

def read(name,limit=65536):
 d=private()
 try:
  try:f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
  except FileNotFoundError:return None
  try:
   s=os.fstat(f)
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>limit:raise RuntimeError('private sampler file changed')
   b=os.read(f,limit+1)
   if len(b)!=s.st_size:raise RuntimeError('private sampler unstable read')
   return b
  finally:os.close(f)
 finally:os.close(d)

def write(name,value):
 data=json.dumps(value,separators=(',',':')).encode()
 if len(data)>65536:raise RuntimeError('sampler summary bounds')
 d=private();tmp='.write-'+os.urandom(16).hex()
 try:
  f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
  with os.fdopen(f,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  existing=read(name)
  os.replace(tmp,name,src_dir_fd=d,dst_dir_fd=d);os.fsync(d)
 finally:
  try:os.unlink(tmp,dir_fd=d)
  except FileNotFoundError:pass
  os.close(d)

def program_hash(pid):return hashlib.sha256((Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0')[2]).hexdigest()
def verified_state():
 raw=read('continuous-state.json')
 if raw is None:return None
 state=json.loads(raw);record=state['worker']
 if not (Path('/proc')/str(record['pid'])).exists() and state.get('phase') in ('failed','stopped'):
  if state.get('nonce')!=nonce or state.get('run')!=run or state.get('programSHA256')!=program_hash(os.getpid()):raise RuntimeError('terminal sampler binding differs')
  return state
 actual=identity(record['pid'])
 if actual!=record or actual['uid']!=0 or state.get('nonce')!=nonce or state.get('run')!=run or state.get('programSHA256')!=program_hash(os.getpid()) or program_hash(record['pid'])!=state['programSHA256']:raise RuntimeError('sampler PID/start/program differs')
 args=(Path('/proc')/str(record['pid'])/'cmdline').read_bytes().split(b'\0')
 if args[3:8]!=[run.encode(),profile.encode(),nonce.encode(),b'observe',b'worker']:raise RuntimeError('sampler argv differs')
 return state

def child_cleanup(child,binding):
 if child is None:return
 if child.poll() is None:
  if identity(child.pid)!=binding or os.getpgid(child.pid)!=child.pid:raise RuntimeError('inhibitor child ownership changed')
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=3)
  except subprocess.TimeoutExpired:
   if identity(child.pid)!=binding:raise RuntimeError('inhibitor PID changed during cleanup')
   os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=3)
 else:child.wait(timeout=3)
 # A dead wrapper is not proof that its D-Bus holder/command has gone away.
 # Never signal a reused group after losing the original leader identity.
 remaining=[]
 for proc in Path('/proc').iterdir():
  if not proc.name.isdigit():continue
  try:fields=(proc/'stat').read_text().rsplit(') ',1)[1].split()
  except FileNotFoundError:continue
  if int(fields[2])==child.pid and fields[0]!='Z':remaining.append(int(proc.name))
 if remaining:raise RuntimeError('inhibitor group still contains live descendants')

def worker(support,xres):
 scope={'__name__':'fixed-continuous-observation'};exec(support,scope)
 original_command=scope['command'];child=None;binding=None
 started=time.monotonic();deadline=started+LEASE;sample_deadline=started+SAMPLE_BUDGET
 def command(args,**kwargs):
  remaining=sample_deadline-time.monotonic()
  if remaining<=0:raise RuntimeError('continuous sampler180s command budget exhausted')
  kwargs['timeout']=min(kwargs.get('timeout',8),remaining)
  return original_command(args,**kwargs)
 scope['command']=command
 state={'schema':'linux-gui-continuous-v1','run':run,'nonce':nonce,'worker':identity(os.getpid()),'programSHA256':program_hash(os.getpid()),'phase':'starting','sequence':0,'sampleCount':0,'rawSize':0,'observations':[],'leaseExpiresMs':tick()+LEASE*1000}
 primary=None
 raw_fd=None
 try:
  pids=command(['pgrep','-u','1000','-x','gnome-shell'],limit=4096).split()
  if len(pids)!=1:raise RuntimeError('unique GNOME unavailable for inhibitor')
  shell,env=scope['process_identity'](int(pids[0]));state['gnome']=shell
  if shell['uid']!=1000 or shell['exe']!='/usr/bin/gnome-shell' or env.get(b'GALLIUM_DRIVER')!=b'softpipe':raise RuntimeError('owned GNOME environment changed')
  display=env[b'DISPLAY'].decode();auth=env[b'XAUTHORITY'].decode()
  if not re.fullmatch(r':[0-9]+(?:\.[0-9]+)?',display) or not auth.startswith('/run/user/1000/'):raise RuntimeError('inhibitor display escaped')
  prefix=['runuser','-u','lab','--','env','XDG_RUNTIME_DIR=/run/user/1000','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus','DISPLAY='+display,'XAUTHORITY='+auth]
  app='amnezia-release-lab-'+nonce
  child=subprocess.Popen(prefix+['gnome-session-inhibit','--app-id',app,'--reason','owned-release-lab-visual-review','--inhibit','idle','/usr/bin/sleep',str(LEASE)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
  binding=identity(child.pid);state['inhibitorProcess']=binding
  def bus(method,*args,dest='org.gnome.SessionManager',path='/org/gnome/SessionManager'):
   text=command(prefix+['gdbus','call','--session','--dest',dest,'--object-path',path,'--method',method,*args],limit=8192,timeout=5).decode()
   return text
  def inhibitor_proof():
   if child.poll() is not None or identity(child.pid)!=binding:raise RuntimeError('owned inhibitor died')
   if bus('org.gnome.SessionManager.IsInhibited','8').strip()!='(true,)':raise RuntimeError('GNOME idle inhibition absent')
   text=bus('org.gnome.SessionManager.GetInhibitors');paths=re.findall(r"/org/gnome/SessionManager/Inhibitor[0-9]+",text)
   if not 0<len(paths)<=32:raise RuntimeError('GNOME inhibitor list bounds')
   matches=[]
   for path in paths:
    value=ast.literal_eval(bus('org.gnome.SessionManager.Inhibitor.GetAppId',path=path).strip())
    if value==(app,):matches.append(path)
   if len(matches)!=1:raise RuntimeError('nonce-owned GNOME inhibitor missing')
   return {'appID':app,'path':matches[0],'idleInhibited':True}
  # A short startup gap is diagnostic, never a readiness waiver.
  last_error=None
  for attempt in range(10):
   try:state['inhibitor']=inhibitor_proof();break
   except RuntimeError as error:last_error=error;time.sleep(.2)
  else:raise last_error
  before=json.loads(command(prefix+['/usr/bin/python3','-c',xres],limit=32768))
  state['displayBefore']=before;state['phase']='display-prepared';write('continuous-state.json',state)
  d=private()
  try:raw_fd=os.open('continuous-raw.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
  finally:os.close(d)
  sealed=False;last=None;since=None
  while time.monotonic()<deadline:
   if read('continuous-stop.json') is not None:state['phase']='stopping';break
   if child.poll() is not None or identity(child.pid)!=binding:raise RuntimeError('inhibitor died during visual lease')
   now_shell,_=scope['process_identity'](shell['pid'])
   if not scope['shell_identity_stable'](shell,now_shell):raise RuntimeError('GNOME changed during visual lease')
   if sealed:time.sleep(.2);continue
   if time.monotonic()>sample_deadline:raise RuntimeError('continuous sampler180s deadline')
   raw=scope['observe'](xres)
   encoded=json.dumps(raw,separators=(',',':')).encode()+b'\n'
   if len(encoded)>950000 or state['rawSize']+len(encoded)>MAX_RAW:raise RuntimeError('continuous raw archive bounds')
   if os.write(raw_fd,encoded)!=len(encoded):raise RuntimeError('short sampler archive write')
   os.fsync(raw_fd);state['rawSize']+=len(encoded)
   obs=raw.get('observation');state['sampleCount']+=1
   if type(obs) is not dict or raw.get('xres',{}).get('dpms',{}).get('level')!=0:
    since=None;last=None;state['phase']='waiting-active-display';state['latestDPMS']=raw.get('xres',{}).get('dpms');write('continuous-state.json',state);time.sleep(1);continue
   if obs['shell']['pid']!=shell['pid'] or obs['shell']['start_ticks']!=shell['start_ticks']:raise RuntimeError('sample GNOME binding changed')
   if len(state['observations'])>=64:raise RuntimeError('continuous sample count bounds')
   state['observations'].append(obs);state['latestDPMS']=raw['xres']['dpms'];state['phase']='sampling'
   stamp=obs['monotonic_ms']
   if last is None or stamp-last>10000:since=stamp
   elif stamp<=last:raise RuntimeError('nonincreasing sampler time')
   last=stamp;state['dwellSpanMs']=stamp-since;state['lastObservedMs']=stamp
   capture=read('continuous-capture.json')
   if capture is not None:
    capture=json.loads(capture)
    if stamp-capture['beforeMs']>10000:raise RuntimeError('capture bridge stale')
    if capture['afterMs']<=stamp:
     state['capture']=capture;state['phase']='sealed';sealed=True;state['inhibitor']=inhibitor_proof()
   write('continuous-state.json',state)
   time.sleep(2)
  else:raise RuntimeError('bounded visual inhibitor lease expired')
 except BaseException as error:
  primary=error
  state['phase']='failed';state['errorType']=type(error).__name__;state['errorMessage']=str(error)[:256]
  try:write('continuous-state.json',state)
  except BaseException as state_error:error.add_note('private failure state unavailable: '+type(state_error).__name__)
  raise
 finally:
  if raw_fd is not None:os.close(raw_fd)
  try:child_cleanup(child,binding);state['inhibitorReaped']=True
  except BaseException as cleanup_error:
   state['cleanupErrorType']=type(cleanup_error).__name__
   if primary is None:raise
   primary.add_note('owned inhibitor cleanup failed: '+type(cleanup_error).__name__)
  finally:
   if state['phase']!='failed':state['phase']='stopped'
   try:write('continuous-state.json',state)
   except BaseException as state_error:
    if primary is None:raise
    primary.add_note('private sampler final state unavailable: '+type(state_error).__name__)

def control(operation,payload):
 state=verified_state()
 if state is None:return {'pending':True}
 if operation=='status':
  if state.get('phase') in ('failed','stopped'):return state
  if tick()>=state['leaseExpiresMs'] or identity(state['inhibitorProcess']['pid'])!=state['inhibitorProcess']:raise RuntimeError('owned inhibitor lease/liveness differs')
  # Fresh liveness after full host fences; do not return an old state as live.
  shell=state.get('gnome')
  if shell:
   current=identity(shell['pid'])
   if current['start']!=str(shell['start_ticks']) or current['uid']!=1000:raise RuntimeError('GNOME identity changed after sampler')
  return state
 if operation=='clock':
  value={'beforeMs':tick(),'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'sequence':state['sampleCount']}
  write('continuous-clock.json',value);return value
 if operation=='capture':
  before=json.loads(read('continuous-clock.json'));after=tick()
  if set(payload)!={'sha256','size','beforeMs','bootID','sequence'} or any(payload[k]!=before[k] for k in before) or not re.fullmatch('[0-9a-f]{64}',payload['sha256']) or type(payload['size'])is not int or not 0<payload['size']<=16*1024*1024 or not 0<=after-before['beforeMs']<=10000:raise RuntimeError('capture acknowledgement differs')
  value={**payload,'afterMs':after};write('continuous-capture.json',value);return value
 if operation=='archive':
  if state['phase'] not in ('sealed','failed','stopped'):raise RuntimeError('sampler archive not stable')
  offset=payload.get('offset')
  if type(offset)is not int or not 0<=offset<=state['rawSize']<=MAX_RAW:raise RuntimeError('archive offset bounds')
  d=private()
  try:
   f=os.open('continuous-raw.jsonl',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
   try:
    info=os.fstat(f)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=state['rawSize']:raise RuntimeError('sampler archive identity differs')
    os.lseek(f,offset,0);chunk=os.read(f,min(32768,state['rawSize']-offset));return {'offset':offset,'size':state['rawSize'],'data':base64.b64encode(chunk).decode()}
   finally:os.close(f)
  finally:os.close(d)
 if operation=='stop':
  if state.get('phase') in ('failed','stopped'):return {'stopRequested':False,'alreadyExited':True}
  write('continuous-stop.json',{'nonce':nonce});return {'stopRequested':True}
 raise RuntimeError('unknown fixed sampler operation')

if __name__=='__main__':
 mode,*args=sys.argv[1:]
 if mode=='worker':worker(*(base64.b64decode(v,validate=True).decode() for v in args))
 elif mode=='control':print(json.dumps(control(args[0],json.loads(args[1]))),flush=True)
 else:raise RuntimeError('fixed continuous helper operation required')
