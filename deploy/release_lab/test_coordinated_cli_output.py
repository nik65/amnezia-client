import ast,base64,hashlib,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
HERE=Path(__file__).parent;SOURCE=HERE/'headless_coordinated_rollback_collector.py';TREE=ast.parse(SOURCE.read_text());SCOPE={}
for n in TREE.body:
 if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('IO_COMMON','IO_PROGRAM') for t in n.targets):exec(compile(ast.Module(body=[n],type_ignores=[]),'staged','exec'),SCOPE)
 if isinstance(n,ast.FunctionDef) and n.name=='process_program':exec(compile(ast.Module(body=[n],type_ignores=[]),'staged','exec'),SCOPE)
PROGRAM=SCOPE['process_program']();ROOT=Path.cwd();sys.path.insert(0,str(ROOT))
# Exact historical observer generated from collector preimage 77b3fdfd175ad41f623991ce71198c1a3cc40ee143adc0f71abc9a99aeb75891
OLD_PROGRAM="\nimport base64,hashlib,json,os,pathlib,re,stat,sys,time\nclass Transition(RuntimeError):pass\ndef emit(value):print(json.dumps(value,separators=(',',':')),flush=True)\ndef fdidentity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)\ndef directory(path):\n fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)\n try:\n  for part in pathlib.PurePosixPath(path).parts[1:]:\n   if part in ('','..','.'):raise RuntimeError('directory escaped')\n   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt\n   s=os.fstat(fd)\n   if s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('unprotected source directory')\n  return fd\n except BaseException:os.close(fd);raise\ndef private(path,data):\n fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())\ndef context(run,case,nonce,create=False):\n if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}',x) for x in (run,case,nonce)):raise RuntimeError('invalid collector context')\n root=pathlib.Path('/var/lib/amnezia/.release-lab-coordinated-'+nonce)\n expected=json.dumps({'run_id':run,'case_id':case,'attempt_nonce':nonce},sort_keys=True).encode()\n if create:\n  f=os.open('/tmp/amnezia-release-lab-marker',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n  try:\n   s=os.fstat(f);marker=('amnezia-release-lab:'+run+':linux-headless-x64').encode()\n   if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_size!=len(marker) or os.read(f,4096)!=marker:raise RuntimeError('canonical guest marker differs')\n  finally:os.close(f)\n  os.mkdir(root,0o700);private(root/'owner.json',expected)\n d=directory(str(root))\n try:\n  if stat.S_IMODE(os.fstat(d).st_mode)!=0o700:raise RuntimeError('collector directory mode')\n  f=os.open('owner.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)\n  try:\n   s=os.fstat(f)\n   if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size!=len(expected) or os.read(f,4096)!=expected:raise RuntimeError('collector owner marker')\n  finally:os.close(f)\n finally:os.close(d)\n return root\ndef source(key,root):\n fixed={'profiles':('/var/lib/amnezia/profiles.json',0o600,16*1024*1024),\n 'record':('/var/lib/amnezia/rollback-coordinator/coordinator.json',0o600,48*1024*1024),\n 'retained':('/var/lib/amnezia/rollback-coordinator/amnezia-cli',0o500,64*1024*1024),\n 'unit':('/etc/systemd/system/amnezia-rollback-coordinator.service',0o644,16384),\n 'state':('/var/lib/amnezia/headless-updates.json',0o600,4*1024*1024),\n 'journal':('/var/lib/amnezia/updates/transaction.json',0o600,4*1024*1024)}\n if key in fixed:return fixed[key]\n if key in ('rollback_stdout','resume_stdout'):return(str(root/('output-'+key.split('_')[0])),0o600,1048576)\n if key=='unit_state':return(str(root/'unit-state.json'),0o600,1048576)\n raise RuntimeError('source is not allowlisted')\ndef snapshot(path,mode,limit,logical,root,label,kind='file',inspected=None,metadata=False):\n d=directory(str(pathlib.PurePosixPath(path).parent));name=pathlib.PurePosixPath(path).name\n try:\n  parent_before=os.fstat(d)\n  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)\n  try:\n   before=os.fstat(fd)\n   if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=mode or not 0<before.st_size<=limit:raise RuntimeError('protected descriptor identity')\n   target=root/('capture-'+label);out=os.open(os.devnull,os.O_WRONLY) if metadata else os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);digest=hashlib.sha256();size=0\n   with os.fdopen(out,'wb') as stream:\n    while True:\n     chunk=os.read(fd,min(65536,limit+1-size))\n     if not chunk:break\n     size+=len(chunk)\n     if size>limit:raise RuntimeError('protected descriptor bound')\n     stream.write(chunk);digest.update(chunk)\n    stream.flush()\n    if not metadata:os.fsync(stream.fileno())\n   after=os.fstat(fd);named=os.stat(name,dir_fd=d,follow_symlinks=False)\n   parent_after=os.stat(str(pathlib.PurePosixPath(path).parent),follow_symlinks=False)\n   parent_id=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)\n   if parent_id(parent_before)!=parent_id(parent_after):raise Transition('protected source parent changed')\n   if fdidentity(before)!=fdidentity(after) or fdidentity(after)!=fdidentity(named) or size!=after.st_size:raise Transition('protected descriptor changed')\n   result={'origin':'guest','transport':'qga','path':logical,'source_path':path,'kind':'guest-descriptor-metadata' if metadata else kind,'inspected_path':inspected,'uid':after.st_uid,'gid':after.st_gid,'mode':format(mode,'04o'),'size':size,'sha256':digest.hexdigest(),'nofollow':True,'regular':True,'nlink':after.st_nlink,'stable_identity':True}\n   if not metadata:result.update(physical_path=str(target),physical_mode='0600')\n   return result\n  finally:os.close(fd)\n finally:os.close(d)\n\nroot=context(sys.argv[4],sys.argv[5],sys.argv[6]);argv=json.loads(sys.argv[1]);verb='rollback' if argv[0]=='/usr/local/bin/amnezia-cli' else 'resume'\nif sys.argv[3]!=str(root/('output-'+verb)):raise RuntimeError('process output escaped collector')\nimport hashlib,json,os,pathlib,resource,subprocess,sys,time\nargv=json.loads(sys.argv[1]); expected=sys.argv[2]; output=pathlib.Path(sys.argv[3]); limit=1048576;fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nif argv not in [['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','update-rollback'],['/var/lib/amnezia/rollback-coordinator/amnezia-cli','--rollback-coordinator','resume']]: raise SystemExit('argv')\ndef bound(): resource.setrlimit(resource.RLIMIT_FSIZE,(limit+1,limit+1))\np=subprocess.Popen(argv,stdout=fd,stderr=subprocess.STDOUT,preexec_fn=bound);os.close(fd)\nproc=pathlib.Path('/proc')/str(p.pid); deadline=time.monotonic()+5; identity=None\nwhile time.monotonic()<deadline:\n try:\n  raw=proc.joinpath('stat').read_text(); f=raw[raw.rfind(')')+2:].split(); exe=proc.joinpath('exe').resolve(strict=True); cmd=proc.joinpath('cmdline').read_bytes(); args=[x.decode() for x in cmd.rstrip(b'\\0').split(b'\\0')]\n  uid_slots=[int(x) for x in next(line for line in proc.joinpath('status').read_text().splitlines() if line.startswith('Uid:')).split()[1:]]\n  if uid_slots!=[0,0,0,0]:raise SystemExit('CLI root identity')\n  if str(exe)==argv[0] and args==argv:\n   data=exe.read_bytes()\n   if hashlib.sha256(data).hexdigest()!=expected:\n    p.kill();p.wait();raise SystemExit('cli hash')\n   identity={'pid':p.pid,'start_ticks':int(f[19]),'exe':str(exe),'exe_sha256':expected,'argv':args,'cmdline_sha256':hashlib.sha256(cmd).hexdigest(),'uid_slots':uid_slots,'observed_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')};break\n except (FileNotFoundError,ProcessLookupError): break\n time.sleep(.001)\nif identity is None:\n p.kill();p.wait();raise SystemExit('CLI identity not observed')\ntry:\n check_stat=proc.joinpath('stat').read_text();check_ticks=int(check_stat[check_stat.rfind(')')+2:].split()[19]);check_cmd=proc.joinpath('cmdline').read_bytes()\n check_uid=[int(x) for x in next(line for line in proc.joinpath('status').read_text().splitlines() if line.startswith('Uid:')).split()[1:]]\n if check_cmd and (check_ticks!=identity['start_ticks'] or check_cmd!=cmd or check_uid!=uid_slots or hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()!=expected):raise SystemExit('CLI process changed')\nexcept (FileNotFoundError,ProcessLookupError):pass\ntry:p.wait(timeout=60)\nexcept subprocess.TimeoutExpired:p.kill();p.wait();raise SystemExit('CLI timeout')\nout=output.read_bytes();identity['exit_code']=p.returncode\nif len(out)>limit:raise SystemExit('CLI output bound')\nprint(json.dumps({'process':identity},separators=(',',':')))\n"
OLD_PROGRAM_SHA256='d744fabff8928baec40dde44af358c4d31c834ac6c038cd47e52a12d699dcd73'
assert hashlib.sha256(OLD_PROGRAM.encode()).hexdigest()==OLD_PROGRAM_SHA256

@unittest.skipUnless(os.name=='posix' and os.getuid()==0,'actual root POSIX inert child')
class Actual(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory(dir='/root');self.root=Path(self.temp.name);self.exe=str(Path(sys.executable).resolve());self.sha=hashlib.sha256(Path(self.exe).read_bytes()).hexdigest()
 def tearDown(self):self.temp.cleanup()
 def execute(self,code,old=False,verb='rollback',short=False):
  argv=[self.exe,'-c',code];output=self.root/('output-'+verb)
  if old:
   program=OLD_PROGRAM;program=program[program.index('import hashlib,json,os,pathlib,resource,subprocess,sys,time'):]
   begin=program.index('if argv not in ');end=program.index("raise SystemExit('argv')",begin)+len("raise SystemExit('argv')")
   program=program[:begin]+'if argv!='+repr(argv)+":raise SystemExit('argv')"+program[end:]
  else:
   program=PROGRAM.replace("root=context(run,case,nonce)","root=pathlib.Path("+repr(str(self.root))+")")
   start=program.index('allowed=');end=program.index('\n',start);allowed=[argv,['unselected']] if verb=='rollback' else [['unselected'],argv]
   program=program[:start]+'allowed='+repr(allowed)+program[end:]
   if short:program=program.replace('deadline=time.monotonic()+60','deadline=time.monotonic()+.2')
  response=subprocess.run([sys.executable,'-c',program,json.dumps(argv),self.sha,str(output),'run','case','nonce'],capture_output=True,timeout=6)
  self.assertEqual(response.returncode,0,response.stderr.decode());value=json.loads(response.stdout)
  self.assertEqual(value['process']['argv'],argv);self.assertEqual(value['process']['uid_slots'],[0,0,0,0]);self.assertEqual(value['process']['exe_sha256'],self.sha)
  self.assertEqual(output.stat().st_mode&0o777,0o600)
  return value,output.read_bytes()
 def test_old_sigxfsz_red_new_large_regular_file_and_tiny_stdout_green_both_verbs(self):
  target=self.root/'retained-elf-like';code="import signal,time,pathlib;signal.signal(signal.SIGXFSZ,signal.SIG_DFL);time.sleep(.05);pathlib.Path("+repr(str(target))+").write_bytes(b'x'*2097152);print('{\"ok\":true}')"
  old,data=self.execute(code,old=True);self.assertEqual(old['process']['exit_code'],-25);self.assertEqual(data,b'');self.assertEqual(target.stat().st_size,1048577)
  (self.root/'output-rollback').unlink()
  for verb in ('rollback','resume'):
   value,data=self.execute(code,verb=verb);self.assertEqual(value['process']['exit_code'],0);self.assertEqual(json.loads(data),{'ok':True});self.assertEqual(target.stat().st_size,2097152);self.assertIsNone(value['capture']['reason'])
 def test_flood_stdout_and_stderr_combined_bound(self):
  value,data=self.execute("import os,time;time.sleep(.05);os.write(1,b'x'*800000);os.write(2,b'y'*800000);time.sleep(2)")
  self.assertEqual(value['capture']['reason'],'output-limit');self.assertTrue(value['capture']['truncated']);self.assertEqual(len(data),1048576);self.assertEqual(value['process']['exit_code'],-9)
 def test_timeout_kills_owned_group_and_preserves_partial(self):
  value,data=self.execute("import time;print('partial',flush=True);time.sleep(2)",short=True)
  self.assertEqual(value['capture']['reason'],'deadline');self.assertEqual(value['process']['exit_code'],-9);self.assertEqual(data,b'partial\n')
 def test_nonzero_empty_signal_are_observed_without_synthesizing_success(self):
  for label,code,exit_code,body in [('nonzero',"print('{}');raise SystemExit(7)",7,b'{}\n'),('empty','pass',0,b''),('signal',"import os,signal;os.kill(os.getpid(),signal.SIGTERM)",-15,b'')]:
   with self.subTest(label=label):
    path=self.root/'output-rollback'
    if path.exists():path.unlink()
    value,data=self.execute('import time;time.sleep(.05);'+code);self.assertEqual(value['process']['exit_code'],exit_code);self.assertEqual(data,body)
 def test_diagnostic_empty_descriptor_allowed_only_explicit_not_semantic(self):
  scope={};exec(SCOPE['IO_COMMON'],scope);source=self.root/'empty';source.touch(mode=0o600)
  with self.assertRaises(RuntimeError):scope['snapshot'](str(source),0o600,1048576,'cli:update-rollback',self.root,'strict')
  result=scope['snapshot'](str(source),0o600,1048576,'cli:update-rollback',self.root,'diagnostic',allow_empty=True)
  self.assertEqual(result['size'],0);self.assertEqual(result['sha256'],hashlib.sha256(b'').hexdigest());self.assertEqual(Path(result['physical_path']).read_bytes(),b'')

class Host(unittest.TestCase):
 def collector(self):
  node=next(n for n in TREE.body if isinstance(n,ast.ClassDef) and n.name=='CoordinatedRollbackCollector');methods=[n for n in node.body if isinstance(n,ast.FunctionDef) and n.name in ('_run','_read','_pull')]
  scoped={'CoordinatedCollectionError':RuntimeError,'FIXED_SOCKET':'/run/amnezia/amneziad.sock','RETAINED':'/var/lib/amnezia/rollback-coordinator/amnezia-cli','process_program':lambda:'program','time':time,'IO_PROGRAM':SCOPE['IO_PROGRAM'],'json':json,'base64':base64,'hashlib':hashlib,'os':os}
  cls=ast.ClassDef(name='Collector',bases=[],keywords=[],body=methods,decorator_list=[]);exec(compile(ast.fix_missing_locations(ast.Module(body=[cls],type_ignores=[])),'staged','exec'),scoped)
  c=scoped['Collector']();c._initialize=Mock();c.plan=SimpleNamespace(candidate=SimpleNamespace(cli_sha256='hash'),attempt_nonce='n');c._args=Mock(return_value=[]);c._name=Mock(return_value='diagnostic');c._check=Mock()
  return c
 def test_process_archived_before_nonempty_read_failure_and_empty_diagnostic(self):
  c=self.collector();order=[];value={'process':{'exit_code':-25}};c._exec=Mock(return_value=value);c.archive_original=lambda *args:order.append(('archive',args))
  failure=ValueError('strict nonempty failed')
  def read(*args,**kwargs):
   order.append(('read',kwargs))
   if not kwargs.get('diagnostic_empty'):raise failure
   return {'size':0}
  c._read=read
  with self.assertRaises(ValueError) as caught:c._run('rollback',90)
  self.assertIs(caught.exception,failure);self.assertEqual(order[0],('archive',('rollback-process',value)));self.assertTrue(order[-1][1]['diagnostic_empty'])
 def test_failure_metadata_archived_and_primary_survives_secondary(self):
  c=self.collector();failure=ValueError('descriptor predicate');c._exec=Mock(side_effect=[failure,{'diagnostic_only':True,'size':0,'mode':'0600'}]);c.archive_original=Mock()
  with self.assertRaises(ValueError) as caught:c._read('rollback_stdout')
  self.assertIs(caught.exception,failure);self.assertEqual(c._exec.call_args.args[1][0],'diagnostic-stat');c.archive_original.assert_called_once()
 def test_nonzero_or_outputlimit_never_semantic_success(self):
  for process,capture in [({'exit_code':7},{'reason':None,'truncated':False}),({'exit_code':0},{'reason':'output-limit','truncated':True})]:
   c=self.collector();process={**process,'argv':['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','update-rollback'],'exe_sha256':'hash','uid_slots':[0,0,0,0]};c._exec=Mock(return_value={'process':process,'capture':capture});c._read=Mock(return_value={'bytes_b64':'e30='});c.archive_original=Mock()
   with self.assertRaises(RuntimeError):c._run('rollback',90)
 def test_success_requires_actual_captured_output_hash_and_size_match(self):
  c=self.collector();body=b'{}';digest=hashlib.sha256(body).hexdigest();process={'exit_code':0,'argv':['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','update-rollback'],'exe_sha256':'hash','uid_slots':[0,0,0,0]};capture={'reason':None,'truncated':False,'size':2,'limit':1048576,'sha256':digest}
  c._exec=Mock(return_value={'process':process,'capture':capture});c._read=Mock(return_value={'size':2,'sha256':digest});c.archive_original=Mock()
  self.assertEqual(c._run('rollback',90)[0],process)
  c._read.return_value={'size':2,'sha256':'0'*64}
  with self.assertRaises(RuntimeError):c._run('rollback',90)
 def test_legacy_source_unchanged_has_limit_newobserver_does_not(self):
  from deploy.release_lab.headless_native_reboot_collector import ROLLBACK
  self.assertIn('RLIMIT_FSIZE',ROLLBACK);self.assertNotIn('RLIMIT_FSIZE',PROGRAM);self.assertNotIn('preexec_fn',PROGRAM)
if __name__=='__main__':unittest.main()
