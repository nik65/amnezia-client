"""Owned loopback multi-wave payload RSS regression; Python is test tooling only.

No cgroup/host limit changes. Child RSS is distinct from Docker aggregate memory.
"""
import concurrent.futures as cf,hashlib,http.client,json,os,pathlib,socket,sqlite3,subprocess,tempfile,threading,time
BINARY=os.environ['AMNEZIA_NATIVE_COLLECTOR']
out=os.environ.get('AMNEZIA_NATIVE_MEMORY_RECEIPT')
with tempfile.TemporaryDirectory(prefix='amnezia-owned-stress-') as temp:
 root=pathlib.Path(temp); ids=[c*64 for c in 'abcd']; (root/'tokens.tsv').write_text(''.join(f'{n:064x}\tfixture-token\n' for n in range(200000))+''.join(i+'\tfixture-token\n' for i in ids))
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 process=subprocess.Popen([BINARY,'--root',temp,'--bind','127.0.0.1','--port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 samples=[];done=threading.Event()
 def monitor():
  while not done.wait(.005):
   try:
    values={x.split(':',1)[0]:int(x.split()[1]) for x in pathlib.Path(f'/proc/{process.pid}/status').read_text().splitlines() if x.startswith(('VmRSS:','VmHWM:','VmSize:'))}; samples.append(values)
   except FileNotFoundError:return
 watch=threading.Thread(target=monitor);watch.start()
 def req(client,batch,body,path='/logs',token='fixture-token'):
  c=http.client.HTTPConnection('127.0.0.1',port,timeout=35)
  try:
   c.request('GET' if path=='/healthz' else 'POST',path,body,{'X-Amnezia-Client-Id':client,'X-Amnezia-Log-Token':token,'X-Amnezia-Batch-Id':batch});r=c.getresponse();r.read();return r.status
  finally:c.close()
 try:
  for _ in range(200):
   try:
    if req(ids[0],'0'*64,b'','/healthz')==200:break
   except OSError:time.sleep(.025)
  with cf.ThreadPoolExecutor(4) as pool:
   rejected=list(pool.map(lambda i:req(i,'f'*64,b'x',token='wrong'),ids))
  assert rejected==[403]*4,rejected
  body=b'x'*(15*1024*1024)
  # Arrange periodic receipt maintenance during the fourth large upload,
  # rather than measuring maintenance only after payloads have been released.
  for n in range(252):assert req(ids[0],hashlib.sha256(('seed'+str(n)).encode()).hexdigest(),b'tiny')==204
  phases=[]
  for phase in ['new','legacy-file-recovery','bound-replay']:
   batches=[hashlib.sha256((phase+str(i)).encode()).hexdigest() for i in range(4)] if phase!='bound-replay' else prior
   if phase=='legacy-file-recovery':
    for i,b in zip(ids,batches):
     directory=root/'logs'/i;directory.mkdir(exist_ok=True);(directory/(b+'.log')).write_bytes(body)
   (root/'retention.last').write_text('0\n')
   db=sqlite3.connect(root/'batch-receipts.sqlite3');db.execute('BEGIN EXCLUSIVE')
   with cf.ThreadPoolExecutor(5) as pool:
    tasks=[pool.submit(req,i,b,body) for i,b in zip(ids,batches)]
    time.sleep(1)
    health=pool.submit(req,ids[0],'0'*64,b'','/healthz')
    time.sleep(.1);db.rollback();db.close()
    codes=[f.result() for f in tasks];health_code=health.result()
   assert codes==[204]*4,(phase,codes)
   assert health_code==200,(phase,health_code)
   phases.append({'phase':phase,'uploadStatuses':codes,'health':health_code})
   prior=batches
  for n in range(256):assert req(ids[0],hashlib.sha256(('tiny'+str(n)).encode()).hexdigest(),b'tiny')==204
  assert req(ids[0],'0'*64,b'','/healthz')==200
  peak=max(s['VmHWM'] for s in samples)
  result={'status':'PASS' if peak<96*1024 else 'FAIL_RSS_96MiB','binarySha256':hashlib.sha256(pathlib.Path(BINARY).read_bytes()).hexdigest(),'peakRssKiB':peak,'peakVmSizeKiB':max(s['VmSize'] for s in samples),'rssBudgetKiB':96*1024,'sampleCount':len(samples),'phases':phases,'allowlistBytes':(root/'tokens.tsv').stat().st_size,'allowlistRows':200004,'failedAuthStatuses':rejected,'maintenanceRecords':508,'overlapArrangement':'SQLite exclusive lock plus delayed health request; concurrent maintenance overlap is inferred, not directly observed','retentionMarkerResetPerWave':True,'isolation':'owned child/loopback/temp data only; no Docker/cgroup/host limit changes','limitation':'RSS is not container cgroup aggregate or RLIMIT_AS; image-level96MiB validation remains pending'}
  if out:pathlib.Path(out).write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps(result))
  assert peak<96*1024
 finally:
  done.set();watch.join();process.terminate();process.wait(timeout=10)
