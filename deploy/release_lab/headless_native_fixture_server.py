#!/usr/bin/env python3
"""Guest-only HTTP fixture for exact signed Linux headless update bytes."""
import argparse,base64,hashlib,json,os,stat,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
MAX_LOG=1<<20;MAX_ROWS=4096
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def truncate(p,create=False):
 flags=os.O_WRONLY|os.O_NOFOLLOW|(os.O_CREAT|os.O_EXCL if create else os.O_TRUNC);fd=os.open(p,flags,0o600)
 try:os.fsync(fd)
 finally:os.close(fd)
 s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:raise SystemExit('request log identity')
def artifact_path(doc,expected,expected_size,expected_path=None):
 if not isinstance(doc,dict) or not isinstance(doc.get('payload'),str) or not isinstance(doc.get('signature'),str) or not doc['signature']:raise SystemExit('signed manifest wrapper')
 try:payload=json.loads(base64.b64decode(doc['payload']+'='*(-len(doc['payload'])%4),altchars=b'-_',validate=True))
 except Exception as e:raise SystemExit('signed manifest payload') from e
 row=(payload.get('platforms') or {}).get('linux-headless-x64') if isinstance(payload,dict) else None;url=row.get('url') if isinstance(row,dict) else None;p=urlsplit(url) if isinstance(url,str) else None
 path='/'+p.path.lstrip('/') if p else ''
 absolute=p and p.scheme in ('http','https') and bool(p.netloc);relative=p and not p.scheme and not p.netloc
 if not isinstance(row,dict) or row.get('sha256')!=expected or row.get('size')!=expected_size or isinstance(row.get('size'),bool) or row.get('format')!='amnezia-headless-tar-v1' or not p or not (absolute or relative) or p.query or p.fragment or (expected_path is not None and path!=expected_path) or (expected_path is None and not path.startswith(f'/files/artifacts/{expected}/')):raise SystemExit('headless artifact URL or identity')
 return path
class H(BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def do_GET(self):self.serve(True)
 def do_HEAD(self):self.serve(False)
 def serve(self,body):
  f=self.server.fixture;p=urlsplit(self.path)
  if p.path in ('/__lab__/attempt/reset','/__lab__/request-log'):
   q=parse_qs(p.query)
   if q.get('nonce',[''])[0]!=f['nonce'] or q.get('run_id',[''])[0]!=f['run']:self.send_error(403);return
   if p.path.endswith('/reset'):
    with f['lock']:
     if f['reset']:self.send_error(409);return
     truncate(f['log']);f['rows']=0;f['limited']=False;f['reset']=True
    data=json.dumps({'status':'reset','run_id':f['run']},separators=(',',':')).encode()
   else:
    if not f['reset']:self.send_error(409);return
    data=f['log'].read_bytes()
   self.reply(data,'application/jsonl',body);return
  if p.path=='/healthz':self.reply(json.dumps({'status':'ok','run_id':f['run'],'role':'headless-native-fixture'},separators=(',',':')).encode(),'application/json',body);return
  if p.path==f['manifest_path']:source=f['manifest'];ctype='application/json'
  elif p.path==f['artifact_path']:source=f['artifact'];ctype='application/gzip'
  else:self.send_error(404);self.record(404,0,0,'');return
  length=source.stat().st_size;digest=sha(source);self.send_response(200);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(length));self.send_header('Cache-Control','no-store');self.send_header('X-Amnezia-Run-Id',f['run']);self.send_header('X-Amnezia-Sha256',digest);self.end_headers()
  sent=0
  if body:
   with source.open('rb') as stream:
    for chunk in iter(lambda:stream.read(1<<20),b''):
     self.wfile.write(chunk);sent+=len(chunk)
  self.record(200,sent,length,digest)
 def reply(self,data,ctype,body):
  self.send_response(200);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(data)));self.send_header('X-Amnezia-Run-Id',self.server.fixture['run']);self.end_headers()
  if body:self.wfile.write(data)
 def record(self,status,size,length,digest):
  f=self.server.fixture
  with f['lock']:
   if f['limited']:return
   row={'attempt_nonce':f['nonce'],'bytes':size,'client':self.client_address[0],'content_length':length,'method':self.command,'path':self.path.split('?',1)[0],'run_id':f['run'],'sha256':digest,'status':status,'timestamp':time.time()};line=(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode()
   if f['rows']>=MAX_ROWS or f['log'].stat().st_size+len(line)>MAX_LOG:f['limited']=True;return
   fd=os.open(f['log'],os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
   try:
    view=memoryview(line);written=0
    while view:
     n=os.write(fd,view)
     if n<=0:raise OSError('short request-log write')
     written+=n;view=view[n:]
    os.fsync(fd)
   finally:os.close(fd)
   if written!=len(line):f['limited']=True;return
   f['rows']+=1
def main():
 a=argparse.ArgumentParser();a.add_argument('--manifest',type=Path,required=True);a.add_argument('--apk',dest='artifact',type=Path,required=True);a.add_argument('--manifest-sha256',required=True);a.add_argument('--apk-sha256',dest='artifact_sha256',required=True);a.add_argument('--manifest-path',required=True);a.add_argument('--artifact-path',required=True);a.add_argument('--run-id',required=True);a.add_argument('--attempt-nonce',required=True);a.add_argument('--port',type=int,required=True);a.add_argument('--request-log',type=Path,required=True);x=a.parse_args()
 if not 1024<=x.port<=65535 or sha(x.manifest)!=x.manifest_sha256 or sha(x.artifact)!=x.artifact_sha256:raise SystemExit('fixture input identity')
 doc=json.loads(x.manifest.read_text());path=artifact_path(doc,x.artifact_sha256,x.artifact.stat().st_size,x.artifact_path);x.request_log.parent.mkdir(parents=True,exist_ok=True);truncate(x.request_log,True)
 if not x.manifest_path.startswith('/') or '?' in x.manifest_path or '#' in x.manifest_path:raise SystemExit('manifest path')
 s=ThreadingHTTPServer(('0.0.0.0',x.port),H);s.fixture={'run':x.run_id,'nonce':x.attempt_nonce,'manifest':x.manifest,'manifest_path':x.manifest_path,'artifact':x.artifact,'artifact_path':path,'log':x.request_log,'lock':threading.Lock(),'rows':0,'limited':False,'reset':False};s.serve_forever(.2)
if __name__=='__main__':main()
