"""Owned Hyper-V console pixels and explicit root review before UAC confirmation.

No image heuristic is acceptance. Only an exact-pixel root ACK unlocks the next
consent-bound controller step. This module never invokes a VM or sends input.
"""
from __future__ import annotations
import argparse,hashlib,json,os,re,secrets,struct,time,zlib
from datetime import datetime,timezone,timedelta
from pathlib import Path
try:
 from .windows_evidence_archive import archive_exact_file,validate_archive_record
except ImportError:
 from windows_evidence_archive import archive_exact_file,validate_archive_record

SCHEMA='amnezia.release-lab.windows-consent-visual.v1'
ACK_SCHEMA='amnezia.release-lab.windows-consent-root-review.v1'
METHOD='Msvm_VirtualSystemManagementService.GetVirtualSystemThumbnailImage'
PROOF_FIELDS=('run_id','case_id','vm_id','process_id','creation_time','session_id','owner_sid',
 'consent_path','launcher_pid','launcher_start_time','launcher_session_id','launcher_sid')
SHA=re.compile(r'[0-9a-f]{64}')
ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}')
class ConsentVisualError(RuntimeError):pass
def require(value,message):
 if not value:raise ConsentVisualError(message)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def utc(value):
 require(isinstance(value,str) and value.endswith('Z'),'canonical UTC required')
 require(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z',value),'canonical UTC required')
 try:return datetime.fromisoformat(value[:-1]+'+00:00')
 except ValueError as e:raise ConsentVisualError('invalid UTC') from e
def now():return datetime.now(timezone.utc)
def utc_text():return now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
def _under(root,path):
 root=Path(os.path.abspath(root));path=Path(os.path.abspath(path))
 require(root.is_dir() and not root.is_symlink(),'owned root unavailable')
 try:relative=path.relative_to(root)
 except ValueError as e:raise ConsentVisualError('path escaped owned root') from e
 require(bool(relative.parts),'evidence cannot be owned root')
 cursor=root
 for part in relative.parts:
  cursor=cursor/part;require(not cursor.is_symlink(),'symlinked evidence ancestor')
 return path
def _write(root,path,data):
 path=_under(root,path);path.parent.mkdir(parents=True,exist_ok=True);_under(root,path)
 temporary=_under(root,path.parent/('.'+path.name+'.tmp-'+secrets.token_hex(16)))
 flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
 if hasattr(os,'O_NOFOLLOW'):flags|=os.O_NOFOLLOW
 fd=os.open(temporary,flags,0o600)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  # Exclusive atomic publication: the reader never observes a reserved empty
  # ACK and an existing destination is never overwritten. No mutable temp
  # name remains linked after publication.
  os.link(temporary,path)
  try:
   directory_fd=os.open(path.parent,os.O_RDONLY)
   try:os.fsync(directory_fd)
   finally:os.close(directory_fd)
  except OSError:pass  # NTFS does not expose portable directory fsync.
 finally:temporary.unlink(missing_ok=True)
 return path
def consent_identity(proof):
 require(isinstance(proof,dict) and proof.get('expected_consent') is True,'positive consent process proof required')
 require(proof.get('case_id')=='outer-interactive' and ID.fullmatch(str(proof.get('run_id',''))),'consent run/case invalid')
 require(proof.get('owner_sid')=='S-1-5-18' and proof.get('launcher_sid') not in ('',None,'S-1-5-18'),'consent/launcher owner invalid')
 for name in ('process_id','session_id','launcher_pid','launcher_session_id'):
  require(type(proof.get(name)) is int and proof[name]>0,'consent process/session invalid')
 require(proof['process_id']!=proof['launcher_pid'] and proof['session_id']==proof['launcher_session_id'],'consent is not distinct same-session process')
 require(re.fullmatch(r'[A-Za-z]:[\\/]Windows[\\/]System32[\\/]consent\.exe',str(proof.get('consent_path','')),re.I),'consent executable path invalid')
 require(all(isinstance(proof.get(k),str) and proof[k] for k in ('vm_id','creation_time','launcher_start_time')),'consent identity incomplete')
 return {k:proof[k] for k in PROOF_FIELDS}
def require_same_consent(before,after):
 a=consent_identity(before);require(a==consent_identity(after),'consent process changed around capture/confirmation');return a
def rgb565_png(raw,width,height):
 require(type(width) is int and type(height) is int and 640<=width<=1920 and 480<=height<=1080,'console dimensions outside reviewed bounds')
 require(isinstance(raw,bytes) and len(raw)==width*height*2,'raw RGB565 length invalid')
 rows=bytearray()
 for y in range(height):
  rows.append(0)
  for (p,) in struct.iter_unpack('<H',raw[y*width*2:(y+1)*width*2]):
   r=(p>>11)&31;g=(p>>5)&63;b=p&31
   rows.extend(((r<<3)|(r>>2),(g<<2)|(g>>4),(b<<3)|(b>>2)))
 def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
 return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(bytes(rows),6))+chunk(b'IEND',b'')
def provider_payload(raw,width,height,encoding,offset,octet_qualifier):
 require(type(width) is int and type(height) is int and 640<=width<=1920 and 480<=height<=1080,'provider dimensions outside reviewed bounds')
 require(isinstance(raw,bytes) and octet_qualifier is True,'provider OctetString metadata is not proven')
 expected=width*height*2
 if encoding=='raw-rgb565le':
  require(type(offset) is int and offset==0 and len(raw)==expected,'plain provider payload shape invalid');return raw
 require(encoding=='cim-octet-string-rgb565le' and type(offset) is int and offset==4,'provider encoding/offset invalid')
 require(len(raw)==expected+4 and struct.unpack('>I',raw[:4])[0]==len(raw),'CIM OctetString total-length framing invalid')
 return raw[4:]

def provider_observation(t):
 names=('provider_raw_file_name','provider_raw_sha256','provider_raw_size','provider_encoding','provider_payload_offset','provider_octet_string_qualifier')
 present=[name in t for name in names]
 require(not any(present) or all(present),'partial provider capture metadata')
 return {name:t[name] for name in names} if all(present) else None

def prepare_request(*,owned_root,run_id,version,manifest_sha256,artifact_sha256,parent_sha256,observe,raw_source,attempt_nonce):
 require(ID.fullmatch(run_id) and re.fullmatch('[0-9a-f]{32}',attempt_nonce),'visual run/attempt invalid')
 require(re.fullmatch(r'\d+(?:\.\d+){3}',version),'version invalid')
 require(all(SHA.fullmatch(str(x)) for x in (manifest_sha256,artifact_sha256,parent_sha256)),'release context hash invalid')
 require(observe.get('action')=='ui-observe' and observe.get('injected') is False and observe.get('origin')=='guest'
  and observe.get('transport')=='hyperv-powershell-direct' and observe.get('parent_sha256')==parent_sha256,'observation provenance invalid')
 t=observe.get('console_capture');require(isinstance(t,dict),'owned console capture missing')
 ident=require_same_consent(observe.get('consent'),t.get('consent_after'))
 require(ident['run_id']==run_id and ident['vm_id']==observe.get('vm_id')==t.get('vm_id'),'console VM/run mismatch')
 require(t.get('method')==METHOD and t.get('format')=='rgb565le' and t.get('artifact_sha256')==artifact_sha256,'console method/artifact invalid')
 require(t.get('settings_virtual_system_type')=='Microsoft:Hyper-V:System:Realized' and str(t.get('settings_vm_id','')).lower()==str(ident['vm_id']).lower(),'console not current VM settings')
 require(utc(t['completed_at'])>=utc(t['started_at']) and now()-timedelta(seconds=120)<=utc(t['started_at'])<=now()+timedelta(seconds=5),'console capture stale/future')
 raw=Path(raw_source).read_bytes();require(SHA.fullmatch(str(t.get('sha256',''))) and hashlib.sha256(raw).hexdigest()==t['sha256'] and len(raw)==t.get('size'),'console raw bytes changed')
 png=rgb565_png(raw,t['width'],t['height'])
 provider=provider_observation(t);require(provider is not None,'fresh console capture requires original provider metadata');provider_source=None
 if provider is not None:
  require(re.fullmatch('consent-provider-'+attempt_nonce+r'-[0-9a-f]{32}\.octets',str(provider['provider_raw_file_name'])),'provider file/attempt binding invalid')
  require(SHA.fullmatch(str(provider['provider_raw_sha256'])) and type(provider['provider_raw_size']) is int,'provider hash/size metadata invalid')
  provider_source=Path(raw_source).parent/provider['provider_raw_file_name']
  require(not provider_source.is_symlink() and provider_source.is_file() and provider_source.stat().st_size==provider['provider_raw_size'] and 0<provider['provider_raw_size']<=1920*1080*2+4,'provider source type/size bound invalid')
  provider_bytes=provider_source.read_bytes()
  require(hashlib.sha256(provider_bytes).hexdigest()==provider['provider_raw_sha256'] and len(provider_bytes)==provider['provider_raw_size'],'provider original bytes changed')
  require(provider_payload(provider_bytes,t['width'],t['height'],provider['provider_encoding'],provider['provider_payload_offset'],provider['provider_octet_string_qualifier'])==raw,'provider original does not decode to bound pixels')
 directory=Path(owned_root)/'exports'/run_id/'windows-x64'/'outer-interactive'/('consent-'+attempt_nonce)
 directory=_under(owned_root,directory);directory.mkdir(parents=True,exist_ok=False)
 raw_record=archive_exact_file(Path(owned_root),Path(raw_source),directory,expected_sha256=t['sha256'],expected_size=t['size'],kind='uac-console-rgb565',vm_id=ident['vm_id'],case_id='outer-interactive',attempt_nonce=attempt_nonce)
 pp=_write(owned_root,directory/'consent-console.png',png)
 png_record={'path':str(pp),'sha256':hashlib.sha256(png).hexdigest(),'size':len(png),'kind':'uac-console','vm_id':ident['vm_id'],'case_id':'outer-interactive','attempt_nonce':attempt_nonce}
 request={'schema':SCHEMA,'run_id':run_id,'profile':'windows-x64','case_id':'outer-interactive','version':version,'attempt_nonce':attempt_nonce,'manifest_sha256':manifest_sha256,'artifact_sha256':artifact_sha256,'parent_sha256':parent_sha256,'vm_id':ident['vm_id'],'method':METHOD,'captured_at':t['completed_at'],'consent':ident,'width':t['width'],'height':t['height'],'raw_archive':raw_record,'png_archive':png_record,'visual_review_required':True,'visual_review_passed':False}
 if provider is not None:
  provider_record=archive_exact_file(Path(owned_root),provider_source,directory,expected_sha256=provider['provider_raw_sha256'],expected_size=provider['provider_raw_size'],kind='uac-console-provider-octets',vm_id=ident['vm_id'],case_id='outer-interactive',attempt_nonce=attempt_nonce)
  request['provider_capture']={'original_archive':provider_record,'metadata':provider,'payload_sha256':t['sha256'],'payload_size':t['size']}
 _write(owned_root,directory/'request.json',canonical(request)+b'\n')
 return request
def validate_request(root,r):
 require(r.get('schema')==SCHEMA and r.get('profile')=='windows-x64' and r.get('case_id')=='outer-interactive' and r.get('method')==METHOD,'visual request method/schema invalid')
 require(r.get('visual_review_required') is True and r.get('visual_review_passed') is False,'visual review must still be pending')
 require(ID.fullmatch(str(r.get('run_id',''))) and re.fullmatch('[0-9a-f]{32}',str(r.get('attempt_nonce',''))),'visual request identity invalid')
 require(all(SHA.fullmatch(str(r.get(k,''))) for k in ('manifest_sha256','artifact_sha256','parent_sha256')),'visual request context missing')
 for name,kind in (('raw_archive','uac-console-rgb565'),('png_archive','uac-console')):
  validate_archive_record(Path(root),r[name],kind=kind,vm_id=r['vm_id'],case_id=r['case_id'],attempt_nonce=r['attempt_nonce'])
 raw=Path(r['raw_archive']['path']).read_bytes();png=Path(r['png_archive']['path']).read_bytes()
 require(rgb565_png(raw,r['width'],r['height'])==png,'console PNG is not exact RGB565 conversion')
 if 'provider_capture' in r:
  pc=r['provider_capture'];require(isinstance(pc,dict),'provider capture object required')
  meta=pc.get('metadata');record=pc.get('original_archive');require(isinstance(meta,dict) and isinstance(record,dict),'provider metadata/archive objects required')
  require(set(pc)=={'original_archive','metadata','payload_sha256','payload_size'} and provider_observation(meta)==meta,'provider archive metadata invalid')
  require(re.fullmatch('consent-provider-'+r['attempt_nonce']+r'-[0-9a-f]{32}\.octets',str(meta['provider_raw_file_name'])),'provider archived attempt invalid')
  validate_archive_record(Path(root),record,kind='uac-console-provider-octets',vm_id=r['vm_id'],case_id=r['case_id'],attempt_nonce=r['attempt_nonce'])
  require(record['sha256']==meta['provider_raw_sha256'] and record['size']==meta['provider_raw_size'],'provider source/archive binding changed')
  require(pc['payload_sha256']==r['raw_archive']['sha256'] and pc['payload_size']==len(raw),'provider decoded hash/size changed')
  require(provider_payload(Path(record['path']).read_bytes(),r['width'],r['height'],meta['provider_encoding'],meta['provider_payload_offset'],meta['provider_octet_string_qualifier'])==raw,'provider archive does not decode to reviewed raw pixels')
 return r
def validate_ack(*,owned_root,request,ack):
 require(isinstance(request,dict) and isinstance(ack,dict),'visual request/ACK objects required')
 validate_request(owned_root,request)
 expected={'schema':ACK_SCHEMA,'decision':'accepted','reviewer_role':'root-visual-review','request_sha256':hashlib.sha256(canonical(request)).hexdigest(),'run_id':request['run_id'],'vm_id':request['vm_id'],'attempt_nonce':request['attempt_nonce'],'manifest_sha256':request['manifest_sha256'],'artifact_sha256':request['artifact_sha256'],'png_sha256':request['png_archive']['sha256']}
 require(set(ack)==set(expected)|{'reviewed_at'} and all(ack.get(k)==v for k,v in expected.items()),'visual ACK binding mismatch')
 require(utc(request['captured_at'])<=utc(ack['reviewed_at'])<=utc(request['captured_at'])+timedelta(seconds=120),'visual ACK stale/out of order')
 require(utc(ack['reviewed_at'])<=now()+timedelta(seconds=5),'visual ACK future')
 return ack
def create_ack(*,owned_root,request,viewed_png_sha256):
 validate_request(owned_root,request);require(viewed_png_sha256==request['png_archive']['sha256'],'explicit viewed PNG differs')
 ack={'schema':ACK_SCHEMA,'decision':'accepted','reviewer_role':'root-visual-review','request_sha256':hashlib.sha256(canonical(request)).hexdigest(),'run_id':request['run_id'],'vm_id':request['vm_id'],'attempt_nonce':request['attempt_nonce'],'manifest_sha256':request['manifest_sha256'],'artifact_sha256':request['artifact_sha256'],'png_sha256':viewed_png_sha256,'reviewed_at':utc_text()}
 validate_ack(owned_root=owned_root,request=request,ack=ack)
 target=Path(request['png_archive']['path']).parent/'root-consent-visual-ack.json'
 _write(owned_root,target,canonical(ack)+b'\n');return ack
def wait_for_review(*,owned_root,request,timeout_seconds=90):
 require(type(timeout_seconds) is int and 1<=timeout_seconds<=90,'visual wait must be bounded to90s')
 validate_request(owned_root,request);directory=Path(request['png_archive']['path']).parent
 target=directory/'root-consent-visual-ack.json'
 print(json.dumps({'event':'trusted-windows-consent-visual-review','request':str(directory/'request.json'),'requestSha256':hashlib.sha256(canonical(request)+b'\n').hexdigest(),'png':request['png_archive'],'ackPath':str(target),'runId':request['run_id'],'timeoutSeconds':timeout_seconds}),flush=True)
 deadline=time.monotonic()+timeout_seconds
 while time.monotonic()<deadline:
  if target.exists():
   _under(owned_root,target);require(target.is_file() and target.stat().st_size<=8192,'visual ACK file invalid')
   return validate_ack(owned_root=owned_root,request=request,ack=json.loads(target.read_bytes()))
  time.sleep(.25)
 raise ConsentVisualError('root did not review actual consent console pixels before timeout')
def validate_completed(*,owned_root,proof,observe,confirmed_consent,confirmed_at,completed_at):
 require(isinstance(proof,dict) and set(proof)=={'request','ack'},'root consent visual proof missing')
 r=proof['request'];a=proof['ack'];validate_ack(owned_root=owned_root,request=r,ack=a)
 t=observe.get('console_capture') or {}
 require(r['consent']==require_same_consent(observe.get('consent'),t.get('consent_after')),'reviewed console is not observed consent')
 require(t.get('method')==METHOD and t.get('format')=='rgb565le' and t.get('settings_virtual_system_type')=='Microsoft:Hyper-V:System:Realized'
  and str(t.get('settings_vm_id','')).lower()==str(r['vm_id']).lower()
  and t.get('artifact_sha256')==r['artifact_sha256'] and t.get('vm_id')==r['vm_id']
  and t.get('sha256')==r['raw_archive']['sha256'] and t.get('size')==r['raw_archive']['size']
  and t.get('width')==r['width'] and t.get('height')==r['height'] and t.get('completed_at')==r['captured_at']
  and observe.get('vm_id')==r['vm_id'] and observe.get('parent_sha256')==r['parent_sha256'], 'console observation/archive binding changed')
 observed_provider=provider_observation(t)
 if observed_provider is not None:
  require(r.get('provider_capture',{}).get('metadata')==observed_provider,'provider observation/archive binding changed')
 else:require('provider_capture' not in r,'provider archive lacks observation binding')
 require(r['consent']==consent_identity(confirmed_consent),'confirmed consent differs from reviewed console')
 require(utc(t['started_at'])<=utc(r['captured_at'])<=utc(a['reviewed_at'])<=utc(confirmed_at)<=utc(completed_at),'capture/review/confirmation/completion order invalid')
 return proof
def confirm_after_review(*,owned_root,request,confirm):
 """The callable that injects the fixed guest key is unreachable without ACK."""
 ack=wait_for_review(owned_root=owned_root,request=request)
 result=confirm()
 require(isinstance(result,dict) and result.get('action')=='ui-confirm','confirmation result missing')
 require(request['consent']==consent_identity(result.get('consent')),'confirmation changed reviewed consent')
 require(utc(ack['reviewed_at'])<=utc(result.get('confirmed_at')),'confirmation precedes root pixel ACK')
 return ack,result
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--owned-root',type=Path,required=True);p.add_argument('--request',type=Path,required=True);p.add_argument('--expected-request-sha256',required=True);p.add_argument('--viewed-png-sha256',required=True);p.add_argument('--confirm-reviewed-pixels',action='store_true',required=True);a=p.parse_args()
 request_path=_under(a.owned_root,a.request);request_bytes=request_path.read_bytes();require(SHA.fullmatch(a.expected_request_sha256) and hashlib.sha256(request_bytes).hexdigest()==a.expected_request_sha256,'staged request bytes changed')
 r=json.loads(request_bytes);require(request_path==Path(r['png_archive']['path']).parent/'request.json','request path mismatch')
 print(json.dumps(create_ack(owned_root=a.owned_root,request=r,viewed_png_sha256=a.viewed_png_sha256)))
if __name__=='__main__':main()
