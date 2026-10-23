"""Actual Python/native dispatch against the same private ephemeral SQLite state."""
import concurrent.futures,base64,hashlib,io,json,pathlib,sqlite3,subprocess,sys,tempfile
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import service
probe=sys.argv[1];NOW=1900000000;peer=base64.b64encode(bytes(range(32))).decode();client='c'*64;fp='a'*64;nonce='n'*43
class Handler:
 def __init__(self,path,body,ip):
  self.path='/migration/v1/'+path;raw=json.dumps(body).encode();self.headers={'Content-Length':str(len(raw))};self.rfile=io.BytesIO(raw);self.wfile=io.BytesIO();self.client_address=(ip,1);self.status=None
 def send_error(self,status):self.status=status
 def send_response(self,status):self.status=status
 def send_header(self,*args):pass
 def end_headers(self):pass
with tempfile.TemporaryDirectory() as d:
 d=pathlib.Path(d);d.chmod(0o700)
 subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(d/'signing.pem')],check=True,capture_output=True);(d/'signing.pem').chmod(0o600)
 pub=subprocess.run(['openssl','pkey','-in',str(d/'signing.pem'),'-pubout','-outform','DER'],check=True,capture_output=True).stdout[-32:]
 state={'serverPublicKey':peer,'containerId':'amnezia-awg2','generation':1,'expiresAt':NOW+3600,'signingPublicKey':base64.b64encode(pub).decode(),'endpoint':'vpn.example:51822','parameters':{'S1':'16'},'challengeAddress':'172.29.172.251','challengePort':18082,'peers':{peer:{'sourceIp':'10.8.1.2','targetIp':'10.8.1.2','clientAddress':'10.8.1.2/32','clientId':client}}}
 (d/'ready.json').write_text(json.dumps(state));(d/'handshakes.tsv').write_text(peer+'\t'+str(NOW)+'\n')
 def native(path,body,role='source',ip='10.8.1.2',identity=client,grant_header=None):
  p=subprocess.run([probe,'dispatch',str(d),role,'/migration/v1/'+path,ip,identity,str(NOW)]+([grant_header] if grant_header else []),input=json.dumps(body).encode(),capture_output=True,check=True);status,raw=p.stdout.split(b'\n',1);return int(status),json.loads(raw) if raw else None
 def py(path,body,role='source',ip='10.8.1.2',identity=client):
  h=Handler(path,body,ip)
  with patch('service.time.time',return_value=NOW): service.MigrationService(str(d),role,'amnezia-awg2').dispatch(h,lambda:identity)
  return h.status,json.loads(h.wfile.getvalue()) if h.wfile.getvalue() else None
 bootstrap={'schema':1,'peerPublicKey':peer,'sourceFingerprint':fp,'nonce':nonce}
 status,enroll=native('bootstrap',bootstrap);assert status==200,(status,enroll)
 assert py('bootstrap',bootstrap)==(status,enroll)
 assert native('bootstrap',bootstrap)==(status,enroll)
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
  results=list(executor.map(lambda _:native('bootstrap',bootstrap),range(8)))
 assert all(x==(status,enroll) for x in results)
 assert native('bootstrap',bootstrap,ip='10.8.1.3')[0]==403
 assert native('bootstrap',bootstrap,identity='wrong')[0]==403
 assert native('bootstrap',{**bootstrap,'extra':1})[0]==403
 grant=enroll['grant']
 offer={'schema':1,'peerPublicKey':peer,'sourceFingerprint':fp,'nonce':nonce}
 code,offered=native('offer',offer,grant_header=grant);assert code==200
 h=Handler('offer',offer,'10.8.1.2');h.headers['X-Amnezia-Migration-Grant']=grant
 with patch('service.time.time',return_value=NOW):service.MigrationService(str(d),'source','amnezia-awg2').dispatch(h,lambda:client)
 assert h.status==200 and json.loads(h.wfile.getvalue())==offered
 assert native('offer',offer,grant_header='bad')[0]==403
 # Offer's grant is supplied only in a header in the protocol; challenge uses body.
 with sqlite3.connect(d/'grants.sqlite3') as db: challenge=db.execute('SELECT challenge FROM grants').fetchone()[0]
 body={'schema':1,'peerPublicKey':peer,'generation':1,'grant':grant,'nonce':challenge}
 status,receipt=native('challenge',body,'target');assert status==200
 assert py('challenge',body,'target')==(status,receipt)
 assert native('bootstrap',bootstrap)[0]==403
 ack={'schema':1,'peerPublicKey':peer,'generation':1,'grant':grant,'challengeReceipt':receipt}
 assert native('ack',ack,'target')==py('ack',ack,'target')==(200,{'schema':1,'ok':True,'acknowledged':True,'generation':1})
 assert native('ack',{**ack,'challengeReceipt':{'payload':'bad','signature':'bad'}},'target')[0]==403
 renew={**ack,'nonce':'r'*43}
 status,renewal=native('renew',renew,'target');assert status==200
 payload=json.loads(base64.b64decode(renewal['payload']))
 assert service.sign(payload,str(d))==renewal
 (d/'handshakes.tsv').write_text(peer+'\t'+str(NOW-121)+'\n')
 assert native('renew',{**renew,'nonce':'s'*43},'target')[0]==403
 (d/'handshakes.tsv').write_text(peer+'\t'+str(NOW)+'\n')
 state['expiresAt']=NOW-1;(d/'ready.json').write_text(json.dumps(state))
 assert native('offer',offer,grant_header=grant)[0]==403
 assert native('ack',ack,'target')[0]==200
 assert native('renew',{**renew,'nonce':'s'*43},'target')[0]==200
 assert native('renew',renew,'target')[0]==403
 assert py('renew',renew,'target')[0]==403
 assert native('challenge',{**body,'generation':True},'target')[0]==403
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
  results=list(executor.map(lambda _:native('renew',{**renew,'nonce':'t'*43},'target'),range(8)))
 assert [x[0] for x in results].count(200)==1
 assert [x[0] for x in results].count(403)==7
 with sqlite3.connect(d/'grants.sqlite3') as db:
  db.execute('UPDATE grants SET expires=? WHERE digest=?',(NOW-1,hashlib.sha256(grant.encode()).hexdigest()))
 assert native('ack',ack,'target')[0]==403
 assert native('renew',{**renew,'nonce':'u'*43},'target')[0]==200
 # Authentication failure must not consume the nonce; the same nonce then works.
 assert native('renew',{**renew,'nonce':'v'*43},'target',identity='wrong')[0]==403
 assert native('renew',{**renew,'nonce':'v'*43},'target')[0]==200
 with sqlite3.connect(d/'grants.sqlite3') as db:
  before=db.execute('SELECT COUNT(*) FROM renewalNonces').fetchone()[0]
  db.execute('UPDATE grants SET expires=?',(NOW+100,))
  for i in range(40):
   db.execute('INSERT INTO grants(digest,peer,generation,expires) VALUES(?,?,?,?)',(str(i),peer,1,NOW+100))
 assert native('renew',{**renew,'nonce':'w'*43},'target')[0]==403
 with sqlite3.connect(d/'grants.sqlite3') as db:
  assert db.execute('SELECT COUNT(*) FROM renewalNonces').fetchone()[0]==before
 with sqlite3.connect(d/'grants.sqlite3') as db:assert db.execute('SELECT COUNT(*) FROM renewalNonces').fetchone()[0]==5
print('actual service bootstrap idempotency/scoped auth/challenge Ed25519/ack/renew anti-replay parity PASS')





# A valid config-backed large peer map needs more space than the wire/config cap.
# Integrated CTest supplies the actual generator; standalone control-only runs
# retain a pure Python reference for constructing the same config fixture.
import ipaddress
import prepare
generator = sys.argv[2] if len(sys.argv) > 2 else None
with tempfile.TemporaryDirectory(prefix='awg-control-large-state-') as owned:
 directory=pathlib.Path(owned);directory.chmod(0o700)
 subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(directory/'signing.pem')],check=True,capture_output=True)
 (directory/'signing.pem').chmod(0o600)
 public=subprocess.run(['openssl','pkey','-in',str(directory/'signing.pem'),'-pubout','-outform','DER'],check=True,capture_output=True).stdout[-32:]
 peers={}
 source='[Interface]\nPrivateKey='+'A'*43+'=\nAddress=10.8.0.1/16\nListenPort=51820\n'
 for i in range(6000):
  key=base64.b64encode((i+1).to_bytes(32,'big')).decode()
  address=str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('10.8.0.2'))+i))
  source+='[Peer]\nPublicKey='+key+'\nAllowedIPs='+address+'/32\n'
  peers[key]={'sourceIp':address,'targetIp':address,'clientAddress':address+'/32',
              'clientId':hashlib.sha256(('amnezia-awg2\t'+key).encode()).hexdigest()}
 if generator:
  generated=subprocess.run([generator,'--generate-config-json'],
      input=json.dumps({'source':source,'port':51821,'mtu':1420}).encode(),capture_output=True,check=True,timeout=15)
  value=json.loads(generated.stdout)['result'];quick=value['config'];parameters=value['parameters']
 else:
  parameters,unused,quick,unused_native=prepare.legacy_generate_config(source.encode(),51821,1420)
 assert len(source.encode())<=1024**2 and len(quick.encode())<=1024**2
 first,mapping=next(iter(peers.items()))
 state={'serverPublicKey':first,'containerId':'amnezia-awg2','generation':1,'expiresAt':NOW+3600,
        'signingPublicKey':base64.b64encode(public).decode(),'endpoint':'vpn.example:51821',
        'parameters':parameters,'challengeAddress':'172.29.172.251','challengePort':18082,'peers':peers}
 body={'schema':1,'peerPublicKey':first,'sourceFingerprint':'a'*64,'nonce':'n'*43}
 def state_bytes(value):return json.dumps(value,separators=(',',':')).encode()
 def write_state(value):
  raw=state_bytes(value);(directory/'ready.json').write_bytes(raw);return len(raw)
 def dispatch_large(value):
  result=subprocess.run([probe,'dispatch',owned,'source','/migration/v1/bootstrap',mapping['sourceIp'],mapping['clientId'],str(NOW)],
      input=json.dumps(value).encode(),capture_output=True,check=True,timeout=20)
  status,raw=result.stdout.split(b'\n',1);return int(status),json.loads(raw) if raw else None
 original_size=write_state(state);assert original_size>1024**2
 status,response=dispatch_large(body);assert status==200,(status,original_size)
 handler=Handler('bootstrap',body,mapping['sourceIp'])
 with patch('service.time.time',return_value=NOW):
  service.MigrationService(owned,'source','amnezia-awg2').dispatch(handler,lambda:mapping['clientId'])
 assert handler.status==200 and json.loads(handler.wfile.getvalue())==response
 # Exact8MiB state is accepted; cap+1 is rejected before another grant is stored.
 state['auditPadding']=''
 state['auditPadding']='x'*(8*1024**2-len(state_bytes(state)))
 assert write_state(state)==8*1024**2
 assert dispatch_large(body)==(status,response)
 with sqlite3.connect(directory/'grants.sqlite3') as db:
  before=db.execute('SELECT count(*) FROM grants').fetchone()[0]
 state['auditPadding']+='x';assert write_state(state)==8*1024**2+1
 assert dispatch_large({**body,'nonce':'z'*43})[0]==403
 with sqlite3.connect(directory/'grants.sqlite3') as db:
  assert db.execute('SELECT count(*) FROM grants').fetchone()[0]==before==1
 # Other input classes retain their prior limits despite the state-only increase.
 state.pop('auditPadding');write_state(state)
 canonical_limit=subprocess.run([probe,'canonical'],input=b'"'+b'x'*(1024**2)+b'"',capture_output=True,timeout=10)
 assert canonical_limit.returncode!=0
 request_limit={**body,'nonce':'x'*17000}
 assert dispatch_large(request_limit)[0]==403
print('control6000peer state/native '+('C++' if generator else 'Python-reference')+' generation/8MiB boundary/request+canonical caps PASS')
