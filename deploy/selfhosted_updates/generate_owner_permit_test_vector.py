"""Test-only RFC8032 public vector; never loads or writes a release/private key."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,base64
from unittest import mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
try:
 from . import owner_publication_permit as permit
except ImportError:
 import owner_publication_permit as permit

def generate(destination: Path):
 if destination.exists():raise SystemExit('Refuse overwrite test vector directory')
 destination.mkdir(parents=True)
 # RFC8032 section7.1 TEST1 seed, published public test material, memory only.
 key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
 pub=destination/'rfc8032-public.pem';pub.write_bytes(key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
 document={'schema':1,'version':permit.VERSION,'platforms':{},'headlessProvisioning':None}
 for i,name in enumerate(sorted(permit.PLATFORMS)+['headlessProvisioning']):
  path=destination/'files/artifacts'/str(i)/'item';path.parent.mkdir(parents=True);path.write_bytes(('test-only-artifact-'+str(i)).encode())
  digest,size=permit.regular_digest(path);item={'url':path.relative_to(destination).as_posix(),'sha256':digest,'size':size}
  if name=='android-arm64-v8a':item['versionCode']=permit.ANDROID_CODE
  if name=='headlessProvisioning':document[name]=item
  else:document['platforms'][name]=item
 raw=permit.canonical(document)
 (destination/'manifest.json').write_bytes(permit.canonical({'schema':'amnezia-selfhosted-update-v1','signatureAlgorithm':'Ed25519','payload':permit.manifest.b64url(raw),'signature':base64.b64encode(key.sign(raw)).decode()}))
 publisher=destination/'publisher.sh';publisher.write_bytes(b'test-only-publisher-no-execution')
 class FixedTime(datetime):
  @classmethod
  def now(cls,tz=None):return datetime(2026,10,19,0,30,tzinfo=timezone.utc)
 with mock.patch.object(permit,'datetime',FixedTime),mock.patch.object(permit.manifest,'sign_payload',side_effect=lambda path,raw:base64.b64encode(key.sign(raw)).decode()):
  payload=permit.issue_owner_permit(bundle=destination,publisher=publisher,public_key=pub,private_key=Path('RFC8032_TEST_VECTOR_MEMORY_ONLY'),output=destination/'owner-publication-permit.json',acknowledge=permit.VERSION,issued_at='2026-10-19T00:00:00Z',expires_at='2026-10-19T01:00:00Z')
 (destination/'expected.json').write_bytes(permit.canonical({'now':'2026-10-19T00:30:00Z','payload':payload,'testOnly':True,'releaseKeyRead':False,'privateKeyFileCreated':False}))
 return destination

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(generate(a.output.resolve()))
