from __future__ import annotations
import base64,copy,json,tempfile,unittest
from pathlib import Path
from datetime import datetime,timedelta,timezone
from unittest import mock
try:
 from . import owner_publication_permit as permit
except ImportError:
 import owner_publication_permit as permit

class OwnerPermitTests(unittest.TestCase):
 def payload(self):
  now=datetime.now(timezone.utc).replace(microsecond=0)
  return dict(schema=1,policyId=permit.POLICY,version=permit.VERSION,androidVersionCode=2199,manifestSha256='1'*64,publisherSha256='2'*64,artifacts=[dict(path=f'files/artifacts/{i}/item',sha256=str(i)*64,size=10) for i in range(5)],issuedAt=(now-timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),expiresAt=(now+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),acceptanceStatus='owner-approved-unverified',unverifiedTargets=list(permit.TARGETS),invocation='normal')
 def envelope(self,p=None,domain=None):
  raw=(domain or permit.DOMAIN)+permit.canonical(p or self.payload())
  return permit.canonical(dict(schema=permit.SCHEMA,signatureAlgorithm='Ed25519',payload=permit.manifest.b64url(raw),signature=base64.b64encode(b'x'*64).decode()))
 def test_exact_policy_roundtrip_injected_verifier(self):
  p=self.payload()
  with mock.patch.object(permit,'verify_signature') as verify:self.assertEqual(permit.decode_permit(self.envelope(p),Path('public')),p)
  verify.assert_called_once()
 def test_wrong_constants_missing_unknown_pass_fields(self):
  mutations=[lambda p:p.update(version='5.0.3.12'),lambda p:p.update(androidVersionCode=2198),lambda p:p.update(androidVersionCode=True),lambda p:p.update(schema=True),lambda p:p.update(policyId='amnezia-release-full-v1'),lambda p:p.update(acceptanceStatus='PASS'),lambda p:p.update(invocation='automatic'),lambda p:p.update(invocation='manual'),lambda p:p.update(acceptanceStatus='manual-approved-unverified'),lambda p:p.update(receipts=[]),lambda p:p.update(unverifiedTargets=[]),lambda p:p.update(unverifiedTargets=list(reversed(permit.TARGETS))),lambda p:p.pop('invocation')]
  for mutate in mutations:
   p=self.payload();mutate(p)
   with self.assertRaises(SystemExit):permit.validate_payload(p)
 def test_lifetime_canonical_expired_future_long(self):
  now=datetime.now(timezone.utc).replace(microsecond=0)
  for issued,expires in [(now+timedelta(seconds=1),now+timedelta(hours=1)),(now-timedelta(hours=2),now-timedelta(hours=1)),(now-timedelta(seconds=1),now+timedelta(hours=25))]:
   p=self.payload();p.update(issuedAt=issued.strftime('%Y-%m-%dT%H:%M:%SZ'),expiresAt=expires.strftime('%Y-%m-%dT%H:%M:%SZ'))
   with self.assertRaises(SystemExit):permit.validate_payload(p,now=now)
  for v in ('2026-01-01T01:00:00+00:00','2026-02-30T00:00:00Z','2026-01-01T00:00:00.000Z'):
   with self.assertRaises(SystemExit):permit.timestamp(v)
 def test_exact_hash_and_closure_binding(self):
  p=self.payload()
  for kw in ({'manifest_sha256':'f'*64},{'publisher_sha256':'f'*64},{'artifacts':p['artifacts'][:-1]}):
   with self.assertRaises(SystemExit):permit.validate_payload(p,**kw)
 def test_path_count_size_order_hash_unsafe_chars(self):
  changes=[lambda a:a.pop(),lambda a:a.append(a[0]),lambda a:a[0].update(path='files/../escape'),lambda a:a[0].update(path='files/a\\b'),lambda a:a[0].update(size=True),lambda a:a[0].update(size=0),lambda a:a[0].update(sha256='A'*64),lambda a:a.reverse(),lambda a:a[0].update(extra='PASS')]
  for change in changes:
   a=copy.deepcopy(self.payload()['artifacts']);change(a)
   with self.assertRaises(SystemExit):permit.artifact_records(a)
  for char in (':','?','#','\x00','\x1f','\x7f','\u00e9'):
   a=copy.deepcopy(self.payload()['artifacts']);a[0]['path']='files/bad'+char+'item'
   with self.assertRaises(SystemExit):permit.artifact_records(a)
 def test_json_duplicate_nonfinite_domain_envelope(self):
  for raw in (b'{"a":1,"a":2}',b'{"size":NaN}'):
   with self.assertRaises(SystemExit):permit.strict_json(raw)
  with mock.patch.object(permit,'verify_signature') as verify,self.assertRaises(SystemExit):permit.decode_permit(self.envelope(domain=b'amnezia-release-acceptance-v1\n'),Path('public'))
  verify.assert_not_called()
  with mock.patch.object(permit,'verify_signature') as verify,self.assertRaises(SystemExit):permit.decode_permit(self.envelope(domain=b'amnezia-manual-publication-permit-v1\n'),Path('public'))
  verify.assert_not_called()
  for change in (lambda e:e.update(extra=True),lambda e:e.update(schema=permit.manifest.RELEASE_ACCEPTANCE_SCHEMA),lambda e:e.update(payload=e['payload']+'='),lambda e:e.update(signature='bad')):
   e=json.loads(self.envelope());change(e)
   with self.assertRaises(SystemExit):permit.decode_permit(permit.canonical(e),Path('public'))
 def test_canonical_envelope_payload(self):
  canonical=self.envelope()
  for data in (canonical+b'\n',json.dumps(json.loads(canonical),indent=2).encode()):
   with self.assertRaises(SystemExit):permit.decode_permit(data,Path('public'))
  p=self.payload();raw=permit.DOMAIN+json.dumps(p,indent=2).encode();e=json.loads(canonical);e['payload']=permit.manifest.b64url(raw)
  with self.assertRaises(SystemExit):permit.decode_permit(permit.canonical(e),Path('public'))
 def test_runtime128k_limit_before_crypto(self):
  with mock.patch.object(permit,'verify_signature') as verify,self.assertRaises(SystemExit):permit.decode_permit(b' '* (permit.MAX_PERMIT_BYTES+1),Path('public'))
  verify.assert_not_called()
 def test_regular_file_symlink(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);p=root/'input';p.write_bytes(b'content');self.assertEqual(permit.regular_digest(p)[1],7)
   with self.assertRaises(SystemExit):permit.regular_digest(root)
   try:(root/'link').symlink_to(p)
   except OSError:return
   with self.assertRaises(SystemExit):permit.regular_digest(root/'link')
 def write_manifest(self,root,doc):
  (root/'manifest.json').write_bytes(permit.canonical(dict(schema='amnezia-selfhosted-update-v1',signatureAlgorithm='Ed25519',payload=permit.manifest.b64url(permit.canonical(doc)),signature=base64.b64encode(b'x'*64).decode())))
 def bundle(self,root):
  doc=dict(schema=1,version=permit.VERSION,platforms={},headlessProvisioning=None)
  for i,name in enumerate(sorted(permit.PLATFORMS)+['headlessProvisioning']):
   p=root/'files'/str(i)/'artifact';p.parent.mkdir(parents=True);p.write_bytes(('artifact'+str(i)).encode());digest,size=permit.regular_digest(p);item=dict(url=p.relative_to(root).as_posix(),sha256=digest,size=size)
   if name=='android-arm64-v8a':item['versionCode']=2199
   if name=='headlessProvisioning':doc[name]=item
   else:doc['platforms'][name]=item
  self.write_manifest(root,doc);publisher=root/'publisher.sh';publisher.write_bytes(b'publisher');return doc,publisher
 def test_five_files_actual_binding_mutation_extra(self):
  for mode in ('valid','mutation','extra'):
   with tempfile.TemporaryDirectory() as tmp,mock.patch.object(permit,'verify_signature'):
    root=Path(tmp);doc,publisher=self.bundle(root)
    if mode=='valid':self.assertEqual(len(permit.bundle_bindings(root,publisher,Path('pub'))['artifacts']),5)
    else:
     (root/('files/0/artifact' if mode=='mutation' else 'files/extra')).write_bytes(b'changed')
     with self.assertRaises(SystemExit):permit.bundle_bindings(root,publisher,Path('pub'))
 def test_manifest_version_platform_remote_encoded_and_rollback(self):
  changes=[lambda d:d.update(version='5.0.3.14'),lambda d:d['platforms']['android-arm64-v8a'].update(versionCode=2200),lambda d:d['platforms'].pop('linux-headless-x64'),lambda d:d.update(rollback={'x':1}),lambda d:d['headlessProvisioning'].update(url='https://example.com/item')]
  changes += [lambda d,value=value:d['headlessProvisioning'].update(url='files/bad'+value+'item') for value in ('%23','%3F','%3A','%00')]
  for change in changes:
   with tempfile.TemporaryDirectory() as tmp,mock.patch.object(permit,'verify_signature'):
    root=Path(tmp);doc,publisher=self.bundle(root);change(doc);self.write_manifest(root,doc)
    with self.assertRaises(SystemExit):permit.bundle_bindings(root,publisher,Path('pub'))
 def issue_args(self,root,p):
  return dict(bundle=root,publisher=root/'publisher',public_key=root/'pub',private_key=root/'mock-only',output=root/'owner-publication-permit.json',acknowledge=permit.VERSION,issued_at=p['issuedAt'],expires_at=p['expiresAt'])
 def test_ack_time_mutation_reject_before_signer(self):
  for mode in ('ack','time','mutation','output','full'):
   with tempfile.TemporaryDirectory() as tmp,mock.patch.object(permit.manifest,'sign_payload') as sign:
    root=Path(tmp);p=self.payload();kw=self.issue_args(root,p);binding={k:p[k] for k in ('manifestSha256','publisherSha256','artifacts')}
    if mode=='ack':kw['acknowledge']=''
    if mode=='time':kw['issued_at']='invalid'
    if mode=='output':kw['output'].write_bytes(b'existing')
    if mode=='full':(root/'release-acceptance.json').write_bytes(b'existing')
    side=[binding,{**binding,'manifestSha256':'e'*64}] if mode=='mutation' else [binding]
    with mock.patch.object(permit,'bundle_bindings',side_effect=side),self.assertRaises(SystemExit):permit.issue_owner_permit(**kw)
    sign.assert_not_called()
 def test_mocked_issuer_exact_domain_no_lf_no_full_sidecar(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);p=self.payload();binding={k:p[k] for k in ('manifestSha256','publisherSha256','artifacts')};kw=self.issue_args(root,p)
   with mock.patch.object(permit,'bundle_bindings',return_value=binding),mock.patch.object(permit,'verify_signature'),mock.patch.object(permit.manifest,'sign_payload',return_value=base64.b64encode(b'x'*64).decode()) as sign:permit.issue_owner_permit(**kw)
   self.assertTrue(sign.call_args.args[1].startswith(permit.DOMAIN));self.assertFalse((root/'release-acceptance.json').exists());data=kw['output'].read_bytes();self.assertEqual(data,permit.canonical(json.loads(data)));self.assertFalse(data.endswith(b'\n'))
 def test_postsign_change_or_invalid_signature_never_writes(self):
  for mode in ('changed','signature'):
   with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);p=self.payload();binding={k:p[k] for k in ('manifestSha256','publisherSha256','artifacts')};kw=self.issue_args(root,p)
    with mock.patch.object(permit,'bundle_bindings',side_effect=[binding,binding,{**binding,'manifestSha256':'e'*64}]),mock.patch.object(permit,'verify_signature',side_effect=SystemExit('bad signature') if mode=='signature' else None),mock.patch.object(permit.manifest,'sign_payload',return_value=base64.b64encode(b'x'*64).decode()),self.assertRaises(SystemExit):permit.issue_owner_permit(**kw)
    self.assertFalse(kw['output'].exists())
 def test_cli_explicit_only_default_and_abbreviation_rejected(self):
  for argv in ([],['issue-acceptance'],['issue-owner-publication-permit'],['--auto'],['issue-owner-publication-permit','--acknowledge-unverified-rel','5.0.3.13']):
   with mock.patch.object(permit,'issue_owner_permit') as issue,mock.patch('sys.stderr'),self.assertRaises(SystemExit):permit.main(argv)
   issue.assert_not_called()
 def test_full_acceptance_still_unavailable(self):
  from deploy.release_lab.publication_acceptance import AcceptanceUnavailable,validate_publication_acceptance
  with self.assertRaises(AcceptanceUnavailable):validate_publication_acceptance(run_id='owner',state_root=Path('.'),manifest_path=Path('m'),outer_artifact=Path('o'),public_key_path=Path('p'))

if __name__=='__main__':unittest.main()
