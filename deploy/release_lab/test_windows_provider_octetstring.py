"""CIM OctetString provider preservation and root-review boundary tests; no VM."""
from pathlib import Path
import copy,hashlib,json,struct,unittest
from . import windows_consent_visual as v
from . import test_windows_consent_visual as base_tests
class ProviderTests(unittest.TestCase):
 setUp=base_tests.ConsentPixelsTests.setUp
 request=base_tests.ConsentPixelsTests.request
 accepted=base_tests.ConsentPixelsTests.accepted
 def framed(self):
  framed=struct.pack('>I',len(self.raw)+4)+self.raw
  name='consent-provider-'+'d'*32+'-'+'e'*32+'.octets'
  self.provider=self.root/name;self.provider.write_bytes(framed)
  self.obs['console_capture'].update(provider_raw_file_name=name,provider_raw_sha256=hashlib.sha256(framed).hexdigest(),provider_raw_size=len(framed),provider_encoding='cim-octet-string-rgb565le',provider_payload_offset=4,provider_octet_string_qualifier=True)
  return framed
 def test_strict_framing_rejects_malformed_alternates(self):
  raw=self.framed(); expected=len(raw)
  bad=[b'',raw[:-1],raw+b'x',struct.pack('<I',expected)+raw[4:],struct.pack('>I',expected-4)+raw[4:],struct.pack('>I',expected+1)+raw[4:],raw+raw,b'head'+raw[4:]]
  for candidate in bad:
   with self.subTest(size=len(candidate)),self.assertRaises(v.ConsentVisualError):v.provider_payload(candidate,640,480,'cim-octet-string-rgb565le',4,True)
 def test_framed_and_plain_decode_exactly_and_wrong_metadata_refused(self):
  framed=self.framed();self.assertEqual(v.provider_payload(framed,640,480,'cim-octet-string-rgb565le',4,True),self.raw)
  self.assertEqual(v.provider_payload(self.raw,640,480,'raw-rgb565le',0,True),self.raw)
  for w,h,enc,offset,qual in [(640,480,'unknown',4,True),(640,480,'cim-octet-string-rgb565le',0,True),(640,480,'cim-octet-string-rgb565le',True,True),(640,480,'cim-octet-string-rgb565le',4,False),(640,480,'cim-octet-string-rgb565le',4,1),(True,480,'cim-octet-string-rgb565le',4,True),(640,481,'cim-octet-string-rgb565le',4,True)]:
   with self.subTest(enc=enc,offset=offset,qual=qual),self.assertRaises(v.ConsentVisualError):v.provider_payload(framed,w,h,enc,offset,qual)
 def test_original_archived_and_survives_guest_source_removal(self):
  framed=self.framed();r,a=self.accepted();record=r['provider_capture']['original_archive'];self.assertEqual(Path(record['path']).read_bytes(),framed)
  self.provider.unlink();self.source.unlink();v.validate_ack(owned_root=self.root,request=r,ack=a)
  t=v.utc_text();v.validate_completed(owned_root=self.root,proof={'request':r,'ack':a},observe=self.obs,confirmed_consent=self.proof,confirmed_at=t,completed_at=t)
 def test_modified_original_rejected_before_request(self):
  self.framed();self.provider.write_bytes(b'changed')
  with self.assertRaises(v.ConsentVisualError):self.request()
 def test_modified_archived_original_rejected_after_ack(self):
  self.framed();r,a=self.accepted();Path(r['provider_capture']['original_archive']['path']).write_bytes(b'changed')
  with self.assertRaises(RuntimeError):v.validate_ack(owned_root=self.root,request=r,ack=a)
 def test_provider_claim_without_original_or_partial_fields_refused(self):
  self.framed();self.provider.unlink()
  with self.assertRaises(v.ConsentVisualError):self.request()
  del self.obs['console_capture']['provider_payload_offset']
  with self.assertRaises(v.ConsentVisualError):self.request()
 def test_metadata_mutations_rejected_and_not_ignored_on_completed(self):
  self.framed();r,a=self.accepted();t=v.utc_text()
  for key,value in [('provider_raw_sha256','f'*64),('provider_raw_size',4),('provider_encoding','raw-rgb565le'),('provider_payload_offset',0),('provider_octet_string_qualifier',False)]:
   bad=copy.deepcopy(self.obs);bad['console_capture'][key]=value
   with self.subTest(key=key),self.assertRaises(v.ConsentVisualError):v.validate_completed(owned_root=self.root,proof={'request':r,'ack':a},observe=bad,confirmed_consent=self.proof,confirmed_at=t,completed_at=t)
 def test_removed_provider_archive_not_accepted_with_matching_observation(self):
  self.framed();r=self.request();r.pop('provider_capture')
  # Even if a caller obtains a newly signed local review for a modified request,
  # completion must reject dropping the actual provider observation.
  a=v.create_ack(owned_root=self.root,request=r,viewed_png_sha256=r['png_archive']['sha256']);t=v.utc_text()
  with self.assertRaises(v.ConsentVisualError):v.validate_completed(owned_root=self.root,proof={'request':r,'ack':a},observe=self.obs,confirmed_consent=self.proof,confirmed_at=t,completed_at=t)
 def test_fresh_capture_dropping_all_provider_metadata_rejected(self):
  self.framed()
  for name in list(self.obs['console_capture']):
   if name.startswith('provider_'):del self.obs['console_capture'][name]
  with self.assertRaises(v.ConsentVisualError):self.request()
 def test_malformed_provider_objects_rejected_clearly(self):
  self.framed();r=self.request()
  for capture in (None,[],{'metadata':None,'original_archive':{}}):
   bad=copy.deepcopy(r);bad['provider_capture']=capture
   with self.assertRaises(v.ConsentVisualError):v.validate_request(self.root,bad)
 def test_symlink_original_rejected(self):
  self.framed();target=self.root/'other.octets';self.provider.rename(target)
  try:self.provider.symlink_to(target)
  except OSError:self.skipTest('symlink privilege unavailable')
  with self.assertRaises(v.ConsentVisualError):self.request()
if __name__=='__main__':unittest.main()
