"""Inert console/consent/root-review trust boundary regressions. No VM access."""
from pathlib import Path
import copy,hashlib,json,struct,tempfile,time,unittest,zlib
from datetime import timedelta
from unittest.mock import Mock,patch
from . import windows_consent_visual as v
from . import lab
from .windows_evidence_archive import archive_exact_file

class ConsentPixelsTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.raw=(struct.pack('<HHHH',0xf800,0x07e0,0x001f,0xffff)*(640*480//4))
  self.source=self.root/'console.rgb565';self.source.write_bytes(self.raw)
  self.t0=v.utc_text();self.proof={'run_id':'owned-run','case_id':'outer-interactive','vm_id':'owned-vm','expected_consent':True,'process_id':144,'creation_time':'consent-start','session_id':1,'owner_sid':'S-1-5-18','consent_path':r'C:\Windows\System32\consent.exe','launcher_pid':142,'launcher_start_time':'launcher-start','launcher_session_id':1,'launcher_sid':'S-1-5-21-1000'}
  self.obs={'action':'ui-observe','injected':False,'origin':'guest','transport':'hyperv-powershell-direct','vm_id':'owned-vm','parent_sha256':'b'*64,'consent':copy.deepcopy(self.proof),'console_capture':{'method':v.METHOD,'format':'rgb565le','vm_id':'owned-vm','settings_vm_id':'owned-vm','settings_virtual_system_type':'Microsoft:Hyper-V:System:Realized','artifact_sha256':'a'*64,'width':640,'height':480,'sha256':hashlib.sha256(self.raw).hexdigest(),'size':len(self.raw),'started_at':self.t0,'completed_at':self.t0,'consent_after':copy.deepcopy(self.proof)}}
  provider_name='consent-provider-'+'d'*32+'-'+'e'*32+'.octets'
  (self.root/provider_name).write_bytes(self.raw)
  self.obs['console_capture'].update(provider_raw_file_name=provider_name,provider_raw_sha256=hashlib.sha256(self.raw).hexdigest(),provider_raw_size=len(self.raw),provider_encoding='raw-rgb565le',provider_payload_offset=0,provider_octet_string_qualifier=True)
 def request(self):return v.prepare_request(owned_root=self.root,run_id='owned-run',version='5.0.3.16',manifest_sha256='c'*64,artifact_sha256='a'*64,parent_sha256='b'*64,observe=self.obs,raw_source=self.source,attempt_nonce='d'*32)
 def accepted(self):
  r=self.request();a=v.create_ack(owned_root=self.root,request=r,viewed_png_sha256=r['png_archive']['sha256']);return r,a
 def test_exact_rgb565_colors_rows_and_dimensions(self):
  p=v.rgb565_png(self.raw,640,480);self.assertEqual(struct.unpack('>II',p[16:24]),(640,480))
  data=b'';at=8
  while at<len(p):
   n=struct.unpack('>I',p[at:at+4])[0];kind=p[at+4:at+8]
   if kind==b'IDAT':data+=p[at+8:at+8+n]
   at+=n+12
  rows=zlib.decompress(data);self.assertEqual(rows[:13],bytes([0,255,0,0,0,255,0,0,0,255,255,255,255]));self.assertEqual(len(rows),480*(640*3+1))
 def test_raw_truncation_extra_header_and_bad_dimensions_rejected(self):
  for raw,w,h in ((self.raw[:-1],640,480),(b'head'+self.raw,640,480),(self.raw,0,480),(self.raw,640,True),(self.raw,640,10000)):
   with self.subTest(w=w,h=h,length=len(raw)),self.assertRaises(v.ConsentVisualError):v.rgb565_png(raw,w,h)
 def test_observed_same_consent_and_actual_console_required(self):
  for mutate in (lambda o:o.pop('console_capture'),lambda o:o['console_capture'].__setitem__('method','CopyFromScreen'),lambda o:o['console_capture'].__setitem__('settings_virtual_system_type','Microsoft:Hyper-V:Snapshot:Realized'),lambda o:o['console_capture'].__setitem__('settings_vm_id','foreign'),lambda o:o['console_capture'].__setitem__('vm_id','foreign'),lambda o:o['console_capture'].__setitem__('artifact_sha256','e'*64),lambda o:o['console_capture']['consent_after'].__setitem__('process_id',145),lambda o:o['consent'].__setitem__('owner_sid','S-1-5-21'),lambda o:o['consent'].__setitem__('expected_consent',False)):
   original=copy.deepcopy(self.obs);mutate(self.obs)
   with self.assertRaises(v.ConsentVisualError):self.request()
   self.obs=original
 def test_future_stale_and_swapped_capture_times_rejected(self):
  for k,value in (('started_at',(v.now()-timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')),('started_at',(v.now()+timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')),('completed_at','2000-01-01T00:00:00Z')):
   original=copy.deepcopy(self.obs);self.obs['console_capture'][k]=value
   with self.assertRaises(v.ConsentVisualError):self.request()
   self.obs=original
 def test_raw_hash_or_size_change_never_creates_review(self):
  self.source.write_bytes(b'changed')
  with self.assertRaises(v.ConsentVisualError):self.request()
  self.assertFalse((self.root/'exports').exists())
 def test_request_archives_before_ack_and_never_auto_accepts(self):
  r=self.request();self.assertTrue(Path(r['png_archive']['path']).is_file());self.assertTrue(Path(r['raw_archive']['path']).is_file())
  self.assertFalse(r['visual_review_passed']);self.assertFalse((Path(r['png_archive']['path']).parent/'root-consent-visual-ack.json').exists())
 def test_exact_root_ack_and_completed_proof_accepted(self):
  r,a=self.accepted();confirmed=v.utc_text()
  self.assertEqual(v.validate_completed(owned_root=self.root,proof={'request':r,'ack':a},observe=self.obs,confirmed_consent=self.proof,confirmed_at=confirmed,completed_at=confirmed)['ack'],a)
 def test_wrong_viewed_png_rejected_and_no_ack_written(self):
  r=self.request()
  with self.assertRaises(v.ConsentVisualError):v.create_ack(owned_root=self.root,request=r,viewed_png_sha256='e'*64)
  self.assertFalse((Path(r['png_archive']['path']).parent/'root-consent-visual-ack.json').exists())
 def test_ack_is_exclusive_and_bound_to_every_context_field(self):
  r,a=self.accepted()
  with self.assertRaises(FileExistsError):v.create_ack(owned_root=self.root,request=r,viewed_png_sha256=r['png_archive']['sha256'])
  for field in ('run_id','vm_id','attempt_nonce','manifest_sha256','artifact_sha256','png_sha256','request_sha256','reviewer_role'):
   bad=copy.deepcopy(a);bad[field]='foreign'
   with self.subTest(field=field),self.assertRaises(v.ConsentVisualError):v.validate_ack(owned_root=self.root,request=r,ack=bad)
 def test_ack_before_capture_and_after_two_minutes_rejected(self):
  r,a=self.accepted()
  for t in (v.utc(r['captured_at'])-timedelta(seconds=1),v.utc(r['captured_at'])+timedelta(seconds=121)):
   bad=copy.deepcopy(a);bad['reviewed_at']=t.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
   with self.assertRaises(v.ConsentVisualError):v.validate_ack(owned_root=self.root,request=r,ack=bad)
 def test_changed_png_after_review_rejected(self):
  r,a=self.accepted();Path(r['png_archive']['path']).write_bytes(b'new pixels')
  with self.assertRaises(RuntimeError):v.validate_ack(owned_root=self.root,request=r,ack=a)
 def test_symlink_and_foreign_paths_rejected(self):
  r,a=self.accepted();r['png_archive']['path']=str(self.root.parent/'foreign.png')
  with self.assertRaises(RuntimeError):v.validate_ack(owned_root=self.root,request=r,ack=a)
 def test_replaced_consent_after_ack_or_completion_before_review_rejected(self):
  r,a=self.accepted();bad=copy.deepcopy(self.proof);bad['process_id']=146
  for proof,confirmed_at,completed_at in ((bad,v.utc_text(),v.utc_text()),(self.proof,'2000-01-01T00:00:00Z',v.utc_text()),(self.proof,v.utc_text(),'2000-01-01T00:00:00Z')):
   with self.assertRaises(v.ConsentVisualError):v.validate_completed(owned_root=self.root,proof={'request':r,'ack':a},observe=self.obs,confirmed_consent=proof,confirmed_at=confirmed_at,completed_at=completed_at)
 def test_wait_refuses_missing_ack_no_implicit_pass(self):
  r=self.request()
  with patch.object(v.time,'monotonic',side_effect=[0,2]),self.assertRaisesRegex(v.ConsentVisualError,'did not review'):v.wait_for_review(owned_root=self.root,request=r,timeout_seconds=1)
 def test_old_weak_desktop_receipt_is_not_accepted(self):
  png=self.root/'desktop.png';png.write_bytes(b'\x89PNG\r\n\x1a\n'+b'not-consent'*200)
  args={'owned_root':self.root,'source':png,'archive_dir':self.root/'exports/weak','expected_sha256':hashlib.sha256(png.read_bytes()).hexdigest(),'expected_size':png.stat().st_size,'vm_id':'owned-vm','case_id':'outer-interactive','attempt_nonce':'d'*32}
  ui=archive_exact_file(**args,kind='uac');app=archive_exact_file(**args,kind='app-window')
  receipt={'run_id':'owned-run','archive_attempt_nonce':'d'*32,'installed_app_window':{'vm_id':'owned-vm','screenshot':{'archive':app}},'hyperv_ui':{'screenshot_archive':ui}}
  with self.assertRaises(RuntimeError):lab.validate_hyperv_interactive_archives(self.root,receipt)
 def test_new_full_archive_validator_requires_reviewed_console(self):
  r,a=self.accepted();png=Path(r['png_archive']['path']);desktop=archive_exact_file(self.root,png,self.root/'exports/desktop',expected_sha256=r['png_archive']['sha256'],expected_size=png.stat().st_size,kind='installer-desktop',vm_id='owned-vm',case_id='outer-interactive',attempt_nonce='d'*32)
  app=archive_exact_file(self.root,png,self.root/'exports/app',expected_sha256=r['png_archive']['sha256'],expected_size=png.stat().st_size,kind='app-window',vm_id='owned-vm',case_id='outer-interactive',attempt_nonce='d'*32)
  t=v.utc_text();receipt={'run_id':'owned-run','archive_attempt_nonce':'d'*32,'installed_app_window':{'vm_id':'owned-vm','screenshot':{'archive':app}},'hyperv_ui':{'screenshot_archive':desktop,'observe':self.obs,'confirm':{'consent':self.proof,'confirmed_at':t},'installer_completion':{'completed_at':t},'consent_visual':{'request':r,'ack':a}}}
  lab.validate_hyperv_interactive_archives(self.root,receipt)
  for field in ('consent_visual','observe','confirm'):
   bad=copy.deepcopy(receipt);bad['hyperv_ui'].pop(field)
   with self.assertRaises(RuntimeError):lab.validate_hyperv_interactive_archives(self.root,bad)
 def test_powershell_roundtrip_seven_fractional_digits_supported(self):self.assertEqual(v.utc('2026-10-27T22:00:00.1234567Z').microsecond,123456)
 def test_confirmation_callable_unreachable_when_root_has_not_reviewed_pixels(self):
  r=self.request();confirm=Mock()
  with patch.object(v,'wait_for_review',side_effect=v.ConsentVisualError('not reviewed')):
   with self.assertRaises(v.ConsentVisualError):v.confirm_after_review(owned_root=self.root,request=r,confirm=confirm)
  confirm.assert_not_called()
 def test_confirmation_callable_runs_only_after_review_and_retains_identity(self):
  r,a=self.accepted();events=[]
  def reviewed(**kw):events.append('root-reviewed');return a
  def confirm():events.append('confirm');return {'action':'ui-confirm','consent':self.proof,'confirmed_at':v.utc_text()}
  with patch.object(v,'wait_for_review',side_effect=reviewed):ack,result=v.confirm_after_review(owned_root=self.root,request=r,confirm=confirm)
  self.assertEqual(events,['root-reviewed','confirm']);self.assertEqual(ack,a);self.assertEqual(result['consent'],self.proof)
 def test_ack_publication_never_exposes_empty_or_partial_destination(self):
  r=self.request();original=v.os.link;seen=[]
  def atomic(source,target):
   self.assertFalse(Path(target).exists());data=Path(source).read_bytes();self.assertTrue(data.endswith(b'\n'));self.assertEqual(json.loads(data)['schema'],v.ACK_SCHEMA);seen.append(True);return original(source,target)
  with patch.object(v.os,'link',side_effect=atomic):a=v.create_ack(owned_root=self.root,request=r,viewed_png_sha256=r['png_archive']['sha256'])
  self.assertEqual(seen,[True]);self.assertEqual(v.validate_ack(owned_root=self.root,request=r,ack=a),a)

if __name__=='__main__':unittest.main()
