"""Truthful legacy-eight archive with authenticated CLI capability marker."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('cli_bundle_manifest',ROOT/'deploy/selfhosted_updates/make_manifest.py')
manifest=importlib.util.module_from_spec(spec);spec.loader.exec_module(manifest)
spec=importlib.util.spec_from_file_location('legacy_bundle_fixture',Path(__file__).with_name('test_native_helper_bundle.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
SOURCE=(Path(__file__).with_name('install_headless.sh')).read_text()

class CliNativeBundleTests(unittest.TestCase):
 def setUp(self):
  self.base=fixture.NativeHelperBundleTests();self.base.setUp();self.addCleanup(self.base.doCleanups)
  self.root=Path(self.base.temporary.name);self.package=dict(self.base.package)
  self.bundle=self.root/'package';self.bundle.mkdir();self.archive=self.root/'fixture.tar.gz'
 def write(self,helper='amnezia-cli',*,cli_mode=0o755,extra=False):
  if helper is not None:self.package['nativeHelper']=helper
  else:self.package.pop('nativeHelper',None)
  names=list(manifest.HEADLESS_PROVISIONING_FILES)
  if helper=='amnezia-headless-fs' or extra:names.append('amnezia-headless-fs')
  for name in names:
   if name not in {'SHA256SUMS','package-manifest.json'}:(self.bundle/name).write_bytes((name+' fixture\n').encode())
  (self.bundle/'package-manifest.json').write_text(json.dumps(self.package))
  self.checksums(names)
  with tarfile.open(self.archive,'w:gz') as t:
   for name in names:
    b=(self.bundle/name).read_bytes();m=tarfile.TarInfo('headless-package/'+name);m.size=len(b)
    m.mode=cli_mode if name=='amnezia-cli' else 0o755 if name=='amnezia-headless-fs' else 0o644;t.addfile(m,io.BytesIO(b))
  return names
 def checksums(self,names):
  (self.bundle/'SHA256SUMS').write_text(''.join(hashlib.sha256((self.bundle/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names if n!='SHA256SUMS'))
 def receipt_program(self):
  return SOURCE.split('if ! python3 - "$VERIFIED_RECEIPT" "$PACKAGE_ROOT"',1)[1].split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
 def receipt(self,*,duplicate=False,omit=False,tamper=False):
  names=list(manifest.HEADLESS_NATIVE_PROVISIONING_FILES if self.package.get('nativeHelper')=='amnezia-headless-fs' else manifest.HEADLESS_PROVISIONING_FILES)
  sha=self.bundle/'SHA256SUMS';lines=sha.read_text().splitlines();helper=self.package.get('nativeHelper')
  if duplicate:lines += [next(x for x in lines if x.endswith('  '+helper))]
  if omit:lines=[x for x in lines if not x.endswith('  '+helper)]
  sha.write_text('\n'.join(lines)+'\n')
  if tamper:(self.bundle/helper).write_bytes(b'changed after authenticated checksums')
  key=self.root/'public.pem';key.write_bytes(b'public key fixture')
  digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
  v=dict(schema=1,tool='amnezia-verify-provisioning-v1',verified=True,manifestSha256='a'*64,publicKeySha256=digest(key),archiveSha256='b'*64,archiveSize=1,version='9.9.9.9',packageVersion='9.9.9.9',packageFiles=names,packageManifestSha256=digest(self.bundle/'package-manifest.json'),checksumsSha256=digest(sha))
  rec=self.root/'receipt.json';rec.write_text(json.dumps(v))
  return subprocess.run(['python3','-c',self.receipt_program(),str(rec),str(self.bundle),str(key),v['publicKeySha256'],v['packageManifestSha256'],v['checksumsSha256'],v['manifestSha256']],capture_output=True,text=True)
 def test_truthful_new_cli_eight_and_legacy_eight_and_nine(self):
  for marker,count in [('amnezia-cli',8),(None,8),('amnezia-headless-fs',9)]:
   with self.subTest(marker=marker):
    self.write(marker);self.assertEqual(len(manifest.inspect_headless_provisioning(self.archive)['files']),count)
    r=self.receipt();self.assertEqual(r.returncode,0,r.stderr)
 def test_cli_native_checksum_missing_duplicate_changed_rejected(self):
  for option in ('duplicate','omit','tamper'):
   with self.subTest(option=option):
    self.write();r=self.receipt(**{option:True});self.assertNotEqual(r.returncode,0)
    self.assertIn('native helper',r.stderr)
 def test_cli_capability_unknown_or_ninth_file_rejected(self):
  self.write('foreign')
  with self.assertRaises(SystemExit):manifest.inspect_headless_provisioning(self.archive)
  self.write(extra=True)
  with self.assertRaisesRegex(SystemExit,'unexpected file set'):manifest.inspect_headless_provisioning(self.archive)
 def test_cli_native_mode_must_be_plain_executable(self):
  for mode in (0o644,0o777,0o4755):
   self.write(cli_mode=mode)
   with self.assertRaisesRegex(SystemExit,'CLI must have mode'):manifest.inspect_headless_provisioning(self.archive)
 def test_signed_cli_native_bundle_verifies_as_truthful_eight(self):
  self.write();inner=manifest.inspect_headless_provisioning(self.archive)
  private=self.root/'test-private.pem';public=self.root/'test-public.pem';openssl=manifest.openssl_command()
  subprocess.run([openssl,'genpkey','-algorithm','ED25519','-out',str(private)],check=True,capture_output=True)
  subprocess.run([openssl,'pkey','-in',str(private),'-pubout','-out',str(public)],check=True,capture_output=True)
  metadata=dict(url='files/artifacts/fixture/package.tar.gz',format=manifest.HEADLESS_PROVISIONING_FORMAT,sha256=manifest.sha256(self.archive),size=self.archive.stat().st_size,version='9.9.9.9',packageVersion='9.9.9.9',packageFiles=inner['files'],packageManifestSha256=inner['packageManifestSha256'],checksumsSha256=inner['checksumsSha256'])
  payload=dict(version='9.9.9.9',platforms={'linux-headless-x64':dict(sha256='a'*64,size=1,format=manifest.HEADLESS_ARTIFACT_FORMAT)},headlessProvisioning=metadata)
  raw=json.dumps(payload,separators=(',',':')).encode();signed=self.root/'signed.json'
  signed.write_text(json.dumps(dict(schema='amnezia-selfhosted-update-v1',signatureAlgorithm='Ed25519',payload=manifest.b64url(raw),signature=manifest.sign_payload(private,raw))))
  spec=importlib.util.spec_from_file_location('cli_signed_verifier',Path(__file__).with_name('verify_provisioning_bundle.py'))
  verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
  receipt=verifier.verify_manifest_and_bundle(signed,public,self.archive,manifest.sha256(public))
  self.assertIs(receipt['verified'],True);self.assertEqual(receipt['packageFiles'],list(manifest.HEADLESS_PROVISIONING_FILES))
 def test_cli_marker_activation_after_both_runtime_checks(self):
  old=SOURCE.index('NATIVE_HELPER="$PACKAGE_ROOT/amnezia-headless-fs"')
  new=SOURCE.index('NATIVE_HELPER="$PACKAGE_ROOT/amnezia-cli"')
  self.assertGreater(old,SOURCE.index('native helper does not match authenticated checksums'))
  self.assertGreater(new,SOURCE.index('if ! version_output='));self.assertGreater(new,SOURCE.index('done\n',SOURCE.index('for binary in amneziad amnezia-cli; do')))
  self.assertLess(SOURCE.index('if [[ "$RECOVER_ONLY" -eq 1 ]]'),new)
  self.assertIn('NATIVE_HELPER_ARGS=(--provisioning-fs)',SOURCE)
 def test_reused_old_stage_does_not_leak_ninth_file(self):
  # Execute the actual stage-creation and final tar statements, without build.
  build=Path(__file__).with_name('build_headless_release.sh').read_text()
  create=next(line for line in build.splitlines() if line.startswith('STAGE_DIR='))
  create+='\nPACKAGE_DIR="$STAGE_DIR/headless-package"\nmkdir -p "$PACKAGE_DIR"\n'
  old=self.root/'stage/headless-package';old.mkdir(parents=True);(old/'amnezia-headless-fs').write_text('old helper')
  command='set -eu\nTMPDIR="$1"\n'+create+'\nprintf "%s" "$PACKAGE_DIR"'
  r=subprocess.run(['bash','-c',command,'fixture',str(old.parent)],capture_output=True,text=True,check=True)
  fresh=Path(r.stdout);self.assertNotEqual(fresh,old);self.assertEqual(list(fresh.iterdir()),[])
  self.assertIn('--directory "$STAGE_DIR"',build)

if __name__=='__main__':unittest.main(verbosity=2)
