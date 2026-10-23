"""Owned local filesystem negatives; subprocess timeout bounds every native call.
The optional hook interposes reads only inside the explicitly named fixture.
"""
import argparse,json,os,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--probe',required=True);p.add_argument('--hook',required=True);a=p.parse_args()
good=json.dumps({'policy':{'revision':7,'contentSha256':'sha256:'+'a'*64}})
count=0
for mode in ['missing-directory','missing-file','regular','symlink','parent-symlink','hardlink','fifo','directory','large','exact-limit','over-limit','replace','mutate','parent']:
 with tempfile.TemporaryDirectory(prefix='awg-policy-fs-native-') as temporary:
  root=Path(temporary);source=root/'source';source.mkdir();rules=source/'rules.json';directory=source;env=dict(os.environ)
  if mode=='missing-directory':directory=root/'absent'
  elif mode=='missing-file':pass
  elif mode=='symlink':outside=root/'outside';outside.write_text(good);rules.symlink_to(outside)
  elif mode=='hardlink':outside=root/'outside';outside.write_text(good);os.link(outside,rules)
  elif mode=='fifo':os.mkfifo(rules)
  elif mode=='directory':rules.mkdir()
  else:
   raw=good
   if mode=='large':raw=' '*(2*1024*1024)+good
   elif mode=='exact-limit':raw+=' '*(1024*1024-len(raw))
   elif mode=='over-limit':raw+=' '*(1024*1024+1-len(raw))
   rules.write_text(raw)
   if mode=='parent-symlink':directory=root/'alias';directory.symlink_to(source,target_is_directory=True)
   if mode in ['replace','mutate','parent']:
    (source/'replacement').write_text(good)
    env.update(LD_PRELOAD=a.hook,POLICY_TEST_DIRECTORY=str(source),POLICY_TEST_ACTION=mode)
  r=subprocess.run([a.probe,str(directory)],env=env,capture_output=True,text=True,timeout=2)
  if mode=='missing-directory':assert r.returncode==0 and r.stdout.strip()=='absent',(mode,r.stdout,r.stderr)
  elif mode in ['regular','exact-limit']:assert r.returncode==0 and r.stdout.strip()=='epoch',(mode,r.stdout,r.stderr)
  elif mode=='missing-file':assert r.returncode==3 and r.stdout.strip()=='managed_client_policy_not_ready',(mode,r.stdout)
  else:assert r.returncode==3 and r.stdout.strip()=='policy_source_untrusted',(mode,r.returncode,r.stdout,r.stderr)
  count+=1
print(f'native pinned policy filesystem: {count} owned fixtures passed')
