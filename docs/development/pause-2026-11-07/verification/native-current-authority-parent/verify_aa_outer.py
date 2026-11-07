"""Prove AA's actual outer shell fails to preserve an owned work exit23."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

p=argparse.ArgumentParser();p.add_argument('--subject',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.geteuid()!=0
os.umask(0o077);a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs={str(path):sha(path) for path in [a.subject/'run_aa.sh',a.subject/'INPUT_SNAPSHOT.json',Path(__file__).resolve()]}
case=a.out/'subject';case.mkdir(mode=0o700)
for name in ['run_aa.sh','INPUT_SNAPSHOT.json']:shutil.copyfile(a.subject/name,case/name)
assert (case/'run_aa.sh').read_bytes()==(a.subject/'run_aa.sh').read_bytes()
private=a.out/'private-tmp';private.mkdir(mode=0o700)
bin_dir=a.out/'bin';bin_dir.mkdir(mode=0o700)
# Only CMake's compilation boundary is modeled. The real AA shell and its
# final Python writer run unchanged; the work body really exits23.
cmake=r'''#!/usr/bin/python3
import os,sys
from pathlib import Path
root=Path(os.environ['AA_PARENT_CASE']).resolve();args=sys.argv[1:]
build=root/'build'
if args==['-S',str(root),'-B',str(build),'-DCMAKE_BUILD_TYPE=Debug']:
 build.mkdir(mode=0o700,exist_ok=True)
 work=build/'aa_current_authority_tests'
 work.write_text('#!/usr/bin/python3\nprint("works=1 checks=1 failures=1 workFailures=1")\nraise SystemExit(23)\n')
 work.chmod(0o700)
elif args!=['--build',str(build),'-j2']:raise SystemExit('unexpected CMake boundary shape')
'''
(bin_dir/'cmake').write_text(cmake);(bin_dir/'cmake').chmod(0o700)
result=dict(componentPass=False,allFunctionsPass=False,releasePass=False,published=False,
 scope='Actual unmodified AA outer shell/final writer under an exact-shaped inert CMake adapter. Only owned harmless Python failing worker runs; no product, guest, root, network, service or installation.',startedUtc=datetime.now(timezone.utc).isoformat())
code=1
try:
    env=dict(PATH=str(bin_dir)+':/usr/bin:/bin',HOME=str(a.out),TMPDIR=str(private),LANG='C',LC_ALL='C',AA_PARENT_CASE=str(case))
    proc=subprocess.run(['/bin/bash','--noprofile','--norc',str(case/'run_aa.sh')],stdin=subprocess.DEVNULL,capture_output=True,env=env,timeout=30)
    (a.out/'actual-outer.stdout').write_bytes(proc.stdout);(a.out/'actual-outer.stderr').write_bytes(proc.stderr)
    observed=json.loads((case/'RESULT.json').read_text())
    result.update(actualOuterNativeExit=proc.returncode,actualResult=observed)
    assert observed['greenExit']==23 and observed['verdict']=='FAILED' and observed['workFailures']==1
    result['falseGreenReproduced']=proc.returncode==0
    assert proc.returncode!=0,'actual AA outer shell returned0 after real owned work23 and FAILED result'
    code=0;result['componentPass']=True
except Exception as error:result.update(exceptionType=type(error).__name__,exception=str(error))
finally:
    unchanged=all(sha(Path(path))==digest for path,digest in inputs.items())
    if not unchanged:code=1;result['componentPass']=False
    result.update(nativeExit=code,inputs=inputs,inputsUnchanged=unchanged,finishedUtc=datetime.now(timezone.utc).isoformat())
    (a.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ['nativeExit','componentPass','actualOuterNativeExit','falseGreenReproduced','inputsUnchanged','exception'] if key in result}))
sys.exit(code)
