"""Only capability/invalid arguments: never invoke production network adapter."""
import json
import subprocess
import sys

binary=sys.argv[1]
def invoke(args,expected,output=b''):
    result=subprocess.run([binary,*args],input=b'',capture_output=True,timeout=5)
    assert result.returncode==expected,(args,result.returncode)
    assert result.stdout==output and result.stderr==b'',(args,result.stdout,result.stderr)

capability=b'{"result":{"policyEpochVersion":1}}\n'
invoke(['--policy-epoch-capability'],0,capability)
assert json.loads(capability)['result']['policyEpochVersion']==1
invoke(['--policy-epoch-capability','extra'],2)
hash_value='sha256:'+'a'*64
cases=[[],['1'],['1',hash_value,'extra']]
cases += [[revision,hash_value]for revision in ('0','01','-1','+1','true','1.0','9007199254740992','9'*100)]
cases += [['1',value]for value in ('a'*64,'SHA256:'+'a'*64,'sha256:'+'A'*64,hash_value+'\n','')]
for args in cases:invoke(['--check-policy-epoch',*args],2)
print(str(len(cases)+2)+' CLI cases passed; no production network request')
