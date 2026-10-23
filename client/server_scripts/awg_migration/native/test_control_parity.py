"""Standalone canonical/HMAC/Ed25519 byte parity; public ephemeral fixtures only."""
import base64,hashlib,hmac,json,pathlib,subprocess,sys,tempfile
probe=sys.argv[1]
def run(mode,value,*args,good=True):
 p=subprocess.run([probe,mode,*args],input=value,stdout=subprocess.PIPE)
 assert (p.returncode==0)==good
 return p.stdout
cases=['\ud800\udc00','\U0010ffff',None,True,False,0,-9223372036854775808,9223372036854775807,{},[],{'z':'Привет 😀','a':'\b\f\n\r\t\u0000"\\/','é': [1,False,None]}, {'nested':{'x':{'a':1}}}]
cases += [chr(i) for i in range(256)]
for x in cases:
 raw=json.dumps(x).encode()
 expected=json.dumps(x,separators=(',',':'),sort_keys=True).encode()
 assert run('canonical',raw)==expected
 assert run('grant',raw)==base64.urlsafe_b64encode(hmac.new(b'public-test-secret',expected,hashlib.sha384).digest()).rstrip(b'=')
for bad in [b'{}\x00',b'{}\x00{}',b'null\x00garbage',b'"\\ud800"',b'"\\udfff"',b'{"a":1,"a":2}',b'{"a":1,"\\u0061":2}',b'{"x":{"a":1,"a":2}}',b'{}x',b'{"x":1.5}',b'"\xff"',b'9223372036854775808',b'-9223372036854775809',b'[1,]',b'{"a":1,}']:
 run('canonical',bad,good=False)
# Deterministic prefix/suffix mutation corpus: raw controls, adjacent JSON,
# trailing garbage and embedded sentinel must never hide bytes from signatures.
for valid in [b'{}',b'null',b'[]',b'"value"',b'{"a":1}']:
 for bad in [b'\x00',b'\x00{}',b'\x01',b'\xff',b'x',b'{}',b'[]']:
  run('canonical',bad+valid,good=False)
  run('canonical',valid+bad,good=False)
 assert run('canonical',b' \t\r\n'+valid+b' \n')==valid
with tempfile.TemporaryDirectory() as d:
 d=pathlib.Path(d);d.chmod(0o700)
 subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(d/'signing.pem')],check=True,capture_output=True)
 (d/'signing.pem').chmod(0o600)
 raw=b'{"z":"\\u00e9","a":1}'
 native=json.loads(run('sign',raw,str(d)))
 expected=b'{"a":1,"z":"\\u00e9"}'
 assert base64.b64decode(native['payload'])==expected
 (d/'payload').write_bytes(expected)
 signed=subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(d/'signing.pem'),'-in',str(d/'payload')],check=True,capture_output=True).stdout
 assert base64.b64decode(native['signature'])==signed
 (d/'signing.pem').chmod(0o644)
 run('sign',raw,str(d),good=False)
print('canonical Unicode/nested/duplicate rejection + HMAC + actual Ed25519 byte parity PASS')




