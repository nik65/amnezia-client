import json,os,shlex,shutil,socket,subprocess,sys,threading,time,types

import pytest

from deploy.release_lab.nested_cuttlefish_app_executor import _fixture_health_command


def _serve(response,delay=0):
 listener=socket.socket();listener.bind(("127.0.0.1",0));listener.listen(1);port=listener.getsockname()[1];seen=[]
 def worker():
  conn,_=listener.accept()
  with conn:
   data=b""
   while b"\r\n\r\n" not in data:data+=conn.recv(4096)
   seen.append(data)
   if delay:time.sleep(delay)
   if response is not None:conn.sendall(response)
  listener.close()
 threading.Thread(target=worker,daemon=True).start();return port,seen


def _run_reconstructed(tmp_path,port,response,delay=0,broken=False,wrong_request=False):
 toybox=tmp_path/"toybox"
 toybox.write_text("""#!/bin/sh
if [ "$1" = base64 ]; then exec base64 "$2"; fi
if [ "$1" = nc ]; then shift; shift; shift; host="$1"; port="$2"; exec __PYTHON__ -c 'import socket,sys;s=socket.create_connection((sys.argv[1],int(sys.argv[2])),3);s.sendall(sys.stdin.buffer.read());s.shutdown(socket.SHUT_WR);sys.stdout.buffer.write(s.recv(65536))' "$host" "$port"; fi
exit 127
""".replace("__PYTHON__",shlex.quote(sys.executable)),encoding="utf-8",newline="\n");os.chmod(toybox,0o755)
 port,seen=_serve(response,delay);request,argv=_fixture_health_command("127.0.0.1",port);script=argv[-1][1:-1] if broken else argv[-1]
 if wrong_request:
  import base64
  encoded=base64.b64encode(request.encode("ascii")).decode("ascii");wrong=base64.b64encode(request.replace("/healthz","/stale").encode("ascii")).decode("ascii");script=script.replace(encoded,wrong)
 remote=" ".join(["sh","-c",script]);env={**os.environ,"PATH":str(tmp_path)+os.pathsep+os.environ["PATH"]}
 try:result=subprocess.run([shutil.which("sh"),"-c",remote],capture_output=True,timeout=5,env=env)
 except subprocess.TimeoutExpired as exc:result=types.SimpleNamespace(returncode=124,stdout=exc.stdout or b"",stderr=exc.stderr or b"")
 return request,seen,result


def test_reconstructed_adb_shell_health_command_exact_request_and_body(tmp_path):
 body=b'{"status":"ok","run_id":"run","role":"consumer-fixture"}';response=b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body
 request,seen,result=_run_reconstructed(tmp_path,0,response)
 assert result.returncode==0 and result.stdout==response and seen==[request.encode("ascii")]


@pytest.mark.parametrize("kind",["delayed","never","broken","stale","wrong-body","wrong-request"])
def test_reconstructed_health_negative_receipts_are_decisive(tmp_path,kind):
 body=(b'{"status":"ok","run_id":"old","role":"consumer-fixture"}' if kind=="stale" else b'{"status":"bad"}' if kind=="wrong-body" else b'{"status":"ok","run_id":"run","role":"consumer-fixture"}')
 response=None if kind=="never" else b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body
 request,seen,result=_run_reconstructed(tmp_path,0,response,delay=.05 if kind=="delayed" else 0,broken=kind=="broken",wrong_request=kind=="wrong-request")
 if kind=="delayed":assert result.returncode==0 and result.stdout.endswith(body) and seen==[request.encode("ascii")]
 elif kind=="broken":assert result.returncode!=0 and not any(b"GET /healthz HTTP/1.1" in row for row in seen)
 elif kind=="wrong-request":assert len(seen)==1 and seen[0]!=request.encode("ascii") and b"GET /stale HTTP/1.1" in seen[0]
 else:assert result.returncode==0 and (result.stdout==b"" if kind=="never" else result.stdout.endswith(body))
