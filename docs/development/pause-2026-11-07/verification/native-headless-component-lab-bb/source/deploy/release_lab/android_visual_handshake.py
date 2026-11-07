"""Immutable, mutation-lock-independent Android visual decision store."""
from __future__ import annotations
import hashlib,json,os,re,stat,time
from pathlib import Path
ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}");SHA=re.compile(r"[0-9a-f]{64}")
class VisualHandshakeError(RuntimeError):pass
def _canonical(v):return (json.dumps(dict(v),sort_keys=True,separators=(",",":"))+"\n").encode()
def _png_size(p):
 if len(p)<33 or p[:8]!=b"\x89PNG\r\n\x1a\n" or p[8:16]!=b"\x00\x00\x00\rIHDR":raise VisualHandshakeError("invalid PNG IHDR")
 w=int.from_bytes(p[16:20],"big");h=int.from_bytes(p[20:24],"big")
 if not 1<=w<=8192 or not 1<=h<=8192:raise VisualHandshakeError("invalid PNG dimensions")
 return w,h
def _open_parent(root,path,create=False):
 root=Path(root);path=Path(path)
 try:parts=path.relative_to(root).parts
 except ValueError:raise VisualHandshakeError("visual store path escaped")
 if not parts:raise VisualHandshakeError("visual store path missing")
 if os.name=="nt":
  parent=path.parent
  if create:parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  return None,parent,parts[-1]
 flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0);fd=os.open(root,flags)
 try:
  for part in parts[:-1]:
   try:nfd=os.open(part,flags,dir_fd=fd)
   except FileNotFoundError:
    if not create:raise
    os.mkdir(part,0o700,dir_fd=fd);nfd=os.open(part,flags,dir_fd=fd)
   os.close(fd);fd=nfd
  return fd,None,parts[-1]
 except BaseException:
  os.close(fd);raise
def _regular(path,root):
 expected=Path(path).lstat()
 if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):raise VisualHandshakeError("visual store file is not regular")
 dfd,parent,name=_open_parent(root,path);flags=os.O_RDONLY|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0);fd=os.open(parent/name if parent else name,flags,dir_fd=dfd)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or (st.st_dev,st.st_ino)!=(expected.st_dev,expected.st_ino):raise VisualHandshakeError("visual store file is not regular")
  chunks=[]
  while True:
   part=os.read(fd,65536)
   if not part:break
   chunks.append(part)
  return b"".join(chunks)
 finally:
  os.close(fd)
  if dfd is not None:os.close(dfd)
def _exclusive(path,payload,root):
 dfd,parent,name=_open_parent(root,path,True);fd=os.open(parent/name if parent else name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_BINARY",0)|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=dfd)
 try:
  with os.fdopen(fd,"wb",closefd=False) as stream:stream.write(payload);stream.flush();os.fsync(fd)
 finally:os.close(fd)
 if dfd is not None:
  try:os.fsync(dfd)
  finally:os.close(dfd)
 if _regular(path,root)!=payload:raise VisualHandshakeError("visual store write readback differs")
class AndroidVisualHandshakeStore:
 def __init__(self,root,clock=time.time):self.root=Path(root).resolve();self.clock=clock
 def _base(self,run,nonce):
  if not ID.fullmatch(run) or not re.fullmatch(r"[0-9a-f]{48}",nonce):raise VisualHandshakeError("invalid visual handshake identity")
  anchor=self.root/"runs"/run/"controller"/"android-visual";resolved=anchor.resolve()
  if resolved!=anchor.absolute():raise VisualHandshakeError("visual handshake ancestry is not canonical")
  # Reject every already-existing symlink/non-directory ancestor.  Files are then
  # opened with O_NOFOLLOW and consumed through the held descriptor.
  current=self.root
  for component in ("runs",run,"controller","android-visual"):
   current=current/component
   if current.exists():
    st=current.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):raise VisualHandshakeError("visual handshake ancestry is unsafe")
  base=anchor/nonce
  return base
 def request(self,r,png):
  run=str(r.get("run_id",""));nonce=str(r.get("attempt_nonce",""));seq=r.get("sequence");review=r.get("review_seconds")
  kind=r.get("kind");expected={"update":"Update","unknown-sources":"Allow from this source"}
  if r.get("schema")!=1 or r.get("origin")!="guest" or r.get("transport")!="qga-adb" or isinstance(seq,bool) or not isinstance(seq,int) or not 1<=seq<=32 or kind not in expected or r.get("action")!=expected.get(kind) or r.get("state")!="operator-unclassified" or r.get("bounds") is not None or isinstance(review,bool) or not isinstance(review,(int,float)) or not 5<=review<=90 or not isinstance(png,bytes) or len(png)>16<<20:raise VisualHandshakeError("invalid visual request")
  for name in ("display_owner","action_target"):
   if not isinstance(r.get(name),dict):raise VisualHandshakeError("invalid visual identity schema")
  owner=r["display_owner"];target=r["action_target"]
  if set(owner)!={"package","activity","pid","uid"} or not all(isinstance(owner[x],str) and owner[x] for x in ("package","activity")) or any(isinstance(owner[x],bool) or not isinstance(owner[x],int) or owner[x]<=0 for x in ("pid","uid")):raise VisualHandshakeError("invalid display owner")
  if set(target)!={"package","version_code","artifact_sha256","artifact_size"} or not isinstance(target["package"],str) or not target["package"] or isinstance(target["version_code"],bool) or not isinstance(target["version_code"],int) or target["version_code"]<=0 or not SHA.fullmatch(str(target["artifact_sha256"])) or isinstance(target["artifact_size"],bool) or not isinstance(target["artifact_size"],int) or target["artifact_size"]<=0:raise VisualHandshakeError("invalid action target")
  w,h=_png_size(png);created=float(self.clock());expires=created+float(review);rid=f"{seq:02d}-{r['kind']}";base=self._base(run,nonce);pp=base/"images"/(rid+".png");_exclusive(pp,png,self.root);pm={"path":str(pp),"sha256":hashlib.sha256(png).hexdigest(),"size":len(png),"width":w,"height":h};bound={**dict(r),"created_at":created,"expires_at":expires,"request_id":rid,"png":pm};raw=_canonical(bound);rp=base/"requests"/(rid+".json");_exclusive(rp,raw,self.root)
  return {"origin":"controller","immutable":True,"run_id":run,"attempt_nonce":nonce,"request_id":rid,"request_path":str(rp),"request_sha256":hashlib.sha256(raw).hexdigest(),"request_size":len(raw),"png_path":str(pp),"png_sha256":pm["sha256"],"png_size":len(png),"png_width":w,"png_height":h,"created_at":created,"expires_at":expires,"request_record":bound}
 def decide(self,run,nonce,rid,rsha,decision,bounds=None):
  if not ID.fullmatch(rid) or not SHA.fullmatch(rsha) or decision not in ("approve","refresh","reject"):raise VisualHandshakeError("invalid visual decision")
  base=self._base(run,nonce);rp=base/"requests"/(rid+".json");raw=_regular(rp,self.root)
  if hashlib.sha256(raw).hexdigest()!=rsha:raise VisualHandshakeError("visual request changed")
  req=json.loads(raw);pm=req.get("png",{});pp=base/"images"/(rid+".png");png=_regular(pp,self.root)
  if req.get("run_id")!=run or req.get("attempt_nonce")!=nonce or req.get("request_id")!=rid or Path(str(pm.get("path"))).resolve()!=pp.resolve() or hashlib.sha256(png).hexdigest()!=pm.get("sha256") or len(png)!=pm.get("size") or list(_png_size(png))!=[pm.get("width"),pm.get("height")]:raise VisualHandshakeError("visual request/PNG binding mismatch")
  now=float(self.clock())
  if now>req.get("expires_at",0):raise VisualHandshakeError("visual request expired")
  if decision=="approve":
   if not isinstance(bounds,(list,tuple)) or len(bounds)!=4 or any(isinstance(x,bool) or not isinstance(x,int) for x in bounds):raise VisualHandshakeError("approve requires integer bounds")
   a,b,c,d=bounds
   if not (0<=a<c<=pm["width"] and 0<=b<d<=pm["height"]):raise VisualHandshakeError("decision bounds outside PNG")
   bounds=[a,b,c,d]
  elif bounds is not None:raise VisualHandshakeError("non-approve decision cannot carry bounds")
  v={"schema":1,"run_id":run,"attempt_nonce":nonce,"request_id":rid,"request_sha256":rsha,"decision":decision,"bounds":bounds,"decided_at":now,"origin":"operator","input_only":True};out=_canonical(v);dp=base/"decisions"/(rid+".json");_exclusive(dp,out,self.root);return {**v,"origin":"controller","immutable":True,"path":str(dp),"sha256":hashlib.sha256(out).hexdigest(),"size":len(out)}
 def poll(self,ack):
  run=str(ack.get("run_id",""));nonce=str(ack.get("attempt_nonce",""));rid=str(ack.get("request_id",""));base=self._base(run,nonce);rp=base/"requests"/(rid+".json");raw=_regular(rp,self.root)
  if str(rp)!=ack.get("request_path") or hashlib.sha256(raw).hexdigest()!=ack.get("request_sha256"):raise VisualHandshakeError("visual ack path/hash invalid")
  req=json.loads(raw);pp=base/"images"/(rid+".png");png=_regular(pp,self.root)
  if str(pp)!=ack.get("png_path") or hashlib.sha256(png).hexdigest()!=ack.get("png_sha256") or len(png)!=ack.get("png_size"):raise VisualHandshakeError("visual PNG changed")
  dp=base/"decisions"/(rid+".json")
  if not dp.exists():return None
  draw=_regular(dp,self.root);v=json.loads(draw)
  if v.get("request_sha256")!=ack.get("request_sha256") or v.get("run_id")!=run or v.get("attempt_nonce")!=nonce or v.get("request_id")!=rid or v.get("decision") not in ("approve","refresh","reject") or v.get("input_only") is not True or v.get("decided_at",0)>req.get("expires_at",0):raise VisualHandshakeError("visual decision is stale or tampered")
  return {**v,"origin":"controller","immutable":True,"path":str(dp),"sha256":hashlib.sha256(draw).hexdigest(),"size":len(draw)}
