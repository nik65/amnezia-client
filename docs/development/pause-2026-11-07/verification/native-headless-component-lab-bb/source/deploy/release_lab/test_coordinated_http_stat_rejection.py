"""Actual staged COMMON.checked on inert root-owned private temporary files."""
import ast,importlib.util,json,os,pathlib,stat,sys,tempfile
import pytest
from . import headless_coordinated_http_fixture as M
SOURCE=pathlib.Path(M.__file__)
DIFF={'before_sha256': '954e4b174444a99cec4458eb0f426ad0a71878b07edef775ad85c861f0b50703', 'removed': "  if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_nlink!=1 or a.st_mode&0o022 or a.st_size>limit:raise RuntimeError('protected fixture file')", 'inserted': "  if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_nlink!=1 or a.st_mode&0o022 or a.st_size>limit:\n   reasons=[]\n   if not stat.S_ISREG(a.st_mode):reasons.append('not-regular')\n   if a.st_uid!=0:reasons.append('non-root-uid')\n   if a.st_nlink!=1:reasons.append('link-count')\n   if a.st_mode&0o022:reasons.append('group-or-world-writable')\n   if a.st_size>limit:reasons.append('size-limit')\n   metadata={'regular':stat.S_ISREG(a.st_mode),'uid':a.st_uid,'gid':a.st_gid,'mode':format(stat.S_IMODE(a.st_mode),'04o'),'nlink':a.st_nlink,'size':a.st_size,'limit':limit,'inputbasename':p.name[:80],'reasons':reasons}\n   raise RuntimeError('protected fixture file '+json.dumps(metadata,sort_keys=True,separators=(',',':')))"}
BEFORE_SHA256='954e4b174444a99cec4458eb0f426ad0a71878b07edef775ad85c861f0b50703'

def test_exact_inverse_only_rejection_message_changed():
 diff=DIFF;after=SOURCE.read_bytes();old=diff['removed'].replace('\n','\r\n').encode();new=diff['inserted'].replace('\n','\r\n').encode()
 if new not in after:old=diff['removed'].encode();new=diff['inserted'].encode()
 assert after.count(new)==1;assert __import__('hashlib').sha256(after.replace(new,old)).hexdigest()==BEFORE_SHA256

@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:1)()!=0,reason='actual POSIX root temporary fixtures')
@pytest.mark.parametrize('mode',[0o600,0o644])
def test_normal_success_bytes_and_predicate_unchanged(mode):
 scope={};exec(M.COMMON,scope)
 with tempfile.TemporaryDirectory(prefix='fixture-stat-',dir='/root') as directory:
  path=pathlib.Path(directory)/'original';path.write_bytes(b'exact private bytes');path.chmod(mode);assert scope['checked'](path,100)==b'exact private bytes'

@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:1)()!=0,reason='actual POSIX root temporary fixtures')
@pytest.mark.parametrize('fault,reason',[('mode','group-or-world-writable'),('uid','non-root-uid'),('links','link-count'),('size','size-limit'),('fifo','not-regular')])
def test_actual_stat_rejection_metadata_is_bounded_and_contains_no_data(fault,reason):
 scope={};exec(M.COMMON,scope)
 with tempfile.TemporaryDirectory(prefix='fixture-stat-',dir='/root') as directory:
  path=pathlib.Path(directory)/('input-'+'x'*150);payload=b'private-file-content-never-printed';path.write_bytes(payload);path.chmod(0o600);limit=100
  if fault=='mode':path.chmod(0o666)
  elif fault=='uid':os.chown(path,1000,1000)
  elif fault=='links':os.link(path,path.with_name('second-link'))
  elif fault=='size':limit=1
  elif fault=='fifo':path.unlink();os.mkfifo(path,0o600)
  with pytest.raises(RuntimeError) as error:scope['checked'](path,limit)
  message=str(error.value);assert message.startswith('protected fixture file ');assert len(message)<512;assert payload.decode() not in message;assert str(path.parent) not in message
  metadata=json.loads(message.removeprefix('protected fixture file '));assert reason in metadata['reasons'];assert len(metadata['inputbasename'])==80;assert metadata['limit']==limit;assert set(metadata)=={'regular','uid','gid','mode','nlink','size','limit','inputbasename','reasons'}
  actual=path.lstat();assert metadata['uid']==actual.st_uid;assert metadata['gid']==actual.st_gid;assert metadata['mode']==format(stat.S_IMODE(actual.st_mode),'04o');assert metadata['nlink']==actual.st_nlink;assert metadata['size']==actual.st_size

@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:1)()!=0,reason='actual POSIX root temporary fixtures')
def test_symlink_is_still_rejected_by_nofollow_before_read():
 scope={};exec(M.COMMON,scope)
 with tempfile.TemporaryDirectory(prefix='fixture-stat-',dir='/root') as directory:
  root=pathlib.Path(directory);target=root/'target';target.write_bytes(b'private symlink target');target.chmod(0o600);link=root/'link';link.symlink_to(target)
  with pytest.raises(OSError) as error:scope['checked'](link,100)
  assert len(str(error.value))<512;assert 'private symlink target' not in str(error.value)
