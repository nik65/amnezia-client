import base64,hashlib,importlib.util,json,os,threading,time
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT=Path(__file__).parent
spec=importlib.util.spec_from_file_location('procfs_read_subject',ROOT/'guest_helpers/linux_gui_window_evidence.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def test_actual_pipe_short_reads_are_joined_until_real_eof():
    reader,writer=os.pipe();chunks=[b'first',b'second',b'third'];counts=[];original=os.read
    def write():
        try:
            for chunk in chunks:os.write(writer,chunk);time.sleep(.02)
        finally:os.close(writer)
    thread=threading.Thread(target=write);thread.start()
    def read(fd,n):
        block=original(fd,n);counts.append(len(block));return block
    try:
        with patch.object(m.os,'read',side_effect=read):actual=m.bounded_fd_read(reader,100)
        assert actual==b''.join(chunks) and counts[-1]==0 and len(counts)>=4
    finally:os.close(reader);thread.join(timeout=1)


@pytest.mark.parametrize('length',[32767,32768,32769,100000])
def test_actual_maps_short_reads_keep_budget_and_honest_complete(tmp_path,length):
    path=tmp_path/'controlled-maps';data=(b'library-map\n'*10000)[:length];path.write_bytes(data)
    identity=m.proc_identity(os.getpid());original_open=os.open;original_read=os.read;map_fds=set();reads=[]
    def opened(name,flags,*args,**kw):
        if name=='maps':
            fd=original_open(path,flags);map_fds.add(fd);return fd
        return original_open(name,flags,*args,**kw)
    def short_read(fd,maximum):
        if fd in map_fds:
            reads.append(maximum)
            return original_read(fd,min(maximum,137))
        return original_read(fd,maximum)
    with patch.object(m.os,'open',side_effect=opened),patch.object(m.os,'read',side_effect=short_read):record=m.process_maps_snapshot(identity)
    assert base64.b64decode(record['body_base64'])==data[:32768]
    assert record['capturedSize']==min(length,32768)
    assert record['truncated']==(length>32768)
    assert record['complete']==(length<=32768)
    assert len(reads)>1 and max(reads)<=32769


def test_maps_identity_change_still_rejects_partial_or_complete_capture():
    identity=m.proc_identity(os.getpid())
    with patch.object(m,'same_process',side_effect=[True,True,False]):
        with pytest.raises(m.EvidenceError,match='during maps'):m.process_maps_snapshot(identity)


def test_loop_retains_only_requested_bytes_from_large_actual_file(tmp_path):
    path=tmp_path/'large';path.write_bytes(b'x'*1000000);fd=os.open(path,os.O_RDONLY)
    try:assert m.bounded_fd_read(fd,65537)==b'x'*65537
    finally:os.close(fd)


def test_existing_diagnostic_deadline_checked_before_additional_reads(tmp_path):
    path=tmp_path/'bounded';path.write_bytes(b'actual');fd=os.open(path,os.O_RDONLY)
    try:
        with pytest.raises(m.EvidenceError,match='deadline'):m.bounded_fd_read(fd,100,deadline=time.monotonic()-1)
        assert os.lseek(fd,0,os.SEEK_CUR)==0
    finally:os.close(fd)
