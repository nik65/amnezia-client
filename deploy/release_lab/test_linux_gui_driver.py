import struct
import zlib
import pytest
import hashlib
from unittest.mock import Mock
from .linux_gui_driver import LinuxGuiDriverError, ppm_to_png

def png_rows(png):
    assert png.startswith(b'\x89PNG\r\n\x1a\n')
    at=8; compressed=b''; geometry=None
    while at<len(png):
        size=struct.unpack('>I',png[at:at+4])[0];kind=png[at+4:at+8];data=png[at+8:at+8+size]
        assert zlib.crc32(kind+data)&0xffffffff==struct.unpack('>I',png[at+8+size:at+12+size])[0]
        if kind==b'IHDR':geometry=struct.unpack('>IIBBBBB',data)
        if kind==b'IDAT':compressed+=data
        at+=12+size
    return geometry,zlib.decompress(compressed)

def test_exact_ppm_pixels_survive_png_encoding():
    pixels=b'\x00\x0a\x20\xff\x80\x01'
    geometry,rows=png_rows(ppm_to_png(b'P6\n# QEMU image\n2 1\n255\n'+pixels))
    assert geometry==(2,1,8,2,0,0,0)
    assert rows==b'\0'+pixels

@pytest.mark.parametrize('header,raster',[(b'P3\n1 1\n255\n',b'abc'),(b'P6\n1 1\n65535\n',b'abc'),(b'P6\n0 1\n255\n',b''),(b'P6\n999999999 999999999\n255\n',b''),(b'P6\n1 1\n255\n',b'ab'),(b'P6\n1 1\n255\n',b'abcd'),(b'P6\n#missingend',b'')])
def test_untrusted_ppm_rejected(header,raster):
    with pytest.raises(LinuxGuiDriverError):ppm_to_png(header+raster)

def test_crlf_header_and_binary_whitespace_pixel_not_stripped():
    _,rows=png_rows(ppm_to_png(b'P6\r\n1 1\r\n255\r\n\x0a\x20\x0d'))
    assert rows==b'\0\x0a\x20\x0d'

def driver_inputs(tmp_path,monkeypatch):
    from .lab import LabController
    from .linux_gui_driver import HELPER
    controller=LabController(tmp_path)
    monkeypatch.setattr(controller,'assert_mutation_context',lambda:None)
    controller._mutation_lock_depth=1;controller._mutation_lock_fd=123
    def record(name,data):
        p=tmp_path/name;p.write_bytes(data)
        return {'path':str(p),'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    run={'candidate_version':'5.0.3.14','artifacts':{'linux-x64':record('candidate.run',b'actual file fixture')},'semantic_helper_records':{HELPER:record('helper.py',b'helper fixture')}}
    binding={'pid':42,'uuid':'unique','proc_start_time':'123','qmp_socket':'/owned/qmp','qga_socket':'/owned/qga'}
    monkeypatch.setattr(controller,'get_run',lambda _:run)
    monkeypatch.setattr(controller,'owned_vm',lambda *_:dict(binding))
    return controller,run,binding

def test_missing_live_lock_rejected_before_archive_creation(tmp_path,monkeypatch):
    from .linux_gui_driver import LinuxGuiDriver
    c,_,_=driver_inputs(tmp_path,monkeypatch);c._mutation_lock_depth=0;c._mutation_lock_fd=None
    with pytest.raises(LinuxGuiDriverError,match='mutation session'):LinuxGuiDriver(c,'run-14','a'*64)
    assert not (tmp_path/'exports').exists()

def test_changed_guest_blocks_helper_staging(tmp_path,monkeypatch):
    from .linux_gui_driver import LinuxGuiDriver
    c,_,binding=driver_inputs(tmp_path,monkeypatch);driver=LinuxGuiDriver(c,'run-14','a'*64)
    driver.qga=Mock();binding['pid']=99
    with pytest.raises(LinuxGuiDriverError,match='identity changed'):driver.stage_and_launch()
    driver.qga.write_file.assert_not_called();driver.qga.guest_exec_wait.assert_not_called()

def test_changed_planned_bytes_block_guest_effects(tmp_path,monkeypatch):
    from .linux_gui_driver import LinuxGuiDriver
    c,run,_=driver_inputs(tmp_path,monkeypatch);driver=LinuxGuiDriver(c,'run-14','a'*64)
    driver.qga=Mock();__import__('pathlib').Path(run['artifacts']['linux-x64']['path']).write_bytes(b'tampered fixture')
    with pytest.raises(LinuxGuiDriverError,match='changed'):driver.stage_and_launch()
    driver.qga.write_file.assert_not_called();driver.qga.guest_exec_wait.assert_not_called()

def test_capture_cannot_precede_owned_launch(tmp_path,monkeypatch):
    from .linux_gui_driver import LinuxGuiDriver
    c,_,_=driver_inputs(tmp_path,monkeypatch);driver=LinuxGuiDriver(c,'run-14','a'*64)
    with pytest.raises(LinuxGuiDriverError,match='order conflict'):driver.capture_and_collect()

def test_boolean_qga_exitcode_cannot_be_success(tmp_path,monkeypatch):
    from .linux_gui_driver import LinuxGuiDriver
    c,_,_=driver_inputs(tmp_path,monkeypatch);driver=LinuxGuiDriver(c,'run-14','a'*64)
    driver.qga=Mock();driver.qga.guest_exec_wait.return_value={'exitcode':False,'stdout':'{}'}
    with pytest.raises(LinuxGuiDriverError,match='operation failed'):driver.stage_and_launch()
    assert not (driver.archive/'launch.json').exists()


def test_launch_failure_retains_private_snapshot_even_with_ordinary_archive(tmp_path,monkeypatch):
    import json
    from .linux_gui_driver import LinuxGuiDriver
    c,_,_=driver_inputs(tmp_path,monkeypatch);driver=LinuxGuiDriver(c,'run-14','a'*64);driver.qga=Mock()
    (tmp_path/'ordinary-evidence.json').write_text('{}')
    primary=RuntimeError('actual IPC response timeout')
    diagnostic={'schema':'amnezia.release-lab.linux-gui-window.v1','phase':'diagnose','diagnosticOnly':True,'origin':'qga','injected':False,'run_id':'run-14','profile':'linux-x64-gui','attempt_nonce':driver.nonce,'application.log':{'body_base64':'YWN0dWFs'}}
    driver.qga.guest_exec_wait.side_effect=[primary,{'exitcode':0,'stdout':json.dumps(diagnostic)}]
    with pytest.raises(RuntimeError,match='actual IPC response timeout'):driver.stage_and_launch()
    assert json.loads((driver.archive/'launch-failure.private.json').read_bytes())==diagnostic
    assert driver.qga.guest_exec_wait.call_args_list[1].args[1][1]=='diagnose'
    assert driver.qga.guest_exec_wait.call_args_list[1].kwargs['timeout']==20


@pytest.mark.parametrize('lost',[False,True])
def test_launch_diagnostic_failure_or_lost_ownership_preserves_primary(tmp_path,monkeypatch,lost):
    from .linux_gui_driver import LinuxGuiDriver
    c,_,binding=driver_inputs(tmp_path,monkeypatch);driver=LinuxGuiDriver(c,'run-14','a'*64);driver.qga=Mock();primary=RuntimeError('original launch error')
    def fail(*a,**kw):
        if lost:binding['pid']=99
        raise primary if driver.qga.guest_exec_wait.call_count==1 else OSError('secondary diagnostic IO')
    driver.qga.guest_exec_wait.side_effect=fail
    with pytest.raises(RuntimeError,match='original launch error'):driver.stage_and_launch()
    assert primary.__notes__
    assert driver.qga.guest_exec_wait.call_count==(1 if lost else 2)


def test_private_archive_io_failure_never_replaces_launch_primary(tmp_path,monkeypatch):
    import json
    from .linux_gui_driver import LinuxGuiDriver
    c,_,_=driver_inputs(tmp_path,monkeypatch);driver=LinuxGuiDriver(c,'run-14','a'*64);driver.qga=Mock();primary=RuntimeError('original IPC timeout')
    diagnostic={'schema':'amnezia.release-lab.linux-gui-window.v1','phase':'diagnose','diagnosticOnly':True,'origin':'qga','injected':False,'run_id':'run-14','profile':'linux-x64-gui','attempt_nonce':driver.nonce}
    driver.qga.guest_exec_wait.side_effect=[primary,{'exitcode':0,'stdout':json.dumps(diagnostic)}]
    def fail_write(*a,**k):raise OSError('inert private archive fsync error')
    monkeypatch.setattr(__import__(LinuxGuiDriver.__module__,fromlist=['_write_new']),'_write_new',fail_write)
    with pytest.raises(RuntimeError,match='original IPC timeout'):driver.stage_and_launch()
    assert any('private GUI launch capture' in n for n in primary.__notes__)
