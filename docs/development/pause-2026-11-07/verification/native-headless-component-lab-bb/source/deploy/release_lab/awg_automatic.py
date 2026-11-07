"""Automatic preparation diagnostic through lab-owned server QMP/QGA only."""
import argparse,hashlib,json,re,secrets
from pathlib import Path
from .lab import LabController,LabError,QgaClient,QmpClient,require_qmp_return,repo_root

PROFILE='server-router'
SOURCE_FILES=('prepare.py','automatic.py','trusted_image.py','service.py','target.py','policy.py','journal.py','feeds.py')


def stage_and_run(controller,run_id,source_root,output):
    if controller.dry_run or controller.test_mode: raise LabError('real diagnostic required')
    source_root=Path(source_root).resolve();output=Path(output)
    if output.exists(): raise LabError('receipt already exists')
    run=controller.get_run(run_id)
    if run.get('automatic_migration_wan') is None: raise LabError('explicit planned WAN diagnostic required')
    with controller.mutation_session('automatic-migration-diagnostic'):
        if run['profiles'][PROFILE].get('vm') is None:
            controller.start(run_id,PROFILE)
        controller.guest_probe(run_id,PROFILE)
        vm=controller.owned_vm(run_id,PROFILE)
        qmp=QmpClient(Path(vm['qmp_socket']))
        actual_uuid=require_qmp_return(qmp.request('query-uuid'),'query-uuid')['return']['UUID']
        if actual_uuid.lower()!=vm['uuid'].lower(): raise LabError('QMP UUID mismatch')
        qga=QgaClient(Path(vm['qga_socket']))
        root='/var/lib/amnezia-release-lab/automatic-'+run_id
        marker='amnezia-release-lab:'+run_id+':'+PROFILE
        setup="""import os,pathlib,sys
assert os.geteuid()==0
assert pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==sys.argv[1].lower()
p=pathlib.Path('/tmp/amnezia-release-lab-marker');expected=sys.argv[2].encode()
if os.path.lexists(p): assert not p.is_symlink() and p.stat().st_uid==0 and p.read_bytes().strip()==expected
else:
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.write(fd,expected);os.close(fd)
parent=pathlib.Path('/var/lib/amnezia-release-lab')
if parent.exists(): assert not parent.is_symlink() and parent.stat().st_uid==0 and not parent.stat().st_mode&0o022
else: parent.mkdir(mode=0o700)
pathlib.Path(sys.argv[3]).mkdir(mode=0o700)
"""
        controller.owned_vm(run_id,PROFILE)
        result=qga.guest_exec_wait('/usr/bin/python3',['-c',setup,vm['uuid'],marker,root],timeout=30)
        if result.get('exitcode')!=0: raise LabError('guest root/marker initialization failed')
        files={name:(source_root/'client/server_scripts/awg_migration'/name).read_bytes() for name in SOURCE_FILES}
        files['guest.py']=(repo_root()/'deploy/release_lab/awg_automatic_guest.py').read_bytes()
        # Exact production collector source, with normal production substitutions.
        source=(source_root/'client/core/controllers/selfhosted/exportController.cpp').read_text()
        collector=''.join(re.findall(r'R"PY\d*\((.*?)\)PY\d*"',source,re.S))
        if not collector: raise LabError('production collector closure missing')
        replacements={'__MAX_UPLOAD_BYTES__':str(15*1024*1024),'__MAX_CLIENT_BYTES__':str(30*1024*1024),'__PORT__':'17866','__UPLOAD_PATH__':'/logs','__BOOTSTRAP_PATH__':'/bootstrap'}
        for before,after in replacements.items(): collector=collector.replace(before,after)
        files['collector.py']=collector.encode()
        plan={'runId':run_id,'profile':PROFILE,'uuid':vm['uuid'],'marker':marker,'root':root,
              'dnsProxyFixture':run_id in ('dns-proxy-awg-20261008','dns-proxy-topology-20261008','dns-proxy-topology-r2-20261008'),
              'sourceDnsFirstFixture':run_id in ('dns-proxy-topology-20261008','dns-proxy-topology-r2-20261008'),
              'sourceCommit':'e2e4b2bce4cdf2621bd202388ec78702ac7d749b+owned-DNS-topology-patch',
              'legacyImage':'amneziavpn/amneziawg-go@sha256:3c78eb57ef5cb44f63aed185e79c104593c854a5ebde3e1075470301bcc77c44',
              'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
        for name,data in files.items():
            controller.owned_vm(run_id,PROFILE);qga.write_file(root+'/'+name,data)
        controller.owned_vm(run_id,PROFILE)
        if hashlib.sha256(qga.read_file(root+'/guest.py')).hexdigest()!=plan['files']['guest.py']: raise LabError('guest helper readback mismatch')
        qga.write_file(root+'/plan.json',json.dumps(plan,sort_keys=True).encode())
        # Guest-only networking, after PID/UUID/QMP/QGA and marker proof.
        network="""import os,pathlib,subprocess,sys
assert os.geteuid()==0
assert pathlib.Path('/tmp/amnezia-release-lab-marker').read_text().strip()==sys.argv[1]
assert pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==sys.argv[2].lower()
links=subprocess.check_output(['ip','-j','link','show']);import json
interfaces=[x['ifname'] for x in json.loads(links) if x['ifname']!='lo' and not x['ifname'].startswith(('docker','br-','veth'))]
assert len(interfaces)==1
iface=interfaces[0]
subprocess.run(['ip','link','set',iface,'up'],check=True)
subprocess.run(['ip','addr','replace','10.0.2.15/24','dev',iface],check=True)
subprocess.run(['ip','route','replace','default','via','10.0.2.2','dev',iface],check=True)
pathlib.Path('/etc/resolv.conf').write_text('nameserver 10.0.2.3\\n')
"""
        controller.owned_vm(run_id,PROFILE)
        result=qga.guest_exec_wait('/usr/bin/python3',['-c',network,marker,vm['uuid']],timeout=30)
        if result.get('exitcode')!=0: raise LabError('guest diagnostic network setup failed')
        controller.owned_vm(run_id,PROFILE)
        result=qga.guest_exec_wait('/usr/bin/python3',[root+'/guest.py',root+'/plan.json'],timeout=1200)
        try: receipt=json.loads(result['stdout'])
        except (KeyError,ValueError): raise LabError('private guest receipt missing') from None
        if (receipt.get('origin'),receipt.get('runId'),receipt.get('uuid'),receipt.get('marker'))!=('guest',run_id,vm['uuid'],marker): raise LabError('guest receipt binding mismatch')
        receipt['sourceHashes']=plan['files'];receipt['controllerBinding']={k:vm[k] for k in ('pid','proc_start_time','uuid','qmp_socket','qga_socket')}
        receipt['networkContract']=run['automatic_migration_wan']
        output.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
        return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--run-id',required=True);p.add_argument('--source-root',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    args=p.parse_args()
    receipt=stage_and_run(LabController(Path('/var/lib/amnezia-release-lab')),args.run_id,args.source_root,args.output)
    print(json.dumps(receipt,sort_keys=True));raise SystemExit(0 if receipt['passed'] else 1)
