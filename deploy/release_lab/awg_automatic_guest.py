"""Guest-only real Docker automatic preparation; guarded diagnostic fixture."""
import hashlib,json,os,socket,subprocess,sys,time
from pathlib import Path


def command(*args, data=None, timeout=240, check=True):
    result=subprocess.run(args,input=data,capture_output=True,timeout=timeout)
    if check and result.returncode:
        # Never export process output: VPN config, tokens and private keys occur.
        raise RuntimeError('command_failed:'+':'.join(str(a) for a in args[:4])+':'+str(result.returncode))
    return result


def guard(plan):
    if os.geteuid()!=0 or plan['profile']!='server-router': raise ValueError('guest root/profile')
    if Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()!=plan['uuid'].lower(): raise ValueError('guest UUID')
    if Path('/tmp/amnezia-release-lab-marker').read_text().strip()!=plan['marker']: raise ValueError('guest marker')
    if plan['marker']!='amnezia-release-lab:'+plan['runId']+':server-router': raise ValueError('run marker')
    root=Path(plan['root'])
    names={'prepare.py','automatic.py','trusted_image.py','service.py','target.py','policy.py','journal.py','feeds.py','guest.py','collector.py'}
    if set(plan['files'])!=names: raise ValueError('source role allowlist')
    if root!=Path('/var/lib/amnezia-release-lab')/('automatic-'+plan['runId']): raise ValueError('root path')
    if root.is_symlink() or root.resolve()!=root or root.stat().st_uid or root.stat().st_mode&0o077: raise ValueError('root ownership')
    for name,digest in plan['files'].items():
        path=root/name
        if path.is_symlink() or path.stat().st_uid or hashlib.sha256(path.read_bytes()).hexdigest()!=digest: raise ValueError('source bytes')
    return root


def scenario(plan):
    root=guard(plan)
    sys.path.insert(0,str(root))
    import trusted_image,prepare
    checks={}
    # Real registry pull and private executable probes, with production resolver.
    image=trusted_image.resolve_image(prepare.run)
    checks['officialImageIdentityBinaryVersion']=image==trusted_image.IMAGE
    legacy=plan['legacyImage']
    cached=command('docker','image','inspect',legacy,check=False)
    if cached.returncode or legacy not in json.loads(cached.stdout)[0].get('RepoDigests',[]):
        command('docker','pull','--platform','linux/amd64',legacy)
    source=root/'source'
    existing=command('docker','inspect','amnezia-awg2',check=False)
    if existing.returncode==0:
        observed=json.loads(existing.stdout)[0]
        if observed['Config']['Image']!=legacy or not any(m['Source']==str(source) and m['Destination']=='/opt/amnezia/awg' and not m['RW'] for m in observed['Mounts']): raise ValueError('fixture source ownership')
        if command('docker','inspect','amnezia-awg2-migration-1',check=False).returncode==0:
            from journal import Journal
            j=Journal('/opt/amnezia/awg-migration/amnezia-awg2/1',prepare.run)
            if j.value['phase']!='ready' or j.owned('amnezia-awg2-migration-1') is None: raise ValueError('fixture target ownership')
    else:
        command('docker','network','create','--subnet','172.29.172.0/24','amnezia-dns-net')
        source.mkdir(mode=0o700)
        def key(): return command('docker','run','--rm','--network','none','--entrypoint','awg',legacy,'genkey').stdout.decode().strip()
        private,client,psk=key(),key(),key()
        public=command('docker','run','--rm','-i','--network','none','--entrypoint','awg',legacy,'pubkey',data=(client+'\n').encode()).stdout.decode().strip()
        config='[Interface]\nPrivateKey = '+private+'\nAddress = 10.88.0.1/24\nListenPort = 51820\nMTU = 1420\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 16\nS2 = 16\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n\n[Peer]\nPublicKey = '+public+'\nPresharedKey = '+psk+'\nAllowedIPs = 10.88.0.2/32\n'
        (source/'awg0.conf').write_text(config);(source/'awg0.conf').chmod(0o600)
        (source/'start.sh').write_text('#!/bin/sh\nset -eu\nawg-quick up /opt/amnezia/awg/awg0.conf\nwhile :; do sleep 60; done\n')
        command('docker','run','-d','--name','amnezia-awg2','--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv4.ip_forward=1','--log-driver','none','-p','51820:51820/udp','-v',str(source)+':/opt/amnezia/awg:ro','--entrypoint','sh',legacy,'/opt/amnezia/awg/start.sh')
        command('docker','network','connect','amnezia-dns-net','amnezia-awg2')
        for _ in range(25):
            if command('docker','exec','amnezia-awg2','awg','show','awg0','dump',check=False).returncode==0: break
            time.sleep(1)
        else: raise ValueError('legacy source readiness')
    legacy_version=command('docker','exec','amnezia-awg2','amneziawg-go','--version').stdout.decode().strip()
    initial_source=json.loads(command('docker','inspect','amnezia-awg2').stdout)[0]
    initial_dump=hashlib.sha256(command('docker','exec','amnezia-awg2','awg','showconf','awg0').stdout).hexdigest()
    Path('/opt/amnezia/client-logs').mkdir(parents=True,mode=0o700,exist_ok=True)
    Path('/opt/amnezia/client-logs/collector.py').write_bytes((root/'collector.py').read_bytes())
    # Inventory is actual ss/socket state and actual docker inspection.
    busy=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);busy.bind(('0.0.0.0',51821))
    try:
        argv=('python3','-B',str(root/'prepare.py'),'--source','amnezia-awg2','--host','fixture.invalid','--automatic')
        first=command(*argv,timeout=600)
        receipt=json.loads(first.stdout)
        if not receipt.get('prepared'): raise ValueError('prepare receipt rejected')
        state=Path('/opt/amnezia/awg-migration/amnezia-awg2/1')
        ready=json.loads((state/'ready.json').read_text())
        checks['busyPortAutomaticallySkipped']=ready['endpoint']=='fixture.invalid:51822'
        checks['generationOneAutomaticallySelected']=ready['generation']==1
        original=(source/'awg0.conf').read_bytes()
        target_interface,target_peers=prepare.parse_config((state/'awg0.conf').read_bytes())
        source_interface,source_peers=prepare.parse_config(original)
        checks['keysPskPeersAndAddressPreserved']=target_peers==source_peers and all(target_interface[k]==source_interface[k] for k in ('PrivateKey','Address','MTU'))
        checks['oldSourceConfigUnchanged']=command('docker','exec','amnezia-awg2','cat','/opt/amnezia/awg/awg0.conf').stdout==original
        actual=command('docker','exec',ready['targetContainer'],'awg','showconf','awg0').stdout.decode()
        fields=dict(line.strip().split(' = ',1) for line in actual.splitlines() if ' = ' in line)
        checks['actualHeaderProtectionAndS1S4']=all(fields.get(k)==ready['parameters'][k] for k in ('HeaderProtectionKey','S1','S2','S3','S4'))
        repeated=json.loads(command(*argv,timeout=600).stdout)
        checks['repeatGenerationSigningIdentityStable']=receipt==repeated and json.loads((state/'ready.json').read_text())['signingPublicKey']==ready['signingPublicKey']
        checks['repeatNoExtraGeneration']=sorted(p.name for p in state.parent.iterdir() if p.is_dir())==['1']
        stable_state=hashlib.sha256((state/'transaction.json').read_bytes()).hexdigest()
        drift=command('python3','-B',str(root/'prepare.py'),'--source','amnezia-awg2','--host','changed.invalid','--automatic',timeout=600,check=False)
        drift_receipt=json.loads(drift.stdout)
        checks['automaticReadyDriftFailsWithoutMutation']=drift.returncode!=0 and drift_receipt.get('reason')=='migration_ready_drift' and stable_state==hashlib.sha256((state/'transaction.json').read_bytes()).hexdigest()
        final_source=json.loads(command('docker','inspect','amnezia-awg2').stdout)[0]
        checks['legacyContainerNotRestarted']=initial_source['Id']==final_source['Id'] and initial_source['State']['StartedAt']==final_source['State']['StartedAt']
        checks['legacyNativeConfigurationUnchanged']=initial_dump==hashlib.sha256(command('docker','exec','amnezia-awg2','awg','showconf','awg0').stdout).hexdigest()
    finally: busy.close()
    return {'passed':all(checks.values()),'checks':checks,'sourceMode':'real official legacy image; protocol2.1 mapping unproven',
            'legacyImage':legacy,'legacyRuntimeVersion':legacy_version,'sourceCommit':plan['sourceCommit'],
            'origin':'guest','transport':'qga','runId':plan['runId'],'uuid':plan['uuid'],'marker':plan['marker'],
            'automaticDockerProvisioning':True,'releasePassed':False,'network':'diagnostic guest WAN; no host forwarding'}


if __name__=='__main__':
    plan=json.loads(Path(sys.argv[1]).read_text())
    try: result=scenario(plan)
    except Exception as error:
        result={'passed':False,'origin':'guest','transport':'qga','runId':plan['runId'],'uuid':plan['uuid'],'marker':plan['marker'],'errorType':type(error).__name__,'error':str(error) if isinstance(error,(ValueError,RuntimeError)) else 'private guest operation failed','releasePassed':False}
    print(json.dumps(result,sort_keys=True))
    # QGA rejects nonzero before delivering structured stdout; the controller
    # evaluates passed and exits nonzero while retaining this failure receipt.
    raise SystemExit(0)
