"""Owned read-only planner regression: no Docker/ss/sockets/server operations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--probe', required=True)
parser.add_argument('--hook', required=True)
args = parser.parse_args()
probe, hook = str(Path(args.probe).resolve()), str(Path(args.hook).resolve())
base = str(Path(__file__).resolve().parent.parent)
good = {'phase': 'ready', 'sourceDigest': hashlib.sha256(b'source').hexdigest(),
        'request': {'host': 'vpn.example', 'image': 'pinned', 'port': 51822, 'generation': 1}}
changed = json.loads(json.dumps(good))
changed['request']['port'] = 51823
count = 0
for runtime in ('native', 'python'):
    for swap in (False, True):
        with tempfile.TemporaryDirectory(prefix='awg-planner-read-audit-', dir='/tmp') as temp:
            directory = Path(temp) / 'amnezia-awg2/1'
            directory.mkdir(parents=True)
            journal = directory / 'transaction.json'
            replacement = Path(str(journal) + '.replacement')
            journal.write_text(json.dumps(good))
            env = dict(os.environ)
            for key in ('LD_PRELOAD', 'AWG_OWNED_JOURNAL', 'AWG_OWNED_REPLACEMENT'):
                env.pop(key, None)
            if swap:
                replacement.write_text(json.dumps(changed))
                env.update(LD_PRELOAD=hook, AWG_OWNED_JOURNAL=str(journal),
                           AWG_OWNED_REPLACEMENT=str(replacement))
            if runtime == 'native':
                command = [probe]
                body = json.dumps(dict(mode='automatic', root=temp, source='amnezia-awg2',
                    host='vpn.example', image='pinned', raw='source', sourcePort=51820,
                    occupied=[51821])).encode()
            else:
                command = ['python3', '-B', '-c',
                    "import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import automatic\n"
                    "try:\n value=automatic.plan(Path(sys.argv[2]),'amnezia-awg2','vpn.example','pinned',b'source',51820,{51821});print(json.dumps({'ok':True,'value':value}))\n"
                    "except Exception as e:print(json.dumps({'ok':False,'error':str(e)}))", base, temp]
                body = b''
            result = subprocess.run(command, input=body, env=env, capture_output=True, timeout=5)
            assert result.returncode == 0 and result.stderr == b'', (runtime, swap, result.stderr)
            value = json.loads(result.stdout)
            value.pop('calls', None)
            if swap:
                assert not replacement.exists(), 'owned hook did not actually swap journal'
                assert json.loads(journal.read_text())['request']['port'] == 51823
                assert value == {'ok': False, 'error': 'migration_journal_conflict'}, (runtime, value)
            else:
                assert value == {'ok': True, 'value': good['request']}, (runtime, value)
            count += 1
print(f'plannerStabilityCases={count} passed=true realDockerCommands=0 udpBindings=0 ownedTempOnly=true')
