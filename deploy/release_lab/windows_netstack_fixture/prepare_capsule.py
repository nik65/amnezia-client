"""Offline named synthetic fixture inputs. Never launches a product or helper."""
import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


def prepare(output, helper, observer, artifact_sha256, installed_exe_sha256):
    if any(len(x) != 64 or any(c not in "0123456789abcdef" for c in x) for x in (artifact_sha256, installed_exe_sha256)):
        raise ValueError("exact rebuilt candidate hashes required")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = [X25519PrivateKey.generate() for _ in range(3)]
    private = [k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()) for k in keys]
    public = [k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for k in keys]
    b64 = lambda b: base64.b64encode(b).decode()
    # Small explicit set, no padding and no historical production equivalence.
    prefixes = sorted({str(ipaddress.ip_network(x)) for x in (
        '172.29.172.251/32', '172.29.172.252/32', '172.29.172.253/32',
        '198.18.0.0/24', '198.19.255.128/25')})
    client = '10.244.31.2'
    native = ('[Interface]\nPrivateKey = ' + b64(private[0]) + '\nAddress = ' + client + '/32\nMTU = 1280\n'
              '[Peer]\nPublicKey = ' + b64(public[1]) + '\nEndpoint = 127.0.0.1:1\nAllowedIPs = ' + ', '.join(prefixes) + '\nPersistentKeepalive = 1\n')
    last = dict(hostName='127.0.0.1', port=1, client_ip=client+'/32', client_priv_key=b64(private[0]),
        client_pub_key=b64(public[0]), server_pub_key=b64(public[1]), psk_key=b64(bytes(32)),
        allowed_ips=prefixes, persistent_keep_alive='1', mtu='1280', config=native)
    profile = dict(format_version=1, description='SYNTHETIC Windows dataplane v1', hostName='127.0.0.1',
        defaultContainer='amnezia-awg2', dns1='172.29.172.251', dns2='172.29.172.252',
        containers=[dict(container='amnezia-awg2', awg=dict(port='1', transport_proto='udp', last_config=json.dumps(last)))],
        clientLogs=dict(clientId='owned-synthetic-fixture', token='disabled', enabled=False))
    config = dict(source_private_key=private[1].hex(), target_private_key=private[2].hex(),
        client_public_key=public[0].hex(), client_address=client, ttl_seconds=150)
    plan = dict(client_address=client, route_shape='synthetic-windows-dataplane-v1', fixture_prefix_count=len(prefixes))
    documents = {'profile-template.json': profile, 'expected-routes.json': prefixes,
                 'routes.json': dict(schema=1, fixture='synthetic-windows-dataplane-v1', prefixes=prefixes),
                 'config.json': config, 'observer-plan.json': plan}
    for name, value in documents.items():
        (output/name).write_text(json.dumps(value, sort_keys=True, separators=(',', ':')), encoding='utf-8')
    paths = dict(helper=helper, observer=observer, profile=output/'profile-template.json',
        expected_routes=output/'expected-routes.json', routes=output/'routes.json', config=output/'config.json', observer_plan=output/'observer-plan.json')
    files = {k: dict(path=str(p.resolve()), size=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for k,p in paths.items()}
    manifest = dict(schema=1, candidate_artifact_sha256=artifact_sha256, installed_exe_sha256=installed_exe_sha256, files=files)
    path = output/'manifest.json'
    path.write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')), encoding='utf-8')
    print(json.dumps(dict(manifest=str(path.resolve()), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        route_shape=plan['route_shape'], unique_prefixes=len(prefixes), runtime_pass=False, migration_pass=False)))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--helper',type=Path,required=True)
    p.add_argument('--observer',type=Path,required=True)
    p.add_argument('--artifact-sha256',required=True)
    p.add_argument('--installed-exe-sha256',required=True)
    a=p.parse_args()
    prepare(a.output,a.helper,a.observer,a.artifact_sha256,a.installed_exe_sha256)
