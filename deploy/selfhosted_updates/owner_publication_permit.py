"""Explicit owner-authorized normal-flow publication permit for the owner-approved 5.0.3.13.

This is not release acceptance. Ordinary builds never invoke this issuer.
No acquisition PASS records are accepted or manufactured here.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import unquote, urlsplit
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
try:
    from . import make_manifest as manifest
except ImportError:
    import make_manifest as manifest

SCHEMA = 'amnezia-owner-publication-permit-v1'
DOMAIN = (SCHEMA + '\n').encode('ascii')
POLICY = 'amnezia-owner-release-50313-v1'
VERSION = '5.0.3.13'
ANDROID_CODE = 2199
TARGETS = ['android-real-device', 'linux-gui', 'linux-headless', 'windows-runtime']
FIELDS = {'schema','policyId','version','androidVersionCode','manifestSha256','publisherSha256','artifacts','issuedAt','expiresAt','acceptanceStatus','unverifiedTargets','invocation'}
PLATFORMS = {'windows-x64','linux-x64','android-arm64-v8a','linux-headless-x64'}
MAX_BYTES = 1024 * 1024
MAX_PERMIT_BYTES = 128 * 1024

def fail(message):
    raise SystemExit('OWNER_PERMIT_REJECTED: ' + message)

def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',',':')).encode('utf-8')

def strict_json(data: bytes):
    if not data or len(data) > MAX_BYTES:
        fail('JSON size')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=manifest.strict_json_object,
                          parse_constant=lambda value: fail('nonfinite JSON number'))
    except (ValueError, UnicodeError) as error:
        fail('invalid UTF-8 JSON: ' + str(error))

def no_links(path: Path):
    for current in (path, *path.parents):
        st = current.lstat()
        if stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
            fail('symlink/reparse point')

def regular_digest(path: Path, *, limit: int | None = None) -> tuple[str, int]:
    """Stream through one descriptor, then reject mutation/replacement or links."""
    no_links(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or (limit and before.st_size > limit):
        fail('nonregular, empty or oversized input')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            fail('input replaced before read')
        count = 0
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            count += len(block)
            if count > before.st_size:
                fail('input grew during read')
            digest.update(block)
        after = os.fstat(stream.fileno())
    no_links(path)
    final = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    # Windows path stat and descriptor stat can expose different ctime semantics.
    # Compare each ctime through the same API while binding inode/size/mtime across APIs.
    if (count != before.st_size or identity(before) != identity(after) or identity(before) != identity(final)
            or before.st_ctime_ns != final.st_ctime_ns or opened.st_ctime_ns != after.st_ctime_ns):
        fail('input changed during read')
    return digest.hexdigest(), count

def read_small(path: Path) -> bytes:
    digest, size = regular_digest(path, limit=MAX_BYTES)
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        fail('small input changed')
    no_links(path)
    return data

def verify_signature(public_key: Path, raw: bytes, signature: bytes):
    try:
        key = load_pem_public_key(read_small(public_key))
        if not isinstance(key, Ed25519PublicKey) or len(signature) != 64:
            fail('Ed25519 key/signature required')
        key.verify(signature, raw)
    except Exception as error:
        fail('signature verification: ' + str(error))

def decode64(value, url=False):
    if not isinstance(value, str) or not value:
        fail('missing base64')
    try:
        if url:
            if not re.fullmatch(r'[A-Za-z0-9_-]+', value):
                fail('noncanonical base64url')
            data = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
            canonical = manifest.b64url(data)
        else:
            data = base64.b64decode(value, validate=True)
            canonical = base64.b64encode(data).decode('ascii')
        if canonical != value:
            fail('noncanonical base64')
        return data
    except (ValueError, TypeError) as error:
        fail('invalid base64: ' + str(error))

def artifact_records(value):
    if not isinstance(value, list) or len(value) != 5:
        fail('exactly five inner artifacts required')
    previous = ''
    for item in value:
        if not isinstance(item, dict) or set(item) != {'path','sha256','size'}:
            fail('artifact exact fields')
        name = item['path']
        if (not isinstance(name, str) or not name.startswith('files/') or '\\' in name
                or name <= previous or len(name.encode('utf-8')) > 4096
                or any(ord(c) < 0x20 or ord(c) == 0x7f or ord(c) > 0x7e or c in ':?#' for c in name)
                or any(x in ('', '.', '..') for x in name.split('/'))):
            fail('unsafe, duplicate or unordered artifact path')
        if (not isinstance(item['sha256'], str) or not manifest.SHA256_RE.fullmatch(item['sha256'])
                or type(item['size']) is not int or not 0 < item['size'] <= manifest.MAX_POLICY_GENERATION):
            fail('artifact hash/size')
        previous = name
    return value

def timestamp(value):
    if not isinstance(value, str) or not manifest.CANONICAL_UTC_RE.fullmatch(value):
        fail('canonical UTC required')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        fail('invalid UTC date')

def validate_payload(payload, *, manifest_sha256=None, publisher_sha256=None, artifacts=None, now=None):
    if not isinstance(payload, dict) or set(payload) != FIELDS:
        fail('exact owner payload fields')
    if (type(payload['schema']) is not int or payload['schema'] != 1
            or payload['policyId'] != POLICY or payload['version'] != VERSION
            or type(payload['androidVersionCode']) is not int or payload['androidVersionCode'] != ANDROID_CODE
            or payload['acceptanceStatus'] != 'owner-approved-unverified'
            or payload['unverifiedTargets'] != TARGETS or payload['invocation'] != 'normal'):
        fail('owner13/2199 policy/constants')
    for name, expected in [('manifestSha256',manifest_sha256),('publisherSha256',publisher_sha256)]:
        actual = payload[name]
        if not isinstance(actual, str) or not manifest.SHA256_RE.fullmatch(actual) or (expected is not None and actual != expected):
            fail('hash binding: ' + name)
    artifact_records(payload['artifacts'])
    if artifacts is not None and payload['artifacts'] != artifacts:
        fail('exact artifact closure mismatch')
    issued, expires = timestamp(payload['issuedAt']), timestamp(payload['expiresAt'])
    now = now or datetime.now(timezone.utc)
    if not issued <= now < expires or not issued < expires <= issued + timedelta(hours=24):
        fail('future, expired or excessive permit lifetime')
    return payload

def decode_permit(data: bytes, public_key: Path, **expected):
    if not data or len(data) > MAX_PERMIT_BYTES:
        fail('owner permit exceeds runtime128KiB limit')
    envelope = strict_json(data)
    if (not isinstance(envelope, dict) or set(envelope) != {'schema','signatureAlgorithm','payload','signature'}
            or envelope['schema'] != SCHEMA or envelope['signatureAlgorithm'] != 'Ed25519'):
        fail('exact owner envelope fields/domain')
    if canonical(envelope) != data:
        fail('noncanonical owner envelope')
    raw, signature = decode64(envelope['payload'], True), decode64(envelope['signature'])
    if not raw.startswith(DOMAIN):
        fail('wrong signature domain')
    payload = strict_json(raw[len(DOMAIN):])
    if canonical(payload) != raw[len(DOMAIN):]:
        fail('noncanonical owner payload')
    verify_signature(public_key, raw, signature)
    return validate_payload(payload, **expected)

def bundle_bindings(bundle: Path, publisher: Path, public_key: Path):
    bundle = bundle.absolute()
    no_links(bundle)
    data = read_small(bundle/'manifest.json')
    envelope = strict_json(data)
    if (not isinstance(envelope, dict) or set(envelope) != {'schema','signatureAlgorithm','payload','signature'}
            or envelope['schema'] != 'amnezia-selfhosted-update-v1' or envelope['signatureAlgorithm'] != 'Ed25519'):
        fail('exact update manifest envelope')
    raw = decode64(envelope['payload'], True)
    verify_signature(public_key, raw, decode64(envelope['signature']))
    document = strict_json(raw)
    if not isinstance(document, dict):
        fail('manifest payload object required')
    platforms = document.get('platforms')
    if (document.get('version') != VERSION or type(document.get('schema')) is not int or document['schema'] not in (1,2)
            or not isinstance(platforms, dict) or set(platforms) != PLATFORMS
            or not all(isinstance(item, dict) for item in platforms.values())
            or type(platforms['android-arm64-v8a'].get('versionCode')) is not int
            or platforms['android-arm64-v8a']['versionCode'] != ANDROID_CODE
            or document.get('rollback') or document.get('rollbackArtifacts')):
        fail('signed manifest must be exact13/2199 four platforms without rollback')
    items = list(platforms.values()) + [document.get('headlessProvisioning')]
    expected = []
    for item in items:
        if not isinstance(item, dict) or item.get('openExternal') or not isinstance(item.get('url'), str):
            fail('local signed artifact required')
        url = item['url']; parsed = urlsplit(url)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            fail('artifact URL must be local relative')
        name = unquote(url)
        expected.append({'path':name,'sha256':item.get('sha256'),'size':item.get('size')})
    expected.sort(key=lambda e:e['path'])
    artifact_records(expected)
    files_root = bundle/'files'; no_links(files_root)
    actual=[]
    for path in sorted(files_root.rglob('*')):
        no_links(path)
        if path.is_dir(): continue
        digest,size=regular_digest(path)
        actual.append({'path':path.relative_to(bundle).as_posix(),'sha256':digest,'size':size})
    if actual != expected:
        fail('bundle files differ from all five signed manifest artifacts')
    publisher_sha,size = regular_digest(publisher)
    return {'manifestSha256':hashlib.sha256(data).hexdigest(),'publisherSha256':publisher_sha,'artifacts':actual}

def issue_owner_permit(*, bundle: Path, publisher: Path, public_key: Path, private_key: Path,
                        output: Path, acknowledge: str, issued_at: str, expires_at: str):
    if acknowledge != VERSION:
        fail('explicit owner owner-unverified acknowledgement required')
    if output.name != 'owner-publication-permit.json' or output.exists():
        fail('new detached owner-publication-permit.json required; refuse overwrite')
    no_links(output.parent)
    output_parent_identity = (output.parent.stat().st_dev, output.parent.stat().st_ino)
    def check_output_destination():
        no_links(output.parent)
        if output.exists() or (output.parent.stat().st_dev, output.parent.stat().st_ino) != output_parent_identity:
            fail('output destination changed or exists')
    if output.parent.resolve() != bundle.resolve() or (bundle/'release-acceptance.json').exists():
        fail('owner sidecar must sit beside manifest without full-acceptance sidecar')
    # No private-key read/sign before complete public checks and exact closure.
    bindings=bundle_bindings(bundle,publisher,public_key)
    payload={'schema':1,'policyId':POLICY,'version':VERSION,'androidVersionCode':ANDROID_CODE,
             'issuedAt':issued_at,'expiresAt':expires_at,'acceptanceStatus':'owner-approved-unverified',
             'unverifiedTargets':list(TARGETS),'invocation':'normal',**bindings}
    validate_payload(payload)
    if bindings != bundle_bindings(bundle,publisher,public_key):
        fail('bundle/publisher changed before signing')
    raw=DOMAIN+canonical(payload)
    prototype={'schema':SCHEMA,'signatureAlgorithm':'Ed25519','payload':manifest.b64url(raw),'signature':base64.b64encode(bytes(64)).decode('ascii')}
    if len(canonical(prototype)) > MAX_PERMIT_BYTES:
        fail('permit exceeds runtime size limit')
    check_output_destination()
    signature=manifest.sign_payload(private_key,raw)
    envelope={'schema':SCHEMA,'signatureAlgorithm':'Ed25519','payload':manifest.b64url(raw),'signature':signature}
    encoded=canonical(envelope)
    # Verify signing identity against existing trusted PUBLIC key and rehash after signing.
    decode_permit(encoded,public_key,**{'manifest_sha256':bindings['manifestSha256'],
                  'publisher_sha256':bindings['publisherSha256'],'artifacts':bindings['artifacts']})
    if bindings != bundle_bindings(bundle,publisher,public_key):
        fail('bundle/publisher changed during signing')
    check_output_destination()
    with output.open('xb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    if regular_digest(output, limit=MAX_PERMIT_BYTES) != (hashlib.sha256(encoded).hexdigest(), len(encoded)):
        fail('written permit changed')
    return payload

def main(argv=None):
    parser=argparse.ArgumentParser(allow_abbrev=False,description='Explicit owner-approved owner-unverified13/2199 permit; not acceptance')
    parser.add_argument('command',choices=['issue-owner-publication-permit'])
    for name in ('bundle','publisher-script','public-key','private-key','output'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--acknowledge-unverified-release',required=True,choices=[VERSION])
    parser.add_argument('--issued-at',required=True)
    parser.add_argument('--expires-at',required=True)
    args=parser.parse_args(argv)
    issue_owner_permit(bundle=args.bundle,publisher=args.publisher_script,public_key=args.public_key,
                        private_key=args.private_key,output=args.output,acknowledge=args.acknowledge_unverified_release,
                        issued_at=args.issued_at,expires_at=args.expires_at)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
