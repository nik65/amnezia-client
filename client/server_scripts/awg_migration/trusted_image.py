"""Reviewed official AWG 3.1 image catalog; invoked by authenticated admin only.

Provenance: https://hub.docker.com/v2/repositories/amneziavpn/amneziawg-go/tags/3.1.20260814
Official Dockerfile: https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260814/Dockerfile
The upstream Dockerfile builds directly, so version.go retains 0.0.20250522.
The immutable manifest and binary hash identify this reviewed v3 image, rather
than interpreting that stale string as its protocol version. Preparation must
also observe actual HeaderProtectionKey/S1/S2/S3/S4 configuration roundtrips.
No registry name, tag, command or architecture is supplied by an operator.
"""
import json
import subprocess

IMAGE = 'amneziavpn/amneziawg-go@sha256:4e1fd2840f8d26eb6ec8bc1598e66f2f17f5d0201cd2baadbde560c104d4fc9d'
IMAGE_ID = 'sha256:777f70bf17917842a532ffba9643e92284ffc003e054a567e64fca74f97b8aff'
BINARY_SHA256 = '6d96502ebd9ed6f9d17bdecd637cba7502c9960fed1b6922b3882784417a036d'
REPORTED_VERSION = 'amneziawg-go 0.0.20250522\n\nUserspace AmneziaWG daemon for linux-amd64.\nInformation available at https://amnezia.org'


def identity_matches(image):
    # Classic Docker reports the config hash; the containerd image store reports
    # the manifest hash and descriptor. Both must retain this exact RepoDigest.
    if IMAGE not in (image.get('RepoDigests') or []):
        return False
    manifest = IMAGE.rsplit('@', 1)[1]
    return (image.get('Id') == IMAGE_ID or
            (image.get('Id') == manifest and
             image.get('Descriptor', {}).get('digest') == manifest))


def resolve_image(run):
    """Pull only reviewed bytes, verify Linux amd64 and isolated executable probe.

    run is the existing private-output subprocess runner. No TUN device, mount,
    network, host namespace, or elevated container capability is used here.
    """
    try:
        host = json.loads(run('docker', 'info', '--format', '{{json .}}'))
        if host.get('OSType') != 'linux' or host.get('Architecture') not in ('x86_64', 'amd64'):
            raise ValueError('unsupported_server_architecture')
        try:
            cached = json.loads(run('docker', 'image', 'inspect', IMAGE))
        except Exception:
            cached = []
        if not (len(cached) == 1 and identity_matches(cached[0])
                and cached[0].get('Os') == 'linux' and cached[0].get('Architecture') == 'amd64'):
            try:
                run('docker', 'pull', '--platform', 'linux/amd64', IMAGE)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                # Only the download operation is retryable. Identity/executable
                # probe errors below retain their permanent trust failure.
                raise ValueError('image_fetch_unavailable') from None
        images = json.loads(run('docker', 'image', 'inspect', IMAGE))
        if len(images) != 1 or not identity_matches(images[0]):
            raise ValueError('trusted_image_unavailable')
        if images[0].get('Os') != 'linux' or images[0].get('Architecture') != 'amd64':
            raise ValueError('unsupported_server_architecture')
        sandbox = ('docker', 'run', '--rm', '--network', 'none', '--read-only',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '--pids-limit', '32', '--memory', '64m', '--cpus', '1')
        hashed = run(*sandbox, '--entrypoint', 'sha256sum', IMAGE, '/usr/bin/amneziawg-go').decode().strip()
        if hashed != BINARY_SHA256 + '  /usr/bin/amneziawg-go':
            raise ValueError('trusted_image_unavailable')
        version = run(*sandbox, '--entrypoint', '/usr/bin/amneziawg-go', IMAGE, '--version').decode().strip()
        if version != REPORTED_VERSION:
            raise ValueError('trusted_image_unavailable')
        # All commands subsequently used by the fixed startup script must exist.
        tools = run(*sandbox, '--entrypoint', 'sh', IMAGE, '-c',
                    'set -eu; for tool in awg awg-quick amneziawg-go iptables ip sleep mv cat cut sha256sum; do command -v "$tool" >/dev/null; done; printf ready').decode()
        if tools != 'ready':
            raise ValueError('trusted_image_unavailable')
        return IMAGE
    except ValueError as error:
        if str(error) in ('unsupported_server_architecture', 'image_fetch_unavailable'):
            raise
        raise ValueError('trusted_image_unavailable') from None
    except Exception:
        raise ValueError('trusted_image_unavailable') from None
