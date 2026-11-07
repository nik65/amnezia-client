"""Fixed owned-guest observation program; emits raw journal before failing.

Invoked by the fixed controller fixture only. XRes source is hash-bound by that
controller, never accepted from an operator callback or a guest PASS file.
"""
import base64
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid

LIMIT = 524288


def command(args, *, limit=LIMIT, timeout=12, allow_codes=(0,)):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    counts = dict.fromkeys(chunks, 0)
    deadline = time.monotonic() + timeout
    try:
        for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise RuntimeError('bounded guest observation timed out')
            for key, _ in selector.select(min(.1, max(.001, deadline-time.monotonic()))):
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                name = key.data
                counts[name] += len(data)
                retained = sum(len(value) for value in chunks.values())
                chunks[name].extend(data[:max(0, limit-retained)])
                if sum(counts.values()) > limit:
                    raise RuntimeError('bounded guest observation truncated')
        code = process.wait(timeout=max(.001, deadline-time.monotonic()))
        if code not in allow_codes:
            raise RuntimeError('guest observation command failed')
        return bytes(chunks['stdout'])
    except BaseException as error:
        print(json.dumps({'schema':'linux-desktop-command-failure-v1',
                          'error_type':type(error).__name__, 'counts':counts,
                          'stdout_base64':base64.b64encode(chunks['stdout']).decode(),
                          'stderr_base64':base64.b64encode(chunks['stderr']).decode(),
                          'truncated':sum(counts.values()) > limit}), flush=True)
        raise
    finally:
        selector.close()
        if process.returncode is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdout.close()
        process.stderr.close()


def process_identity(pid):
    path = Path('/proc') / str(pid)
    fields = (path/'stat').read_text().rsplit(')', 1)[1].split()
    uid = int(re.search(r'^Uid:\s+(\d+)', (path/'status').read_text(), re.M).group(1))
    env = dict(item.split(b'=', 1) for item in (path/'environ').read_bytes().split(b'\0') if b'=' in item)
    return {'pid': pid, 'start_ticks': int(fields[19]), 'exe': os.readlink(path/'exe'), 'uid': uid, 'state': fields[0]}, env


def journal_crashes(records):
    """Conservative crash/restart detector over complete filtered boot records."""
    starts = 0
    crash = False
    for row in records:
        message = row.get('MESSAGE', '')
        if not isinstance(message, str):
            raise RuntimeError('malformed journal message')
        lowered = message.lower()
        if 'GNOME Shell started' in message:
            starts += 1
        desktop = any(x in lowered for x in ('gnome-shell', 'gnome shell', 'gnome-session', 'llvmpipe', 'mutter'))
        if desktop and any(x in lowered for x in ('segfault', 'sigsegv', 'crashed with signal', 'dumped core', 'fatal error')):
            crash = True
        if row.get('COREDUMP_COMM') in ('gnome-shell', 'gnome-session-b', 'gnome-session', 'mutter'):
            crash = True
    return crash or starts > 1, starts


def journal_boot_selector(boot):
    parsed = uuid.UUID(boot)
    if str(parsed) != boot:
        raise RuntimeError('kernel boot identity is not canonical')
    # /proc exposes RFC UUID text; journalctl's boot descriptor uses sd-id128 hex.
    return parsed.hex


def shell_identity_stable(before, after):
    fields = ('pid', 'start_ticks', 'exe', 'uid')
    return (before.get('state') in ('R','S','I') and after.get('state') in ('R','S','I')
            and all(name in before and before[name] == after.get(name) for name in fields))


def observe(xres_source):
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    journal = command(['journalctl', '--boot='+journal_boot_selector(boot), '--no-pager', '-o', 'json',
                       '_COMM=gnome-shell', '+', '_COMM=gnome-session-b', '+',
                       'SYSLOG_IDENTIFIER=systemd-coredump', '+', '_TRANSPORT=kernel'])
    # Keep exact bytes for controller archival, including a failed probe.
    raw = {'schema': 'linux-desktop-live-probe-v1', 'boot_id': boot,
           'journal_base64': base64.b64encode(journal).decode(), 'observation': None}
    try:
        rows = [json.loads(line) for line in journal.splitlines()]
        if not rows or any(type(row) is not dict or row.get('_BOOT_ID', '').replace('-', '') != boot.replace('-', '') for row in rows):
            raise RuntimeError('journal boot identity missing or changed')
        crash, starts = journal_crashes(rows)
        if crash:
            raise RuntimeError('desktop crash or restart in current boot')
        if starts == 0:
            raw['pending_reason'] = 'desktop-startup-not-observed'
            return raw
        pids = command(['pgrep', '-u', '1000', '-x', 'gnome-shell'], limit=4096, allow_codes=(0, 1)).split()
        if not pids:
            raw['pending_reason'] = 'desktop-process-not-present'
            return raw
        if len(pids) != 1:
            raise RuntimeError('unique GNOME process unavailable')
        shell, env = process_identity(int(pids[0]))
        if env.get(b'GALLIUM_DRIVER') != b'softpipe':
            raise RuntimeError('GNOME softpipe environment differs')
        prefix = ['runuser', '-u', 'lab', '--', 'env', 'XDG_RUNTIME_DIR=/run/user/1000']
        initialized = command(prefix+['systemctl', '--user', 'show', 'gnome-session-initialized.target', '-pActiveState', '--value'], limit=4096).strip() == b'active'
        if not initialized:
            raw['pending_reason'] = 'desktop-initialization-pending'
            return raw
        for key in (b'DISPLAY', b'XAUTHORITY'):
            if key not in env:
                raise RuntimeError('owned display environment unavailable')
        display, auth = env[b'DISPLAY'].decode(), env[b'XAUTHORITY'].decode()
        if not re.fullmatch(r':[0-9]+(?:\.[0-9]+)?', display) or not auth.startswith('/run/user/1000/'):
            raise RuntimeError('display escaped local lab session')
        xres_bytes = command(prefix+['DISPLAY='+display, 'XAUTHORITY='+auth, '/usr/bin/python3', '-c', xres_source], limit=32768)
        # Preserve the bounded actual reply before parsing or pending/failure
        # branches; a missing identity must remain diagnosable after cleanup.
        raw['xres_reply_base64'] = base64.b64encode(xres_bytes).decode()
        xres = json.loads(xres_bytes)
        raw['xres'] = xres
        if xres.get('identityGap'):
            raw['pending_reason'] = 'wm-initialization-pending'
            return raw
        if xres.get('localPID') != shell['pid']:
            raise RuntimeError('XRes WM ownership unavailable')
        after, _ = process_identity(shell['pid'])
        if not shell_identity_stable(shell, after):
            raise RuntimeError('GNOME identity changed during observation')
        sessions = command(['loginctl', 'list-sessions', '--no-legend'], limit=16384).decode().splitlines()
        matching = []
        for line in sessions:
            fields = line.split()
            if len(fields) > 2 and fields[2] == 'lab':
                props = command(['loginctl', 'show-session', fields[0], '-pType', '-pActive', '-pState', '-pClass', '-pUser'], limit=4096).decode()
                if dict(item.split('=', 1) for item in props.splitlines()) == {'Type':'x11','Active':'yes','State':'active','Class':'user','User':'1000'}:
                    matching.append(fields[0])
        if len(matching) != 1:
            raise RuntimeError('unique initialized lab session unavailable')
        raw['observation'] = {'schema':'linux-desktop-observation-v1', 'boot_id':boot,
            'monotonic_ms':int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000),
            'session':{'initialized':initialized, 'active':True, 'type':'x11', 'uid':1000},
            'shell':shell, 'wm':{'owner_pid':xres['localPID'], 'owner_start_ticks':after['start_ticks']},
            'crash_history':{'complete_since_boot':True, 'events':[]}}
        return raw
    except BaseException as error:
        raw['error_type'] = type(error).__name__
        print(json.dumps(raw), flush=True)
        raise


if __name__ == '__main__':
    print(json.dumps(observe(base64.b64decode(sys.argv[1], validate=True).decode())), flush=True)
