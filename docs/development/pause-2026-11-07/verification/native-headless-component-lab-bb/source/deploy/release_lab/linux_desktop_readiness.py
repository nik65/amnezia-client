"""Pure GNOME readiness predicate, ONLY behind owned live acquisition.

Caller observations and pixel files are not authenticated by this module.
The controller must acquire/rehash them live under its ownership fences.
No result is GUI acceptance or PASS: pixels require separate root review.
"""
from dataclasses import dataclass
import re
import uuid


class DesktopObservationError(ValueError):
    pass


def _keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise DesktopObservationError('invalid observation shape')


def _integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise DesktopObservationError('invalid integer')


def _boot(value):
    if type(value) is not str:
        raise DesktopObservationError('invalid boot identity')
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise DesktopObservationError('invalid boot identity') from None


@dataclass(frozen=True)
class ReadinessDecision:
    ready_for_root_visual_review: bool
    reason: str
    boot_id: str
    observed_monotonic_ms: int
    dwell_started_ms: int | None
    shell_identity: tuple
    pixel_binding: tuple | None  # absent for explicitly nonvisual dwell samples


class DesktopReadinessTracker:
    def __init__(self, *, uid=1000, executable='/usr/bin/gnome-shell', dwell_ms=30000,
                 maximum_poll_gap_ms=10000):
        _integer(uid)
        _integer(dwell_ms, 1)
        _integer(maximum_poll_gap_ms, 1)
        if type(executable) is not str or not executable.startswith('/'):
            raise DesktopObservationError('invalid expected executable')
        self.uid, self.executable = uid, executable
        self.dwell_ms, self.maximum_poll_gap_ms = dwell_ms, maximum_poll_gap_ms
        self._boot = self._identity = self._last = self._since = None
        self._tainted_boots = set()

    def observe(self, observation):
        # Any malformed sample breaks continuous dwell, including callers that
        # catch validation errors and later continue feeding observations.
        try:
            return self._observe(observation)
        except DesktopObservationError:
            self._since = None
            raise

    def break_continuity(self):
        self._since = self._last = None  # sticky crash/PID-change taint survives gaps

    def observe_nonvisual(self, observation):
        """Accumulate real continuous health; never grants visual readiness."""
        try:
            return self._observe(observation, nonvisual=True)
        except DesktopObservationError:
            self._since = None
            raise

    def _observe(self, o, nonvisual=False):
        names = ('schema', 'boot_id', 'monotonic_ms', 'session', 'shell', 'wm', 'crash_history')
        _keys(o, names if nonvisual else (*names, 'pixels'))
        if o['schema'] != 'linux-desktop-observation-v1':
            raise DesktopObservationError('invalid schema')
        _boot(o['boot_id'])
        now = o['monotonic_ms']
        _integer(now)
        session, shell, wm, history = (o[k] for k in ('session', 'shell', 'wm', 'crash_history'))
        pixels = None if nonvisual else o['pixels']
        _keys(session, ('initialized', 'active', 'type', 'uid'))
        if type(session['initialized']) is not bool or type(session['active']) is not bool:
            raise DesktopObservationError('invalid session flags')
        _integer(session['uid'])
        if session['type'] not in ('x11', 'wayland'):
            raise DesktopObservationError('invalid session type')
        _keys(shell, ('pid', 'start_ticks', 'exe', 'uid', 'state'))
        _integer(shell['pid'], 1)
        _integer(shell['start_ticks'], 1)
        _integer(shell['uid'])
        if type(shell['exe']) is not str or not shell['exe'].startswith('/') or shell['state'] not in ('R', 'S', 'D', 'I', 'T', 't', 'Z', 'X'):
            raise DesktopObservationError('invalid process metadata')
        _keys(wm, ('owner_pid', 'owner_start_ticks'))
        _integer(wm['owner_pid'], 1)
        _integer(wm['owner_start_ticks'], 1)
        # Negative evidence is sticky as soon as it validates: later malformed
        # history/pixels must not erase an already observed process restart.
        identity = (shell['pid'], shell['start_ticks'], shell['exe'], shell['uid'], wm['owner_pid'], wm['owner_start_ticks'])
        if (self._boot == o['boot_id'] and self._identity is not None
                and self._identity[:4] != identity[:4]):
            self._tainted_boots.add(o['boot_id'])
        _keys(history, ('complete_since_boot', 'events'))
        if type(history['complete_since_boot']) is not bool or type(history['events']) is not list or len(history['events']) > 4096:
            raise DesktopObservationError('invalid crash history')
        for event in history['events']:
            _keys(event, ('boot_id', 'monotonic_ms', 'component', 'event', 'pid', 'start_ticks'))
            _boot(event['boot_id'])
            _integer(event['monotonic_ms'])
            _integer(event['pid'], 1)
            _integer(event['start_ticks'], 1)
            if event['component'] not in ('gnome-shell', 'gnome-session', 'mutter') or event['event'] not in ('crash', 'restart'):
                raise DesktopObservationError('invalid crash record')
            if event['boot_id'] == o['boot_id']:
                if event['monotonic_ms'] > now:
                    raise DesktopObservationError('future crash record')
                # Commit each validated crash immediately, even if a later
                # event or the diagnostic pixel record proves malformed.
                self._tainted_boots.add(o['boot_id'])
        if pixels is not None:
            _keys(pixels, ('path', 'sha256', 'size', 'captured_monotonic_ms', 'diagnosticOnly'))
            _integer(pixels['size'], 1)
            _integer(pixels['captured_monotonic_ms'])
        if pixels is not None and (type(pixels['path']) is not str or not pixels['path'].startswith('/')
                or type(pixels['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', pixels['sha256'])
                or pixels['diagnosticOnly'] is not True or pixels['captured_monotonic_ms'] > now):
            raise DesktopObservationError('invalid diagnostic pixel capture')
        if self._boot == o['boot_id'] and self._last is not None and now <= self._last:
            raise DesktopObservationError('nonincreasing observation time')
        reason = 'dwelling'
        healthy = True
        if o['boot_id'] in self._tainted_boots:
            healthy, reason = False, 'desktop-crash-or-restart-since-boot'
        elif not history['complete_since_boot']:
            healthy, reason = False, 'crash-history-incomplete'
        elif not session['initialized'] or not session['active'] or session['uid'] != self.uid:
            healthy, reason = False, 'session-not-initialized'
        elif shell['uid'] != self.uid or shell['exe'] != self.executable or shell['state'] not in ('R', 'S', 'I'):
            healthy, reason = False, 'shell-not-healthy'
        elif (wm['owner_pid'], wm['owner_start_ticks']) != (shell['pid'], shell['start_ticks']):
            healthy, reason = False, 'stale-wm-owner'
        continuity = (self._boot == o['boot_id'] and self._identity == identity
                      and self._last is not None and now - self._last <= self.maximum_poll_gap_ms)
        if not healthy:
            self._since = None
        elif self._since is None or not continuity:
            self._since = now
        self._boot, self._identity, self._last = o['boot_id'], identity, now
        ready = healthy and now - self._since >= self.dwell_ms
        if ready and (pixels is None or pixels['captured_monotonic_ms'] <= self._since):
            ready, reason = False, 'fresh-pixel-capture-required'
        elif ready:
            reason = 'ready-for-root-visual-review'
        return ReadinessDecision(ready, reason, o['boot_id'], now, self._since, identity,
                                 None if pixels is None else (pixels['path'], pixels['sha256'], pixels['size'], pixels['captured_monotonic_ms']))
