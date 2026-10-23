import unittest
from .linux_desktop_readiness import DesktopObservationError, DesktopReadinessTracker

BOOT = '11111111-1111-4111-8111-111111111111'


def sample(now=0):
    return {'schema': 'linux-desktop-observation-v1', 'boot_id': BOOT, 'monotonic_ms': now,
            'session': {'initialized': True, 'active': True, 'type': 'x11', 'uid': 1000},
            'shell': {'pid': 80, 'start_ticks': 100, 'exe': '/usr/bin/gnome-shell', 'uid': 1000, 'state': 'S'},
            'wm': {'owner_pid': 80, 'owner_start_ticks': 100},
            'crash_history': {'complete_since_boot': True, 'events': []},
            'pixels': {'path': '/private/desktop.png', 'sha256': 'a' * 64, 'size': 100,
                       'captured_monotonic_ms': now, 'diagnosticOnly': True}}


class DesktopReadinessTests(unittest.TestCase):
    def dwell(self, tracker):
        for now in (0, 10000, 20000, 30000):
            result = tracker.observe(sample(now))
        return result

    def test_dwell_only_permits_root_pixel_review(self):
        result = self.dwell(DesktopReadinessTracker())
        self.assertTrue(result.ready_for_root_visual_review)
        self.assertFalse(hasattr(result, 'PASS'))
        self.assertEqual(result.pixel_binding, ('/private/desktop.png', 'a' * 64, 100, 30000))

    def test_same_live_pid_and_wm_with_sigsegv_rejected_and_taint_sticks(self):
        tracker = DesktopReadinessTracker()
        self.dwell(tracker)
        o = sample(40000)
        o['crash_history']['events'] = [{'boot_id': BOOT, 'monotonic_ms': 35000,
            'component': 'gnome-shell', 'event': 'crash', 'pid': 80, 'start_ticks': 100}]
        self.assertFalse(tracker.observe(o).ready_for_root_visual_review)
        self.assertEqual(tracker.observe(sample(50000)).reason, 'desktop-crash-or-restart-since-boot')

    def test_pid_reuse_and_restart_without_crash_record_rejected(self):
        for field, value in (('pid', 81), ('start_ticks', 101)):
            tracker = DesktopReadinessTracker()
            tracker.observe(sample())
            o = sample(10000)
            o['shell'][field] = value
            o['wm']['owner_pid'] = o['shell']['pid']
            o['wm']['owner_start_ticks'] = o['shell']['start_ticks']
            self.assertEqual(tracker.observe(o).reason, 'desktop-crash-or-restart-since-boot')

    def test_validated_crash_stays_sticky_when_pixels_or_later_event_invalid(self):
        for invalid_part in ('pixels', 'later-event'):
            tracker = DesktopReadinessTracker()
            tracker.observe(sample())
            o = sample(10000)
            o['crash_history']['events'] = [{'boot_id': BOOT, 'monotonic_ms': 9000,
                'component': 'gnome-shell', 'event': 'crash', 'pid': 80, 'start_ticks': 100}]
            if invalid_part == 'pixels':
                o['pixels']['sha256'] = 'invalid'
            else:
                o['crash_history']['events'].append({'malformed': True})
            with self.subTest(invalid_part=invalid_part), self.assertRaises(DesktopObservationError):
                tracker.observe(o)
            for now in (20000, 30000, 40000, 50000):
                decision = tracker.observe(sample(now))
                self.assertFalse(decision.ready_for_root_visual_review)
                self.assertEqual(decision.reason, 'desktop-crash-or-restart-since-boot')

    def test_validated_restart_stays_sticky_when_pixel_record_invalid(self):
        tracker = DesktopReadinessTracker()
        tracker.observe(sample())
        o = sample(10000)
        o['shell']['start_ticks'] = 101
        o['wm']['owner_start_ticks'] = 101
        o['pixels']['sha256'] = 'invalid'
        with self.assertRaises(DesktopObservationError):
            tracker.observe(o)
        for now in (20000, 30000, 40000, 50000):
            decision = tracker.observe(sample(now))
            self.assertFalse(decision.ready_for_root_visual_review)
            self.assertEqual(decision.reason, 'desktop-crash-or-restart-since-boot')

    def test_stale_wm_initialization_and_zombie_fail_closed(self):
        for section, field, value, reason in (
                ('wm', 'owner_start_ticks', 99, 'stale-wm-owner'),
                ('session', 'initialized', False, 'session-not-initialized'),
                ('shell', 'state', 'Z', 'shell-not-healthy'),
                ('shell', 'uid', 0, 'shell-not-healthy'),
                ('shell', 'exe', '/tmp/gnome-shell', 'shell-not-healthy'),
                ('crash_history', 'complete_since_boot', False, 'crash-history-incomplete')):
            o = sample()
            o[section][field] = value
            self.assertEqual(DesktopReadinessTracker().observe(o).reason, reason)

    def test_stale_pixels_and_poll_gap_do_not_complete_dwell(self):
        tracker = DesktopReadinessTracker()
        for now in (0, 10000, 20000):
            tracker.observe(sample(now))
        o = sample(30000)
        o['pixels']['captured_monotonic_ms'] = 0
        self.assertEqual(tracker.observe(o).reason, 'fresh-pixel-capture-required')
        self.assertFalse(tracker.observe(sample(50000)).ready_for_root_visual_review)

    def test_malformed_sample_breaks_dwell_and_rejects_imported_healthy(self):
        tracker = DesktopReadinessTracker()
        tracker.observe(sample())
        bad = sample(10000)
        bad['healthy'] = True
        with self.assertRaises(DesktopObservationError):
            tracker.observe(bad)
        self.assertEqual(tracker.observe(sample(20000)).dwell_started_ms, 20000)
        bad_cases = []
        for path, value in ((('shell', 'pid'), True), (('pixels', 'diagnosticOnly'), False),
                            (('pixels', 'sha256'), 'invalid'), (('session', 'initialized'), 'yes')):
            o = sample()
            o[path[0]][path[1]] = value
            bad_cases.append(o)
        o = sample()
        o['crash_history']['events'] = [{'boot_id': BOOT, 'monotonic_ms': 1,
            'component': 'gnome-shell', 'event': 'crash', 'pid': 80, 'start_ticks': 100}]
        bad_cases.append(o)
        o = sample()
        o['crash_history']['events'] = [{'status': 'PASS'}]
        bad_cases.append(o)
        for o in bad_cases:
            with self.subTest(observation=o), self.assertRaises(DesktopObservationError):
                DesktopReadinessTracker().observe(o)

    def test_new_boot_resets_dwell_and_nonincreasing_time_rejected(self):
        tracker = DesktopReadinessTracker()
        self.dwell(tracker)
        with self.assertRaises(DesktopObservationError):
            tracker.observe(sample(30000))
        o = sample(1)
        o['boot_id'] = '22222222-2222-4222-8222-222222222222'
        self.assertEqual(tracker.observe(o).dwell_started_ms, 1)


if __name__ == '__main__':
    unittest.main()
