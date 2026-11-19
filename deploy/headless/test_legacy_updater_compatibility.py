"""Portable contract regressions; authenticator mocks are not signature evidence."""
import unittest
from pathlib import Path
from unittest.mock import patch
import check_legacy_updater_compatibility as c

class ContractTests(unittest.TestCase):
    def payload(self, files=None):
        return {'version': '5.0.3.18', 'headlessProvisioning': {'packageFiles': list(c.LEGACY_FILES) if files is None else files}}
    def test_exact_legacy_shape(self):
        c.validate_file_contract(self.payload(), c.LEGACY_FILES)
    def test_ninth_file_rejected_even_after_authentication(self):
        with self.assertRaisesRegex(SystemExit, 'signing alone'):
            c.validate_file_contract(self.payload(list(c.LEGACY_FILES)+['amnezia-verify-provisioning-native']), c.LEGACY_FILES)
    def test_reordered_rejected(self):
        with self.assertRaises(SystemExit):c.validate_file_contract(self.payload(list(reversed(c.LEGACY_FILES))), c.LEGACY_FILES)
    def test_missing_rejected(self):
        with self.assertRaises(SystemExit):c.validate_file_contract(self.payload(list(c.LEGACY_FILES[:-1])), c.LEGACY_FILES)
    def test_duplicate_rejected(self):
        with self.assertRaises(SystemExit):c.validate_file_contract(self.payload(list(c.LEGACY_FILES[:-1])+['amneziad']), c.LEGACY_FILES)
    def test_string_rejected(self):
        with self.assertRaises(SystemExit):c.validate_file_contract(self.payload('SHA256SUMS'), c.LEGACY_FILES)
    def test_missing_provisioning_rejected(self):
        with self.assertRaises(SystemExit):c.validate_file_contract({}, c.LEGACY_FILES)
    def test_unknown_baseline_source_rejected(self):
        with self.assertRaises(SystemExit):c.baseline_contract(b'unknown source')
    def test_existing_authenticator_receives_both_pinned_inputs(self):
        with patch.object(c,'baseline_contract',return_value=c.LEGACY_FILES), patch.object(c,'decode_manifest_envelope',return_value=(self.payload(),b'payload','signature')), patch.object(c,'verify_signature') as auth:
            result=c.check(b'source',b'old',b'new',Path('public.pem'),'a'*64)
            self.assertEqual(auth.call_count,2)
            auth.assert_called_with(Path('public.pem'),b'payload','signature','a'*64)
            self.assertFalse(result['release_acceptance']);self.assertFalse(result['runtime_tested'])
    def test_signature_failure_is_not_suppressed(self):
        with patch.object(c,'baseline_contract',return_value=c.LEGACY_FILES), patch.object(c,'decode_manifest_envelope',return_value=(self.payload(),b'payload','signature')), patch.object(c,'verify_signature',side_effect=SystemExit('signature failed')):
            with self.assertRaisesRegex(SystemExit,'signature failed'):c.check(b'',b'',b'',Path('public.pem'),'a'*64)
    def test_valid_signatures_still_reject_ninth(self):
        old=self.payload();new=self.payload(list(c.LEGACY_FILES)+['amnezia-verify-provisioning-native'])
        with patch.object(c,'baseline_contract',return_value=c.LEGACY_FILES), patch.object(c,'decode_manifest_envelope',side_effect=[(old,b'old','sig'),(new,b'new','sig')]), patch.object(c,'verify_signature'):
            with self.assertRaisesRegex(SystemExit,'signing alone'):c.check(b'',b'',b'',Path('public.pem'),'a'*64)
    def test_wrong_baseline_version_rejected(self):
        p=self.payload();p['version']='5.0.3.17'
        with patch.object(c,'baseline_contract',return_value=c.LEGACY_FILES), patch.object(c,'decode_manifest_envelope',return_value=(p,b'x','sig')), patch.object(c,'verify_signature'):
            with self.assertRaisesRegex(SystemExit,'exact 5.0.3.18'):c.check(b'',b'',b'',Path('public.pem'),'a'*64)
if __name__=='__main__':unittest.main()
