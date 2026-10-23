"""Pure orchestration tests; no real keys, signing, release files or runtime."""
import copy
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from . import coordinated_release_acceptance as facade
from . import trusted_acquisition_export as authority


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        public = Path(self.tmp.name) / 'mock-public'; public.write_bytes(b'no key')
        self.binding = {'manifest': 'final'}
        self.context = SimpleNamespace(verify=Mock(), binding=lambda: copy.deepcopy(self.binding),
            manifest={'sha256': 'a'*64}, publisher={'sha256': 'b'*64}, version='5.0.3.14',
            android_code=2200, artifacts=[{'path':'files/a','size':1,'sha256':'c'*64}], public_key=public)
        self.old = SimpleNamespace(verify=Mock())
        self.now = authority.utc_now()
        self.proofs = {}
        for target in ('android','windows','linux-gui',facade.COORDINATED_TARGET):
            self.proofs[target] = {'target':target, 'runId':'run-a','profileId':'profile-a',
                'binding':copy.deepcopy(self.binding), 'expiresAt':authority.utc_text(self.now+timedelta(minutes=30)),
                'cleanupCapture':{'raw':'actual-original'}, 'rawCapture':{'raw':'actual-original'},
                'provenance':[{'path':'original'}]}
        self.proofs[facade.COORDINATED_TARGET]['semantics'] = dict.fromkeys(facade.COORDINATED_SEMANTICS, True)
        self.inputs = dict(context=self.context, windows_export={'role':'windows'}, gui_export={'role':'linux-gui'},
            coordinated_headless_export={'role':facade.COORDINATED_TARGET}, android_export={'role':'android'},
            original_android_context=self.old, original_android_bytes=b'original')
        self.patches = [patch.object(authority,'verify_export',side_effect=lambda e,**k:copy.deepcopy(self.proofs[e['role']])),
            patch.object(facade,'verify_android_equivalence',side_effect=lambda *a,**k:(copy.deepcopy(self.proofs['android']),{'historical':True})),
            patch.object(facade,'_verify_coordinated',side_effect=lambda e,**k:copy.deepcopy(self.proofs[e['role']]))]
        for p in self.patches: p.start(); self.addCleanup(p.stop)

    def prepare(self): return facade.prepare_coordinated_matrix(**self.inputs)

    def test_complete_distinct_originals_and_digest(self):
        before=copy.deepcopy({k:v for k,v in self.inputs.items() if k.endswith('_export')})
        receipts,proof,expiry=self.prepare()
        self.assertEqual([r['platform'] for r in receipts],['android','linux','windows'])
        self.assertEqual(proof['observations'][2]['target'],facade.COORDINATED_TARGET)
        self.assertEqual(receipts[1]['receiptSha256'],facade._digest([self.proofs['linux-gui'],self.proofs[facade.COORDINATED_TARGET]]))
        self.assertEqual(before,{k:v for k,v in self.inputs.items() if k.endswith('_export')})

    def test_wrong_old_role(self):
        self.inputs['windows_export']={'role':'android'}
        with self.assertRaises(authority.TrustedAcquisitionError):self.prepare()

    def test_duplicate_export(self):
        self.inputs['gui_export']=self.inputs['windows_export']
        with self.assertRaises(authority.TrustedAcquisitionError):self.prepare()

    def test_legacy_headless_shape_rejected(self):
        self.proofs[facade.COORDINATED_TARGET]['target']='linux-headless'
        with self.assertRaises(authority.TrustedAcquisitionError):self.prepare()

    def test_missing_false_extra_stage(self):
        original=copy.deepcopy(self.proofs[facade.COORDINATED_TARGET]['semantics'])
        for variant in ({**original,'resume':False},{k:v for k,v in original.items() if k!='heldReboot'},{**original,'rollback':True}):
            with self.subTest(variant=variant):
                self.proofs[facade.COORDINATED_TARGET]['semantics']=variant
                with self.assertRaises(authority.TrustedAcquisitionError):self.prepare()

    def test_wrong_current_binding(self):
        self.proofs[facade.COORDINATED_TARGET]['binding']={'manifest':'old'}
        with self.assertRaises(authority.TrustedAcquisitionError):self.prepare()

    def test_bool_is_not_integer_in_nested_binding(self):
        self.binding['nested']={'size':1}
        for p in self.proofs.values():p['binding']=copy.deepcopy(self.binding)
        self.proofs[facade.COORDINATED_TARGET]['binding']['nested']['size']=True
        with self.assertRaises(authority.TrustedAcquisitionError):self.prepare()

    def test_expired_original(self):
        self.proofs['android']['expiresAt']=authority.utc_text(self.now-timedelta(seconds=1))
        with self.assertRaises(authority.TrustedAcquisitionError):self.prepare()

    def test_source_verifiers_fail_closed(self):
        for name,owner in (('verify_export',authority),('verify_android_equivalence',facade),('_verify_coordinated',facade)):
            with self.subTest(name=name),patch.object(owner,name,side_effect=authority.TrustedAcquisitionError('raw/source/signature/cleanup rejected')):
                with self.assertRaises(authority.TrustedAcquisitionError):self.prepare()

    def test_second_validation_failure_never_accesses_key(self):
        first=self.prepare()
        with patch.object(facade,'prepare_coordinated_matrix',side_effect=[first,authority.TrustedAcquisitionError('changed')]),patch.object(authority.make_manifest,'verify_public_key_matches_private') as key,patch.object(authority.make_manifest,'acceptance_envelope') as sign:
            with self.assertRaises(authority.TrustedAcquisitionError):facade.issue_coordinated_acceptance(private_key='never-open',**self.inputs)
            key.assert_not_called();sign.assert_not_called()

    def test_second_mutation_never_accesses_key(self):
        first=self.prepare(); changed=copy.deepcopy(first);changed[1]['observations'][0]['payload']['rawCapture']={'mutated':True}
        with patch.object(facade,'prepare_coordinated_matrix',side_effect=[first,changed]),patch.object(authority.make_manifest,'verify_public_key_matches_private') as key:
            with self.assertRaises(authority.TrustedAcquisitionError):facade.issue_coordinated_acceptance(private_key='never-open',**self.inputs)
            key.assert_not_called()

    def test_second_source_or_context_mutation_never_accesses_key(self):
        first=self.prepare()
        for field in ('aggregateProducer','binding'):
            changed=copy.deepcopy(first);changed[1][field]={'mutated':True}
            with self.subTest(field=field),patch.object(facade,'prepare_coordinated_matrix',side_effect=[first,changed]),patch.object(authority.make_manifest,'verify_public_key_matches_private') as key:
                with self.assertRaises(authority.TrustedAcquisitionError):facade.issue_coordinated_acceptance(private_key='never-open',**self.inputs)
                key.assert_not_called()

    def test_key_mismatch_never_signs(self):
        with patch.object(authority.make_manifest,'verify_public_key_matches_private',side_effect=SystemExit('mismatch')),patch.object(authority.make_manifest,'acceptance_envelope') as sign:
            with self.assertRaises(SystemExit):facade.issue_coordinated_acceptance(private_key='mock-only',**self.inputs)
            sign.assert_not_called()

    def test_mock_signing_exact_client_schema_and_minimum_ttl(self):
        with patch.object(authority.make_manifest,'verify_public_key_matches_private') as key,patch.object(authority.make_manifest,'acceptance_envelope',return_value={'mock':True}) as sign,patch.object(authority,'verify_full_acceptance') as verify:
            facade.issue_coordinated_acceptance(private_key='mock-only',**self.inputs)
            payload=sign.call_args.args[0]
            self.assertEqual(payload['policyId'],'amnezia-release-full-v1')
            self.assertLessEqual(authority._utc(payload['expiresAt']),self.now+timedelta(minutes=30))
            self.assertEqual(payload['artifacts'],self.context.artifacts)
            key.assert_called_once();verify.assert_called_once()


if __name__=='__main__':unittest.main()
