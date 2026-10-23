"""RFC7748 section6.1: https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
Pure OpenSSL X25519 vectors and inert prepare bridge tests.
"""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import prepare
from test_native_ready_runtime import SOURCE, PrepareHarness, A
BIN=os.environ.get('AWG_GENERATION_TEST_BIN')
VECTORS=[('dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=', 'hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo='), ('XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=', '3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=')]

class Protocol(unittest.TestCase):
    def test_capability_types_and_fixed_wire(self):
        adapter=prepare.NativePolicy(b'owned')
        for value in ({}, {'serverKeyVersion':True}, {'serverKeyVersion':2}, {'serverKeyVersion':1,'extra':0}):
            with mock.patch.object(adapter,'_invoke',return_value=value):
                with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'): adapter.server_key_capability()
        with mock.patch.object(adapter,'_invoke',return_value={'serverKeyVersion':1}) as call:
            adapter.server_key_capability()
        self.assertEqual(json.loads(call.call_args.args[0]),{'op':'server-key-capability'})
    def test_invalid_input_and_response(self):
        adapter=prepare.NativePolicy(b'owned')
        with mock.patch.object(adapter,'_invoke',side_effect=AssertionError('transport')):
            for raw in ('text',b'\xff',b'x'*(1024**2+1)):
                with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'): adapter.server_public_key(raw)
        for value in (None,True,{},'', 'A'*43, '!'*43+'='):
            with mock.patch.object(adapter,'_invoke',return_value=value):
                with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'): adapter.server_public_key(SOURCE)

@unittest.skipUnless(BIN,'compiled fixture required')
class Native(unittest.TestCase):
    def setUp(self): self.adapter=prepare.NativePolicy(Path(BIN).read_bytes())
    def test_rfc7748_vectors_and_noncanonical_padding(self):
        self.adapter.server_key_capability()
        for private, public in VECTORS:
            raw=SOURCE.replace(A.encode(),private.encode(),1)
            self.assertEqual(self.adapter.server_public_key(raw),public)
            alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            changed=private[:-2]+alphabet[alphabet.index(private[-2])|1]+'='
            self.assertEqual(base64.b64decode(private),base64.b64decode(changed))
            with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'):
                self.adapter.server_public_key(raw.replace(private.encode(),changed.encode(),1))
    def test_rfc_scalar_clamping_is_openssl_owned(self):
        private,public=VECTORS[0]
        rawkey=bytearray(base64.b64decode(private))
        for low,high in ((0,0),(7,128),(3,64)):
            changed=bytearray(rawkey)
            changed[0]=(changed[0]&248)|low
            changed[31]=(changed[31]&63)|high
            encoded=base64.b64encode(changed)
            self.assertEqual(self.adapter.server_public_key(SOURCE.replace(A.encode(),encoded,1)),public)

    def test_real_prepare_native_derivation_without_pubkey_command(self):
        expected=self.adapter.server_public_key(SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            harness=PrepareHarness(Path(directory),self.adapter.raw,native_server_key=True)
            actual=harness.run
            def run(*args,**kwargs):
                if args[:3]==('docker','exec','-i') and 'pubkey' in args[-1]: raise AssertionError('legacy pubkey')
                return actual(*args,**kwargs)
            harness.run=run
            observed=[]
            def ready(adapter,source,target,state,pin,automatic): observed.append(state['serverPublicKey'])
            with mock.patch.object(prepare.NativePolicy,'ready_target',autospec=True,side_effect=ready):
                self.assertTrue(harness.execute(True)['prepared'])
            state=json.loads((Path(directory)/"amnezia-awg/1/ready.json").read_text())
            self.assertEqual(state["serverPublicKey"],expected)
            self.assertTrue(observed)
            self.assertTrue(all(key==expected for key in observed))
    def test_capability_failure_prevents_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            harness=PrepareHarness(Path(directory),self.adapter.raw)
            with mock.patch.object(prepare.NativePolicy,'server_key_capability',side_effect=ValueError('native_generation_rejected')):
                with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'): harness.execute(True)
            self.assertEqual(list(Path(directory).iterdir()),[])
            self.assertIsNone(harness.journal)

if __name__=='__main__': unittest.main()
