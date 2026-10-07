"""Feed the Qt production-request fixture to the real server dispatcher.

No listener, tunnel, guest, filesystem installer or live service is started.
Only signing is stubbed by the existing server fixture: request-schema handling
and grant issuance/validation use the actual MigrationService and SQLite state.
"""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "client/server_scripts/awg_migration"))
from test_service import MigrationServiceTests


class HeadlessWireContractTests(unittest.TestCase):
    setUp = MigrationServiceTests.setUp
    tearDown = MigrationServiceTests.tearDown
    request = MigrationServiceTests.request

    def test_production_request_fixture_is_accepted_for_bootstrap_and_offer(self):
        fixture = json.loads(Path(__file__).with_name("awg_migration_wire_contract.json").read_text())
        bootstrap = self.request("bootstrap", fixture["request"])
        self.assertEqual(200, bootstrap.status)
        issued = bootstrap.response()
        for name in ("serverPublicKey", "peerPublicKey", "containerId", "sourceFingerprint", "nonce"):
            self.assertEqual(fixture["binding"][name], issued[name])
        offer = self.request("offer", fixture["request"], headers={"X-Amnezia-Migration-Grant": issued["grant"]})
        self.assertEqual(200, offer.status)

    def test_response_identity_fields_are_rejected_in_request(self):
        fixture = json.loads(Path(__file__).with_name("awg_migration_wire_contract.json").read_text())
        request = dict(fixture["request"], serverPublicKey=fixture["binding"]["serverPublicKey"], containerId=fixture["binding"]["containerId"])
        self.assertEqual(403, self.request("bootstrap", request).status)

if __name__ == "__main__":
    unittest.main()
