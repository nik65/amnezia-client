"""Real-phone predicate tests use fake live transports, never release permits."""
import ast
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from deploy.release_lab import android_real_device_acceptance as acceptance
from deploy.release_lab import android_real_device_acquisition as acquisition


CLIENT = "5"*64
INSTALLATION = "8477ff23-1d33-4c03-a113-9f6a857af530"


class LiveAndroidPredicateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.records = {}
        for name in ("apk", "manifest", "plink", "adb", "helper", "key"):
            path = self.root/name
            path.write_bytes((name+" exact bytes").encode())
            self.records[name] = acquisition.file_record(path)
        self.now = int(time.time())
        self.installed_after = self.now-120
        self.record_epoch = self.now-3
        self.record_ms = self.record_epoch*1000+125
        self.message = "Handle event: STATISTICS_UPDATE"
        self.pid = 100
        self.tid = 101
        self.local = f"{self.record_epoch}.125 {self.pid} {self.tid} D AmneziaActivity: {self.message}\n"
        self.uid_log = self.local
        self.extra_server = None
        self.verify_count = 0
        self.ssh_calls = []
        self.mutate_after_server = False
        owner = self
        class Context:
            version = "5.0.3.14"
            android_code = 2200
            manifest = owner.records["manifest"]
            def candidate(self, platform):
                owner.assertEqual(platform, "android-arm64-v8a")
                return owner.records["apk"]
            def verify(self):
                owner.verify_count += 1
                acquisition._verify_record(owner.records["apk"])
                acquisition._verify_record(owner.records["manifest"])
        self.context = Context()
        self.device = {"schema": 1, "state": "acquired-not-accepted", "run_id": "real-current",
                       "profile": "android-real-device", "transport": "adb-selected-physical-device",
                       "binding": {"serial": "e87861c7", "processes": [
                           {"pid":100,"uid":10426,"name":"org.amnezia.vpn","start_ticks":123},
                           {"pid":200,"uid":10426,"name":"org.amnezia.vpn:amneziaAwgService","start_ticks":124}]},
                       "vpn_observations":[{"network":114,"interface":"tun0","owner_uid":10426,"connected":True,"validated":True}],
                       "producer":self.records["helper"],"adb":self.records["adb"],
                       "installed_before":{"version":"5.0.3.14","version_code":2200,"sha256":self.records["apk"]["sha256"]},
                       "installed_after":{"version":"5.0.3.14","version_code":2200,"sha256":self.records["apk"]["sha256"]}}

    def phone(self, **kwargs):
        self.assertEqual(kwargs["serial"], "e87861c7")
        self.assertEqual(kwargs["candidate"], self.records["apk"])
        self.assertEqual(kwargs["manifest"], self.records["manifest"])
        originals = [{"label":f"logcat:{self.pid}","stdout_b64":base64.b64encode(self.local.encode()).decode()},
                     {"label":"uid-logcat","stdout_b64":base64.b64encode(self.uid_log.encode()).decode()},
                     {"label":"challenge-after","stdout_b64":base64.b64encode(b"original closeout").decode()}]
        return {**self.device,"raw_capture":json.dumps(originals).encode()}

    def server_file(self, *, body=None, pid=None, installation=INSTALLATION, accepted=None):
        stamp=datetime.fromtimestamp(self.record_epoch,timezone.utc).strftime("%m-%d %H:%M:%S")+".125Z"
        body=body if body is not None else f"{stamp} {self.pid if pid is None else pid} {self.tid} D [main] {getattr(self,'tag','AmneziaActivity')}: {self.message}\n".encode()
        digest=hashlib.sha256(body).hexdigest();batch="b"*64
        return {"name":"20261022-130000-123456789-"+installation+"-android-"+batch+".log",
                "receipt":{"batch_id":batch,"accepted_at":self.now-1 if accepted is None else accepted,
                           "body_sha256":digest,"body_length":len(body)},
                "size":len(body),"sha256":digest,"bytes_b64":base64.b64encode(body).decode()}

    def ssh(self, command, **kwargs):
        self.ssh_calls.append((command,kwargs))
        self.assertEqual(command[:4], [str(self.root/"plink"),"-batch","-noagent","-ssh"])
        self.assertIn(acceptance.HOST_KEY, command)
        self.assertIn(acceptance.SERVER, command)
        source=kwargs["input_bytes"].decode()
        self.assertIn("?mode=ro",source)
        self.assertIn("PRAGMA query_only=ON",source)
        for forbidden in ("INSERT INTO", "DELETE FROM", "UPDATE ", "docker restart", "iptables"):
            self.assertNotIn(forbidden, source)
        line=next(x for x in source.splitlines() if x.startswith("PARAMETERS="))
        parameters=json.loads(ast.literal_eval(line[len("PARAMETERS=json.loads("):-1]))
        self.assertEqual(parameters["client_id"],CLIENT)
        self.assertEqual(parameters["installation_id"],INSTALLATION)
        value={"schema":1,"challenge":parameters["nonce"],"server":acceptance.SERVER,
               "boot_id":"123e4567-e89b-12d3-a456-426614174000","uid":0,"captured_at":self.now,
               "client_id":CLIENT,"installation_id":INSTALLATION,"files":[self.server_file()]}
        if self.extra_server: self.extra_server(value)
        if self.mutate_after_server:(self.root/"manifest").write_bytes(b"changed context")
        return subprocess.CompletedProcess(command,0,json.dumps(value).encode(),b"")

    def produce(self):
        stamp=datetime.fromtimestamp(self.installed_after,timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        producer=acceptance.AndroidLiveProducer(serial="e87861c7",client_id=CLIENT,
            installation_id=INSTALLATION,installed_after_utc=stamp)
        with patch.object(acceptance,"PINNED_PLINK",self.root/"plink"), \
             patch.object(acceptance,"PINNED_KEY",self.root/"key"), \
             patch.object(acquisition,"acquire_android_device",side_effect=self.phone), \
             patch.object(acquisition,"_bounded_process",side_effect=self.ssh):
            return producer.acquire(self.context)

    def test_live_sources_correlate_only_after_actual_predicate(self):
        proof=self.produce()
        self.assertEqual(proof["target"],"android")
        self.assertEqual(proof["profileId"],"android-real-device")
        self.assertEqual(set(proof["semantics"]),{"installedIdentity","serviceIdentity","vpnValidated","realLogDelivery","noFatal","readonlyCloseout"})
        self.assertTrue(all(proof["semantics"].values()))
        self.assertEqual(self.verify_count,2)
        self.assertNotIn("signature",proof)
        self.assertNotIn("passed",proof)
        self.assertIsInstance(proof["rawCapture"],bytes)
        raw=json.loads(proof["rawCapture"])
        self.assertIn(b"STATISTICS_UPDATE",base64.b64decode(json.loads(base64.b64decode(raw["device_original_bytes_b64"]))[0]["stdout_b64"]))
        self.assertEqual(len(raw["correlated_deliveries"]),1)
        self.assertIn(b"original closeout",base64.b64decode(json.loads(proof["cleanupCapture"])["original_device_closeout"][0]["stdout_b64"]))

    def test_main_process_statistics_are_valid_without_handshake_each_batch(self):
        self.assertTrue(self.produce()["semantics"]["realLogDelivery"])

    def test_realistic_file_logcat_one_millisecond_difference(self):
        self.local=self.local.replace(".125 ",".126 ")
        self.assertTrue(self.produce()["semantics"]["realLogDelivery"])

    def test_large_or_ambiguous_record_timestamp_difference_rejected(self):
        self.local=self.local.replace(".125 ",".131 ")
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"matches current"):self.produce()
        self.local=self.local.replace(".131 ",".125 ")+self.local.replace(".131 ",".126 ")
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"matches current"):self.produce()

    def test_placeholder_ack_is_not_delivery_acceptance(self):
        self.extra_server=lambda v:v.update(files=[self.server_file(body=b"[redacted sensitive line]\n")])
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"non-placeholder"):self.produce()

    def test_real_service_sample_is_correlated_without_claiming_connectivity(self):
        self.pid=200
        self.tid=201
        self.tag="AmneziaVpnService"
        for message in ("RemoteLogServiceSample connected=true counters=unknown",
                        "RemoteLogServiceSample connected=true counters=fresh rxBytes=123 txBytes=456 sampleAgeMs=15000"):
            self.message=message
            self.local=f"{self.record_epoch}.125 {self.pid} {self.tid} D {self.tag}: {message}\n"
            with self.subTest(message=message):self.assertTrue(self.produce()["semantics"]["realLogDelivery"])
        self.device["vpn_observations"][0]["validated"]=False
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"validated VPN"):self.produce()

    def test_service_sample_does_not_admit_arbitrary_diagnostics_or_stale_claims(self):
        for message in ("RemoteLogServiceSample connected=true counters=healthy",
                        "RemoteLogServiceSample connected=true counters=fresh rxBytes=123 txBytes=456 sampleAgeMs=15001",
                        "RemoteLogServiceSample connected=true counters=unknown token=secret"):
            self.assertIsNone(acceptance.SAFE_MESSAGE.fullmatch(message))

    def test_nonce_replay_is_rejected(self):
        self.extra_server=lambda v:v.update(challenge="0"*64)
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"challenge"):self.produce()

    def test_file_must_match_accepted_database_hash_and_size(self):
        self.extra_server=lambda v:v["files"][0]["receipt"].update(body_sha256="0"*64)
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"receipt/file bytes"):self.produce()

    def test_other_installation_is_rejected(self):
        self.extra_server=lambda v:v.update(files=[self.server_file(installation="123e4567-e89b-12d3-a456-426614174000")])
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"installation/batch"):self.produce()

    def test_old_receipt_does_not_accept_new_installed_bytes(self):
        self.extra_server=lambda v:v.update(files=[self.server_file(accepted=self.installed_after-1)])
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"identity/time"):self.produce()

    def test_wrong_pid_cannot_correlate(self):
        self.extra_server=lambda v:v.update(files=[self.server_file(pid=999)])
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"matches current"):self.produce()

    def test_post_install_fatal_uid_log_rejected_before_server(self):
        self.uid_log+=f"{self.now-1}.000 500 501 E AndroidRuntime: FATAL EXCEPTION: main\n"
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"fatal/ANR"):self.produce()
        self.assertFalse(self.ssh_calls)

    def test_nonvalidated_or_missing_service_rejected_before_server(self):
        self.device["vpn_observations"][0]["validated"]=False
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"service/validated"):self.produce()
        self.assertFalse(self.ssh_calls)

    def test_old_phone_record_is_not_fresh_correlation(self):
        self.local=self.local.replace(str(self.record_epoch),str(self.installed_after-1))
        with self.assertRaisesRegex(acceptance.AndroidAcceptanceError,"post-install phone record"):self.produce()

    def test_context_mutation_during_server_capture_is_rejected(self):
        self.mutate_after_server=True
        with self.assertRaises(acquisition.AndroidAcquisitionError):self.produce()

    def test_server_clock_and_strict_uid_types(self):
        for change in (lambda v:v.update(captured_at=self.now-120),lambda v:v.update(uid=False)):
            self.extra_server=change
            with self.subTest(change=change),self.assertRaises(acceptance.AndroidAcceptanceError):self.produce()

    def test_subject_traversal_emulator_and_noncanonical_time_rejected(self):
        for field,value in (("client_id","../escape"),("serial","emulator-5554"),
                            ("installation_id","../escape"),("installed_after_utc","2026-10-22 10:00:00")):
            args=dict(serial="e87861c7",client_id=CLIENT,installation_id=INSTALLATION,installed_after_utc="2026-10-22T10:00:00Z")
            args[field]=value
            with self.subTest(field=field),self.assertRaises(acceptance.AndroidAcceptanceError):acceptance.AndroidLiveProducer(**args)

    def test_no_imported_receipt_or_caller_transport_entrypoint(self):
        with self.assertRaises(TypeError):acceptance.AndroidLiveProducer(receipt={"passed":True})

    def test_mutated_subject_is_revalidated_before_live_transports(self):
        stamp=datetime.fromtimestamp(self.installed_after,timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for field,value in (("serial","emulator-5554"),("client_id","../escape"),
                            ("installation_id","../escape"),("installed_after",True)):
            producer=acceptance.AndroidLiveProducer(serial="e87861c7",client_id=CLIENT,
                installation_id=INSTALLATION,installed_after_utc=stamp)
            setattr(producer,field,value)
            with self.subTest(field=field),patch.object(acquisition,"acquire_android_device") as phone:
                with self.assertRaises(acceptance.AndroidAcceptanceError):producer.acquire(self.context)
                phone.assert_not_called()

    def test_actual_android_exporter_utc_record_format(self):
        # Safe line preserved by the earlier read-only server capture; the
        # Kotlin exporter emits UTC explicitly, independent of phone locale.
        line="10-22 10:09:41.164Z 18124 18192 I [DefaultDispatcher-worker-1] AmneziaVpnService: RemoteLogRedaction reason=0 count=2"
        record=acceptance.SERVER_RECORD.fullmatch(line)
        self.assertIsNotNone(record)
        utc=datetime.strptime("2026-"+record[1],"%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
        self.assertEqual(int(utc.timestamp()*1000),1792663781164)
        self.assertEqual(record[6],"RemoteLogRedaction reason=0 count=2")


if __name__=="__main__":unittest.main()
