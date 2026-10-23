"""Compile and execute the actual Android sanitizer self-contract on a host JVM.
No Android device, installer, VPN or application is started. Supply a Kotlin
compiler dependency classpath; generated files stay in --output.
"""
import argparse,hashlib,json,subprocess,os
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--compiler-classpath',required=True);p.add_argument('--output',required=True);p.add_argument('--orchestration',action='store_true');a=p.parse_args()
root=Path(__file__).resolve().parents[3]
source=root/'client/android/src/org/amnezia/vpn/AmneziaVpnService.kt'
s=source.read_text();out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
def part(start,end):return s[s.index(start):s.index(end,s.index(start))]
header=part('private const val CLIENT_LOGS_KEY','@SuppressLint("Registered")')
chunks=[part('    private fun remoteLogOriginCheckpointOffset(', '    private fun beginRemoteLogRecovery('),part('    private fun remoteLogBatchEndOffset(', '    private fun advanceRemoteLogRecoveryCheckpoint('),part('    private fun isValidRemoteLogToken(', '    private fun remoteLogTargetIdentity('),part('    private fun remoteLogTargetIdentity(', '    private fun remoteLogCursorPrefsKey('),part('    private fun sha256Hex(value: String)', '    /**\n     * Utils methods')]
# The only platform stub supplies a deterministic installation identity; the
# sanitizer, retry logic, hashing and complete self-contract are actual source.
text='import java.util.*\nimport java.text.SimpleDateFormat\nimport java.security.MessageDigest\nprivate const val TAG="AmneziaVpnService"\n'+header+'\nprivate fun remoteLogInstallationId()="00000000-0000-0000-0000-000000000001"\n'+'\n'.join(chunks)+'\nfun main(){check(verifyRemoteLogSanitizerContract());println("contractVerified=true")}\n'
heartbeat_source=root/'client/android/src/org/amnezia/vpn/RemoteLogServiceHeartbeat.kt'
text=text.replace('\nfun main(){', '\n'+heartbeat_source.read_text().split('\n',1)[1]+'\nfun main(){',1)
if a.orchestration:
    text=text[:text.rindex('\nfun main()')]
    text+=part('    private fun beginRemoteLogRecovery(', '    private fun remoteLogBatchEndOffset(')
    text+=part('    private fun advanceRemoteLogRecoveryCheckpoint(', '    private fun remoteLogTokenPrefsKey(')
    text+=part('    private fun prepareRemoteLogPayload(', '    private fun isValidRemoteLogToken(')
    text+=part('    private fun remoteLogAnchor(', '    private fun readLimitedUtf8(')
    # Only Android logging/preferences are replaced. The cursor preparation,
    # ACK construction, recovery and sanitizer are the actual implementation.
    text+='''
private var testCursor=RemoteLogCursor()
private val remoteLogSanitizerContractVerified=true
private var remoteLogRedactionReason=0
private var remoteLogRedactionCount=0L
private object Log { fun i(tag:String,msg:String){};fun w(tag:String,msg:String){} }
private fun loadRemoteLogCursor(target:RemoteLogTarget)=testCursor
private fun saveRemoteLogCursor(target:RemoteLogTarget,cursor:RemoteLogCursor):Boolean {testCursor=cursor;return true}
private fun writeRemoteLogOriginCheckpoint():String?="00000000-0000-0000-0000-000000000002"
fun main(){
 check(verifyRemoteLogSanitizerContract())
 val source=("safe-record\\n".repeat(10000)).toByteArray()
 val secrets=RemoteLogExplicitSecretSet(listOf("current-secret-token-123"))
 val old=sha256Hex("old-secret-set");val current=remoteLogExplicitSecretsSha256(secrets)
 val target=RemoteLogTarget("https://example.invalid","test-client","test-token",false,"test-cache")
 fun cursor()=RemoteLogCursor(initialized=true,offset=source.size,
  fingerprint=sha256Hex(source.copyOfRange(0,CLIENT_LOGS_CURSOR_FINGERPRINT_BYTES)),
  fingerprintBytes=CLIENT_LOGS_CURSOR_FINGERPRINT_BYTES,anchor=remoteLogAnchor(source,source.size),
  sanitizerSecretTransitionEndOffset=source.size,sanitizerAwaitingStableSource=true,
  sanitizerTransitionPrefixSha256=sha256Hex(source),sanitizerExplicitSecretsSha256=current,
  sanitizerAcceptedSecretsSha256=old)
 testCursor=cursor()
 val mutated=source.copyOf();mutated[70000]='X'.code.toByte()
 prepareRemoteLogPayload(target,mutated,secrets)
 check(testCursor.sanitizerAcceptedSecretsSha256!=current) {"rewritten middle accepted through legacy confirmation"}
 check(testCursor.sanitizerRecoveryQuarantine) {"rewritten prefix did not enter recovery"}
 testCursor=cursor()
 val appended=source+"safe-tail\\n".toByteArray()
 val payload=prepareRemoteLogPayload(target,appended,secrets)
 check(testCursor.sanitizerAcceptedSecretsSha256==current)
 check(payload!=null && payload.data.toString(Charsets.UTF_8).contains("safe-tail"))
 testCursor=cursor().copy(pendingEndOffset=appended.size,
  pendingBodySha256=sha256Hex(appended.copyOfRange(source.size,appended.size)),
  pendingBatchId=sha256Hex("pending-batch"))
 val pending=prepareRemoteLogPayload(target,appended,secrets)
 check(pending!=null && pending.cursorAfterUpload.sanitizerAcceptedSecretsSha256==old)
 check(pending.cursorBeforeUpload.sanitizerTransitionPrefixSha256.isEmpty())
 check(remoteLogRedactionReason==2) {"26-byte transition placeholder misclassified"}
 testCursor=cursor()
 val changed=prepareRemoteLogPayload(target,appended,RemoteLogExplicitSecretSet(listOf("different-secret-token-456")))
 check(changed!=null && changed.cursorAfterUpload.sanitizerAcceptedSecretsSha256==old)
 check(changed.cursorBeforeUpload.sanitizerTransitionPrefixSha256.isEmpty())
 val partial=source.copyOf();partial[partial.lastIndex]='X'.code.toByte()
 testCursor=cursor().copy(anchor=remoteLogAnchor(partial,partial.size),sanitizerTransitionPrefixSha256=sha256Hex(partial))
 prepareRemoteLogPayload(target,partial,secrets)
 check(testCursor.sanitizerAcceptedSecretsSha256==old)
 testCursor=cursor().copy(sanitizerSecretMode="quoted",sanitizerSecretQuote="\\\"")
 val carried=prepareRemoteLogPayload(target,source+"hidden-tail\\\"\\nsafe-tail\\n".toByteArray(),secrets)
 check(carried!=null && !carried.data.toString(Charsets.UTF_8).contains("hidden-tail"))

 // Exercise the actual prepare/ACK lifecycle, not just boundary predicates.
 fun freshBatch(bytes:ByteArray,mode:String="",quote:String=""):RemoteLogPayload {
  val fingerprintSize=minOf(bytes.size,CLIENT_LOGS_CURSOR_FINGERPRINT_BYTES)
  testCursor=RemoteLogCursor(initialized=true,offset=0,
   fingerprint=sha256Hex(bytes.copyOfRange(0,fingerprintSize)),fingerprintBytes=fingerprintSize,
   sanitizerExplicitSecretsSha256=current,sanitizerAcceptedSecretsSha256=current,
   sanitizerSecretMode=mode,sanitizerSecretQuote=quote)
  return prepareRemoteLogPayload(target,bytes,secrets)!!
 }
 fun nextAckedBatch(bytes:ByteArray,batch:RemoteLogPayload):RemoteLogPayload {
  testCursor=batch.cursorAfterUpload
  return prepareRemoteLogPayload(target,bytes,secrets)!!
 }
 val ordinary="health=ok\\n".repeat(120000).toByteArray()
 // A quiet background service still emits measured, rate-limited telemetry.
 check(remoteLogHeartbeatDue(null,0))
 check(!remoteLogHeartbeatDue(0,59999) && remoteLogHeartbeatDue(0,60000))
 check(!remoteLogHeartbeatDue(60000,60001))
 check(remoteLogHeartbeatDue(60000,0) && !remoteLogHeartbeatDue(null,-1))
 val serviceLine=remoteLogServiceHeartbeatLine(60000,59000,1234,5678)
 check(serviceLine=="RemoteLogServiceSample connected=true counters=fresh rxBytes=1234 txBytes=5678 sampleAgeMs=1000")
 check(!serviceLine.contains("healthy") && !serviceLine.contains("token"))
 check(!remoteLogSampleCountersAvailable(0,0) && !remoteLogSampleCountersAvailable(null,10))
 check(remoteLogSampleCountersAvailable(0,1) && remoteLogSampleCountersAvailable(1,0))
 for (bad in listOf(remoteLogServiceHeartbeatLine(60000,null,null,null),
                    remoteLogServiceHeartbeatLine(60000,44999,1234,5678),
                    remoteLogServiceHeartbeatLine(60000,60001,1234,5678),
                    remoteLogServiceHeartbeatLine(60000,59000,0,0),
                    remoteLogServiceHeartbeatLine(60000,59000,-1,5678))) {
  check(bad=="RemoteLogServiceSample connected=true counters=unknown")
 }
 val heartbeatBytes=(serviceLine+"\\n").toByteArray()
 val heartbeatBatch=freshBatch(heartbeatBytes)
 check(heartbeatBatch.data.contentEquals(heartbeatBytes)) {"real counters were redacted"}
 // New periodic observations cannot rewrite a failed in-flight batch.
 testCursor=heartbeatBatch.cursorBeforeUpload
 val heartbeatRetry=prepareRemoteLogPayload(target,heartbeatBytes+heartbeatBytes,secrets)!!
 check(heartbeatRetry.batchId==heartbeatBatch.batchId && heartbeatRetry.data.contentEquals(heartbeatBatch.data))
 testCursor=heartbeatRetry.cursorAfterUpload
 val subsequentHeartbeat=prepareRemoteLogPayload(target,heartbeatBytes+heartbeatBytes,secrets)!!
 check(subsequentHeartbeat.data.contentEquals(heartbeatBytes))
 // Existing origin/cursor recovery remains fail-closed on rotation.
 testCursor=heartbeatBatch.cursorAfterUpload
 val rotatedHeartbeat=prepareRemoteLogPayload(target,("rotated-prefix\\n"+serviceLine+"\\n").toByteArray(),secrets)
 check(testCursor.sanitizerRecoveryQuarantine) {"rotated service source bypassed quarantine"}
 check(rotatedHeartbeat==null || !rotatedHeartbeat.data.toString(Charsets.UTF_8).contains("rxBytes=1234"))
 val ordinaryFirst=freshBatch(ordinary)
 check(ordinaryFirst.cursorAfterUpload.offset==1048570) {"ordinary batch split a record"}
 check(ordinaryFirst.cursorAfterUpload.sanitizerSecretMode.isEmpty())
 check(remoteLogRedactionReason==0) {"readable payload classified as redacted"}
 check(nextAckedBatch(ordinary,ordinaryFirst).data.toString(Charsets.UTF_8).contains("health=ok"))
 // A persisted retry must retain its exact pending extent and batch identity.
 testCursor=ordinaryFirst.cursorBeforeUpload
 val retriedOrdinary=prepareRemoteLogPayload(target,ordinary,secrets)!!
 check(retriedOrdinary.cursorBeforeUpload.pendingEndOffset==ordinaryFirst.cursorBeforeUpload.pendingEndOffset)
 check(retriedOrdinary.batchId==ordinaryFirst.batchId && retriedOrdinary.data.contentEquals(ordinaryFirst.data))

 // Old pending batches are immutable even if their historical cut was partial.
 freshBatch(ordinary)
 val historicalCut=CLIENT_LOGS_MAX_BATCH_RAW_BYTES
 testCursor=testCursor.copy(pendingEndOffset=historicalCut,
  pendingBodySha256=sha256Hex(ordinary.copyOfRange(0,historicalCut)),pendingBatchId=sha256Hex("historical-partial-batch"))
 val partialPending=prepareRemoteLogPayload(target,ordinary,secrets)!!
 check(partialPending.cursorAfterUpload.offset==historicalCut)
 check(partialPending.cursorAfterUpload.sanitizerSecretMode=="fail-closed")
 testCursor=partialPending.cursorBeforeUpload
 val partialRetry=prepareRemoteLogPayload(target,ordinary,secrets)!!
 check(partialRetry.batchId==partialPending.batchId && partialRetry.data.contentEquals(partialPending.data))
 val unicode="health=\\u0416\\uD83D\\uDE00\\n".repeat(100000).toByteArray()
 val unicodeFirst=freshBatch(unicode)
 check(unicode[unicodeFirst.cursorAfterUpload.offset-1]=='\\n'.code.toByte())
 check(unicodeFirst.cursorAfterUpload.sanitizerSecretMode.isEmpty())
 check(!unicodeFirst.data.toString(Charsets.UTF_8).contains('\\uFFFD'))
 check(nextAckedBatch(unicode,unicodeFirst).cursorAfterUpload.sanitizerSecretMode.isEmpty())

 val boundary=CLIENT_LOGS_MAX_BATCH_RAW_BYTES
 val exact=("x".repeat(boundary-1)+"\\nhealth=after-exact\\n").toByteArray()
 val exactFirst=freshBatch(exact)
 check(exactFirst.cursorAfterUpload.offset==boundary && exactFirst.cursorAfterUpload.sanitizerSecretMode.isEmpty())
 check(nextAckedBatch(exact,exactFirst).data.toString(Charsets.UTF_8).contains("health=after-exact"))
 val oversized=("x".repeat(boundary+20)+"\\nhealth=after-oversized\\n").toByteArray()
 val oversizedFirst=freshBatch(oversized)
 check(oversizedFirst.cursorAfterUpload.sanitizerSecretMode=="fail-closed")
 check(!nextAckedBatch(oversized,oversizedFirst).data.toString(Charsets.UTF_8).contains("health=after-oversized"))
 val quoted=("password=\\""+"s".repeat(boundary-40)+"\\n"+"secret-continuation-987".repeat(10)+"\\"\\nhealth=after-quoted\\n").toByteArray()
 val quotedFirst=freshBatch(quoted)
 check(quotedFirst.cursorAfterUpload.sanitizerSecretMode=="quoted")
 val quotedNext=nextAckedBatch(quoted,quotedFirst).data.toString(Charsets.UTF_8)
 check(!quotedNext.contains("secret-continuation-987") && quotedNext.contains("health=after-quoted"))
 val structured=("password={\\"nested\\":[\\""+"s".repeat(boundary-60)+"\\n"+"structured-secret-789".repeat(10)+"\\"]}\\nhealth=after-structured\\n").toByteArray()
 val structuredFirst=freshBatch(structured)
 check(structuredFirst.cursorAfterUpload.sanitizerSecretMode=="structured")
 val structuredNext=nextAckedBatch(structured,structuredFirst).data.toString(Charsets.UTF_8)
 check(!structuredNext.contains("structured-secret-789") && structuredNext.contains("health=after-structured"))
 val pem=("-----BEGIN PRIVATE KEY-----\\n"+"s".repeat(boundary-60)+"\\n"+"pem-secret-654".repeat(10)+"\\n-----END PRIVATE KEY-----\\nhealth=after-pem\\n").toByteArray()
 val pemFirst=freshBatch(pem)
 check(pemFirst.cursorAfterUpload.sanitizerBlockEndMarker.isNotEmpty())
 val pemNext=nextAckedBatch(pem,pemFirst).data.toString(Charsets.UTF_8)
 check(!pemNext.contains("pem-secret-654") && pemNext.contains("health=after-pem"))
 val partialEof=freshBatch("health=partial-record".toByteArray())
 check(partialEof.cursorAfterUpload.sanitizerSecretMode=="fail-closed")
 check(!partialEof.data.toString(Charsets.UTF_8).contains("health=partial-record"))
 val alreadyClosed=freshBatch(ordinary,"fail-closed")
 check(alreadyClosed.cursorAfterUpload.sanitizerSecretMode=="fail-closed")
 check(alreadyClosed.data.size==25 && remoteLogRedactionReason==5) {"25-byte fail-closed placeholder misclassified"}
 check(!alreadyClosed.data.toString(Charsets.UTF_8).contains("health=ok"))

 println("contractVerified=true orchestrationVerified=true batchBoundariesVerified=true")
}
'''
k=out/'ActualSanitizerContract.kt';k.write_text(text)
cp=a.compiler_classpath;classes=out/'classes'
cmd=['java','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(classes),str(k)]
c=subprocess.run(cmd,capture_output=True,text=True);(out/'compile.txt').write_text(c.stdout+c.stderr);assert c.returncode==0,(out/'compile.txt').read_text()
r=subprocess.run(['java','-cp',str(classes)+os.pathsep+cp,'ActualSanitizerContractKt'],capture_output=True,text=True);(out/'run.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
receipt={'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'extracted_sha256':hashlib.sha256(k.read_bytes()).hexdigest(),'compile_exit':c.returncode,'run_exit':r.returncode,'contract_verified':'contractVerified=true' in r.stdout,'orchestration_verified':'orchestrationVerified=true' in r.stdout,'batch_boundaries_verified':'batchBoundariesVerified=true' in r.stdout}
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
