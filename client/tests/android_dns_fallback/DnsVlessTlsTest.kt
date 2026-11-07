package org.amnezia.vpn

import java.io.ByteArrayInputStream
import java.net.*
import java.security.KeyStore
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.*

private fun context(path: String, trusted: Boolean): SSLContext {
    val store = KeyStore.getInstance("PKCS12").apply { java.io.FileInputStream(path).use { load(it, "fixture-only".toCharArray()) } }
    val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, "fixture-only".toCharArray()) }
    val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(if (trusted) store else null as KeyStore?) }
    return SSLContext.getInstance("TLS").apply { init(keys.keyManagers, trust.trustManagers, null) }
}
private fun exact(input: java.io.InputStream, size: Int): ByteArray {
    val bytes=ByteArray(size); var offset=0
    while(offset<size) { val n=input.read(bytes,offset,size-offset); check(n>0); offset+=n }; return bytes
}
private fun lazyTls(path:String, host:String, trusted:Boolean, productionDefault:Boolean=false):Boolean {
    val workers=Executors.newCachedThreadPool()
    val server=context(path,true).serverSocketFactory.createServerSocket(0,1,InetAddress.getLoopbackAddress()) as SSLServerSocket
    val gateway=ServerSocket(0,1,InetAddress.getLoopbackAddress())
    val web=workers.submit {
        try { (server.accept() as SSLSocket).use { socket ->
            socket.soTimeout=3000; socket.startHandshake()
            val reader=socket.inputStream.bufferedReader();var line=reader.readLine();check(line.startsWith("HEAD "))
            while(!line.isNullOrEmpty())line=reader.readLine()
            socket.outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray());socket.outputStream.flush()
        }} catch(_:Exception){}
    }
    val proxy=workers.submit {
        try { gateway.accept().use { client ->
            client.soTimeout=3000
            // VLESS request here is fixture data; the real request encoder remains in verify().
            check(exact(client.inputStream,3).contentEquals(byteArrayOf(0,1,2)))
            // A lazy VLESS server deliberately waits for ClientHello before response framing.
            val record=exact(client.inputStream,5);check(record[0].toInt()==22)
            val hello=exact(client.inputStream,((record[3].toInt() and 255) shl 8) or (record[4].toInt() and 255))
            Socket(InetAddress.getLoopbackAddress(),server.localPort).use { remote ->
                remote.soTimeout=3000
                // Fragment response/addon, then preserve every TLS byte.
                for(b in byteArrayOf(0,3,7,8,9)){client.outputStream.write(b.toInt());client.outputStream.flush()}
                remote.outputStream.write(record);remote.outputStream.write(hello);remote.outputStream.flush()
                val upload=workers.submit { try{client.inputStream.copyTo(remote.outputStream)}catch(_:Exception){} }
                try {remote.inputStream.copyTo(client.outputStream)}catch(_:Exception){}
                upload.cancel(true)
            }
        }} catch(_:Exception){}
    }
    var passed=false
    try { Socket(InetAddress.getLoopbackAddress(),gateway.localPort).use { socket ->
        socket.outputStream.write(byteArrayOf(0,1,2));socket.outputStream.flush()
        val client = if (productionDefault) DnsVlessTls(socket,host,timeoutMs=3000)
            else DnsVlessTls(socket,host,context(path,trusted),3000)
        client.use { tls ->
            tls.startHandshake();tls.write("HEAD / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
            check(dnsHttpsSuccess { tls.read() });passed=true
        }
    }} catch(_:SSLException) {} finally {server.close();gateway.close();proxy.cancel(true);web.cancel(true);workers.shutdownNow();workers.awaitTermination(4,TimeUnit.SECONDS)}
    return passed
}
fun main(args:Array<String>) {
    var checks=0
    fun verify(value:Boolean){checks++;check(value){"TLS test $checks"}}
    fun status(text:String)=ByteArrayInputStream(text.toByteArray()).let{dnsHttpsSuccess{it.read()}}
    val secret = "private-host.example/credential-7e79166d-198d-46d4-bdda-ea4b743496a5"
    val certificateFailure = java.security.cert.CertificateException("Domain specific configurations require $secret")
    certificateFailure.stackTrace = arrayOf(StackTraceElement("android.security.net.config.RootTrustManager", "checkServerTrusted", secret, 115),
        StackTraceElement(secret, secret, secret, 123))
    val chain = SSLHandshakeException(secret).apply { initCause(certificateFailure) }
    val summary = dnsTlsFailureSummary(chain)
    verify(summary.contains("domain_config_requires_hostname"))
    verify(summary.contains("android.security.net.config.RootTrustManager.checkServerTrusted:115"))
    verify(!summary.contains(secret) && !summary.contains("credential-") && !summary.contains("private-host"))
    val cycleA = Exception(secret); val cycleB = Exception(secret)
    cycleA.initCause(cycleB); cycleB.initCause(cycleA)
    verify(dnsTlsFailureSummary(cycleA).endsWith(";truncated"))
    var deep:Throwable = java.security.cert.CertificateException("Trust anchor for certification path not found: $secret")
    repeat(30) { deep = SSLHandshakeException(secret.repeat(200)).apply { initCause(deep) } }
    verify(dnsTlsFailureSummary(deep).length <= 2400)
    verify(dnsTlsFailureSummary(deep).endsWith(";truncated"))
    verify(!dnsTlsFailureSummary(deep).contains(secret))
    for ((message, code) in listOf("Not in handshake; no session available" to "handshake_session_missing",
        "Trust anchor for certification path not found" to "trust_anchor_missing", "Pin verification failed" to "certificate_pin_failed",
        "Hostname mismatch" to "hostname_check_failed", "Certificate expired" to "certificate_expired",
        "Certificate not yet valid" to "certificate_not_yet_valid", "CERTIFICATE_VERIFY_FAILED" to "certificate_verify_failed",
        "WRONG_VERSION_NUMBER" to "wrong_tls_version")) {
        verify(dnsTlsFailureSummary(SSLHandshakeException(message+secret)).contains(":"+code+"["))
    }
    for ((message, code) in listOf("BAD_RECORD_MAC" to "bad_record_mac", "DECRYPTION_FAILED" to "decryption_failed",
        "DECRYPT_ERROR" to "decrypt_error", "HANDSHAKE_FAILURE" to "handshake_failure")) {
        verify(dnsTlsFailureSummary(SSLProtocolException(message+secret)).contains(":"+code+"["))
    }
    verify(dnsTlsFailureSummary(IllegalArgumentException("Bad address")).contains(":invalid_vpn_builder_address["))
    verify(dnsTlsFailureSummary(IllegalArgumentException("dns_tun_probe_failed")).contains(":dns_tun_probe_failed["))
    verify(!dnsTlsFailureSummary(IllegalArgumentException("dns_tun_probe_failed"+secret)).contains(":dns_tun_probe_failed["))
    val nativeSecret="DO_NOT_EMIT_PASSWORD_TOKEN"
    val nativeMessage="Read error: error:1000012A:SSL routines:OPENSSL_internal:$nativeSecret ($secret)"
    val nativeSummary=dnsTlsFailureSummary(SSLProtocolException(nativeMessage))
    verify(nativeSummary.contains("ssl_codes=1000012a"))
    verify(!nativeSummary.contains(nativeSecret) && !nativeSummary.contains(secret) && !nativeSummary.contains("OPENSSL_internal"))
    verify(!dnsTlsFailureSummary(Exception(nativeMessage)).contains("ssl_codes="))
    verify(!dnsTlsFailureSummary(SSLProtocolException("error:1000012a-not-code:SSL routines:"+secret)).contains("ssl_codes="))
    val manyNative=dnsTlsFailureSummary(SSLProtocolException((nativeMessage+"\n").repeat(100)))
    verify(manyNative.contains("ssl_codes=1000012a,1000012a)"))
    verify(!manyNative.contains("ssl_codes=1000012a,1000012a,1000012a"))
    verify(manyNative.length<=2400 && !manyNative.contains(nativeSecret) && !manyNative.contains(secret))
    verify(dnsTlsFailureSummary(SSLProtocolException("ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT "+secret)).contains(":tls_session_context_mismatch["))
    // A process-global socket TLS context must not seed this engine-only ticket cache or trust.
    val globalBefore=SSLContext.getDefault()
    val socketContext=context(args[0],true)
    try {
        SSLContext.setDefault(socketContext)
        val engineContext=dnsProbeTlsContext()
        verify(engineContext!==socketContext && engineContext!==globalBefore)
        verify(engineContext===dnsProbeTlsContext())
        verify(engineContext.clientSessionContext!==socketContext.clientSessionContext)
        verify(engineContext.serverSessionContext!==socketContext.serverSessionContext)
        verify(SSLContext.getDefault()===socketContext)
        // The global context trusts this fixture, whereas platform default trust must reject it.
        verify(!lazyTls(args[0],"localhost",true,productionDefault=true))
        verify(SSLContext.getDefault()===socketContext)
    } finally { SSLContext.setDefault(globalBefore) }
    verify(status("HTTP/1.1 200 OK\r\n"));verify(status("HTTP/1.0 302 Found\r\n"))
    verify(status("HTTP/1.1 204 \r\n"));verify(!status("HTTP/1.1 400 Bad Request\r\n"))
    verify(!status("HTTP/1.1 200 OK\n"));verify(!status("HTTP/1.1 200 OK\rX"))
    verify(!status("HTTP/1.1 200 OK"));verify(!status("HTTP/1.1 200 "+"x".repeat(256)+"\r\n"))
    verify(!status("HTTP/1.1 200 OK\u0000\r\n"));verify(!status("HTTP/2 200 OK\r\n"))
    verify(!Regex("HTTP/1\\.[01] [23][0-9]{2}.*").matches("HTTP/1.1 200 OK\r"))
    val framed=DnsVlessResponseInput(ByteArrayInputStream(byteArrayOf(0,3,8,9,10,21,22)))
    verify(framed.read(ByteArray(0),0,0)==0);verify(framed.read()==21);verify(framed.read()==22);verify(framed.read()==-1)
    for(bytes in listOf(byteArrayOf(1,0,22),byteArrayOf(),byteArrayOf(0),byteArrayOf(0,2,9))) {
        verify(runCatching{DnsVlessResponseInput(ByteArrayInputStream(bytes)).read()}.isFailure)
    }
    verify(lazyTls(args[0],"localhost",true))
    verify(!lazyTls(args[0],"wrong.example",true))
    verify(!lazyTls(args[0],"localhost",false))
    // A silent peer must terminate within the bounded deadline, without an HTTP success.
    ServerSocket(0,1,InetAddress.getLoopbackAddress()).use { listener ->
        val worker=Executors.newSingleThreadExecutor();val task=worker.submit{listener.accept().use{Thread.sleep(700)}}
        val before=System.nanoTime()
        Socket(InetAddress.getLoopbackAddress(),listener.localPort).use { socket ->
            verify(runCatching {DnsVlessTls(socket,"localhost",context(args[0],true),200).use{it.startHandshake()}}.isFailure)
        }
        verify(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-before)<1500)
        task.cancel(true);worker.shutdownNow()
    }
    // Every addon byte arrives before the per-read timeout, but the total must still expire.
    ServerSocket(0,1,InetAddress.getLoopbackAddress()).use { listener ->
        val worker=Executors.newSingleThreadExecutor()
        val task=worker.submit { try { listener.accept().use { peer ->
            peer.soTimeout=1000; exact(peer.inputStream,1)
            for(byte in byteArrayOf(0,20)+ByteArray(20){7}) {
                peer.outputStream.write(byte.toInt());peer.outputStream.flush();Thread.sleep(65)
            }
        }} catch(_:Exception){} }
        val before=System.nanoTime()
        Socket(InetAddress.getLoopbackAddress(),listener.localPort).use { socket ->
            verify(runCatching {DnsVlessTls(socket,"localhost",context(args[0],true),250).use{it.startHandshake()}}.isFailure)
        }
        val elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-before)
        task.cancel(true);worker.shutdownNow();worker.awaitTermination(2,TimeUnit.SECONDS)
        verify(elapsed in 150..800)
    }
    println("DnsVlessTls actual lazy VLESS + TLS/HTTP, wrong hostname, untrusted certificate, fragmented addons, malformed/truncated headers, deadline and slow-trickle total deadline: $checks PASS")
}
