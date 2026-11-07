import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import javax.net.ssl.*;

public class DnsTunnelProbe {
 static String hex(byte[] b) {StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format("%02x",v&255));return s.toString();}
 static String sha(byte[] b)throws Exception{return hex(MessageDigest.getInstance("SHA-256").digest(b));}
 static Map<String,String> headers(InputStream in)throws Exception {
  ByteArrayOutputStream b=new ByteArrayOutputStream();int state=0;
  while(b.size()<16384) {int c=in.read();if(c<0)throw new EOFException("headers");b.write(c);state=(state==0&&c==13)?1:(state==1&&c==10)?2:(state==2&&c==13)?3:(state==3&&c==10)?4:0;if(state==4)break;}
  if(state!=4)throw new IOException("oversize headers");String[] lines=b.toString("US-ASCII").split("\r\n");Map<String,String> h=new HashMap<>();h.put(":status",lines[0]);
  for(int i=1;i<lines.length;i++){int p=lines[i].indexOf(':');if(p>0)h.put(lines[i].substring(0,p).toLowerCase(Locale.ROOT),lines[i].substring(p+1).trim());}return h;
 }
 static Socket open(int port)throws Exception{Socket s=new Socket();s.connect(new InetSocketAddress("127.0.0.1",port),5000);s.setSoTimeout(90000);return s;}
 static void send(Socket s,String text)throws Exception{s.getOutputStream().write(text.getBytes(StandardCharsets.US_ASCII));s.getOutputStream().flush();}
 public static void main(String[] args)throws Exception{
  int port=Integer.parseInt(args[0]);String token=new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.US_ASCII).trim();String mode=args[2];long start=System.nanoTime();
  try(Socket s=open(port)){
   if(mode.equals("transfer")||mode.equals("unauthorized")){
    int n=Integer.parseInt(args[3]);byte[] data=new byte[n];for(int i=0;i<n;i++)data[i]=(byte)((i*73+i/127)%256);
    send(s,"POST /probe HTTP/1.1\r\nHost: probe\r\nAuthorization: Bearer "+(mode.equals("unauthorized")?"invalid":token)+"\r\nContent-Length: "+n+"\r\nConnection: close\r\n\r\n");s.getOutputStream().write(data);s.getOutputStream().flush();Map<String,String> h=headers(s.getInputStream());
    if(mode.equals("unauthorized")){if(!h.get(":status").contains(" 401 "))throw new IOException("unauthorized accepted");System.out.println("PASS unauthorized HTTP401");return;}
    if(!h.get(":status").contains(" 200 "))throw new IOException(h.get(":status"));
    if(!sha(data).equals(h.get("x-upload-sha256")))throw new IOException("upload hash mismatch");
    if(!Integer.toString(n).equals(h.get("content-length")))throw new IOException("length mismatch");byte[] down=new byte[n];new DataInputStream(s.getInputStream()).readFully(down);
    if(!sha(down).equals(h.get("x-download-sha256")))throw new IOException("download hash mismatch");for(int i=0;i<n;i++)if(down[i]!=(byte)((i*37+i/256)%256))throw new IOException("pattern mismatch");
    System.out.println("PASS transfer bytes_each_direction="+n+" upload_sha256="+sha(data)+" download_sha256="+sha(down)+" seconds="+((System.nanoTime()-start)/1e9));
   }else if(mode.equals("https")||mode.equals("forbidden")){
    String host=mode.equals("forbidden")?"localhost":args[3];send(s,"CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\nAuthorization: Bearer "+token+"\r\n\r\n");Map<String,String> h=headers(s.getInputStream());
    if(mode.equals("forbidden")){if(!h.get(":status").contains(" 403 "))throw new IOException("forbidden target accepted");System.out.println("PASS forbidden target HTTP403");return;}
    if(!h.get(":status").contains(" 200 "))throw new IOException(h.get(":status"));
    try(SSLSocket tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(s,host,443,true)){
     SSLParameters p=tls.getSSLParameters();p.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(p);tls.setSoTimeout(90000);tls.startHandshake();
     send(tls,"GET / HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: Amnezia-DNS-Diagnostic/1\r\nConnection: close\r\n\r\n");Map<String,String> response=headers(tls.getInputStream());ByteArrayOutputStream b=new ByteArrayOutputStream();byte[] buf=new byte[8192];int n;
     while((n=tls.getInputStream().read(buf))!=-1){b.write(buf,0,n);if(b.size()>1048576)throw new IOException("body exceeds bound");}
     if(!response.get(":status").contains(" 200 "))throw new IOException(response.get(":status"));
     System.out.println("PASS HTTPS host="+host+" status="+response.get(":status")+" tls="+tls.getSession().getProtocol()+" verified_certificate=true body_bytes="+b.size()+" body_sha256="+sha(b.toByteArray())+" seconds="+((System.nanoTime()-start)/1e9));
    }
   }else throw new IllegalArgumentException("mode");
  }
 }
}
