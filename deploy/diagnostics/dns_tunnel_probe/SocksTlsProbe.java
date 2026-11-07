import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.*;
import org.json.JSONObject;

/** Standalone physical-device probe: authenticated SOCKS, verified public TLS. */
public final class SocksTlsProbe {
 public static void main(String[] args) throws Exception {
  JSONObject credentials=new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.UTF_8));
  String host=args[2]; int port=Integer.parseInt(args[0]); long started=System.nanoTime();
  try(Socket socket=new Socket()) {
   socket.connect(new InetSocketAddress("127.0.0.1",port),5000);socket.setSoTimeout(45000);
   DataOutputStream out=new DataOutputStream(socket.getOutputStream());DataInputStream in=new DataInputStream(socket.getInputStream());
   out.write(new byte[]{5,1,2});out.flush();if(in.readUnsignedByte()!=5||in.readUnsignedByte()!=2)throw new IOException("SOCKS auth method");
   byte[] user=credentials.getString("user").getBytes(StandardCharsets.UTF_8),pass=credentials.getString("password").getBytes(StandardCharsets.UTF_8);
   out.writeByte(1);out.writeByte(user.length);out.write(user);out.writeByte(pass.length);out.write(pass);out.flush();
   if(in.readUnsignedByte()!=1||in.readUnsignedByte()!=0)throw new IOException("SOCKS authentication rejected");
   byte[] destination=host.getBytes(StandardCharsets.US_ASCII);out.write(new byte[]{5,1,0,3});out.writeByte(destination.length);out.write(destination);out.writeShort(443);out.flush();
   if(in.readUnsignedByte()!=5||in.readUnsignedByte()!=0)throw new IOException("SOCKS connect rejected");in.readUnsignedByte();int type=in.readUnsignedByte();int length=type==1?4:type==4?16:type==3?in.readUnsignedByte():-1;if(length<0)throw new IOException("SOCKS address type");in.readFully(new byte[length+2]);
   try(SSLSocket tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(socket,host,443,true)) {
    SSLParameters p=tls.getSSLParameters();p.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(p);tls.setSoTimeout(45000);tls.startHandshake();
    tls.getOutputStream().write(("GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));tls.getOutputStream().flush();
    BufferedReader reader=new BufferedReader(new InputStreamReader(tls.getInputStream(),StandardCharsets.US_ASCII));String status=reader.readLine();if(status==null||!status.matches("HTTP/1\\.[01] [23][0-9]{2}.*"))throw new IOException("Unexpected HTTP status: "+status);
    System.out.println("PASS host="+host+" status="+status+" tls="+tls.getSession().getProtocol()+" verified_certificate=true seconds="+(System.nanoTime()-started)/1e9);
   }
  }
 }
}
