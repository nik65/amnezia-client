import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** Verifies DNS UDP carried inside the authenticated TCP/VLESS/DNSTT path. */
public final class SocksUdpProbe {
 public static void main(String[] args) throws Exception {
  JSONObject c=new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.UTF_8));
  try(Socket s=new Socket("127.0.0.1",Integer.parseInt(args[0]));DatagramSocket udp=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))) {
   s.setSoTimeout(15000);udp.setSoTimeout(15000);DataOutputStream out=new DataOutputStream(s.getOutputStream());DataInputStream in=new DataInputStream(s.getInputStream());
   out.write(new byte[]{5,1,2});out.flush();if(in.readUnsignedByte()!=5||in.readUnsignedByte()!=2)throw new IOException("method");
   byte[] u=c.getString("user").getBytes("UTF-8"),p=c.getString("password").getBytes("UTF-8");out.writeByte(1);out.writeByte(u.length);out.write(u);out.writeByte(p.length);out.write(p);out.flush();if(in.readUnsignedByte()!=1||in.readUnsignedByte()!=0)throw new IOException("auth");
   out.write(new byte[]{5,3,0,1,127,0,0,1});out.writeShort(udp.getLocalPort());out.flush();if(in.readUnsignedByte()!=5||in.readUnsignedByte()!=0)throw new IOException("UDP associate");in.readByte();if(in.readUnsignedByte()!=1)throw new IOException("IPv4 relay required");byte[] a=new byte[4];in.readFully(a);int port=in.readUnsignedShort();
   ByteArrayOutputStream raw=new ByteArrayOutputStream();DataOutputStream dns=new DataOutputStream(raw);dns.writeShort(0x63a7);dns.writeShort(0x100);dns.writeShort(1);dns.writeShort(0);dns.writeShort(0);dns.writeShort(0);for(String label:"example.com".split("\\.")){dns.writeByte(label.length());dns.writeBytes(label);}dns.writeByte(0);dns.writeShort(1);dns.writeShort(1);
   ByteArrayOutputStream packet=new ByteArrayOutputStream();packet.write(new byte[]{0,0,0,1,1,1,1,1,0,53});packet.write(raw.toByteArray());byte[] payload=packet.toByteArray();udp.send(new DatagramPacket(payload,payload.length,InetAddress.getByAddress(a),port));
   byte[] b=new byte[4096];DatagramPacket answer=new DatagramPacket(b,b.length);udp.receive(answer);
   if(answer.getLength()<22||b[2]!=0||b[3]!=1||b[10]!=0x63||(b[11]&255)!=0xa7||(b[12]&128)==0||(b[13]&15)!=0||((b[16]&255)*256+(b[17]&255))==0)throw new IOException("invalid DNS reply");
   System.out.println("PASS UDP DNS example.com through SOCKS/VLESS/DNSTT bytes="+answer.getLength()+" answers="+((b[16]&255)*256+(b[17]&255)));
  }
 }
}
