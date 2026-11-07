import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Arrays;
import org.json.JSONObject;

/** Unauthenticated req_pq_multi only. Never logs in or sends a Telegram message. */
public final class TelegramMtprotoProbe {
 static byte[] exact(DataInputStream in,int n)throws IOException {byte[] b=new byte[n];in.readFully(b);return b;}
 public static void main(String[] args)throws Exception {
  JSONObject c=new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])),"UTF-8"));
  String[] targets={"149.154.167.50","2001:67c:4e8:f002::a"};
  for(int round=0;round<3;round++)for(String host:targets){
   long start=System.nanoTime();JSONObject r=new JSONObject().put("target",host).put("round",round).put("ok",false);
   try(Socket s=new Socket("127.0.0.1",Integer.parseInt(args[0]))) {
    s.setSoTimeout(12000);DataInputStream in=new DataInputStream(s.getInputStream());DataOutputStream out=new DataOutputStream(s.getOutputStream());
    out.write(new byte[]{5,1,2});out.flush();if(in.readUnsignedByte()!=5||in.readUnsignedByte()!=2)throw new IOException("method");
    byte[] u=c.getString("user").getBytes("UTF-8"),p=c.getString("password").getBytes("UTF-8");out.writeByte(1);out.writeByte(u.length);out.write(u);out.writeByte(p.length);out.write(p);out.flush();if(in.readUnsignedByte()!=1||in.readUnsignedByte()!=0)throw new IOException("auth");
    byte[] a=InetAddress.getByName(host).getAddress();out.write(new byte[]{5,1,0,(byte)(a.length==4?1:4)});out.write(a);out.writeShort(443);out.flush();if(in.readUnsignedByte()!=5)throw new IOException("SOCKS version");int reply=in.readUnsignedByte();r.put("socks_reply",reply);if(reply!=0)throw new IOException("SOCKS rejected");in.readByte();int type=in.readUnsignedByte();exact(in,(type==1?4:type==4?16:in.readUnsignedByte())+2);
    byte[] nonce=new byte[16];new SecureRandom().nextBytes(nonce);ByteBuffer msg=ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN).putLong(0).putLong((System.currentTimeMillis()/1000)<<32).putInt(20).putInt(0xbe7e8ef1).put(nonce);
    out.write(new byte[]{(byte)0xef,10});out.write(msg.array());out.flush();int size=in.readUnsignedByte();if(size==127){byte[] b=exact(in,3);size=(b[0]&255)|((b[1]&255)<<8)|((b[2]&255)<<16);}size*=4;if(size<40||size>4096)throw new IOException("response size");byte[] response=exact(in,size);boolean ok=ByteBuffer.wrap(response).order(ByteOrder.LITTLE_ENDIAN).getInt(20)==0x05162463&&Arrays.equals(nonce,Arrays.copyOfRange(response,24,40));r.put("ok",ok).put("resPQ_bytes",size);
   }catch(Exception e){r.put("error",e.getClass().getSimpleName()+":"+e.getMessage());}
   r.put("seconds",(System.nanoTime()-start)/1e9);System.out.println(r.toString());
  }
 }
}
