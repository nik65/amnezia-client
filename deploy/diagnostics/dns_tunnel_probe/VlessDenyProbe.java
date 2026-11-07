import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import org.json.JSONObject;

/** Negative probe: bad UUID and private SSH target must close without target data. */
public final class VlessDenyProbe {
 public static void main(String[] args)throws Exception {
  JSONObject config=new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])),"UTF-8"));
  boolean invalid=args[2].equals("invalid");UUID id=invalid?UUID.randomUUID():UUID.fromString(config.getString("vlessId"));
  try(Socket s=new Socket("127.0.0.1",Integer.parseInt(args[0]))) {
   s.setSoTimeout(15000);OutputStream out=s.getOutputStream();out.write(0);out.write(ByteBuffer.allocate(16).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).array());
   out.write(new byte[]{0,1,0,22,1,127,0,0,1});out.flush();InputStream in=s.getInputStream();int first=in.read();
   if(first>=0){if(first!=0)throw new IOException("unexpected response");int len=in.read();if(len<0)throw new EOFException();for(int n=0;n<len;n++)if(in.read()<0)throw new EOFException();if(in.read()!=-1)throw new IOException("private target returned data");}
   System.out.println("PASS denied "+(invalid?"invalid_vless_uuid":"private_destination"));
  }
 }
}
