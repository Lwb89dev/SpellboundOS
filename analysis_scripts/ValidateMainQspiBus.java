// Actual main NAND bus/feature packets joined to main HAL/FIFO and revision bodies.
//@category SpellboundOS
import com.google.gson.*;
import java.util.*;

public class ValidateMainQspiBus extends ValidateMainQspiHal {
 private static final String BUS_CONFIG="{\"init\":1881762480,\"transfer\":1881762852,\"read_feature\":1882021290,\"write_feature\":1882021390,\"version\":2161399148,\"clock_select\":2161334284,\"pinmux\":2161392164,\"gpio\":2161328888,\"controller_init\":2161330884,\"dma_init\":1881800760,\"command\":2161330992,\"receive_poll\":2161331304,\"receive_bounce\":2161331552,\"transmit_poll\":2161331648,\"transmit_bounce\":2161331888,\"copy\":1888779020,\"diagnostic\":1881761844,\"logger\":1881880738,\"assertion\":2161337594,\"ranges\":[[1881762480,370],[1881762852,938],[1882021290,100],[1882021390,108]],\"logs\":{\"1889647476\":\"command_error\",\"1889647512\":\"receive_bounce_error\",\"1889647580\":\"transmit_bounce_error\",\"1889647652\":\"receive_poll_error\",\"1889647716\":\"transmit_poll_error\"},\"guards\":[{\"address\":1881762480,\"size\":370,\"sha256\":\"cd883f10874ffa0d0a0c0a61a9bcc5b9f5e97da4bc15704a9b767fd0076abbc7\"},{\"address\":1881762852,\"size\":938,\"sha256\":\"1e8f2570ed783b41497de82112e94798920bb9ffbd745d81e85c304737d237ce\"},{\"address\":1882021290,\"size\":100,\"sha256\":\"eeb3306b86c99b76c1881aed97dcebaf93411af971d08ed975dd8e58874ef177\"},{\"address\":1882021390,\"size\":108,\"sha256\":\"490dbfa98ddfa99a2ff0375a38a4dbf0b778eb00527b6e587dedb39f59a9d3d9\"},{\"address\":2160068548,\"size\":20,\"sha256\":\"0052a47961a0f941dd3d97beca4b258b8be0cbd7553cf4e8ee92e8f735f65074\"},{\"address\":1889738828,\"size\":184,\"sha256\":\"2e1217166b3942f8e42486bd55379b45b87f2f51085d04688b626452159c89dd\"}],\"data_guards\":[{\"address\":2160068548,\"size\":20,\"sha256\":\"0052a47961a0f941dd3d97beca4b258b8be0cbd7553cf4e8ee92e8f735f65074\"},{\"address\":1889738828,\"size\":184,\"sha256\":\"2e1217166b3942f8e42486bd55379b45b87f2f51085d04688b626452159c89dd\"}]}";
 private static final long BOUNCE=0x80d93960L,PACKET=0x81306000L;
 private JsonObject bus;private byte[] originalPacket;
 @Override protected void configure()throws Exception {
  bus=JsonParser.parseString(BUS_CONFIG).getAsJsonObject();
  for(JsonElement item:bus.getAsJsonArray("ranges"))cfg.getAsJsonArray("ranges").add(item.deepCopy());
  for(JsonElement item:bus.getAsJsonArray("guards"))cfg.getAsJsonArray("guards").add(item.deepCopy());
  for(JsonElement item:bus.getAsJsonArray("data_guards"))cfg.getAsJsonArray("data_guards").add(item.deepCopy());
 }
 @Override protected boolean pointer(long p,int n){return super.pointer(p,n)||n>=0&&n<=512&&p>=BOUNCE&&p+n<=BOUNCE+512||n==1&&p>=0x81000000L&&p+1<=0x81001000L;}
 @Override protected void setupExtra(Helper e){
  byte[] guard=new byte[576];Arrays.fill(guard,(byte)0xa5);e.writeMemory(toAddr(BOUNCE-32),guard);e.writeMemory(toAddr(PACKET-32),Arrays.copyOf(guard,96));
  put(e,0x80c10e38L,1,0);put(e,0x80c10e39L,1,0);put(e,0x70f8e6f8L,4,0x70a3204cL);
  JsonObject packet=c.getAsJsonObject("bus");for(Object[] f:new Object[][]{{0,"write_byte",1},{1,"dummy_byte",1},{2,"force_block",1},{4,"command_lines",1},{8,"opcode",4},{12,"address_bytes",1},{16,"address",4},{24,"size",4},{28,"data_lines",1}})put(e,PACKET+(int)f[0],(int)f[2],packet.get((String)f[1]).getAsLong());put(e,PACKET+20,4,BUFFER+c.get("alignment").getAsLong());originalPacket=mem(e,PACKET,32);
 }
 @Override protected boolean dispatchExtra(Helper e,String mode)throws Exception {
  if(!mode.equals("bus"))throw new IllegalStateException("Connected main bus entry");JsonObject packet=c.getAsJsonObject("bus");String kind=packet.get("mode").getAsString();
  if(kind.equals("transfer"))entry(e,bus.get("transfer").getAsLong(),0x70a3204cL,PACKET);
  else if(kind.equals("read_feature"))entry(e,bus.get("read_feature").getAsLong(),packet.get("feature_register").getAsLong(),BUFFER);
  else if(kind.equals("write_feature"))entry(e,bus.get("write_feature").getAsLong(),packet.get("feature_register").getAsLong(),packet.get("feature_value").getAsLong());
  else throw new IllegalStateException("Main bus packet entry");return true;
 }
 @Override protected boolean service(Helper e,long pc)throws Exception {
  if(pc==bus.get("copy").getAsLong()){
   long out=r(e,0),in=r(e,1);int n=(int)r(e,2);if(n<0||n>64||!pointer(out,n)||!pointer(in,n)||out!=BOUNCE&&in!=BOUNCE)throw new IllegalStateException("Main bounce copy bounds");actions.add((out==BOUNCE?"copy_to_bounce:":"copy_from_bounce:")+n);if(n>0)e.writeMemory(toAddr(out),mem(e,in,n));ret(e,out);return true;
  }
  if(pc==bus.get("logger").getAsLong()){JsonElement tag=bus.getAsJsonObject("logs").get(Long.toString(r(e,3)));if(tag==null)throw new IllegalStateException("Unexpected main bus log");actions.add("log:"+tag.getAsString());ret(e,0);return true;}
  if(pc==bus.get("diagnostic").getAsLong()){actions.add("diagnostic");ret(e,0);return true;}
  if(pc==bus.get("assertion").getAsLong()){stopped=new JsonObject();stopped.addProperty("kind","assertion");stopped.addProperty("owner",r(e,1));stopped.addProperty("line",r(e,2));e.writeRegister(e.getPCRegister(),END);return true;}
  return super.service(e,pc);
 }
 @Override protected void snapshotExtra(Helper e,JsonObject row)throws Exception {
  row.addProperty("bounce_sha256",hash(mem(e,BOUNCE,512)));byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);
  for(long p:new long[]{BOUNCE-32,BOUNCE+512,PACKET-32,PACKET+32})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Main bus/HAL guards");
  if(!Arrays.equals(originalPacket,mem(e,PACKET,32)))throw new IllegalStateException("Main bus packet changed");
  if(mem(e,0x80c10e38L,1)[0]!=0||mem(e,0x80c10e39L,1)[0]!=0||word(e,0x70f8e6f8L)!=0x70a3204cL)throw new IllegalStateException("Main bus fixture state changed");
 }
}
