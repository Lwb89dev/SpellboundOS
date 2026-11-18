// Original main probe/platform/bus/feature path with supplied HAL; root consumers inherited.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.util.*;

public class ValidateMainNandBusProbe extends ValidateMainObjects {
 private static final String BUS_CONFIG="{\"init\":1881762480,\"transfer\":1881762852,\"read_feature\":1882021290,\"write_feature\":1882021390,\"version\":2161399148,\"clock_select\":2161334284,\"pinmux\":2161392164,\"gpio\":2161328888,\"controller_init\":2161330884,\"dma_init\":1881800760,\"command\":2161330992,\"receive_poll\":2161331304,\"receive_bounce\":2161331552,\"transmit_poll\":2161331648,\"transmit_bounce\":2161331888,\"copy\":1888779020,\"diagnostic\":1881761844,\"logger\":1881880738,\"assertion\":2161337594,\"ranges\":[[1881762480,370],[1881762852,938],[1882021290,100],[1882021390,108]],\"logs\":{\"1889647476\":\"command_error\",\"1889647512\":\"receive_bounce_error\",\"1889647580\":\"transmit_bounce_error\",\"1889647652\":\"receive_poll_error\",\"1889647716\":\"transmit_poll_error\"},\"guards\":[{\"address\":1881762480,\"size\":370,\"sha256\":\"cd883f10874ffa0d0a0c0a61a9bcc5b9f5e97da4bc15704a9b767fd0076abbc7\"},{\"address\":1881762852,\"size\":938,\"sha256\":\"1e8f2570ed783b41497de82112e94798920bb9ffbd745d81e85c304737d237ce\"},{\"address\":1882021290,\"size\":100,\"sha256\":\"eeb3306b86c99b76c1881aed97dcebaf93411af971d08ed975dd8e58874ef177\"},{\"address\":1882021390,\"size\":108,\"sha256\":\"490dbfa98ddfa99a2ff0375a38a4dbf0b778eb00527b6e587dedb39f59a9d3d9\"},{\"address\":2160068548,\"size\":20,\"sha256\":\"0052a47961a0f941dd3d97beca4b258b8be0cbd7553cf4e8ee92e8f735f65074\"},{\"address\":1889738828,\"size\":184,\"sha256\":\"2e1217166b3942f8e42486bd55379b45b87f2f51085d04688b626452159c89dd\"}],\"data_guards\":[{\"address\":2160068548,\"size\":20,\"sha256\":\"0052a47961a0f941dd3d97beca4b258b8be0cbd7553cf4e8ee92e8f735f65074\"},{\"address\":1889738828,\"size\":184,\"sha256\":\"2e1217166b3942f8e42486bd55379b45b87f2f51085d04688b626452159c89dd\"}]}";
 private static final long CTRL=0x80d94a60L,BOUNCE=0x80d93960L,DMA0=0x80c10df4L,DMA1=0x80c10db0L,REINIT=0x80c10e38L,DISABLED=0x80c10e39L;
 private JsonObject bus;private int commands,reads,writes,count,opcode,feature;private long data;private boolean packetWrite;
 private long at(String key){return bus.get(key).getAsLong();}
 @Override protected void configure()throws Exception {
  bus=JsonParser.parseString(BUS_CONFIG).getAsJsonObject();
  for(String[] pair:new String[][]{{"ranges","main_probe_ranges"},{"guards","main_probe_guards"},{"data_guards","main_probe_data_guards"}})
   for(JsonElement item:bus.getAsJsonArray(pair[0]))cfg.getAsJsonArray(pair[1]).add(item.deepCopy());
  for(var item:bus.getAsJsonObject("logs").entrySet())cfg.getAsJsonObject("logs").add(item.getKey(),item.getValue());
 }
 @Override protected void setupProbe(EmulatorHelper e){
  super.setupProbe(e);if(!c.get("native_main_bus").getAsBoolean()||!c.get("native_main_root").getAsBoolean())throw new IllegalStateException("Connected main bus scope");
  commands=reads=writes=count=opcode=feature=0;data=0;packetWrite=false;
  byte[] guard=new byte[544];Arrays.fill(guard,(byte)0xa5);
  e.writeMemory(toAddr(CTRL-32),Arrays.copyOf(guard,128));e.writeMemory(toAddr(BOUNCE),guard);
  e.writeMemory(toAddr(DMA1),Arrays.copyOf(guard,68));e.writeMemory(toAddr(DMA0),Arrays.copyOf(guard,80));
  put(e,REINIT,1,0);put(e,DISABLED,1,c.get("bus_disabled").getAsBoolean()?1:0);
  put(e,0x9a000004L,4,0x1000001L);put(e,0x9a00000cL,4,0x20000001L);
 }
 private boolean stack(long p,int n){return p>=0x81000000L&&p+n<=0x81001000L;}
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(pc==at("init")){probeIndex=probeChipIndex(r(e,0));probeBusCalls++;actions.add("probe_bus_native:"+probeIndex);return false;}
  if(pc==at("read_feature")||pc==at("write_feature"))return false;
  if(pc==at("transfer")){
   long p=r(e,1);if(!stack(p,32))throw new IllegalStateException("Probe bus packet bound");byte[] b=mem(e,p,32);
   opcode=(int)word(e,p+8);feature=(int)word(e,p+16);count=(int)word(e,p+24);data=word(e,p+20);packetWrite=b[0]!=0;
   if(b[1]!=0||b[2]!=1||b[4]!=1||b[28]!=1||(count>0&&!stack(data,count)))throw new IllegalStateException("Probe packet fields");
   long selected=word(e,0x70f8e6f8L);
   if(opcode==0x9f){if(r(e,0)!=0||count!=5||feature!=0||b[12]!=1||packetWrite)throw new IllegalStateException("Probe ID fields");probeIdReads++;}
   else{probeChipIndex(selected);if(r(e,0)!=selected)throw new IllegalStateException("Probe packet context");
    if(opcode==0xff){if(count!=0||feature!=0||data!=0||b[12]!=0||!packetWrite)throw new IllegalStateException("Probe reset fields");}
    else if(opcode==0x0f||opcode==0x1f){if(count!=1||feature<0||feature>255||b[12]!=1||packetWrite!=(opcode==0x1f))throw new IllegalStateException("Probe feature fields");if(packetWrite)probeFeatureWrites++;else probeFeatureReads++;}
    else throw new IllegalStateException("Unexpected probe opcode");
   }
   actions.add("probe_packet:"+opcode+":"+feature+":"+count+":"+(packetWrite?1:0));return false;
  }
  if(pc==at("version")){actions.add("version_query");ret(e,c.get("bus_revision").getAsLong());return true;}
  if(pc==at("clock_select")){if(r(e,0)!=1&&r(e,0)!=2)throw new IllegalStateException("Clock selection");actions.add("clock_select:"+r(e,0));ret(e,c.get("bus_init_status").getAsLong());return true;}
  if(pc==at("pinmux")||pc==at("gpio")){boolean pin=pc==at("pinmux");if(r(e,0)!=0||r(e,1)!=127||r(e,2)!=(pin?63:1))throw new IllegalStateException("Pin arguments");actions.add(pin?"pinmux:0:127:63":"gpio:0:127:1");ret(e,c.get("bus_init_status").getAsLong());return true;}
  if(pc==at("controller_init")){if(r(e,0)!=CTRL)throw new IllegalStateException("Controller init");actions.add("controller_init:"+c.get("bus_init_status").getAsLong());ret(e,c.get("bus_init_status").getAsLong());return true;}
  if(pc==at("dma_init")){long p=r(e,0);if(p!=DMA0&&p!=DMA1)throw new IllegalStateException("DMA pointer");actions.add("dma_init:"+(p==DMA0?0:1)+":"+hash(mem(e,p,44))+":"+c.get("bus_init_status").getAsLong());ret(e,c.get("bus_init_status").getAsLong());return true;}
  if(pc==at("command")){
   long p=r(e,1);if(r(e,0)!=CTRL||r(e,2)!=1000||!stack(p,44))throw new IllegalStateException("HAL command bounds");
   long[] expected={packetWrite?2:0,0,opcode,1,1,feature,1,count>0?1:0,1,count,0};String action="command";
   for(int i=0;i<11;i++){long v=word(e,p+i*4);if(v!=expected[i])throw new IllegalStateException("HAL packet conversion field "+i);action+=":"+v;}
   long status=++commands==c.get("bus_command_fail_at").getAsInt()?-9:0;actions.add(action+":"+status);
   if(status==0&&commands==c.get("bus_disable_after").getAsInt())put(e,DISABLED,1,1);ret(e,status);return true;
  }
  if(pc==at("receive_poll")||pc==at("transmit_poll")){
   boolean write=pc==at("transmit_poll");long p=r(e,1);if(r(e,0)!=CTRL||r(e,2)!=1000||p!=data||!stack(p,count)||write!=packetWrite)throw new IllegalStateException("Probe HAL data");
   long status=write?(++writes==c.get("bus_write_fail_at").getAsInt()?-9:0):(++reads==c.get("bus_read_fail_at").getAsInt()?-9:0);
   actions.add((write?"transmit_poll:":"receive_poll:")+count+(write?":"+hash(mem(e,p,count)):"")+":"+status);
   if(status==0){
    if(write){if(opcode!=0x1f||count!=1)throw new IllegalStateException("Feature transmit");probeFeatures.put((long)feature,mem(e,p,1)[0]&255L);}
    else if(opcode==0x9f){byte[] id=new byte[5];for(int i=0;i<5;i++)id[i]=probeIdReads<=11*c.get("probe_delayed_rounds").getAsInt()?(byte)255:(byte)c.getAsJsonArray("probe_id").get(i).getAsInt();e.writeMemory(toAddr(p),id);}
    else{if(opcode!=0x0f||!probeFeatures.containsKey((long)feature))throw new IllegalStateException("Feature receive backing");long v=probeFeatures.get((long)feature)^(probeFeatureReads==c.get("probe_feature_mismatch_at").getAsInt()?1:0);put(e,p,1,v);}
   }
   ret(e,status);return true;
  }
  if(pc==at("diagnostic")){actions.add("diagnostic");ret(e,0);return true;}
  // Fences mark authored single-thread ordering; no device/cache effects are emulated.
  var instruction=getInstructionAt(toAddr(pc));if(instruction!=null&&instruction.getMnemonicString().startsWith("fence")){actions.add("fence");e.writeRegister(e.getPCRegister(),pc+instruction.getLength());return true;}
  return super.probeService(e,pc);
 }
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){
  super.probeSnapshot(e,row);row.addProperty("bus_reinit",mem(e,REINIT,1)[0]&255);row.addProperty("bus_disabled",mem(e,DISABLED,1)[0]&255);
  row.addProperty("bus_commands",commands);row.addProperty("bus_reads",reads);row.addProperty("bus_writes",writes);row.addProperty("bus_controller_hex",HexFormat.of().formatHex(mem(e,CTRL,64)));
  JsonArray dma=new JsonArray(),mmio=new JsonArray();try{for(long p:new long[]{DMA0,DMA1})dma.add(hash(mem(e,p,48)));}catch(Exception ex){throw new IllegalStateException(ex);}
  for(long p:new long[]{0x9a000004L,0x9a00000cL})mmio.add(word(e,p));row.add("bus_dma_sha256",dma);row.add("bus_mmio",mmio);
 }
 @Override protected void validateExtra(EmulatorHelper e)throws Exception {
  byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);
  for(long p:new long[]{CTRL-32,CTRL+64,BOUNCE+512})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Main bus guard");
  if(!Arrays.equals(Arrays.copyOf(guard,20),mem(e,DMA1+48,20))||!Arrays.equals(Arrays.copyOf(guard,20),mem(e,DMA0+48,20))||!Arrays.equals(Arrays.copyOf(guard,10),mem(e,DMA0+70,10)))throw new IllegalStateException("Main DMA guard");
 }
}
