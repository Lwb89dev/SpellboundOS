// Actual main probe/root through original platform, QSPI FIFO and DMA initialization.
//@category SpellboundOS
import ghidra.app.emulator.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import com.google.gson.*;
import java.util.*;

public class ValidateMainNandFullProbe extends ValidateMainObjects {
 private static final String HAL_CONFIG="{\"pack\":2161330176,\"complete\":2161330376,\"wait_receive\":2161330516,\"wait_transmit\":2161330664,\"tx_count\":2161330812,\"rx_count\":2161330848,\"init\":2161330884,\"command\":2161330992,\"receive\":2161331304,\"receive_dma\":2161331552,\"transmit\":2161331648,\"transmit_dma\":2161331888,\"clock\":2161334284,\"version\":2161399148,\"tick\":2161398940,\"frequency\":2161398960,\"dma_setup\":1881801376,\"dma_wait\":1881801560,\"strcmp\":1888786464,\"ranges\":[[2161330176,100],[2161330376,140],[2161330516,148],[2161330664,148],[2161330812,36],[2161330848,36],[2161330884,108],[2161330992,204],[2161331304,248],[2161331552,96],[2161331648,240],[2161331888,88],[2161334284,52],[2161399148,86]],\"guards\":[{\"address\":2161330176,\"size\":100,\"sha256\":\"d81728d94ec968a8022bdf7cd2c799cdd65fdbe9c81fe3e8279b0f1750187ca8\"},{\"address\":2161330376,\"size\":140,\"sha256\":\"5c43692373eb63fa3689c149a3da5e14cbb9a5c247aa784f9393216514a8d657\"},{\"address\":2161330516,\"size\":148,\"sha256\":\"fb54106945149f0adcc42b5e19f04eb33712bdade8b67aa871b3a2443a971dd8\"},{\"address\":2161330664,\"size\":148,\"sha256\":\"613d4f163b6098fac11a43c891069db3f3570485369f0035548fb9f688d855c7\"},{\"address\":2161330812,\"size\":36,\"sha256\":\"23f0432a05059b34c075ae3b853d8042bb22a71cd30f0ee056f8eff3f02b715e\"},{\"address\":2161330848,\"size\":36,\"sha256\":\"42c4cd8a20418deeb8f7f9c7568c4df0993e9e95ff0957530f69f313c01f79e8\"},{\"address\":2161330884,\"size\":108,\"sha256\":\"00754e5d66f0e683b7574bfe16e58619d92ad41b9f5860c63ed5741d81bea4c3\"},{\"address\":2161330992,\"size\":204,\"sha256\":\"29a15157d715409e04279787c466da24e5fa0699d76bec9d38ff649924ff16ca\"},{\"address\":2161331304,\"size\":248,\"sha256\":\"4b3d8e3416cf27b727cd8744bbe60327ef3a453df6be3dd556da6cfddbb1ad38\"},{\"address\":2161331552,\"size\":96,\"sha256\":\"e516225b2455b37107ba00bb52832e92d49b3ac79f47b13b1a5ad593d041fdc6\"},{\"address\":2161331648,\"size\":240,\"sha256\":\"c1d5acbaf50138e8f02ad63d68a24ba9fe92f5774ba8b1b8f9eaf3ed7a9d1f0d\"},{\"address\":2161331888,\"size\":88,\"sha256\":\"1e61b977e0fbafed189155c36bf3b8eb64481da377f24ff541aff3ad413f71cc\"},{\"address\":2161334284,\"size\":52,\"sha256\":\"8c398da0431498ac449a53359d83ea8b99c00d97dd6cce6465cad08955b9ce67\"},{\"address\":2161399148,\"size\":86,\"sha256\":\"4bf62f942d22c8f8bf9f51d44c03d03f5b811851a2184355173f036ae9e76f4e\"},{\"address\":1889174740,\"size\":8,\"sha256\":\"c04da2a2ed09a7b3bcbb243d672f998255800572ba63f514839d255d1a1d2255\"},{\"address\":1889174748,\"size\":8,\"sha256\":\"ba0f00ea8eed52463c26f35110d25090713fe37859f813dbc3cf397f9a604848\"}],\"data_guards\":[{\"address\":1889174740,\"size\":8,\"sha256\":\"c04da2a2ed09a7b3bcbb243d672f998255800572ba63f514839d255d1a1d2255\"},{\"address\":1889174748,\"size\":8,\"sha256\":\"ba0f00ea8eed52463c26f35110d25090713fe37859f813dbc3cf397f9a604848\"}]}",BUS_CONFIG="{\"init\":1881762480,\"transfer\":1881762852,\"read_feature\":1882021290,\"write_feature\":1882021390,\"version\":2161399148,\"clock_select\":2161334284,\"pinmux\":2161392164,\"gpio\":2161328888,\"controller_init\":2161330884,\"dma_init\":1881800760,\"command\":2161330992,\"receive_poll\":2161331304,\"receive_bounce\":2161331552,\"transmit_poll\":2161331648,\"transmit_bounce\":2161331888,\"copy\":1888779020,\"diagnostic\":1881761844,\"logger\":1881880738,\"assertion\":2161337594,\"ranges\":[[1881762480,370],[1881762852,938],[1882021290,100],[1882021390,108]],\"logs\":{\"1889647476\":\"command_error\",\"1889647512\":\"receive_bounce_error\",\"1889647580\":\"transmit_bounce_error\",\"1889647652\":\"receive_poll_error\",\"1889647716\":\"transmit_poll_error\"},\"guards\":[{\"address\":1881762480,\"size\":370,\"sha256\":\"cd883f10874ffa0d0a0c0a61a9bcc5b9f5e97da4bc15704a9b767fd0076abbc7\"},{\"address\":1881762852,\"size\":938,\"sha256\":\"1e8f2570ed783b41497de82112e94798920bb9ffbd745d81e85c304737d237ce\"},{\"address\":1882021290,\"size\":100,\"sha256\":\"eeb3306b86c99b76c1881aed97dcebaf93411af971d08ed975dd8e58874ef177\"},{\"address\":1882021390,\"size\":108,\"sha256\":\"490dbfa98ddfa99a2ff0375a38a4dbf0b778eb00527b6e587dedb39f59a9d3d9\"},{\"address\":2160068548,\"size\":20,\"sha256\":\"0052a47961a0f941dd3d97beca4b258b8be0cbd7553cf4e8ee92e8f735f65074\"},{\"address\":1889738828,\"size\":184,\"sha256\":\"2e1217166b3942f8e42486bd55379b45b87f2f51085d04688b626452159c89dd\"}],\"data_guards\":[{\"address\":2160068548,\"size\":20,\"sha256\":\"0052a47961a0f941dd3d97beca4b258b8be0cbd7553cf4e8ee92e8f735f65074\"},{\"address\":1889738828,\"size\":184,\"sha256\":\"2e1217166b3942f8e42486bd55379b45b87f2f51085d04688b626452159c89dd\"}]}",DMA_CONFIG="{\"init\":1881800760,\"setup_irq\":1881801152,\"cancel\":1881801316,\"setup\":1881801376,\"remaining\":1881801528,\"wait\":1881801560,\"tick\":2161398884,\"prepare\":1881800352,\"finish\":1881800452,\"callback_a\":1879052288,\"callback_b\":1879056384,\"ranges\":[[1881800760,388],[1881801152,162],[1881801316,58],[1881801376,150],[1881801528,28],[1881801560,194]],\"guards\":[{\"address\":1881800760,\"size\":388,\"sha256\":\"62cbd9af6fae44f8b5742c2e6ea363fcd109e8054bfaeb3302e5a74947069ec2\"},{\"address\":1881801152,\"size\":162,\"sha256\":\"b3a179a5e9265500297bb1071f1190bcca1c98817aa3117a9a7340adc7834efe\"},{\"address\":1881801316,\"size\":58,\"sha256\":\"af24620efafac4d7870df9f3dddfaa2b04da08fd8e6e9d739ee052663ba6018a\"},{\"address\":1881801376,\"size\":150,\"sha256\":\"cfce33a095142823ac3765bd40f6c73a758432dc84030c34d4063fd78dd1a5ef\"},{\"address\":1881801528,\"size\":28,\"sha256\":\"f4108ec707a7124c2625c29db37bf0da941d15205408364520929a78018b8be2\"},{\"address\":1881801560,\"size\":194,\"sha256\":\"9985aae8a70d67cb9b9810ca3d6be4381d12c09cb2b8dd4b85454cd4a0551c0c\"}]}";
 private static final long CTRL=0x80d94a60L,TX=0x80c10df4L,RX=0x80c10db0L,REINIT=0x80c10e38L,DISABLED=0x80c10e39L,TABLE=0x80c11738L,CLOCK=0x9a000024L,SHADOW=0x80c11c4cL,ROM=0x30000024L;
 private JsonObject hal,bus;private Io io;private int commands,reads,writes,ticks;private byte[] rom;
 private class Helper extends EmulatorHelper {
  private Emulator core;Helper(Program p){super(p);}
  @Override protected Emulator newEmulator(){core=super.newEmulator();return core;}
  void filter(MemoryAccessFilter f){core.addMemoryAccessFilter(f);}
 }
 private class Io extends MemoryAccessFilter {
  boolean active,reset;int rxBytes,payloadAt,opcode,reg,resetReads;long clock;java.io.ByteArrayOutputStream tx=new java.io.ByteArrayOutputStream();
  TreeMap<Long,Long> regs=new TreeMap<>(),dmaRegs=new TreeMap<>(),board=new TreeMap<>();
  @Override protected void processRead(AddressSpace space,long p,int n,byte[] data){
   if(!active||!space.getName().equals("ram"))return;long value;
   if(p==CLOCK){if(n!=4)throw new IllegalStateException("Probe clock width");value=clock;actions.add("clock_read:"+value);}
   else if(board.containsKey(p)){if(n!=4)throw new IllegalStateException("Probe board read width");value=board.get(p);actions.add("board_r:"+p+":"+value);}
   else if(p>=0x93080000L&&p<0x93080200L){long at=p-0x93080000L;if(n!=4||!dmaRegs.containsKey(at))throw new IllegalStateException("Probe DMA read");value=dmaRead(at,dmaRegs.get(at));dmaRegs.put(at,value);actions.add("dma_r:"+at+":"+value);}
   else if(p>=0x93240000L&&p<0x93240104L){long at=p-0x93240000L;
    if(at==0x100){if((n!=1&&n!=4)||rxBytes+n>fifoReadBound())throw new IllegalStateException("Probe FIFO read bound");value=0;
     value=fifoResponse(opcode,reg,n,payloadAt);
     payloadAt+=n;rxBytes+=n;
    }else{if(n!=4||!regs.containsKey(at))throw new IllegalStateException("Probe QSPI read");
     if(at==16&&reset){value=resetReads++==0?0x100:0;regs.put(at,value);if((value&0x100)==0)reset=false;}
     else if(at==24||at==36){value=packetFails(at==24,commands)?0:(at==24?3:1);regs.put(at,value);}else value=regs.get(at);
    }actions.add("r:"+at+":"+n+":"+value);
   }else return;
   for(int i=0;i<n;i++)data[i]=(byte)(value>>>(i*8));
  }
  @Override protected void processWrite(AddressSpace space,long p,int n,byte[] data){
   if(!active||!space.getName().equals("ram"))return;long value=0;for(int i=0;i<n;i++)value|=(data[i]&255L)<<(i*8);
   if(p==CLOCK){if(n!=4)throw new IllegalStateException("Probe clock width");clock=value;actions.add("clock_write:"+value);return;}
   if(board.containsKey(p)){if(n!=4)throw new IllegalStateException("Probe board write width");board.put(p,value);actions.add("board_w:"+p+":"+value);return;}
   if(p>=0x93080000L&&p<0x93080200L){long at=p-0x93080000L;if(n!=4||!dmaRegs.containsKey(at))throw new IllegalStateException("Probe DMA write");dmaRegs.put(at,value);actions.add("dma_w:"+at+":"+value);return;}
   if(p>=0x93240000L&&p<0x93240104L){long at=p-0x93240000L;
    if(at==0x100){fifoWrite(opcode,reg,data,tx.size());tx.writeBytes(data);}
    else{if(n!=4||!regs.containsKey(at))throw new IllegalStateException("Probe QSPI write");regs.put(at,at==36&&value==1?0:value);if(at==16&&(value&0x100)!=0)reset=true;if(at==12){commands++;opcode=(int)(value>>>24);reg=regs.get(0L).intValue();payloadAt=0;}}
    actions.add("w:"+at+":"+n+":"+value);
   }
  }
 }
 protected int fifoReadBound(){return 512;}
 protected long dmaRead(long offset,long value){return value;}
 protected boolean packetFails(boolean ready,int commandIndex){return commandIndex==c.get(ready?"full_ready_fail_at":"full_done_fail_at").getAsInt();}
 protected long fifoResponse(int opcode,int reg,int n,int payloadAt){
  if(opcode==0x9f){if(payloadAt+n>5)throw new IllegalStateException("Probe ID FIFO bound");long value=0;for(int i=0;i<n;i++)value|=(probeIdReads<=11*c.get("probe_delayed_rounds").getAsInt()?255L:c.getAsJsonArray("probe_id").get(payloadAt+i).getAsLong())<<(8*i);return value;}
  if(opcode!=0x0f||n!=1||!probeFeatures.containsKey((long)reg))throw new IllegalStateException("Probe feature FIFO backing");return probeFeatures.get((long)reg)^(probeFeatureReads==c.get("probe_feature_mismatch_at").getAsInt()?1:0);
 }
 protected void featureWritten(int reg,long value){probeFeatures.put((long)reg,value);}
 protected void fifoWrite(int opcode,int reg,byte[] data,int total){if(opcode!=0x1f||data.length!=1||total+data.length>64)throw new IllegalStateException("Probe feature FIFO write");featureWritten(reg,data[0]&255L);}
 @Override protected int executionBound(){return 30000;}
 @Override protected EmulatorHelper createEmulator(){Helper e=new Helper(currentProgram);io=new Io();e.filter(io);return e;}
 @Override protected void configure()throws Exception {
  hal=JsonParser.parseString(HAL_CONFIG).getAsJsonObject();bus=JsonParser.parseString(BUS_CONFIG).getAsJsonObject();JsonObject dma=JsonParser.parseString(DMA_CONFIG).getAsJsonObject();
  for(JsonObject config:new JsonObject[]{hal,bus,dma}){for(JsonElement item:config.getAsJsonArray("ranges"))cfg.getAsJsonArray("main_probe_ranges").add(item.deepCopy());for(JsonElement item:config.getAsJsonArray("guards"))cfg.getAsJsonArray("main_probe_guards").add(item.deepCopy());}
  for(JsonElement item:hal.getAsJsonArray("data_guards"))cfg.getAsJsonArray("main_probe_data_guards").add(item.deepCopy());
  for(var item:bus.getAsJsonObject("logs").entrySet())cfg.getAsJsonObject("logs").add(item.getKey(),item.getValue());
 }
 @Override protected void setupProbe(EmulatorHelper e){
  super.setupProbe(e);if(!c.get("native_main_full_probe").getAsBoolean())throw new IllegalStateException("Full probe scope");commands=reads=writes=ticks=0;
  byte[] guard=new byte[204];Arrays.fill(guard,(byte)0xa5);e.writeMemory(toAddr(CTRL-32),Arrays.copyOf(guard,128));e.writeMemory(toAddr(CTRL),new byte[64]);e.writeMemory(toAddr(RX-32),guard);e.writeMemory(toAddr(RX),new byte[136]);
  for(long p:new long[]{REINIT,DISABLED,REINIT+2,REINIT+3})put(e,p,1,0);put(e,DISABLED,1,c.get("bus_disabled").getAsBoolean()?1:0);
  e.writeMemory(toAddr(TABLE-32),guard);e.writeMemory(toAddr(TABLE),new byte[140]);
  for(long[] f:new long[][]{{0,0x11111111L},{4,0x22222222L},{8,0x33333333L},{12,0x44444444L},{16,0x55555555L},{24,0},{32,0x3300},{36,0},{52,0x101},{84,0x101}}){io.regs.put(f[0],f[1]);put(e,0x93240000L+f[0],4,f[1]);}put(e,0x93240100L,4,0);
  for(long[] f:new long[][]{{4,32},{8,0x100},{12,0},{16,0x200},{20,0},{24,0},{36,0}})io.dmaRegs.put(f[0],f[1]);for(int ch=0;ch<7;ch++)for(long[] f:new long[][]{{0x100,0x12340001},{0x104,0xffff},{0x108,0x11111111},{0x10c,0x22222222},{0x110,0x33333333},{0x114,0x44444444}})io.dmaRegs.put(ch*32+f[0],f[1]);for(var item:io.dmaRegs.entrySet())put(e,0x93080000L+item.getKey(),4,item.getValue());
  io.board.put(0x9a000004L,0x1000001L);io.board.put(0x9a00000cL,0x20000001L);for(var item:io.board.entrySet())put(e,item.getKey(),4,item.getValue());
  io.clock=c.get("full_clock_word").getAsLong();put(e,CLOCK,4,io.clock);put(e,SHADOW,4,0xa5a5a5a5L);rom=new byte[64];byte[] text=c.get("full_rom_version").getAsString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);System.arraycopy(text,0,rom,0,text.length);Arrays.fill(rom,32,64,(byte)0xa5);e.writeMemory(toAddr(ROM),rom);io.active=true;
 }
 private boolean stack(long p,long n){return n>=0&&p>=0x81000000L&&p+n<=0x81001000L;}
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(pc==0x70296ab0L){probeIndex=probeChipIndex(r(e,0));probeBusCalls++;actions.add("probe_bus_native:"+probeIndex);return false;}
  if(pc==0x702d5daaL||pc==0x702d5e0eL)return false;
  if(pc==0x70296c24L){
   long p=r(e,1);if(!stack(p,32))throw new IllegalStateException("Full probe packet bound");byte[] b=mem(e,p,32);long opcode=word(e,p+8),reg=word(e,p+16),n=word(e,p+24),out=word(e,p+20);boolean write=b[0]!=0;
   if(b[1]!=0||b[2]!=1||b[4]!=1||b[28]!=1||(n>0&&!stack(out,n)))throw new IllegalStateException("Full probe packet fields");
   if(opcode==0x9f){if(write||r(e,0)!=0||reg!=0||n!=5||b[12]!=1)throw new IllegalStateException("Full ID packet");probeIdReads++;}
   else{long selected=word(e,0x70f8e6f8L);probeChipIndex(selected);if(r(e,0)!=selected)throw new IllegalStateException("Full packet context");if(opcode==0xff){if(!write||n!=0||reg!=0||out!=0||b[12]!=0)throw new IllegalStateException("Full reset packet");}
    else if(opcode==0x0f||opcode==0x1f){if(n!=1||reg>255||b[12]!=1||write!=(opcode==0x1f))throw new IllegalStateException("Full feature packet");if(write)probeFeatureWrites++;else probeFeatureReads++;}else throw new IllegalStateException("Full packet opcode");}
   actions.add("probe_packet:"+opcode+":"+reg+":"+n+":"+(write?1:0));return false;
  }
  if(pc==hal.get("receive").getAsLong()){reads++;return false;}if(pc==hal.get("transmit").getAsLong()){writes++;return false;}
  if(pc==hal.get("tick").getAsLong()){long value=ticks++*1001L;actions.add("tick:"+value);e.writeRegister("a0",value&0xffffffffL);e.writeRegister("a1",value>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));return true;}
  if(pc==hal.get("frequency").getAsLong()){actions.add("frequency:1000");ret(e,1000);return true;}
  if(pc==hal.get("strcmp").getAsLong()){long p=r(e,0);if((p!=0x709a84d4L&&p!=0x709a84dcL)||r(e,1)!=ROM)throw new IllegalStateException("Full ROM comparison");String a=p==0x709a84d4L?"v1.1.03":"v1.1.16",b=c.get("full_rom_version").getAsString();actions.add("compare:"+a+":"+b);ret(e,a.compareTo(b));return true;}
  if(pc==0x80d43a24L||pc==0x80d342f8L){boolean mux=pc==0x80d43a24L;if(r(e,0)!=0||r(e,1)!=127||r(e,2)!=(mux?63:1))throw new IllegalStateException("Full pin arguments");long status=c.get("full_pin_status").getAsLong();actions.add((mux?"platform_pinmux:":"platform_gpio:")+status);ret(e,status);return true;}
  if(pc==bus.get("diagnostic").getAsLong()){actions.add("diagnostic");ret(e,0);return true;}
  var ins=getInstructionAt(toAddr(pc));if(ins!=null&&ins.getMnemonicString().startsWith("fence")){actions.add("fence");e.writeRegister(e.getPCRegister(),pc+ins.getLength());return true;}
  return super.probeService(e,pc);
 }
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){
  super.probeSnapshot(e,row);row.addProperty("full_controller_hex",HexFormat.of().formatHex(mem(e,CTRL,64)));JsonArray contexts=new JsonArray(),registry=new JsonArray();for(long p:new long[]{TX,RX})contexts.add(HexFormat.of().formatHex(mem(e,p,68)));for(int i=0;i<35;i++)registry.add(word(e,TABLE+i*4));row.add("full_dma_contexts_hex",contexts);row.add("full_dma_registry",registry);
  for(Object[] pair:new Object[][]{{"full_dma_mmio",io.dmaRegs},{"full_mmio",io.regs},{"full_board_mmio",io.board}}){JsonObject values=new JsonObject();for(var item:((TreeMap<Long,Long>)pair[1]).entrySet())values.addProperty(Long.toString(item.getKey()),item.getValue());row.add((String)pair[0],values);}
  row.addProperty("full_clock_word",io.clock);row.addProperty("full_clock_shadow",word(e,SHADOW));row.addProperty("full_commands",commands);row.addProperty("full_reads",reads);row.addProperty("full_writes",writes);row.addProperty("full_rx_bytes",io.rxBytes);row.addProperty("full_tx_hex",HexFormat.of().formatHex(io.tx.toByteArray()));
 }
 @Override protected void validateExtra(EmulatorHelper e)throws Exception {
  byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long p:new long[]{CTRL-32,CTRL+64,RX-32,REINIT+4,TABLE-32,TABLE+140})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Full probe guard");
  for(long p:new long[]{TX,RX})for(int off:new int[]{40,41,42,43,48,49,50,51,52,53,54,55,56,57,58,59})if(mem(e,p+off,1)[0]!=0)throw new IllegalStateException("Full probe untouched field changed");
  if(!Arrays.equals(rom,mem(e,ROM,64))||mem(e,REINIT,1)[0]!=0||mem(e,DISABLED,1)[0]!=(c.get("bus_disabled").getAsBoolean()?1:0)||mem(e,REINIT+2,1)[0]!=0||mem(e,REINIT+3,1)[0]!=0)throw new IllegalStateException("Full probe immutable fixture changed");
 }
}
