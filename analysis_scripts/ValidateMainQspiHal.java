// Original main QSPI bodies over authored MMIO, timer, ROM and DMA services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import com.google.gson.*;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateMainQspiHal extends GhidraScript {
 protected static final String CONFIG="{\"pack\":2161330176,\"complete\":2161330376,\"wait_receive\":2161330516,\"wait_transmit\":2161330664,\"tx_count\":2161330812,\"rx_count\":2161330848,\"init\":2161330884,\"command\":2161330992,\"receive\":2161331304,\"receive_dma\":2161331552,\"transmit\":2161331648,\"transmit_dma\":2161331888,\"clock\":2161334284,\"version\":2161399148,\"tick\":2161398940,\"frequency\":2161398960,\"dma_setup\":1881801376,\"dma_wait\":1881801560,\"strcmp\":1888786464,\"ranges\":[[2161330176,100],[2161330376,140],[2161330516,148],[2161330664,148],[2161330812,36],[2161330848,36],[2161330884,108],[2161330992,204],[2161331304,248],[2161331552,96],[2161331648,240],[2161331888,88],[2161334284,52],[2161399148,86]],\"guards\":[{\"address\":2161330176,\"size\":100,\"sha256\":\"d81728d94ec968a8022bdf7cd2c799cdd65fdbe9c81fe3e8279b0f1750187ca8\"},{\"address\":2161330376,\"size\":140,\"sha256\":\"5c43692373eb63fa3689c149a3da5e14cbb9a5c247aa784f9393216514a8d657\"},{\"address\":2161330516,\"size\":148,\"sha256\":\"fb54106945149f0adcc42b5e19f04eb33712bdade8b67aa871b3a2443a971dd8\"},{\"address\":2161330664,\"size\":148,\"sha256\":\"613d4f163b6098fac11a43c891069db3f3570485369f0035548fb9f688d855c7\"},{\"address\":2161330812,\"size\":36,\"sha256\":\"23f0432a05059b34c075ae3b853d8042bb22a71cd30f0ee056f8eff3f02b715e\"},{\"address\":2161330848,\"size\":36,\"sha256\":\"42c4cd8a20418deeb8f7f9c7568c4df0993e9e95ff0957530f69f313c01f79e8\"},{\"address\":2161330884,\"size\":108,\"sha256\":\"00754e5d66f0e683b7574bfe16e58619d92ad41b9f5860c63ed5741d81bea4c3\"},{\"address\":2161330992,\"size\":204,\"sha256\":\"29a15157d715409e04279787c466da24e5fa0699d76bec9d38ff649924ff16ca\"},{\"address\":2161331304,\"size\":248,\"sha256\":\"4b3d8e3416cf27b727cd8744bbe60327ef3a453df6be3dd556da6cfddbb1ad38\"},{\"address\":2161331552,\"size\":96,\"sha256\":\"e516225b2455b37107ba00bb52832e92d49b3ac79f47b13b1a5ad593d041fdc6\"},{\"address\":2161331648,\"size\":240,\"sha256\":\"c1d5acbaf50138e8f02ad63d68a24ba9fe92f5774ba8b1b8f9eaf3ed7a9d1f0d\"},{\"address\":2161331888,\"size\":88,\"sha256\":\"1e61b977e0fbafed189155c36bf3b8eb64481da377f24ff541aff3ad413f71cc\"},{\"address\":2161334284,\"size\":52,\"sha256\":\"8c398da0431498ac449a53359d83ea8b99c00d97dd6cce6465cad08955b9ce67\"},{\"address\":2161399148,\"size\":86,\"sha256\":\"4bf62f942d22c8f8bf9f51d44c03d03f5b811851a2184355173f036ae9e76f4e\"},{\"address\":1889174740,\"size\":8,\"sha256\":\"c04da2a2ed09a7b3bcbb243d672f998255800572ba63f514839d255d1a1d2255\"},{\"address\":1889174748,\"size\":8,\"sha256\":\"ba0f00ea8eed52463c26f35110d25090713fe37859f813dbc3cf397f9a604848\"}],\"data_guards\":[{\"address\":1889174740,\"size\":8,\"sha256\":\"c04da2a2ed09a7b3bcbb243d672f998255800572ba63f514839d255d1a1d2255\"},{\"address\":1889174748,\"size\":8,\"sha256\":\"ba0f00ea8eed52463c26f35110d25090713fe37859f813dbc3cf397f9a604848\"}]}";
 protected static final long END=0x70000000L,CTRL=0x80d94a60L,BUFFER=0x81301000L,FRAME=0x81302000L,DMA0=0x81304000L,DMA1=0x81305000L,CLOCK=0x9a000024L,SHADOW=0x80c11c4cL,ROM=0x30000024L;
 protected JsonObject cfg,c,stopped;protected JsonArray actions;protected int steps,ticks,chunks;protected Io io;
 protected class Helper extends EmulatorHelper {
  private Emulator core;Helper(Program p){super(p);}
  @Override protected Emulator newEmulator(){core=super.newEmulator();return core;}
  void filter(MemoryAccessFilter f){core.addMemoryAccessFilter(f);}
 }
 protected class Io extends MemoryAccessFilter {
  boolean active,reset;int rx;long base,clock;TreeMap<Long,Long> regs=new TreeMap<>();Map<String,Integer> indices=new HashMap<>();ByteArrayOutputStream tx=new ByteArrayOutputStream();
  long next(String key){JsonArray values=c.getAsJsonArray(key);int i=indices.getOrDefault(key,0);indices.put(key,i+1);return values.get(Math.min(i,values.size()-1)).getAsLong();}
  @Override protected void processRead(AddressSpace space,long offset,int size,byte[] data){
   if(!active||!space.getName().equals("ram"))return;long value;
   if(offset==CLOCK){if(size!=4)throw new IllegalStateException("Clock width");value=clock;actions.add("clock_read:"+value);}
   else if(offset>=base&&offset<base+0x104){long at=offset-base;
    if(at==0x100){if((size!=1&&size!=4)||rx+size>512)throw new IllegalStateException("FIFO read bound");value=0;for(int i=0;i<size;i++)value|=((0x5a+(rx+i)*7)&255L)<<(8*i);rx+=size;}
    else{if(size!=4||!regs.containsKey(at))throw new IllegalStateException("Unexpected register read");
     if(at==0x10&&reset){value=next("reset_reads");regs.put(at,value);if((value&0x100)==0)reset=false;}
     else if(at==0x18){value=next("ready");regs.put(at,value);}else if(at==0x24){value=next("done");regs.put(at,value);}else value=regs.get(at);
    }actions.add("r:"+at+":"+size+":"+value);
   }else return;
   for(int i=0;i<size;i++)data[i]=(byte)(value>>>(8*i));
  }
  @Override protected void processWrite(AddressSpace space,long offset,int size,byte[] data){
   if(!active||!space.getName().equals("ram"))return;long value=0;for(int i=0;i<size;i++)value|=(data[i]&255L)<<(8*i);
   if(offset==CLOCK){if(size!=4)throw new IllegalStateException("Clock width");clock=value;actions.add("clock_write:"+value);return;}
   if(offset>=base&&offset<base+0x104){long at=offset-base;
    if(at==0x100){if((size!=1&&size!=4)||tx.size()+size>512)throw new IllegalStateException("FIFO write bound");tx.writeBytes(data);}
    else{if(size!=4||!regs.containsKey(at))throw new IllegalStateException("Unexpected register write");regs.put(at,at==0x24&&value==1?0:value);if(at==0x10&&(value&0x100)!=0)reset=true;}
    actions.add("w:"+at+":"+size+":"+value);
   }
  }
 }
 protected long a(String k){return cfg.get(k).getAsLong();}
 protected long r(Helper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
 protected void put(Helper e,long at,int n,long value){e.writeMemoryValue(toAddr(at),n,value);}
 protected byte[] mem(Helper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
 protected long word(Helper e,long at){byte[] b=mem(e,at,4);long v=0;for(int i=0;i<4;i++)v|=(b[i]&255L)<<(8*i);return v;}
 protected String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 protected void ret(Helper e,long value){e.writeRegister("a0",value&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
 protected String string(Helper e,long at){StringBuilder b=new StringBuilder();for(int i=0;i<32;i++){int v=mem(e,at+i,1)[0]&255;if(v==0)return b.toString();b.append((char)v);}throw new IllegalStateException("String bound");}
 protected boolean pointer(long p,int n){return n>=0&&n<=512&&p>=BUFFER&&p+n<=BUFFER+512;}
 protected boolean service(Helper e,long pc)throws Exception {
  if(pc==a("tick")){JsonArray values=c.getAsJsonArray("ticks");long v=values.get(Math.min(ticks++,values.size()-1)).getAsLong();actions.add("tick:"+Long.toUnsignedString(v));e.writeRegister("a0",v&0xffffffffL);e.writeRegister("a1",v>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));return true;}
  if(pc==a("frequency")){long v=c.get("frequency").getAsLong();actions.add("frequency:"+v);ret(e,v);return true;}
  if(pc==a("strcmp")){long p=r(e,0),q=r(e,1);if((p!=0x709a84d4L&&p!=0x709a84dcL)||q!=ROM)throw new IllegalStateException("Revision comparison");String x=string(e,p),y=string(e,q);actions.add("compare:"+x+":"+y);ret(e,x.compareTo(y));return true;}
  if(pc==a("dma_setup")){
   long p=r(e,0),source=r(e,1),out=r(e,2);int n=(int)r(e,3);boolean receive=p==DMA1;
   if(p!=DMA0&&p!=DMA1||n<0||n>64||receive&&(source!=io.base+0x100||!pointer(out,n))||!receive&&(out!=io.base+0x100||!pointer(source,n)))throw new IllegalStateException("DMA setup bounds");
   long status=c.get("dma_setup_status").getAsLong();actions.add("dma_setup:"+(receive?"receive":"transmit")+":"+n+":"+io.regs.get(32L)+":"+status+":"+hash(receive?new byte[0]:mem(e,source,n)));
   if(receive&&status==0&&c.get("dma_copy").getAsBoolean()){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(0x5a+i*7);if(n>0)e.writeMemory(toAddr(out),b);}ret(e,status);return true;
  }
  if(pc==a("dma_wait")){if(r(e,0)!=DMA0&&r(e,0)!=DMA1||r(e,1)!=c.get("timeout").getAsLong())throw new IllegalStateException("DMA wait arguments");long v=c.get("dma_wait_status").getAsLong();actions.add("dma_wait:"+r(e,1)+":"+io.regs.get(32L)+":"+v);ret(e,v);return true;}
  return false;
 }
 protected void abi(Helper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
 protected void entry(Helper e,long start,long... args)throws Exception {
  e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
  while((pc=e.getExecutionAddress().getOffset())!=END){
   if(++steps>10000)throw new IllegalStateException("Main HAL execution bound");
   if(pc==a("wait_receive")||pc==a("wait_transmit")){int stop=c.get("stop_chunks").getAsInt();if(stop>0&&chunks==stop){actions.add("stop_no_progress:"+chunks);stopped=new JsonObject();stopped.addProperty("kind","bounded_prefix");stopped.addProperty("chunks",chunks);return;}chunks++;}
   if(service(e,pc)){if(stopped!=null)return;continue;}
   boolean allowed=false;for(JsonElement item:cfg.getAsJsonArray("ranges")){JsonArray span=item.getAsJsonArray();long at=span.get(0).getAsLong(),n=span.get(1).getAsLong();if(pc>=at&&pc<at+n){allowed=true;break;}}
   if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(e.getLastError());
  }abi(e);
 }
 protected void configure()throws Exception {}
 protected void setupExtra(Helper e)throws Exception {}
 protected boolean dispatchExtra(Helper e,String mode)throws Exception {return false;}
 protected void snapshotExtra(Helper e,JsonObject row)throws Exception {}
 protected JsonObject execute(JsonObject input)throws Exception {
  c=input;steps=ticks=chunks=0;actions=new JsonArray();stopped=null;Helper e=new Helper(currentProgram);io=new Io();io.base=c.get("base").getAsLong();io.clock=c.get("clock_word").getAsLong();
  try{
   byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
   e.writeMemory(toAddr(CTRL-32),Arrays.copyOf(sentinel,128));for(long[] f:new long[][]{{0,c.get("base_present").getAsBoolean()?io.base:0},{8,c.getAsJsonArray("flags").get(0).getAsLong()},{12,c.getAsJsonArray("flags").get(1).getAsLong()},{16,c.get("controller_mode").getAsLong()},{20,c.get("count").getAsLong()},{32,DMA0},{36,DMA1}})put(e,CTRL+f[0],4,f[1]);
   e.writeMemory(toAddr(BUFFER-32),Arrays.copyOf(sentinel,576));byte[] b=new byte[512];for(int i=0;i<512;i++)b[i]=(byte)(i*3+1);e.writeMemory(toAddr(BUFFER),b);
   e.writeMemory(toAddr(FRAME-32),Arrays.copyOf(sentinel,108));for(int i=0;i<11;i++)put(e,FRAME+i*4,4,c.getAsJsonArray("frame").get(i).getAsLong());byte[] frame=mem(e,FRAME,44);
   for(long[] f:new long[][]{{0,0x11111111L},{4,0x22222222L},{8,0x33333333L},{12,0x44444444L},{16,0x55555555L},{24,0},{32,c.get("control").getAsLong()},{36,0},{52,0x101},{84,c.get("fifo").getAsLong()}}){io.regs.put(f[0],f[1]);put(e,io.base+f[0],4,f[1]);}
   put(e,io.base+0x100,4,0);
   put(e,CLOCK,4,io.clock);put(e,SHADOW,4,0xa5a5a5a5L);byte[] rom=new byte[64];System.arraycopy(c.get("rom_version").getAsString().getBytes(java.nio.charset.StandardCharsets.US_ASCII),0,rom,0,c.get("rom_version").getAsString().length());Arrays.fill(rom,32,64,(byte)0xa5);e.writeMemory(toAddr(ROM),rom);
   setupExtra(e);e.filter(io);io.active=true;String mode=c.get("mode").getAsString();long ctx=c.get("context_present").getAsBoolean()?CTRL:0,p=BUFFER+c.get("alignment").getAsLong(),timeout=c.get("timeout").getAsLong();
   if(!dispatchExtra(e,mode)){
    if(mode.equals("pack"))entry(e,a(mode),FRAME);else if(mode.equals("init"))entry(e,a(mode),ctx);else if(mode.equals("clock"))entry(e,a(mode),c.get("clock_select").getAsLong());else if(mode.equals("version"))entry(e,a(mode));
    else if(mode.equals("tx_count")||mode.equals("rx_count"))entry(e,a(mode),io.base);
    else if(mode.equals("command")||mode.startsWith("command_")){entry(e,a("command"),ctx,c.get("frame_present").getAsBoolean()?FRAME:0,timeout);if(stopped==null&&r(e,0)==0&&!mode.equals("command"))entry(e,a(mode.substring(8)),ctx,p,timeout);}
    else if(mode.equals("complete")||mode.startsWith("wait_"))entry(e,a(mode),ctx,timeout);else entry(e,a(mode),ctx,p,timeout);
   }
   io.active=false;JsonObject row=new JsonObject();row.add("returned",stopped==null?new JsonPrimitive(r(e,0)):JsonNull.INSTANCE);row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);
   row.addProperty("context_hex",HexFormat.of().formatHex(mem(e,CTRL,64)));row.addProperty("buffer_sha256",hash(mem(e,BUFFER,512)));row.addProperty("tx_hex",HexFormat.of().formatHex(io.tx.toByteArray()));row.addProperty("rx_bytes",io.rx);JsonObject regs=new JsonObject();for(var item:io.regs.entrySet())regs.addProperty(Long.toString(item.getKey()),item.getValue());row.add("mmio",regs);row.addProperty("clock_word",io.clock);row.addProperty("clock_shadow",word(e,SHADOW));snapshotExtra(e,row);
   byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{CTRL-32,CTRL+64,BUFFER-32,BUFFER+512,FRAME-32,FRAME+44})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Main HAL guard");if(!Arrays.equals(frame,mem(e,FRAME,44))||!Arrays.equals(rom,mem(e,ROM,64)))throw new IllegalStateException("Main HAL immutable fixture changed");
   for(JsonElement item:cfg.getAsJsonArray("data_guards")){JsonObject g=item.getAsJsonObject();if(!hash(mem(e,g.get("address").getAsLong(),g.get("size").getAsInt())).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Original main HAL data changed");}
   JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray rows=new JsonArray();rows.add(row);observed.add("rows",rows);if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/main-qspi-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
   JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
  }finally{e.dispose();}
 }
 public void run()throws Exception {
  if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();configure();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized main HAL code/data");}
  JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.get("bound_per_case").getAsInt()!=10000||input.getAsJsonArray("cases").size()>100)throw new IllegalStateException("Main HAL vector bound");JsonArray cases=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))cases.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",cases.size());report.addProperty("bound_per_case",10000);report.add("cases",cases);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("MAIN_QSPI_VALIDATION cases="+cases.size());
 }
}
