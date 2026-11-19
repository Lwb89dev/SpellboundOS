// Original mode-zero page read/private DMA and sleep-poll erase after BBT/root.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.util.*;
public class ValidateMainNandAsync extends ValidateMainNandBbtRepair {
 private static final String ASYNC_CONFIG="{\"ranges\":[[1882021912,110],[1882022936,2],[1882023872,156]],\"guards\":[{\"address\":1882021912,\"size\":110,\"sha256\":\"b2d7ff06784e87d0f2ce3d84a3035507f664758b16fdb7e16ac864633577cec9\"},{\"address\":1882022936,\"size\":2,\"sha256\":\"7529d4e6ceb037815e2664a7277abb404b02f0bf9ddbf5c11658f52448221cba\"},{\"address\":1882023872,\"size\":156,\"sha256\":\"f31e56a387757f0ca0b3c572c09ed72420fd7b998367cc8183614b1e4485273d\"}],\"data_guards\":[{\"address\":1895332560,\"size\":1,\"sha256\":\"4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a\"}]}";
 private static final long BUFFER=0x81330000L,BOUNCE=0x80d93960L;
 private String appKind;private int calls,statusReads,sleeps,dmaCalls,commands,dmaTicks,indexA,indexB;private long loaded;private boolean dmaActive;
 private boolean stack(long p,long n){return n>=0&&p>=0x81000000L&&p+n<=0x81001000L;}
 private long signed(long v){return v>=0x80000000L?v-0x100000000L:v;}
 @Override protected void configure()throws Exception {super.configure();JsonObject a=JsonParser.parseString(ASYNC_CONFIG).getAsJsonObject();for(JsonElement item:a.getAsJsonArray("ranges"))cfg.getAsJsonArray("main_probe_ranges").add(item.deepCopy());for(JsonElement item:a.getAsJsonArray("guards"))cfg.getAsJsonArray("main_probe_guards").add(item.deepCopy());for(JsonElement item:a.getAsJsonArray("data_guards"))cfg.getAsJsonArray("main_probe_data_guards").add(item.deepCopy());}
 @Override protected void setupProbe(EmulatorHelper e){super.setupProbe(e);if(!c.get("native_main_async").getAsBoolean())throw new IllegalStateException("Mode-zero scope");appKind=null;calls=statusReads=sleeps=dmaCalls=commands=dmaTicks=indexA=indexB=0;loaded=0;dmaActive=false;byte[] guard=new byte[576];Arrays.fill(guard,(byte)0xa5);e.writeMemory(toAddr(BUFFER-32),Arrays.copyOf(guard,192));e.writeMemory(toAddr(BOUNCE-32),guard);byte[] b=new byte[512];Arrays.fill(b,(byte)c.get("app_bounce_byte").getAsInt());e.writeMemory(toAddr(BOUNCE),b);}
 @Override protected boolean additionalOperation(EmulatorHelper e,String kind)throws Exception {if(!kind.equals("app_read")&&!kind.equals("app_erase"))return super.additionalOperation(e,kind);appKind=kind;calls++;commands=0;try{if(kind.equals("app_read"))entry(e,0x702d6bbeL,op.get("data").getAsBoolean()?BUFFER:0,op.get("offset").getAsLong(),op.get("command").getAsLong(),op.get("size").getAsLong(),0);else entry(e,0x702d730cL,op.get("offset").getAsLong(),0);}finally{appKind=null;}return true;}
 @Override protected boolean packetFails(boolean ready,int index){return appKind!=null?commands==c.get(ready?"app_ready_fail_at":"app_done_fail_at").getAsInt():super.packetFails(ready,index);}
 @Override protected long dmaRead(long at,long value){if(dmaActive&&(at==20||at==24)){JsonArray a=c.getAsJsonArray(at==20?"app_dma_a":"app_dma_b");int i=at==20?indexA++:indexB++;return a.get(Math.min(i,a.size()-1)).getAsLong();}return super.dmaRead(at,value);}
 @Override protected long fifoResponse(int opcode,int reg,int n,int at){
  if(appKind!=null&&opcode==15&&reg==192){if(n!=1)throw new IllegalStateException("Application status width");JsonArray a=c.getAsJsonArray("app_statuses");long value=a.get(Math.min(statusReads++,a.size()-1)).getAsLong();super.fifoResponse(opcode,reg,n,at);return value;}
  if("app_read".equals(appKind)&&opcode==107){if(at+n>op.get("size").getAsInt()||at+n>64)throw new IllegalStateException("Application direct FIFO bound");long value=0;for(int i=0;i<n;i++)value|=((0x5a+loaded*3+(reg&0xffffffffL)+(at+i)*7)&255)<<(8*i);return value;}
  return super.fifoResponse(opcode,reg,n,at);
 }
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(appKind!=null){
   if(pc==0x702d6418L)actions.add("app_callback_invoked");
   if(pc==0x702d6bbeL&&appKind.equals("app_read")){actions.add("app_read_native:"+r(e,1)+":"+r(e,2)+":"+r(e,3));return false;}
   if(pc==0x702d730cL&&appKind.equals("app_erase")){actions.add("app_erase_native:"+r(e,0));return false;}
   if(pc==0x702d5edcL)loaded=r(e,0);
   if(pc==0x702d8010L)actions.add("app_page_retry:"+r(e,0));
   if(pc==0x70296c24L){commands++;long p=r(e,1);if(!stack(p,32))throw new IllegalStateException("Application packet backing");long opcode=word(e,p+8),at=word(e,p+16),n=word(e,p+24),out=word(e,p+20);byte[] b=mem(e,p,32);
    if(opcode==107){if(!appKind.equals("app_read")||!stack(p,36)||r(e,0)!=word(e,0x70f8e6f8L)||b[0]!=0||b[1]!=1||b[2]!=0||b[4]!=1||b[12]!=2||b[28]!=3||n!=op.get("size").getAsLong()||n>64||out!=BUFFER||at!=op.get("command").getAsLong()||word(e,p+32)!=0x702d6418L)throw new IllegalStateException("Mode-zero read packet");actions.add("probe_packet:107:"+at+":"+n+":0");return false;}
    if(opcode==6||opcode==216){if(!appKind.equals("app_erase")||r(e,0)!=word(e,0x70f8e6f8L)||b[0]!=1||b[1]!=0||b[2]!=1||b[4]!=1||b[12]!=(opcode==6?0:3)||b[28]!=1||n!=0||out!=0||opcode==6&&at!=0)throw new IllegalStateException("Mode-zero erase packet");actions.add("probe_packet:"+opcode+":"+at+":0:1");return false;}
   }
   if(pc==0x80d34d60L){if(!appKind.equals("app_read")||r(e,0)!=0x80d94a60L||r(e,1)!=BOUNCE||r(e,2)!=1000)throw new IllegalStateException("Application DMA wrapper");dmaCalls++;return false;}
   if(pc==0x702a02a0L||pc==0x702a0358L){if(r(e,0)!=0x80c10db0L)throw new IllegalStateException("Original application DMA binding");dmaActive=true;return false;}
   if(pc==0x80d45464L){JsonArray a=c.getAsJsonArray("app_dma_ticks");long value=a.get(Math.min(dmaTicks++,a.size()-1)).getAsLong();actions.add("dma_tick:"+Long.toUnsignedString(value));e.writeRegister("a0",value&0xffffffffL);e.writeRegister("a1",value>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));return true;}
   if(pc==0x7029fea0L||pc==0x7029ff04L){long p=r(e,0),n=r(e,1);if(n>64||p!=0&&p!=BOUNCE&&p!=0x93240100L)throw new IllegalStateException("Application DMA cache span");actions.add((pc==0x7029fea0L?"dma_cache_prepare:":"dma_cache_finish:")+p+":"+n);ret(e,0);return true;}
   if(pc==0x70947b0cL&&r(e,0)==BUFFER&&r(e,1)==BOUNCE){long n=r(e,2);if(n!=op.get("size").getAsLong()||n>64)throw new IllegalStateException("Application bounce copy span");e.writeMemory(toAddr(BUFFER),mem(e,BOUNCE,(int)n));actions.add("app_copy_from_bounce:"+n);ret(e,BUFFER);return true;}
   if(pc==0x80d369eeL){if(!appKind.equals("app_erase")||r(e,0)!=1)throw new IllegalStateException("Original sleep argument");sleeps++;actions.add("app_sleep:1");ret(e,0);return true;}
   if(pc==0x702b38a2L){long fmt=r(e,3);String tag=fmt==0x70a31364L?"app_read_result:"+signed(r(e,5)):fmt==0x70a3154cL?"app_erase_result:"+signed(r(e,5)):fmt==0x70a31508L?"app_erase_guard":null;if(tag!=null){actions.add("log:"+tag);ret(e,0);return true;}}
  }
  return super.probeService(e,pc);
 }
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){super.probeSnapshot(e,row);row.addProperty("app_buffer_hex",HexFormat.of().formatHex(mem(e,BUFFER,128)));row.addProperty("app_calls",calls);row.addProperty("app_status_reads",statusReads);row.addProperty("app_sleep_calls",sleeps);row.addProperty("app_loaded",loaded);row.addProperty("app_dma_calls",dmaCalls);try{row.addProperty("app_bounce_sha256",hash(mem(e,BOUNCE,512)));}catch(Exception ex){throw new IllegalStateException(ex);}}
 @Override protected void validateExtra(EmulatorHelper e)throws Exception {super.validateExtra(e);byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long p:new long[]{BUFFER-32,BUFFER+128,BOUNCE-32,BOUNCE+512})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Application buffer guard");byte[] expected=new byte[512];Arrays.fill(expected,(byte)c.get("app_bounce_byte").getAsInt());if(!Arrays.equals(expected,mem(e,BOUNCE,512)))throw new IllegalStateException("Authored bounce backing changed");}
}
