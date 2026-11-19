// Actual main mapped page read/load/busy/direct cache through original FIFO.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.util.*;
public class ValidateMainNandPageRead extends ValidateMainNandBbtMapping {
 private static final String PAGE_CONFIG="{\"ranges\":[[1882024894,366],[1882021804,108],[1882030096,238]],\"guards\":[{\"address\":1882024894,\"size\":366,\"sha256\":\"a1035a344931869c4c6b87462e434f321588bb6d73c3fd555c1df7296a4f68d8\"},{\"address\":1882021804,\"size\":108,\"sha256\":\"3d081e7f2f2635c3bbfa67834d14b8c4558880292df033440d31ee3f9a6c5e43\"},{\"address\":1882030096,\"size\":238,\"sha256\":\"30d7282cafe455c221f75a4a88054b4729d37ad204f271bd2df2fc81bd2ac11d\"}]}";
 private static final long BUFFER=0x81330000L;
 private boolean inPage;private int pageCalls,pageStatuses,pageCaches,pageCommands;private long loaded;
 private boolean stack(long p,long n){return n>=0&&p>=0x81000000L&&p+n<=0x81001000L;}
 @Override protected void configure()throws Exception {super.configure();JsonObject p=JsonParser.parseString(PAGE_CONFIG).getAsJsonObject();for(JsonElement item:p.getAsJsonArray("ranges"))cfg.getAsJsonArray("main_probe_ranges").add(item.deepCopy());for(JsonElement item:p.getAsJsonArray("guards"))cfg.getAsJsonArray("main_probe_guards").add(item.deepCopy());}
 @Override protected void setupProbe(EmulatorHelper e){super.setupProbe(e);if(!c.get("native_main_page_read").getAsBoolean())throw new IllegalStateException("Main page read scope");inPage=false;pageCalls=pageStatuses=pageCaches=pageCommands=0;loaded=0;byte[] b=new byte[192];Arrays.fill(b,(byte)0xa5);e.writeMemory(toAddr(BUFFER-32),b);}
 @Override protected boolean additionalOperation(EmulatorHelper e,String kind)throws Exception {if(!kind.equals("page_read"))return super.additionalOperation(e,kind);inPage=true;pageCalls++;pageCommands=0;try{entry(e,0x702d6bbeL,op.get("data").getAsBoolean()?BUFFER:0,op.get("offset").getAsLong(),op.get("command").getAsLong(),op.get("size").getAsLong(),1);}finally{inPage=false;}return true;}
 @Override protected boolean packetFails(boolean ready,int index){return inPage?pageCommands==c.get(ready?"page_ready_fail_at":"page_done_fail_at").getAsInt():super.packetFails(ready,index);}
 @Override protected long fifoResponse(int opcode,int reg,int n,int at){
  if(inPage&&opcode==15&&reg==192){if(n!=1)throw new IllegalStateException("Page status width");JsonArray a=c.getAsJsonArray("page_statuses");long value=a.get(Math.min(pageStatuses++,a.size()-1)).getAsLong();super.fifoResponse(opcode,reg,n,at);return value;}
  if(inPage&&opcode==0x6b){if(at+n>op.get("size").getAsInt()||at+n>128)throw new IllegalStateException("Main page FIFO bound");long value=0;for(int i=0;i<n;i++)value|=((0x5a+loaded*3+(reg&0xffffffffL)+(at+i)*7)&255)<<(8*i);return value;}
  return super.fifoResponse(opcode,reg,n,at);
 }
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(inPage){
   if(pc==0x702d6bbeL)actions.add("main_page_read_native:"+r(e,1)+":"+r(e,2)+":"+r(e,3));
   if(pc==0x702d5edcL)loaded=r(e,0);
   if(pc==0x702d8010L)actions.add("main_page_retry:"+r(e,0));
   if(pc==0x70296c24L){pageCommands++;long p=r(e,1);if(!stack(p,32))throw new IllegalStateException("Page packet backing");if(word(e,p+8)==0x6b){byte[] b=mem(e,p,32);long n=word(e,p+24),column=word(e,p+16);if(r(e,0)!=word(e,0x70f8e6f8L)||b[0]!=0||b[1]!=1||b[2]!=1||b[4]!=1||b[12]!=2||b[28]!=3||n!=op.get("size").getAsLong()||n>128||word(e,p+20)!=BUFFER||column!=op.get("command").getAsLong())throw new IllegalStateException("Main direct x4 cache packet");pageCaches++;actions.add("probe_packet:107:"+column+":"+n+":0");return false;}}
   if(pc==0x702b38a2L&&r(e,3)==0x70a31364L){long v=r(e,5);actions.add("log:main_page_result:"+(v>=0x80000000L?v-0x100000000L:v));ret(e,0);return true;}
  }
  return super.probeService(e,pc);
 }
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){super.probeSnapshot(e,row);row.addProperty("page_buffer_hex",HexFormat.of().formatHex(mem(e,BUFFER,128)));row.addProperty("page_calls",pageCalls);row.addProperty("page_status_reads",pageStatuses);row.addProperty("page_cache_packets",pageCaches);row.addProperty("page_loaded",loaded);}
 @Override protected void validateExtra(EmulatorHelper e)throws Exception {super.validateExtra(e);byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long p:new long[]{BUFFER-32,BUFFER+128})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Main page buffer guard");}
}
