// Actual recovery page/optional marker reads through original main FIFO.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.util.*;
import java.io.ByteArrayOutputStream;
public class ValidateMainNandBbtRead extends ValidateMainNandBbtMapping {
 private static final String IO_CONFIG="{\"ranges\":[[1882024894,366],[1882021804,108],[1882030096,238],[1882026344,228]],\"guards\":[{\"address\":1882024894,\"size\":366,\"sha256\":\"a1035a344931869c4c6b87462e434f321588bb6d73c3fd555c1df7296a4f68d8\"},{\"address\":1882021804,\"size\":108,\"sha256\":\"3d081e7f2f2635c3bbfa67834d14b8c4558880292df033440d31ee3f9a6c5e43\"},{\"address\":1882030096,\"size\":238,\"sha256\":\"30d7282cafe455c221f75a4a88054b4729d37ad204f271bd2df2fc81bd2ac11d\"},{\"address\":1882026344,\"size\":228,\"sha256\":\"5d9b1f7aab97474ff65240abb04c91817c6201ad5597fd3238f991f6d5f442a6\"}]}";
 private boolean inRecovery,inRead,inMarker;private long recoveryReturn,readReturn,markerReturn,readSize,readColumn,readBuffer,loaded;
 private int pageCalls,markerCalls,statusReads,cachePackets,cacheBytes,recordReads,readCommands;private ByteArrayOutputStream received;
 private long signed(long v){return v>=0x80000000L?v-0x100000000L:v;}
 private boolean stack(long p,long n){return n>=0&&p>=0x81000000L&&p+n<=0x81001000L;}
 @Override protected int executionBound(){return 200000;}
 @Override protected void configure()throws Exception {super.configure();JsonObject p=JsonParser.parseString(IO_CONFIG).getAsJsonObject();for(JsonElement item:p.getAsJsonArray("ranges"))cfg.getAsJsonArray("main_probe_ranges").add(item.deepCopy());for(JsonElement item:p.getAsJsonArray("guards"))cfg.getAsJsonArray("main_probe_guards").add(item.deepCopy());}
 @Override protected void setupProbe(EmulatorHelper e){super.setupProbe(e);if(!c.get("native_main_bbt_read").getAsBoolean())throw new IllegalStateException("Recovery read scope");inRecovery=inRead=inMarker=false;recoveryReturn=readReturn=markerReturn=readSize=readColumn=readBuffer=loaded=0;pageCalls=markerCalls=statusReads=cachePackets=cacheBytes=recordReads=readCommands=0;received=new ByteArrayOutputStream();}
 @Override protected boolean packetFails(boolean ready,int index){return inRead?pageCalls==c.get("recovery_fault_read").getAsInt()&&readCommands==c.get(ready?"recovery_ready_fail_at":"recovery_done_fail_at").getAsInt():super.packetFails(ready,index);}
 @Override protected long fifoResponse(int opcode,int reg,int n,int at){
  if(inRead&&opcode==15&&reg==192){if(n!=1)throw new IllegalStateException("Recovery status width");JsonArray a=c.getAsJsonArray("recovery_statuses");long value=a.get(Math.min(statusReads++,a.size()-1)).getAsLong();super.fifoResponse(opcode,reg,n,at);return value;}
  if(inRead&&opcode==107){if(at+n>readSize||readSize>140)throw new IllegalStateException("Recovery cache FIFO bound");long block=loaded/64;byte[] data;
   if(readColumn==2048){boolean good=false;for(JsonElement item:c.getAsJsonArray("bbt_good_blocks"))if(item.getAsLong()==block)good=true;JsonArray bad=c.getAsJsonObject("marker_bad_pages").getAsJsonArray(Long.toString(block));if(bad!=null)for(JsonElement item:bad)if(item.getAsLong()==loaded%64)good=false;data=new byte[]{(byte)(good?255:0),(byte)(good?255:0)};}
   else{JsonElement hex=c.getAsJsonObject("bbt_record_hex").get(Long.toString(block));data=new byte[140];Arrays.fill(data,(byte)255);Arrays.fill(data,0,12,(byte)0);if(hex!=null)data=HexFormat.of().parseHex(hex.getAsString());}
   if(data.length!=readSize||reg!=(int)readColumn)throw new IllegalStateException("Recovery FIFO source");long value=0;for(int i=0;i<n;i++)value|=(data[at+i]&255L)<<(8*i);received.write(data,at,n);cacheBytes+=n;return value;
  }
  return super.fifoResponse(opcode,reg,n,at);
 }
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(inRead&&pc==readReturn){inRead=false;actions.add("recovery_read_return:"+signed(r(e,0)));}
  if(inMarker&&pc==markerReturn){inMarker=false;actions.add("main_marker_return:"+signed(r(e,0)));}
  if(inRecovery&&pc==recoveryReturn)inRecovery=false;
  if(pc==0x702d58acL){inRecovery=true;recoveryReturn=e.readRegister("ra").longValue()&0xffffffffL;}
  if(inRecovery&&pc==0x702d7168L&&c.get("native_main_bbt_markers").getAsBoolean()){
   if(inMarker||r(e,1)!=1||r(e,0)<1008||r(e,0)>=1024)throw new IllegalStateException("Actual marker query bound");inMarker=true;markerCalls++;markerReturn=e.readRegister("ra").longValue()&0xffffffffL;actions.add("main_marker_native:"+r(e,0));return false;
  }
  if(inRecovery&&pc==0x702d6bbeL){
   if(inRead||!stack(r(e,0),r(e,3))||r(e,4)!=1||r(e,1)/64<1008||r(e,1)/64>=1024)throw new IllegalStateException("Actual recovery read backing");
   readSize=r(e,3);readColumn=r(e,2);readBuffer=r(e,0);if(!(inMarker&&readSize==2&&readColumn==2048||!inMarker&&readSize==140&&readColumn==0&&r(e,1)%64==0))throw new IllegalStateException("Actual recovery read shape");
   inRead=true;readReturn=e.readRegister("ra").longValue()&0xffffffffL;pageCalls++;readCommands=0;received.reset();if(!inMarker){recordReads++;actions.add("bbt_record_read_native:"+r(e,1)+":"+word(e,0x70f9bbacL));}
   actions.add("main_recovery_page_native:"+r(e,1)+":"+readColumn+":"+readSize);return false;
  }
  if(inRead){
   if(pc==0x702d5edcL)loaded=r(e,0);
   if(pc==0x702d8010L)actions.add("main_page_retry:"+r(e,0));
   if(pc==0x70296c24L){readCommands++;long p=r(e,1);if(!stack(p,32))throw new IllegalStateException("Recovery packet backing");if(word(e,p+8)==107){byte[] b=mem(e,p,32);long n=word(e,p+24),col=word(e,p+16);if(r(e,0)!=word(e,0x70f8e6f8L)||b[0]!=0||b[1]!=1||b[2]!=1||b[4]!=1||b[12]!=2||b[28]!=3||n!=readSize||word(e,p+20)!=readBuffer||col!=readColumn)throw new IllegalStateException("Recovery direct x4 packet");cachePackets++;actions.add("probe_packet:107:"+col+":"+n+":0");return false;}}
   if(pc==0x702b38a2L&&r(e,3)==0x70a31364L){actions.add("log:main_page_result:"+signed(r(e,5)));ret(e,0);return true;}
  }
  if(inMarker&&pc==0x702b38a2L){if(r(e,3)==0x70a314a8L){actions.add("log:main_marker_bad");ret(e,0);return true;}if(r(e,3)==0x70a31458L){actions.add("log:main_marker_error:"+signed(r(e,5)));ret(e,0);return true;}}
  if(inRecovery&&pc==0x702b38a2L&&cfg.getAsJsonObject("logs").has(Long.toString(r(e,3))))return false;
  return super.probeService(e,pc);
 }
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){super.probeSnapshot(e,row);row.addProperty("bbt_reads",recordReads);row.addProperty("io_page_calls",pageCalls);row.addProperty("io_marker_calls",markerCalls);row.addProperty("io_status_reads",statusReads);row.addProperty("io_cache_packets",cachePackets);row.addProperty("io_cache_bytes",cacheBytes);row.addProperty("io_last_fifo_hex",HexFormat.of().formatHex(received.toByteArray()));row.addProperty("io_loaded",loaded);}
}
