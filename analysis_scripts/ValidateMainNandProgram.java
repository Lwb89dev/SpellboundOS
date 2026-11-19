// Original mode-zero page program through full BBT/root and initialized TX DMA.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.util.*;
import java.io.ByteArrayOutputStream;
public class ValidateMainNandProgram extends ValidateMainNandBbtRepair {
 private static final String PROGRAM_CONFIG="{\"ranges\":[[1882022330,106],[1882022936,2]],\"guards\":[{\"address\":1882022330,\"size\":106,\"sha256\":\"f73ad8127ddeceab26d4f415d1f9460446aef078bd9c597dac7a23bae33c6e1e\"},{\"address\":1882022936,\"size\":2,\"sha256\":\"7529d4e6ceb037815e2664a7277abb404b02f0bf9ddbf5c11658f52448221cba\"}],\"data_guards\":[{\"address\":1895332560,\"size\":1,\"sha256\":\"4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a\"}]}";
 private static final long BUFFER=0x81330000L,BOUNCE=0x80d93960L;
 private boolean app,dmaActive;private int calls,statusReads,dmaCalls,commands,dmaTicks,indexA,indexB;private long page;private ByteArrayOutputStream tx;private byte[] bounceExpected;
 private byte[] source(){byte[] b=new byte[128];for(int i=0;i<b.length;i++)b[i]=(byte)(0x96+i*11);return b;}
 private boolean stack(long p,long n){return n>=0&&p>=0x81000000L&&p+n<=0x81001000L;}
 private long signed(long v){return v>=0x80000000L?v-0x100000000L:v;}
 @Override protected void configure()throws Exception {super.configure();JsonObject a=JsonParser.parseString(PROGRAM_CONFIG).getAsJsonObject();for(JsonElement item:a.getAsJsonArray("ranges"))cfg.getAsJsonArray("main_probe_ranges").add(item.deepCopy());for(JsonElement item:a.getAsJsonArray("guards"))cfg.getAsJsonArray("main_probe_guards").add(item.deepCopy());for(JsonElement item:a.getAsJsonArray("data_guards"))cfg.getAsJsonArray("main_probe_data_guards").add(item.deepCopy());}
 @Override protected void setupProbe(EmulatorHelper e){super.setupProbe(e);if(!c.get("native_main_program").getAsBoolean())throw new IllegalStateException("Program scope");app=dmaActive=false;calls=statusReads=dmaCalls=commands=dmaTicks=indexA=indexB=0;page=0;tx=new ByteArrayOutputStream();byte[] guard=new byte[576];Arrays.fill(guard,(byte)0xa5);e.writeMemory(toAddr(BUFFER-32),Arrays.copyOf(guard,192));e.writeMemory(toAddr(BUFFER),source());e.writeMemory(toAddr(BOUNCE-32),guard);bounceExpected=new byte[512];Arrays.fill(bounceExpected,(byte)c.get("app_bounce_byte").getAsInt());e.writeMemory(toAddr(BOUNCE),bounceExpected);}
 @Override protected boolean additionalOperation(EmulatorHelper e,String kind)throws Exception {if(!kind.equals("app_program"))return super.additionalOperation(e,kind);app=true;calls++;commands=0;try{entry(e,0x702d6d2cL,op.get("data").getAsBoolean()?BUFFER:0,op.get("offset").getAsLong(),op.get("command").getAsLong(),op.get("size").getAsLong(),0);}finally{app=false;}return true;}
 @Override protected boolean packetFails(boolean ready,int index){return app?commands==c.get(ready?"app_ready_fail_at":"app_done_fail_at").getAsInt():super.packetFails(ready,index);}
 @Override protected long dmaRead(long at,long value){if(dmaActive&&(at==20||at==24)){JsonArray a=c.getAsJsonArray(at==20?"app_dma_a":"app_dma_b");int i=at==20?indexA++:indexB++;return a.get(Math.min(i,a.size()-1)).getAsLong();}return super.dmaRead(at,value);}
 @Override protected void fifoWrite(int opcode,int reg,byte[] data,int total){if(app&&opcode==50){if((reg&0xffffffffL)!=op.get("command").getAsLong()||data.length!=1&&data.length!=4||tx.size()+data.length>512||total+data.length>512)throw new IllegalStateException("Application TX FIFO bound");tx.writeBytes(data);return;}super.fifoWrite(opcode,reg,data,total);}
 @Override protected long fifoResponse(int opcode,int reg,int n,int at){if(app&&opcode==15&&reg==192){if(n!=1)throw new IllegalStateException("Application program status width");JsonArray a=c.getAsJsonArray("app_statuses");long value=a.get(Math.min(statusReads++,a.size()-1)).getAsLong();super.fifoResponse(opcode,reg,n,at);return value;}return super.fifoResponse(opcode,reg,n,at);}
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(app){
   if(pc==0x702d6418L)actions.add("app_callback_invoked");
   if(pc==0x702d6d2cL){actions.add("app_program_native:"+r(e,1)+":"+r(e,2)+":"+r(e,3));return false;}
   if(pc==0x702d6086L)page=r(e,0);
   if(pc==0x70296c24L){commands++;long p=r(e,1);if(!stack(p,32))throw new IllegalStateException("Application packet backing");long opcode=word(e,p+8),at=word(e,p+16),n=word(e,p+24),out=word(e,p+20);byte[] b=mem(e,p,32);
    if(opcode==50){if(!stack(p,36)||r(e,0)!=word(e,0x70f8e6f8L)||b[0]!=1||b[1]!=0||b[2]!=0||b[4]!=1||b[12]!=2||b[28]!=3||n!=op.get("size").getAsLong()||n>64||out!=BUFFER||at!=op.get("command").getAsLong()||word(e,p+32)!=0x702d6418L)throw new IllegalStateException("Mode-zero program packet");actions.add("probe_packet:50:"+at+":"+n+":1");return false;}
    if(opcode==6||opcode==16){if(r(e,0)!=word(e,0x70f8e6f8L)||b[0]!=1||b[1]!=0||b[2]!=1||b[4]!=1||b[12]!=(opcode==6?0:3)||b[28]!=1||n!=0||out!=0||at!=(opcode==6?0:page))throw new IllegalStateException("Application program command packet");actions.add("probe_packet:"+opcode+":"+at+":0:1");return false;}
   }
   if(pc==0x80d34eb0L){if(r(e,0)!=0x80d94a60L||r(e,1)!=BOUNCE||r(e,2)!=1000)throw new IllegalStateException("Application TX DMA wrapper");dmaCalls++;return false;}
   if(pc==0x702a02a0L||pc==0x702a0358L){if(r(e,0)!=0x80c10df4L)throw new IllegalStateException("Original TX DMA binding");dmaActive=true;return false;}
   if(pc==0x80d45464L){JsonArray a=c.getAsJsonArray("app_dma_ticks");long value=a.get(Math.min(dmaTicks++,a.size()-1)).getAsLong();actions.add("dma_tick:"+Long.toUnsignedString(value));e.writeRegister("a0",value&0xffffffffL);e.writeRegister("a1",value>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));return true;}
   if(pc==0x7029fea0L||pc==0x7029ff04L){long p=r(e,0),n=r(e,1);if(n>64||p!=0&&p!=BOUNCE&&p!=0x93240100L)throw new IllegalStateException("Application TX DMA cache span");actions.add((pc==0x7029fea0L?"dma_cache_prepare:":"dma_cache_finish:")+p+":"+n);ret(e,0);return true;}
   if(pc==0x70947b0cL&&r(e,0)==BOUNCE&&r(e,1)==BUFFER){long n=r(e,2);if(n!=op.get("size").getAsLong()||n>64)throw new IllegalStateException("Application TX bounce copy span");byte[] b=mem(e,BUFFER,(int)n);e.writeMemory(toAddr(BOUNCE),b);System.arraycopy(b,0,bounceExpected,0,(int)n);actions.add("app_copy_to_bounce:"+n);ret(e,BOUNCE);return true;}
   if(pc==0x702b38a2L){long fmt=r(e,3);String tag=fmt==0x70a31364L?"app_program_result:"+signed(r(e,5)):fmt==0x70a313b4L?"app_program_guard":null;if(tag!=null){actions.add("log:"+tag);ret(e,0);return true;}}
  }
  return super.probeService(e,pc);
 }
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){super.probeSnapshot(e,row);row.addProperty("app_buffer_hex",HexFormat.of().formatHex(mem(e,BUFFER,128)));row.addProperty("app_calls",calls);row.addProperty("app_status_reads",statusReads);row.addProperty("app_page",page);row.addProperty("app_dma_calls",dmaCalls);row.addProperty("app_tx_hex",HexFormat.of().formatHex(tx.toByteArray()));try{row.addProperty("app_bounce_sha256",hash(mem(e,BOUNCE,512)));}catch(Exception ex){throw new IllegalStateException(ex);}}
 @Override protected void validateExtra(EmulatorHelper e)throws Exception {super.validateExtra(e);byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long p:new long[]{BUFFER-32,BUFFER+128,BOUNCE-32,BOUNCE+512})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Application buffer guard");if(!Arrays.equals(source(),mem(e,BUFFER,128)))throw new IllegalStateException("Program source changed");if(!Arrays.equals(bounceExpected,mem(e,BOUNCE,512)))throw new IllegalStateException("TX bounce backing changed");}
}
