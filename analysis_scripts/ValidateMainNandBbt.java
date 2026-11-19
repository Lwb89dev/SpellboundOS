// Original main BBT resume/verify/CRC within probe/UID/root and later consumers.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.util.*;

public class ValidateMainNandBbt extends ValidateMainNandUidExport {
 private static final String BBT_CONFIG="{\"ranges\":[[1882019484,528],[1882020012,390],[1880494898,46]],\"guards\":[{\"address\":1882019484,\"size\":528,\"sha256\":\"dc53c94710837bff1c517b5f137b3bd4ba979d2405368c53f2cf674f049c13f6\"},{\"address\":1882020012,\"size\":390,\"sha256\":\"ae0b9a666ec0c28610153452a4ee6e38ee02f8d42e9cd73a82ecceee12a9e4fc\"},{\"address\":1880494898,\"size\":46,\"sha256\":\"4d706906003a86cceda033f38ac7094056c3775873afaeb6380489e3f7290457\"}],\"data_guards\":[{\"address\":1889256700,\"size\":1024,\"sha256\":\"12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86\"},{\"address\":1889835388,\"size\":4,\"sha256\":\"9d2fbb7d019778a2cea264523a3dd94a63bf002b7ca1c5855ed19f379a08efbd\"}]}";
 private static final long BBT=0x70f9bbacL,UID=0x70f9bc50L;
 private boolean inBbt;private long returnPc;private Long resumeResult;private int reads;
 private boolean stack(long p,long n){return n>=0&&p>=0x81000000L&&p+n<=0x81001000L;}
 @Override protected void configure()throws Exception {
  super.configure();JsonObject b=JsonParser.parseString(BBT_CONFIG).getAsJsonObject();for(JsonElement item:b.getAsJsonArray("ranges"))cfg.getAsJsonArray("main_probe_ranges").add(item.deepCopy());for(JsonElement item:b.getAsJsonArray("guards"))cfg.getAsJsonArray("main_probe_guards").add(item.deepCopy());for(JsonElement item:b.getAsJsonArray("data_guards"))cfg.getAsJsonArray("main_probe_data_guards").add(item.deepCopy());
 }
 @Override protected void setupProbe(EmulatorHelper e){
  super.setupProbe(e);if(!c.get("native_main_bbt").getAsBoolean())throw new IllegalStateException("Main BBT scope");inBbt=false;returnPc=0;resumeResult=null;reads=0;byte[] b=new byte[196];Arrays.fill(b,(byte)0xa5);e.writeMemory(toAddr(BBT-32),b);put(e,BBT,4,c.get("main_bbt_magic").getAsLong());
 }
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(inBbt&&pc==returnPc){resumeResult=r(e,0);actions.add("main_bbt_return:"+resumeResult);inBbt=false;}
  if(pc==0x702d58acL){if(inBbt||r(e,0)!=1024||r(e,1)!=2048||r(e,2)!=64)throw new IllegalStateException("Main BBT original geometry");inBbt=true;returnPc=e.readRegister("ra").longValue()&0xffffffffL;actions.add("main_bbt_native:1024:2048:64");return false;}
  if(inBbt){
   if(pc==0x70161332L){long n=r(e,2);if(r(e,0)!=0||n>128||!stack(r(e,1),n))throw new IllegalStateException("Main BBT CRC bound");actions.add("bbt_crc:"+n+":"+hash(n==0?new byte[0]:mem(e,r(e,1),(int)n)));return false;}
   if(pc==0x702d7168L){long block=r(e,0);if(r(e,1)!=1||block<1008||block>=1024)throw new IllegalStateException("Main BBT marker bound");boolean good=false;for(JsonElement item:c.getAsJsonArray("bbt_good_blocks"))if(item.getAsLong()==block)good=true;int status=good?0:103;actions.add("bbt_bad_check:"+block+":1:"+status);ret(e,status);return true;}
   if(pc==0x702d6bbeL){long p=r(e,0),page=r(e,1),ppb=word(e,BBT+148),block=page/ppb;if(!stack(p,140)||r(e,2)!=0||r(e,3)!=140||r(e,4)!=1||page%ppb!=0||block<1008||block>=1024)throw new IllegalStateException("Main BBT page read bound");JsonObject spec=c.getAsJsonObject("bbt_records").getAsJsonObject(Long.toString(block));int status=spec!=null&&spec.has("read_status")?spec.get("read_status").getAsInt():0;if(reads++==2)status=c.get("bbt_reread_status").getAsInt();actions.add("bbt_read:"+page+":140:"+word(e,BBT)+":"+status);if(status==0){byte[] b=new byte[140];Arrays.fill(b,(byte)255);Arrays.fill(b,0,12,(byte)0);JsonElement hex=c.getAsJsonObject("bbt_record_hex").get(Long.toString(block));if(hex!=null)b=HexFormat.of().parseHex(hex.getAsString());if(b.length!=140)throw new IllegalStateException("Main BBT record bound");e.writeMemory(toAddr(p),b);}ret(e,status);return true;}
   if(pc==0x702d730cL){if(r(e,0)!=word(e,BBT+156)||r(e,1)!=1)throw new IllegalStateException("Main BBT erase bound");int status=c.get("bbt_erase_status").getAsInt();actions.add("bbt_erase:"+r(e,0)+":1:"+word(e,BBT)+":"+status);ret(e,status);return true;}
   if(pc==0x702d6d2cL){long p=r(e,0);if(!stack(p,140)||r(e,1)!=word(e,BBT+156)*word(e,BBT+148)||r(e,2)!=0||r(e,3)!=140||r(e,4)!=1)throw new IllegalStateException("Main BBT write bound");int status=c.get("bbt_write_status").getAsInt();actions.add("bbt_write:"+r(e,1)+":140:"+word(e,BBT)+":"+hash(mem(e,p,140))+":"+status);ret(e,status);return true;}
   if(pc==0x70947ce8L){long p=r(e,0),n=r(e,2);if(r(e,1)!=0||!(p==BBT&&n==164||stack(p,n)&&(n==124||n==128||n==140)))throw new IllegalStateException("Main BBT zero bound");e.writeMemory(toAddr(p),new byte[(int)n]);ret(e,p);return true;}
   if(pc==0x70947b0cL){if(r(e,0)!=BBT||r(e,2)!=140||!stack(r(e,1),140))throw new IllegalStateException("Main BBT publish bound");e.writeMemory(toAddr(BBT),mem(e,r(e,1),140));actions.add("bbt_publish:140");ret(e,BBT);return true;}
   if(pc==0x70949428L){long p=r(e,0),value=r(e,3);if(r(e,1)!=128||r(e,2)!=0x70a4997cL||value>65535)throw new IllegalStateException("Main BBT format arguments");byte[] b=(Long.toString(value)+" ").getBytes(java.nio.charset.StandardCharsets.US_ASCII);if(!stack(p,b.length+1))throw new IllegalStateException("Main BBT format backing");e.writeMemory(toAddr(p),Arrays.copyOf(b,b.length+1));actions.add("bbt_format:"+value);ret(e,b.length);return true;}
   if(pc==0x702b38a2L){long format=r(e,3);String tag=null;if(format==0x70a30c98L)tag="record";else if(format==0x70a30cecL)tag="magic_error";else if(format==0x70a30d1cL)tag="count_error";else if(format==0x70a30d48L)tag="crc_error";else if(format==0x70a30d84L)tag="loaded";else if(format==0x70a30da4L)tag="entries";else if(format==0x70a30dbcL)tag="too_many_bad";else if(format==0x70a30ddcL)tag="repair_failed";else if(format==0x70a30e00L)tag="no_bbt";if(tag==null)throw new IllegalStateException("Main BBT logger format");actions.add("log:bbt_"+tag);ret(e,0);return true;}
  }
  return super.probeService(e,pc);
 }
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){super.probeSnapshot(e,row);row.addProperty("bbt_state_hex",HexFormat.of().formatHex(mem(e,BBT,164)));row.add("bbt_resume_return",resumeResult==null?JsonNull.INSTANCE:new JsonPrimitive(resumeResult));row.addProperty("bbt_reads",reads);}
 @Override protected void validateUidGuards(EmulatorHelper e)throws Exception {byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long p:new long[]{BBT-32,UID+128})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Main combined BBT/UID backing guard");}
}
