// Actual main context/chip UID export after original probe/platform/FIFO acquisition.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.util.*;

public class ValidateMainNandUidExport extends ValidateMainNandAux {
 private static final long OUT=0x8132e000L,UID=0x70f9bc50L,LENGTH=0x70f8e6f4L;
 private int exports;
 @Override protected void setupProbe(EmulatorHelper e){
  super.setupProbe(e);if(!c.get("native_main_uid_export").getAsBoolean())throw new IllegalStateException("UID export scope");exports=0;byte[] b=new byte[193];Arrays.fill(b,(byte)0xa5);e.writeMemory(toAddr(OUT-32),b);
 }
 @Override protected boolean additionalOperation(EmulatorHelper e,String kind)throws Exception {
  if(!kind.equals("uid_export"))return false;
  if(op.get("command").getAsInt()!=24||!op.get("output").getAsBoolean())throw new IllegalStateException("UID export operation");
  exports++;actions.add("main_uid_export_native");entry(e,0x702d5c26L,24,OUT);return true;
 }
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(pc==0x70947b0cL){long n=r(e,2);if(!op.get("op").getAsString().equals("uid_export")||r(e,0)!=OUT+1||r(e,1)!=UID||n>128||n!=(mem(e,LENGTH,1)[0]&255))throw new IllegalStateException("UID export copy bounds");if(n>0)e.writeMemory(toAddr(OUT+1),mem(e,UID,(int)n));actions.add("copy_uid:"+n);ret(e,OUT+1);return true;}
  return super.probeService(e,pc);
 }
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){super.probeSnapshot(e,row);row.addProperty("export_hex",HexFormat.of().formatHex(mem(e,OUT,129)));row.addProperty("export_calls",exports);}
 @Override protected void validateExtra(EmulatorHelper e)throws Exception {super.validateExtra(e);byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long p:new long[]{OUT-32,OUT+129})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("UID export guard");}
}
