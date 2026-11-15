// Reconstruct only runtime ranges explicitly copied or zeroed by the GNSS startup.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
public class gnss_MapRuntime extends GhidraScript {
 private void copy(String name,long source,long target,int length,boolean executable) throws Exception {
  byte[] bytes=new byte[length];currentProgram.getMemory().getBytes(toAddr(source),bytes);
  var block=currentProgram.getMemory().createInitializedBlock(name,toAddr(target),new ByteArrayInputStream(bytes),length,monitor,false);
  block.setWrite(true);block.setExecute(executable);
 }
 private void zero(String name,long target,int length) throws Exception {
  var block=currentProgram.getMemory().createInitializedBlock(name,toAddr(target),length,(byte)0,monitor,false);
  block.setWrite(true);block.setExecute(false);
 }
 public void run() throws Exception {
  copy("candidate_startup_copy_code",0x04200178L,0x04000000L,0xee4,true);
  copy("candidate_startup_copy_data",0x0420105cL,0x04000ee4L,0x18,false);
  zero("candidate_startup_zero_ram",0x04000efcL,0xbfc8-0xefc);
  zero("candidate_startup_zero_stage",0x0420abb4L,0xf29c-0xabb4);
  currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),toAddr(0x04000000L),toAddr(0x04000ee3L),BigInteger.ONE);
  disassemble(toAddr(0x04000000L));createFunction(toAddr(0x04000000L),"candidate_runtime_copy_entry");
 }
}
