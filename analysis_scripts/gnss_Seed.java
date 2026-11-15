//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import java.math.BigInteger;
public class gnss_Seed extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  var entry=toAddr(args.length==0?0x04200000L:Long.decode(args[0]));
  currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),entry,entry,BigInteger.ONE);
  disassemble(entry);createFunction(entry,"candidate_gnss_entry");
 }
}
