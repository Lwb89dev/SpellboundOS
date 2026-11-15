// Experimental radio mapping: record addresses mapped to bytes after 512-byte prefix.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import java.io.*;
import java.math.BigInteger;
public class SeedRadio extends GhidraScript {
 public void run() throws Exception {
  for(String line:Files.readAllLines(Paths.get(getScriptArgs()[0]))) {
   String[] fields=line.split("\t");
   byte[] bytes=Files.readAllBytes(Paths.get(fields[1]));
   var block=currentProgram.getMemory().createInitializedBlock("candidate_"+fields[0],toAddr(Long.parseLong(fields[0],16)),new ByteArrayInputStream(bytes),bytes.length,monitor,false);
   block.setExecute(true);
  }
  for(long value:new long[]{0x0209a400L,0x02015400L}) {
   var entry=toAddr(value);
   currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),entry,entry,BigInteger.ONE);
   disassemble(entry);createFunction(entry,"candidate_thumb_entry_"+Long.toHexString(value));
  }
 }
}
