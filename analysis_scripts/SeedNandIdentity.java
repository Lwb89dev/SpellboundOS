// Reviewed retry/UID and command boundaries; imported image bytes unchanged.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedNandIdentity extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[218];currentProgram.getMemory().getBytes(toAddr(0x80c29d94L),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("41fb19b785d644fcec82cd273d1e76ec51fbeff374c8e826aef5c5a6f43c7be7"))throw new IllegalStateException("Unrecognized retry level setter");
  for(long[] row:new long[][]{{0x80c29d4cL,0},{0x80c29d94L,1},{0x80c29e6eL,1},{0x80c29f5cL,0},{0x80c28422L,0},
    {0x80c27ce8L,2},{0x80c27d48L,2},{0x80c27e0eL,1},{0x80c27e70L,3},{0x80c2825aL,0},{0x80c282b8L,0},
    {0x80c2836eL,2},{0x80c102f0L,1},{0x80c0184aL,1},{0x80c106f0L,2},{0x80c2e5e8L,3},{0x80c2e014L,3},{0x80c2e1e8L,4},
    {0x80c292eeL,3},{0x80c2de38L,3}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed identity boundary");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
   f.setReturnType(row[0]==0x80c28422L?VoidDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
  }
  println("NAND_IDENTITY_METADATA applied");
 }
}
