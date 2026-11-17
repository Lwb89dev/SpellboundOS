// Original NAND platform/pin helper boundaries; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedNandPlatform extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[32];currentProgram.getMemory().getBytes(toAddr(0x80c13408L),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("81d4aa50985dc9c95a0f9299f6474e46f9efa1d775ced5069f379de51c5ad72e"))throw new IllegalStateException("Unrecognized pin helper");
  for(long[] row:new long[][]{{0x80c10580L,1},{0x80c13408L,3},{0x80df8e94L,3},{0x80df8d94L,6}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed platform boundary");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
   f.setReturnType(row[0]==0x80c10580L?UnsignedIntegerDataType.dataType:VoidDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
   println("PLATFORM_BODY "+Long.toHexString(row[0])+" "+f.getBody());
  }
 }
}
