// Reviewed object open/consumer boundaries; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedObjectLifetime extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[108];currentProgram.getMemory().getBytes(toAddr(0x80c2d04eL),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("4a4e957afed34f21527c099b238f6961f9522eb434414584c597e3261162ef9f"))throw new IllegalStateException("Unrecognized object open");
  for(long[] row:new long[][]{{0x80c2cfe0L,4},{0x80c2d04eL,2},{0x80c2d0baL,5},{0x80c274e6L,2},{0x80c27338L,5},{0x80c27466L,1},{0x80c27424L,1},{0x80c27b64L,2},{0x80c27a90L,0},{0x80c27af2L,0},{0x80c27b2cL,0}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed lifetime boundary");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
  }println("OBJECT_LIFETIME_METADATA applied");
 }
}
