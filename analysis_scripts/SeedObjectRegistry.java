// Reviewed object lookup/registration boundaries; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedObjectRegistry extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[276];currentProgram.getMemory().getBytes(toAddr(0x80c2ceccL),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("2f766470b7db6f56cac235b1ca8448aa3715bece30175ce3bec35b9f91a54b14"))throw new IllegalStateException("Unrecognized object registry");
  for(long[] row:new long[][]{{0x80c2ce64L,2},{0x80c2ceccL,3},{0x80c27524L,1},{0x80c16afaL,1},{0x80c16b86L,2},{0x80c16c2aL,1},{0x80c2e684L,3},{0x80c2e5e8L,3},{0x80c2e014L,3}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed object boundary");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
  }
  println("OBJECT_REGISTRY_METADATA applied");
 }
}
