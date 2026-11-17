// Original NAND dispatch/context/mutex boundaries; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedNandDispatch extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[80];currentProgram.getMemory().getBytes(toAddr(0x80c27c70L),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("ed1c4a361bf69ca203982e1726d6f19db43e3f968e28552afb97d89e134538cf"))throw new IllegalStateException("Unrecognized NAND read wrapper");
  for(long[] row:new long[][]{{0x80c29532L,5},{0x80c275ceL,5},{0x80c2964cL,3},{0x80c27646L,3},{0x80c27c70L,4},{0x80c27b64L,2},{0x80c27a90L,0},{0x80c27af2L,0},{0x80c27b2cL,0},{0x80c292eeL,3}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed NAND dispatch");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(row[0]==0x80c27af2L||row[0]==0x80c27b2cL?VoidDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
  }
  println("NAND_DISPATCH_METADATA applied");
 }
}
