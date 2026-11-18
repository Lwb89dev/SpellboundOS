// Original main DMA init/setup/cancel/count/wait signatures; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.AddressSet;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainDmaBackend extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[388];currentProgram.getMemory().getBytes(toAddr(0x702a0038L),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("62cbd9af6fae44f8b5742c2e6ea363fcd109e8054bfaeb3302e5a74947069ec2"))throw new IllegalStateException("Unrecognized main DMA initializer");
  for(long[] row:new long[][]{{0x702a0038L,1,388},{0x702a01c0L,4,162},{0x702a0264L,1,58},{0x702a02a0L,4,150},{0x702a0338L,2,28},{0x702a0358L,2,194}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main DMA");
   f.setBody(new AddressSet(at,at.add(row[2]-1)));f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
   println("MAIN_DMA_BODY "+Long.toHexString(row[0])+" "+f.getBody());
  }
 }
}
