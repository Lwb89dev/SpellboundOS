// Original relocation and NAND marker boundaries; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedEftlRepair extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[32];currentProgram.getMemory().getBytes(toAddr(0x80c01b6eL),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("eeae7c455bd2a813335406fc67457f72441057ac14f0f5adf65e4a92317be2ca"))throw new IllegalStateException("Unrecognized EFTL repair");
  for(long[] row:new long[][]{{0x80c01b6eL,4},{0x80c0290cL,2},{0x80c29126L,2}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed EFTL repair");
   f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(row[0]==0x80c0290cL?VoidDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);println("REPAIR_BODY "+Long.toHexString(row[0])+" "+f.getBody());
  }
 }
}
