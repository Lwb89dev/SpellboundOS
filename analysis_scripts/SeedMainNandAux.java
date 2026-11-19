// Original main NAND workaround and UID signatures; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.AddressSet;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainNandAux extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[668];currentProgram.getMemory().getBytes(toAddr(0x702d6524L),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("830f63c83d914e86da2efd6390982f8e8e50a2d401d96622ecb7b04ed77b0fa2"))throw new IllegalStateException("Unrecognized main UID");
  for(long[] row:new long[][]{{0x702d7ee6L,0,80},{0x702d7f36L,1,218},{0x702d80feL,0,242},{0x702d6524L,0,668},{0x702d6470L,2,180},{0x702d5f42L,3,106},{0x702d5edcL,1,102},{0x702d6354L,0,98},{0x702d63b6L,0,98},{0x7029681cL,1,20},{0x701648f8L,1,8}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main auxiliary");
   f.setBody(new AddressSet(at,at.add(row[2]-1)));f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(row[0]==0x702d6524L?VoidDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
   println("MAIN_AUX_BODY "+Long.toHexString(row[0])+" "+f.getBody());
  }
 }
}
