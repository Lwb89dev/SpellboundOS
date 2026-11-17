// Original EFTL mutation entry points; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedEftlMutation extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[32];currentProgram.getMemory().getBytes(toAddr(0x80c01eeaL),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("565b9917c30c48269c4993c5d53f8c1b31ccec964adc17a5f9d1b0f9764706ed"))throw new IllegalStateException("Unrecognized EFTL write");
  for(long[] row:new long[][]{{0x80c01eeaL,4},{0x80c01a5aL,2},{0x80c01b6eL,4},{0x80c026a6L,2},{0x80c02806L,4},{0x80c0282aL,2},{0x80c29576L,5},{0x80c275eeL,5},{0x80c27c20L,4},{0x80c232a0L,2},{0x80c23336L,3},{0x80c23384L,3},{0x80c24502L,4},{0x80c245beL,3},{0x80c24652L,4}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed EFTL mutation");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
   if(row[0]==0x80c23384L){f.setName("candidate_80c23384",SourceType.USER_DEFINED);var instruction=getInstructionAt(at);if(instruction==null)throw new IllegalStateException("Rewrite branch missing");instruction.setFlowOverride(FlowOverride.CALL_RETURN);}
   println("MUTATION_BODY "+Long.toHexString(row[0])+" "+f.getBody());
  }
 }
}
