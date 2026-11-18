// Original main NAND probe, matcher and command builders; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainNandProbe extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[804];currentProgram.getMemory().getBytes(toAddr(0x702d685cL),b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("ee7bb6db5149c9e3dd0d1123e9cce9ce14c5112ecde3faec893d5eee48481553"))throw new IllegalStateException("Unrecognized main probe");
  for(long[] row:new long[][]{{0x702d685cL,0},{0x702d6290L,2},{0x702d62f2L,0},{0x702d641aL,3}}){var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main probe");f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);}
  println("MAIN_NAND_PROBE_METADATA applied");
 }
}
