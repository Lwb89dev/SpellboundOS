// Original main NAND bus/platform and feature builders; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainNandBus extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[370];currentProgram.getMemory().getBytes(toAddr(0x70296ab0L),b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("cd883f10874ffa0d0a0c0a61a9bcc5b9f5e97da4bc15704a9b767fd0076abbc7"))throw new IllegalStateException("Unrecognized main bus");
  for(long[] row:new long[][]{{0x70296ab0L,1},{0x70296c24L,2},{0x702d5daaL,2},{0x702d5e0eL,2}}){var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main bus");f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);}
  println("MAIN_NAND_BUS_METADATA applied");
 }
}
