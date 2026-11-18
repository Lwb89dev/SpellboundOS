// Main NAND query/context/root/registry metadata; original bytes unchanged.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainNandStack extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[412];currentProgram.getMemory().getBytes(toAddr(0x702d7414L),b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("bf1bef3b368ab6a6bcf6d66db654f877077e3aa2575f714fa47ca75dd595c1ee"))throw new IllegalStateException("Unrecognized main chip ioctl");
  for(long[] row:new long[][]{{0x702d5b32L,0},{0x702d5ba4L,0},{0x702d5be6L,0},{0x702d5c26L,2},{0x702d7414L,3},{0x702d5ad2L,0},{0x702d54c6L,1},{0x702d5b56L,0},{0x70319252L,2},{0x703192caL,3}}){var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main NAND");f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);}
  println("MAIN_NAND_STACK_METADATA applied");
 }
}
