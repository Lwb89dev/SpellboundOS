// Original main object and NAND-method boundaries; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainObjects extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[130];currentProgram.getMemory().getBytes(toAddr(0x703194e0L),b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("c33c78f7632341dc68d803b7d4f721e390803057a67c573dfed1ca6b6e85fe13"))throw new IllegalStateException("Unrecognized main close");
  for(long[] row:new long[][]{{0x70319470L,2},{0x703194e0L,1},{0x70319562L,4},{0x703195e0L,5},{0x70319664L,1},{0x702d5484L,2},{0x702d5442L,1},{0x702d52c6L,5}}){var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main object");f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);}
  println("MAIN_OBJECT_METADATA applied");
 }
}
