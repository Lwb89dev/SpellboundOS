// Original main page read/cache/retry signatures; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainNandPageRead extends GhidraScript {
 public void run()throws Exception {
  long[][] spans={{0x702d6bbeL,5,366},{0x702d5facL,3,108},{0x702d8010L,1,238}};String[] hashes={"a1035a344931869c4c6b87462e434f321588bb6d73c3fd555c1df7296a4f68d8","3d081e7f2f2635c3bbfa67834d14b8c4558880292df033440d31ee3f9a6c5e43","30d7282cafe455c221f75a4a88054b4729d37ad204f271bd2df2fc81bd2ac11d"};
  for(int k=0;k<spans.length;k++){long[] row=spans[k];var at=toAddr(row[0]);byte[] b=new byte[(int)row[2]];currentProgram.getMemory().getBytes(at,b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals(hashes[k]))throw new IllegalStateException("Unrecognized main page reader");disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main page reader");f.setBody(new AddressSet(at,at.add(row[2]-1)));f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);}
  println("MAIN_PAGE_READ_METADATA applied");
 }
}
