// Original main BBT remapper signatures; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainNandBbtMapping extends GhidraScript {
 public void run()throws Exception {
  long[][] spans={{0x702d5a32L,64},{0x702d5a72L,96}};String[] hashes={"3a02448fa8ad97fcaf8151bf1bd0c80a6c146db7be58c4f09e4cb76a647be6fd","f322fc271bb3dba55d896a70e23396f461077c6c10bce42ecf03fbf5aeb1e6c9"};
  for(int k=0;k<spans.length;k++){long[] row=spans[k];var at=toAddr(row[0]);byte[] b=new byte[(int)row[1]];currentProgram.getMemory().getBytes(at,b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals(hashes[k]))throw new IllegalStateException("Unrecognized main remapper");disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main remapper");f.setBody(new AddressSet(at,at.add(row[1]-1)));f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] p=new Parameter[2];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);}
  println("MAIN_BBT_MAPPING_METADATA applied");
 }
}
