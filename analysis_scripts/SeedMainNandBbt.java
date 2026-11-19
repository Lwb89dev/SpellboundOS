// Actual main BBT verification/resume metadata; original bytes unchanged.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainNandBbt extends GhidraScript {
 public void run()throws Exception {
  long[][] spans={{0x702d569cL,1,528},{0x702d58acL,3,390},{0x70161332L,3,46}};String[] hashes={"dc53c94710837bff1c517b5f137b3bd4ba979d2405368c53f2cf674f049c13f6","ae0b9a666ec0c28610153452a4ee6e38ee02f8d42e9cd73a82ecceee12a9e4fc","4d706906003a86cceda033f38ac7094056c3775873afaeb6380489e3f7290457"};
  for(int k=0;k<spans.length;k++){long[] row=spans[k];var at=toAddr(row[0]);byte[] b=new byte[(int)row[2]];currentProgram.getMemory().getBytes(at,b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals(hashes[k]))throw new IllegalStateException("Unrecognized main BBT");disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main BBT");f.setBody(new AddressSet(at,at.add(row[2]-1)));f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);}
  println("MAIN_BBT_METADATA applied");
 }
}
