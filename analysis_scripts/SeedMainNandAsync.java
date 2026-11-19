// Verified original mode-zero builder/callback/sleep-loop metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainNandAsync extends GhidraScript {
 public void run()throws Exception {
  long[][] spans={{0x702d6018L,4,110},{0x702d6418L,0,2},{0x702d67c0L,2,156}};String[] hashes={"b2d7ff06784e87d0f2ce3d84a3035507f664758b16fdb7e16ac864633577cec9","7529d4e6ceb037815e2664a7277abb404b02f0bf9ddbf5c11658f52448221cba","f31e56a387757f0ca0b3c572c09ed72420fd7b998367cc8183614b1e4485273d"};
  for(int k=0;k<spans.length;k++){long[] row=spans[k];var at=toAddr(row[0]);byte[] b=new byte[(int)row[2]];currentProgram.getMemory().getBytes(at,b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals(hashes[k]))throw new IllegalStateException("Unrecognized main mode-zero body");disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed mode-zero body");f.setBody(new AddressSet(at,at.add(row[2]-1)));f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(row[0]==0x702d6418L?VoidDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);}
  println("MAIN_ASYNC_METADATA applied");
 }
}
