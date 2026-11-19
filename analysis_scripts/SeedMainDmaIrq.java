// Original main IRQ and selected high-half cache guards; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.AddressSet;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainDmaIrq extends GhidraScript {
 public void run()throws Exception {
  long[][] spans={{0x702a041cL,1,250},{0x7029fea0L,2,100},{0x7029ff04L,2,100}};
  String[] hashes={"54a80406ae0a6e904abbf7fb6acdd47fa3e058433318651df85cc14892f952f8","e64c0074c738be7fb278fa37bd95334e8c5a2b3b8c2f8228ce4666357e6c1f7a","bcc87b688c79b8076dcc56b180cbd48a4d729ccd1a8b78078ba87b9efcff9d65"};
  for(int k=0;k<spans.length;k++){long[] row=spans[k];var at=toAddr(row[0]);byte[] b=new byte[(int)row[2]];currentProgram.getMemory().getBytes(at,b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals(hashes[k]))throw new IllegalStateException("Unrecognized main IRQ/cache body");disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main IRQ/cache");f.setBody(new AddressSet(at,at.add(row[2]-1)));f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(row[0]==0x702a041cL?VoidDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);}
  println("MAIN_IRQ_CACHE_METADATA applied");
 }
}
