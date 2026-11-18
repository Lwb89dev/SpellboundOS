// Original main QSPI HAL signatures and shared-tail ownership; metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.AddressSet;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedMainQspiHal extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[204];currentProgram.getMemory().getBytes(toAddr(0x80d34b30L),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("29a15157d715409e04279787c466da24e5fa0699d76bec9d38ff649924ff16ca"))throw new IllegalStateException("Unrecognized main HAL command");
  // Earlier automatic analysis attached the independent completion entry to command.
  var command=getFunctionAt(toAddr(0x80d34b30L));if(command!=null)command.setBody(new AddressSet(toAddr(0x80d34b30L),toAddr(0x80d34bfbL)));
  for(long[] row:new long[][]{{0x80d34800L,1,100},{0x80d348c8L,2,140},{0x80d34954L,2,148},{0x80d349e8L,2,148},{0x80d34a7cL,1,36},{0x80d34aa0L,1,36},{0x80d34ac4L,1,108},{0x80d34b30L,3,204},{0x80d34c68L,3,248},{0x80d34d60L,3,96},{0x80d34dc0L,3,240},{0x80d34eb0L,3,88},{0x80d3580cL,1,52},{0x80d4556cL,0,86}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main HAL");
   f.setBody(new AddressSet(at,at.add(row[2]-1)));f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
   println("MAIN_HAL_BODY "+Long.toHexString(row[0])+" "+f.getBody());
  }
 }
}
