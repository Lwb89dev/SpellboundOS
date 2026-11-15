// Apply a hypothesis for the checksum calling convention, then re-decompile.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
public class DecompileChecksum extends GhidraScript {
 public void run() throws Exception {
  var address=toAddr(0x703ceb56L);
  disassemble(address);
  Function f=getFunctionAt(address);
  if(f==null)f=createFunction(address,"candidate_radio_checksum");
  f.setCallingConvention("__stdcall");
  f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
  f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,
   new ParameterImpl("seed",UnsignedIntegerDataType.dataType,currentProgram),
   new ParameterImpl("data",new PointerDataType(ByteDataType.dataType),currentProgram),
   new ParameterImpl("size",UnsignedIntegerDataType.dataType,currentProgram));
  DecompInterface d=new DecompInterface(); d.openProgram(currentProgram);
  try {var r=d.decompileFunction(f,30,monitor);println(r.decompileCompleted()?r.getDecompiledFunction().getC():r.getErrorMessage());}finally{d.dispose();}
 }
}
