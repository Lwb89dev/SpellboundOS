// QSPI HAL signatures and body ranges; image bytes remain unchanged.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedQspiHal extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[32];currentProgram.getMemory().getBytes(toAddr(0x80df928cL),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("34385c005a655be88e20cc74c0b88baa45a38d5c08952bad6ac5e1bd347936ff"))throw new IllegalStateException("Unrecognized QSPI command");
  for(long[] row:new long[][]{{0x80df9220L,1},{0x80df928cL,3},{0x80df93c4L,3},{0x80df94bcL,3},{0x80df951cL,3},{0x80df960cL,3},
    {0x80df8f38L,1},{0x80df9000L,2},{0x80df9098L,2},{0x80df9138L,2},{0x80df91d8L,1},{0x80df91fcL,1},{0x80df9f80L,1},
    {0x80c12628L,4},{0x80c126e0L,2},{0x80c12218L,0},{0x80c1222cL,0},
    {0x80c106f0L,2},{0x80c27ce8L,2},{0x80c27d48L,2},{0x80c27e70L,3},{0x80c2806cL,4},{0x80c27db0L,0},
    {0x80c123acL,1},{0x80c121e4L,0},{0x80c122f4L,2},{0x80c12350L,2},{0x80c27f3eL,4},{0x80c280d0L,4},{0x80c2de38L,3}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed QSPI boundary");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
   f.setReturnType(row[0]==0x80c12218L||row[0]==0x80c121e4L?UnsignedLongLongDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
   println("QSPI_BODY "+Long.toHexString(row[0])+" "+f.getBody());
  }
 }
}
