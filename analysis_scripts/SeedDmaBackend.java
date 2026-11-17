// Reviewed DMA engine entry signatures; metadata only, no image-byte changes.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedDmaBackend extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[32];currentProgram.getMemory().getBytes(toAddr(0x80c123acL),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("a8c8fe2210075a8ed0cd9bfd9c5faabb52e85de171d462f9c44e8bb3c792a65f"))throw new IllegalStateException("Unrecognized DMA initializer");
  for(long[] row:new long[][]{{0x80c123acL,1},{0x80c12548L,4},{0x80c125ecL,1},{0x80c12628L,4},{0x80c126c0L,2},
    {0x80c126e0L,2},{0x80c1279cL,1},{0x80c121e4L,0},{0x80c122f4L,2},{0x80c12350L,2}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed DMA boundary");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
   f.setReturnType(row[0]==0x80c121e4L?UnsignedLongLongDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
   println("DMA_BODY "+Long.toHexString(row[0])+" "+f.getBody());
  }
 }
}
