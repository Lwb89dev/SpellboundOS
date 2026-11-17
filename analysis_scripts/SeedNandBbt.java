// Reviewed BBT boundaries; metadata only, no image-byte patches.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedNandBbt extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[64];currentProgram.getMemory().getBytes(toAddr(0x80c279d8L),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("2ce1d78c21e8c515ae5cecc8cde1e2d792ef3d10a8043712d76171be680039f6"))throw new IllegalStateException("Unrecognized BBT remapper");
  for(long[] row:new long[][]{{0x80c27662L,1},{0x80c2785aL,3},{0x80c279d8L,2},{0x80c27a18L,2},{0x80c27a78L,0},
    {0x80c00b24L,3},{0x80c29042L,2},{0x80c28a98L,5},{0x80c28c06L,5},{0x80c291e6L,2},
    {0x80c2e014L,3},{0x80c2de38L,3},{0x80c2e1e8L,4}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed BBT boundary");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
  }
  println("NAND_BBT_METADATA applied");
 }
}
