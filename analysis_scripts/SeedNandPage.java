// Reviewed page-operation boundaries; metadata only, no image-byte patches.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;
public class SeedNandPage extends GhidraScript {
 public void run()throws Exception {
  byte[] b=new byte[366];currentProgram.getMemory().getBytes(toAddr(0x80c28a98L),b);
  if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("21fe4647132a935ccaedfab627ff2c61d6429bfc6850afd0e1ce641c2911a16b"))throw new IllegalStateException("Unrecognized page read");
  for(long[] row:new long[][]{{0x80c28a98L,5},{0x80c28c06L,5},{0x80c28d7aL,2},{0x80c28ec4L,4},{0x80c291e6L,2},
    {0x80c2836eL,2},{0x80c286b2L,2},{0x80c102f0L,1},{0x80c27a18L,2},{0x80c279d8L,2},
    {0x80c27e0eL,1},{0x80c27db0L,0},{0x80c27fa8L,1},{0x80c28136L,1},
    {0x80c27f3eL,4},{0x80c27ed6L,4},{0x80c280d0L,4},{0x80c2806cL,4},{0x80c2800aL,3},
    {0x80c29e6eL,1},{0x80c27ce8L,2},{0x80c12154L,1},{0x80c16884L,1}}){
   var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
   if(f==null)throw new IllegalStateException("Cannot seed page boundary");f.setNoReturn(false);f.setInline(false);
   f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
   Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
   f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
  }
  println("NAND_PAGE_METADATA applied");
 }
}
