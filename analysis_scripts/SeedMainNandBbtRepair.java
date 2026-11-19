// Original main repair/erase/program signatures; verified metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.*;
public class SeedMainNandBbtRepair extends GhidraScript {
 public void run()throws Exception {
  long[][] spans={{0x702d730cL,2,264},{0x702d6d2cL,5,372},{0x702d5e7aL,0,98},{0x702d6086L,1,102},{0x702d6152L,3,104},{0x702d6224L,1,108}};String[] hashes={"8a570a2f281d2a04e59e741a682f9c205a3411e62165873db7276a72befd0c1c","372f387a39dcbf57f645d6006715c118fcc9c529a7a0ee7c02f47272dc4d3b31","817ee545a34ec66ca7d9672856f33ae340ab68c93629a096c226b6d8062de178","3602a9be3d66e9f2afe1e5f9db0d16a224fc3a6ef21a12d20670026175c31dc2","670b0a8b4266c349ad1d296f0e1dfefc22c6c8c471255e9d7036ee542ab2e25b","8d430081d27870a4bb468c27d64d302582b9d01f79b2c028035e6adc7b80452a"};
  for(int k=0;k<spans.length;k++){long[] row=spans[k];var at=toAddr(row[0]);byte[] b=new byte[(int)row[2]];currentProgram.getMemory().getBytes(at,b);if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals(hashes[k]))throw new IllegalStateException("Unrecognized main repair body");var body=new AddressSet(at,at.add(row[2]-1));var it=currentProgram.getFunctionManager().getFunctions(body,true);var interior=new ArrayList<Address>();while(it.hasNext()){var f=it.next();if(!f.getEntryPoint().equals(at))interior.add(f.getEntryPoint());}for(var p:interior)currentProgram.getFunctionManager().removeFunction(p);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));if(f==null)throw new IllegalStateException("Cannot seed main repair body");f.setBody(body);f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);Parameter[] params=new Parameter[(int)row[1]];for(int i=0;i<params.length;i++)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);}
  println("MAIN_BBT_REPAIR_METADATA applied");
 }
}
