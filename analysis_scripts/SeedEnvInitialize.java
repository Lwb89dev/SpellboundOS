// Guarded initializer, recovery callbacks, binding and backup/dump signatures.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEnvInitialize extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0x1a8];currentProgram.getMemory().getBytes(toAddr(0x80c0d58eL),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("8c3c191de7b748955e7e3ad4ca936f754ccfd37144d8ec804f9c13e1938b17c8"))throw new IllegalStateException("Unrecognized environment initializer");
        for(long[] row:new long[][]{{0x80c0d58eL,0},{0x80c0d242L,2},{0x80c0cd56L,1},{0x80c0d0f4L,1},{0x80c0bc28L,0},{0x80c0bd10L,0},{0x80c0d67aL,2}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed environment initializer");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("ENV_INITIALIZE_METADATA applied");
    }
}
