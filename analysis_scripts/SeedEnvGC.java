// Guarded signatures for record relocation, sector format and defaults restore.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEnvGC extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0x1c0];currentProgram.getMemory().getBytes(toAddr(0x80c0d184L),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("c7314fb6c4f8a3d72176c4144aa18298fc84cb6148b30b375d6cb4fc976888a5"))throw new IllegalStateException("Unrecognized sector collector/formatter");
        for(long[] row:new long[][]{{0x80c0cfacL,1},{0x80c0d184L,1},{0x80c0d27eL,1},{0x80c0d494L,0},{0x80c0c172L,2}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed GC function");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("ENV_GC_METADATA applied");
    }
}
