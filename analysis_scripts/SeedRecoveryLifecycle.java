// Guarded signatures for selection, synthetic header writes and handoff analysis.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedRecoveryLifecycle extends GhidraScript {
    private void signature(long address,int count,boolean result)throws Exception {
        disassemble(toAddr(address));var f=getFunctionAt(toAddr(address));
        if(f==null)f=createFunction(toAddr(address),"candidate_"+Long.toHexString(address));
        if(f==null)throw new IllegalStateException("Cannot seed recovery lifecycle function");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result?UnsignedIntegerDataType.dataType:VoidDataType.dataType,SourceType.USER_DEFINED);f.setNoReturn(false);f.setInline(false);
        Parameter[] p=new Parameter[count];for(int i=0;i<count;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
    }
    public void run()throws Exception {
        byte[] bytes=new byte[0x2a2];currentProgram.getMemory().getBytes(toAddr(0x80c0e9ccL),bytes);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals("e0b542290231f0112999e76adcfd082d06bd5e8fd4865f4df78d698d31e69ff2"))
            throw new IllegalStateException("Unrecognized recovery selection/preparation/completion code");
        if((currentProgram.getMemory().getShort(toAddr(0x80c00874L))&65535)!=0x8782)
            throw new IllegalStateException("Expected tail handoff instruction absent");
        for(long[] row:new long[][]{{0x80c00b52L,3,1},{0x80c0e438L,2,1},{0x80c0e4d0L,2,0},
            {0x80c0e9ccL,0,1},{0x80c0eaa6L,2,1},{0x80c0ebd4L,1,1},{0x80c0080aL,0,0},
            {0x80c0084aL,1,0},{0x80c0098cL,0,1},{0x80c16344L,0,0}})
            signature(row[0],(int)row[1],row[2]!=0);
        println("RECOVERY_LIFECYCLE_METADATA selected signatures applied; no image entry executed");
    }
}
