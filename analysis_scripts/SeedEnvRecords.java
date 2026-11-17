// Guarded signatures for environment record routines and storage adapters.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEnvRecords extends GhidraScript {
    public void run()throws Exception {
        byte[] bytes=new byte[0x18c];currentProgram.getMemory().getBytes(toAddr(0x80c0cbcaL),bytes);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals("4eb6b0c15b4d694f7e12b5fac15dc443ce04812b509a53e2042070db3b9101fd"))throw new IllegalStateException("Unrecognized environment append");
        // Reject a spurious entry inside the storage-read error block from exploration.
        var interior=getFunctionAt(toAddr(0x80c0bf9eL));if(interior!=null)currentProgram.getFunctionManager().removeFunction(interior.getEntryPoint());
        for(long[] row:new long[][]{{0x80c0bf58L,3,1},{0x80c0bfe2L,3,1},{0x80c0c2f0L,2,1},
            {0x80c0c30aL,2,0},{0x80c0c3a2L,3,0},{0x80c0c5ccL,4,1},{0x80c0c660L,3,1},
            {0x80c0c6f8L,1,0},{0x80c0cbcaL,4,1},{0x80c0cdf6L,2,1},{0x80c0ced6L,3,1}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed environment record function");
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(row[2]!=0?UnsignedIntegerDataType.dataType:VoidDataType.dataType,SourceType.USER_DEFINED);
            f.setNoReturn(false);f.setInline(false);Parameter[] p=new Parameter[(int)row[1]];
            for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("ENV_RECORD_METADATA applied");
    }
}
