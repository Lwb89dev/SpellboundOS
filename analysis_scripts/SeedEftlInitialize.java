// Guarded initializer/geometry boundaries; no image bytes are modified.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEftlInitialize extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0x1c8];currentProgram.getMemory().getBytes(toAddr(0x80c02298L),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("2f0cc83e90ee2e8654f2b2e173599b9fb152246b2cb83ecbfdb93d56b939395c"))throw new IllegalStateException("Unrecognized EFTL initializer");
        for(long[] row:new long[][]{{0x80c29478L,1},{0x80c2964cL,3},{0x80c0285aL,2},
            {0x80c028d8L,2},{0x80c0282aL,2},{0x80c027b0L,3},{0x80c01a0aL,1},{0x80c01d8aL,2},
            {0x80c02460L,1},{0x80c02298L,3},{0x80c231d6L,0}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed initializer boundary");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(row[0]==0x80c231d6L?VoidDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("EFTL_INITIALIZE_METADATA applied");
    }
}
