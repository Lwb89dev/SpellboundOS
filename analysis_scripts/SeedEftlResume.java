// Actual EFTL scan/checksum signatures; image bytes remain unchanged.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEftlResume extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0x160];currentProgram.getMemory().getBytes(toAddr(0x80c01d8aL),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("627b6414298e79230eb17db6291f05d99573c740082fe86d720f61b914e1b2f4"))throw new IllegalStateException("Unrecognized EFTL resume");
        for(long[] row:new long[][]{{0x80c028d8L,2},{0x80c0282aL,2},{0x80c027b0L,3},{0x80c01a0aL,1},{0x80c01d8aL,2}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed EFTL resume boundary");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("EFTL_RESUME_METADATA applied");
    }
}
