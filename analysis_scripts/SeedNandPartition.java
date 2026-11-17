// Reviewed NAND partition/dispatch and OOB signatures; no image bytes changed.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedNandPartition extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0x10e];currentProgram.getMemory().getBytes(toAddr(0x80c2964cL),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("ec5f1d25374014f7a999a83a1f3a9cdf1c3ed702b6f8406c4bcdb45c7428dccc"))throw new IllegalStateException("Unrecognized NAND partition ioctl");
        for(long[] row:new long[][]{{0x80c27646L,3},{0x80c275ceL,5},{0x80c292eeL,3},
            {0x80c243d6L,1},{0x80c29478L,1},{0x80c2964cL,3},{0x80c29532L,5},
            {0x80c02460L,1},{0x80c025d4L,2},{0x80c027b0L,3},{0x80c026a6L,2}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed NAND boundary");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("NAND_PARTITION_METADATA applied");
    }
}
