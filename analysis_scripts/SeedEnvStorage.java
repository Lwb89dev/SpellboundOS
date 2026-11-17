// Guarded device registry, handle setup and NV mirror signatures.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEnvStorage extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0x144];currentProgram.getMemory().getBytes(toAddr(0x80c0be14L),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("fefa8b3423d96dc296037f6ad46effffe838b189fab64480199a0a0d29ae3506"))throw new IllegalStateException("Unrecognized environment storage setup");
        var interior=getFunctionAt(toAddr(0x80c0c27cL));if(interior!=null)currentProgram.getFunctionManager().removeFunction(interior.getEntryPoint());
        for(long[] row:new long[][]{{0x80c0be14L,2},{0x80c0c27aL,0},{0x80c243d6L,1},{0x80c24218L,5},
            {0x80c24446L,4},{0x80c24502L,4},{0x80c245beL,3},{0x80c24652L,4},{0x80c1c51aL,0},
            {0x80c0d736L,3},{0x80c0d776L,3},{0x80c01704L,0},{0x80c1a022L,0}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed storage function");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("ENV_STORAGE_METADATA applied");
    }
}
