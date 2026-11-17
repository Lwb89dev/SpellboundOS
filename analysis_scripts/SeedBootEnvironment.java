// Guarded boot environment, reason, polling and caller-prefix signatures.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedBootEnvironment extends GhidraScript {
    private void signature(long at,int count,boolean result)throws Exception {
        disassemble(toAddr(at));var f=getFunctionAt(toAddr(at));if(f==null)f=createFunction(toAddr(at),"candidate_"+Long.toHexString(at));
        if(f==null)throw new IllegalStateException("Cannot seed boot environment function");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(result?UnsignedIntegerDataType.dataType:VoidDataType.dataType,SourceType.USER_DEFINED);
        f.setNoReturn(false);f.setInline(false);Parameter[] p=new Parameter[count];for(int i=0;i<count;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
    }
    public void run()throws Exception {
        byte[] bytes=new byte[0x150];currentProgram.getMemory().getBytes(toAddr(0x80c0d344L),bytes);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals("96ec9efd27e8cf5624341fde8eb92aa0cc739dc8ef16e3118e3dba715fe6f3b2"))throw new IllegalStateException("Unrecognized boot environment wrappers");
        for(long[] row:new long[][]{{0x80c0d344L,4,1},{0x80c0d3b4L,3,1},{0x80c0d490L,0,1},
            {0x80c0ec70L,0,1},{0x80c00312L,1,1},{0x80c01884L,1,0},{0x80c00450L,0,1},{0x80c00454L,0,0}})
            signature(row[0],(int)row[1],row[2]!=0);
        println("BOOT_ENVIRONMENT_METADATA selected wrappers/policy/prefix applied");
    }
}
