// Guard cache flush bytes and make selected pointer/encoder/IPC signatures explicit.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedCachePipeline extends GhidraScript {
    private void signature(long a,DataType result,int count)throws Exception {
        disassemble(toAddr(a));var f=getFunctionAt(toAddr(a));
        if(f==null)f=createFunction(toAddr(a),"candidate_"+Long.toHexString(a));
        if(f==null)throw new IllegalStateException("Cannot create cache boundary");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result,SourceType.USER_DEFINED);f.setNoReturn(false);f.setInline(false);
        Parameter[] p=new Parameter[count];for(int i=0;i<count;++i)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
    }
    public void run()throws Exception {
        byte[] b=new byte[0xee];currentProgram.getMemory().getBytes(toAddr(0x80f65920L),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals(
            "896c62bd3777d66af7837be105d3d62c0319398e11e6309a42df424c6788cf07"))throw new IllegalStateException("Unrecognized cache flush");
        for(long a:new long[]{0x80f655d2L,0x80f657eeL,0x80f6585eL,0x80f65884L,0x80f658c6L,0x80f9ba6eL})
            signature(a,UnsignedIntegerDataType.dataType,1);
        for(long a:new long[]{0x80f63c2eL,0x80f9b390L,0x80f9b34eL})signature(a,VoidDataType.dataType,1);
        signature(0x80f65920L,VoidDataType.dataType,0);
        signature(0x80fa6278L,UnsignedIntegerDataType.dataType,1);
        signature(0x80fa61caL,UnsignedIntegerDataType.dataType,3);
        signature(0x80fa5d1eL,VoidDataType.dataType,3);
        signature(0x80fa5d5eL,UnsignedIntegerDataType.dataType,1);
        signature(0x80fa5dd2L,VoidDataType.dataType,2);
        signature(0x80fa5e6aL,VoidDataType.dataType,2);
        signature(0x80fa5eb6L,VoidDataType.dataType,3);
        signature(0x80f9a5e6L,UnsignedIntegerDataType.dataType,2);
        signature(0x80f99ce0L,UnsignedIntegerDataType.dataType,2);
        signature(0x80f99c26L,UnsignedIntegerDataType.dataType,3);
        signature(0x80f95226L,UnsignedIntegerDataType.dataType,0);
        println("CACHE_PIPELINE_METADATA buffer/encoder/event/wire boundaries applied");
    }
}
