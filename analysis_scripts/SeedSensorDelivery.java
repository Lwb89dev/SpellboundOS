// Guard packet ownership bytes and seed selected delivery/queue boundaries.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.AddressSet;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedSensorDelivery extends GhidraScript {
    private void signature(long a,DataType result,int count)throws Exception {
        disassemble(toAddr(a));var f=getFunctionAt(toAddr(a));
        if(f==null)f=createFunction(toAddr(a),"candidate_"+Long.toHexString(a));
        if(f==null)throw new IllegalStateException("Cannot create delivery boundary");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result,SourceType.USER_DEFINED);f.setNoReturn(false);f.setInline(false);
        Parameter[] args=new Parameter[count];
        for(int i=0;i<count;++i)args[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,args);
    }
    public void run()throws Exception {
        byte[] bytes=new byte[0x3e];currentProgram.getMemory().getBytes(toAddr(0x80f64622L),bytes);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(
            "b9835d6c053d9c13fbe4e599a8e9bbf43f61a2d4e96b672598489376025cfcb5"))
            throw new IllegalStateException("Unrecognized packet ownership code");
        for(long a:new long[]{0x80f64622L,0x80f6462cL,0x80f63f7aL,0x80f63f96L,0x80f655f8L,
                            0x80f65a0eL,0x80f80aa2L,0x80f80aceL})signature(a,VoidDataType.dataType,1);
        for(long a:new long[]{0x80f635faL,0x80f637dcL})signature(a,VoidDataType.dataType,2);
        signature(0x80f649beL,VoidDataType.dataType,1);
        signature(0x80f85cbeL,UnsignedIntegerDataType.dataType,1);
        signature(0x80f85d14L,UnsignedIntegerDataType.dataType,2);
        signature(0x80fd2c3eL,VoidDataType.dataType,2);
        signature(0x80f82fb8L,VoidDataType.dataType,0);signature(0x80f82fe8L,VoidDataType.dataType,0);
        signature(0x80fa6028L,UnsignedIntegerDataType.dataType,4);
        signature(0x80fa60e4L,UnsignedIntegerDataType.dataType,3);
        signature(0x80f84d24L,VoidDataType.dataType,3);
        signature(0x80fcddf0L,UnsignedIntegerDataType.dataType,3);
        signature(0x80f802deL,UnsignedIntegerDataType.dataType,2);
        signature(0x80f80382L,VoidDataType.dataType,1);
        signature(0x80f747c0L,UnsignedIntegerDataType.dataType,0);
        signature(0x80f648dcL,UnsignedIntegerDataType.dataType,1);
        signature(0x80f66326L,UnsignedIntegerDataType.dataType,1);
        signature(0x80f63d74L,VoidDataType.dataType,0);
        signature(0x80f84a8cL,UnsignedIntegerDataType.dataType,0);
        signature(0x80f65920L,VoidDataType.dataType,0);
        // Restrict address sets to reviewed bodies. The C decompiler can still
        // fold direct tail jumps into callees; native validation bounds govern
        // execution coverage independently of that pseudocode expansion.
        for(long[] span:new long[][]{{0x80f64622L,0xa},{0x80f6462cL,0x34},{0x80f63f7aL,0x1c},
                {0x80f63f96L,0x20},{0x80f649beL,0x5a},{0x80f655f8L,0xa},{0x80f80aa2L,0x2c},
                {0x80f80aceL,0x18},{0x80f82fb8L,0x30},{0x80f82fe8L,0x3e},{0x80f84d24L,0x20}})
            getFunctionAt(toAddr(span[0])).setBody(new AddressSet(toAddr(span[0]),toAddr(span[0]+span[1]-1)));
        println("SENSOR_DELIVERY_METADATA selected packet ownership/delivery/queue signatures applied");
    }
}
