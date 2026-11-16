// Guard selected optical FIFO/recovery bytes and seed explicit native boundaries.
// Changes analysis metadata only; no peripheral or firmware write.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedPpgFifo extends GhidraScript {
    private void signature(long value,DataType result,int count)throws Exception{
        var address=toAddr(value);disassemble(address);var f=getFunctionAt(address);
        if(f==null)f=createFunction(address,"candidate_"+Long.toHexString(value));
        if(f==null)throw new IllegalStateException("Cannot create FIFO function");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result,SourceType.USER_DEFINED);f.setNoReturn(false);
        Parameter[] params=new Parameter[count];
        for(int i=0;i<count;++i)params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
    }
    public void run()throws Exception{
        byte[] bytes=new byte[0x272];currentProgram.getMemory().getBytes(toAddr(0x80f74526L),bytes);
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if(!hash.equals("98b23e61205b0483933b6d19d41e48df208ad1235e181c2e65b4fa6a4f582e91"))
            throw new IllegalStateException("Unrecognized FIFO reader");
        for(long a:new long[]{0x80f74526L,0x80f72e86L,0x80f738beL,0x80f75bf6L})signature(a,VoidDataType.dataType,0);
        signature(0x80f73906L,VoidDataType.dataType,1);
        signature(0x80f72ea4L,UnsignedIntegerDataType.dataType,1);
        signature(0x80f72f18L,IntegerDataType.dataType,2);
        signature(0x80f7f958L,UnsignedIntegerDataType.dataType,0);
        signature(0x80f80aa0L,UnsignedIntegerDataType.dataType,1);
        signature(0x80f8263eL,UnsignedIntegerDataType.dataType,0);
        signature(0x80f82648L,UnsignedIntegerDataType.dataType,0);
        signature(0x80fa40b0L,VoidDataType.dataType,1);
        println("PPG_FIFO_METADATA reviewed boundaries, tick return and ring helpers applied");
    }
}
