// Correct selected sensor control/packet signatures after checking OTA bytes.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedSensorPackets extends GhidraScript {
    private void signature(long a,DataType result,int count)throws Exception {
        disassemble(toAddr(a));var f=getFunctionAt(toAddr(a));
        if(f==null)f=createFunction(toAddr(a),"candidate_"+Long.toHexString(a));
        if(f==null)throw new IllegalStateException("Cannot create sensor boundary");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result,SourceType.USER_DEFINED);f.setNoReturn(false);
        Parameter[] args=new Parameter[count];
        for(int i=0;i<count;++i)args[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,args);
    }
    private void guard(long a,int n,String expected)throws Exception {
        byte[] bytes=new byte[n];currentProgram.getMemory().getBytes(toAddr(a),bytes);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(expected))
            throw new IllegalStateException("Unrecognized sensor code");
    }
    public void run()throws Exception {
        guard(0x80f64238L,0x306,"925ad16479e8136f84c7a623b6391985a76e0ea026bd274ae0ed30ca991e79e3");
        guard(0x80f6453eL,0xa4,"afec2a8694f2248c350c858baf0b273909a3dfb1300a824909b7e1f5c2628acd");
        for(long a:new long[]{0x80f632dcL,0x80f65e2eL,0x80f66298L})signature(a,UnsignedIntegerDataType.dataType,1);
        for(long a:new long[]{0x80f65cd6L,0x80f65ce8L})signature(a,UnsignedIntegerDataType.dataType,0);
        signature(0x80f64238L,UnsignedIntegerDataType.dataType,4);
        signature(0x80f64216L,VoidDataType.dataType,1);
        signature(0x80f763beL,VoidDataType.dataType,3);
        signature(0x80f6453eL,UnsignedIntegerDataType.dataType,2);
        signature(0x80f645e2L,VoidDataType.dataType,1);
        signature(0x80f63302L,UnsignedLongLongDataType.dataType,0);
        println("SENSOR_PACKETS_METADATA selected control and allocation boundaries applied");
    }
}
