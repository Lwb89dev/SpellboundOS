// Guard the main engine cache gate and seed selected registry/event/HR boundaries.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEngineCache extends GhidraScript {
    private void signature(long a,int count,boolean result)throws Exception {
        disassemble(toAddr(a));var f=getFunctionAt(toAddr(a));if(f==null)f=createFunction(toAddr(a),"candidate_"+Long.toHexString(a));
        if(f==null)throw new IllegalStateException("Cannot create engine cache function");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result?UnsignedIntegerDataType.dataType:VoidDataType.dataType,SourceType.USER_DEFINED);f.setNoReturn(false);f.setInline(false);
        Parameter[] p=new Parameter[count];for(int i=0;i<count;++i)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
    }
    public void run()throws Exception {
        byte[] bytes=new byte[0x78];currentProgram.getMemory().getBytes(toAddr(0x704c4148L),bytes);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals("f2bce681d40e5ffb7603fe8791332a04040d621e5dfab3c5adfe08310253dd74"))throw new IllegalStateException("Unrecognized engine cache gate");
        for(long[] row:new long[][]{{0x701e28d8L,3,1},{0x701e29a4L,3,1},{0x701e320eL,1,1},{0x701e328eL,1,1},
            {0x704c3ea8L,1,0},{0x704c3576L,2,0},{0x704c3340L,1,0},{0x704c43e6L,2,1},{0x704c3f3aL,1,1},
            {0x701e53b0L,2,1},{0x704c4148L,1,1},{0x704c31fcL,1,1},{0x704c253eL,1,1},{0x704c2556L,1,1},
            {0x703150f4L,2,1},{0x70314ba4L,1,0},{0x704c4d44L,4,0},{0x704c4c0cL,1,1},{0x704c4c3aL,1,1},
            {0x704c41c0L,0,1},{0x70315634L,0,1}})signature(row[0],(int)row[1],row[2]!=0);
        println("ENGINE_CACHE_METADATA registry, event, fanout and selected HR signatures applied");
    }
}
