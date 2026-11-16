// Explicit main/sensor receiver, borrowed decoder and buffer-delivery boundaries.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedCacheReceiver extends GhidraScript {
    private void signature(long a,int count,boolean result)throws Exception {
        disassemble(toAddr(a));var f=getFunctionAt(toAddr(a));if(f==null)f=createFunction(toAddr(a),"candidate_"+Long.toHexString(a));
        if(f==null)throw new IllegalStateException("Cannot create receiver function");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result?UnsignedIntegerDataType.dataType:VoidDataType.dataType,SourceType.USER_DEFINED);f.setNoReturn(false);f.setInline(false);
        Parameter[] p=new Parameter[count];for(int i=0;i<count;++i)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
    }
    public void run()throws Exception {
        boolean main=getScriptArgs().length==1&&getScriptArgs()[0].equals("main");
        if(getScriptArgs().length!=1||(!main&&!getScriptArgs()[0].equals("sensor")))throw new IllegalArgumentException("main|sensor");
        long entry=main?0x7071fd60L:0x80f993d0L;byte[] bytes=new byte[main?0x1ca:0x122];currentProgram.getMemory().getBytes(toAddr(entry),bytes);
        String expected=main?"ae2e806a62dc907aa218cd0e04ba0c654f4bc8ce774c4234a3c0e3f7f17c0bf5":"fb12e987584d0060c95fca63d7c17d441a72e28209e8c3d2e086400e478e055f";
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(expected))throw new IllegalStateException("Unrecognized receiver");
        long[][] rows=main?new long[][]{{0x7071fd60L,4,1},{0x70720ac0L,2,1},{0x707200f2L,2,1},{0x70722a98L,1,0},
            {0x7032db3aL,3,0},{0x7032dbaeL,1,1},{0x7032dca6L,1,1},{0x7032dd0cL,1,1},{0x7032ddaaL,2,1},
            {0x701e4ce0L,1,1},{0x701e4f04L,1,1},{0x701e4f7cL,1,1},{0x701e4fa6L,1,1},{0x701e4ff0L,1,1},
            {0x701e3cb8L,1,0},{0x701e330eL,1,0},{0x7071ed94L,1,0}}:
            new long[][]{{0x80f993d0L,4,1},{0x80f99ea8L,2,1},{0x80f996e4L,2,1},{0x80f9afa0L,1,0},
            {0x80fa5ae0L,3,0},{0x80fa5b28L,1,1},{0x80fa5b9aL,1,1},{0x80fa5c00L,1,1},{0x80fa5c96L,2,1},
            {0x80f655d2L,1,1},{0x80f657eeL,1,1},{0x80f6585eL,1,1},{0x80f65884L,1,1},{0x80f658c6L,1,1},
            {0x80f645e2L,1,0},{0x80f63c2eL,1,0},{0x80f9891cL,1,0}};
        for(long[] row:rows)signature(row[0],(int)row[1],row[2]!=0);
        println("CACHE_RECEIVER_METADATA "+(main?"main":"sensor")+" selected signatures applied");
    }
}
