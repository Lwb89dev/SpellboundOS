// Selected main algorithm registry/lifecycle and actual HR adapter signatures.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedAlgorithmManager extends GhidraScript {
    private void signature(long address,int count,boolean result)throws Exception {
        disassemble(toAddr(address));var f=getFunctionAt(toAddr(address));
        if(f==null)f=createFunction(toAddr(address),"candidate_"+Long.toHexString(address));
        if(f==null)throw new IllegalStateException("Cannot seed algorithm function");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result?UnsignedIntegerDataType.dataType:VoidDataType.dataType,SourceType.USER_DEFINED);
        f.setNoReturn(false);f.setInline(false);
        Parameter[] parameters=new Parameter[count];
        for(int i=0;i<count;i++)parameters[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,parameters);
    }
    public void run()throws Exception {
        byte[] guard=new byte[0x46a];currentProgram.getMemory().getBytes(toAddr(0x704c4a1eL),guard);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(guard)).equals("c765b206b73ceb3e3574d088a756b741099e61a72acc846de7d4186e1581b23d"))
            throw new IllegalStateException("Unrecognized algorithm manager");
        for(long[] row:new long[][]{{0x704c4a1eL,0,1},{0x704c4a22L,0,0},{0x704c4a24L,1,1},
            {0x704c4ac2L,1,1},{0x704c4b86L,1,0},{0x704c4c0cL,1,1},{0x704c4c3aL,1,1},
            {0x704c4cb6L,1,0},{0x704c4d3cL,1,1},{0x704c4d40L,1,0},{0x704c4d44L,4,0},
            {0x704c4e00L,2,0},{0x704c4e58L,3,0},{0x70313446L,1,1},{0x7031345aL,3,1},
            {0x70313470L,0,0},{0x70313478L,0,1},{0x7031348eL,0,0},
            {0x7089b82cL,3,1},{0x7089adcaL,0,1},{0x7089d110L,1,1}})
            signature(row[0],(int)row[1],row[2]!=0);
        println("ALGORITHM_MANAGER_METADATA applied");
    }
}
