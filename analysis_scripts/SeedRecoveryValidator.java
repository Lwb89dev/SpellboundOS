// Guarded boot CRC and read-only recovery validation signatures.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedRecoveryValidator extends GhidraScript {
    private void signature(long address,int count)throws Exception {
        disassemble(toAddr(address));var f=getFunctionAt(toAddr(address));
        if(f==null)f=createFunction(toAddr(address),"candidate_"+Long.toHexString(address));
        if(f==null)throw new IllegalStateException("Cannot seed boot function");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);f.setNoReturn(false);f.setInline(false);
        Parameter[] parameters=new Parameter[count];for(int i=0;i<count;i++)parameters[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,parameters);
    }
    public void run()throws Exception {
        byte[] guard=new byte[0x54];currentProgram.getMemory().getBytes(toAddr(0x80c00b24L),guard);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(guard)).equals("4eb88ef657bf687d1f4f783909cdfdb382e2d1e448adb4099e6b2a28060a918d"))
            throw new IllegalStateException("Unrecognized boot CRC routines");
        for(long[] row:new long[][]{{0x80c00b24L,3},{0x80c00b52L,3},{0x80c0e578L,3},{0x80c0e6eaL,8},
            {0x80c0e7e0L,4},{0x80c0e9c2L,1},{0x80c0e3c2L,3},{0x80c0e38cL,4},{0x80c0e180L,4},{0x80c0e144L,2}})
            signature(row[0],(int)row[1]);
        println("RECOVERY_VALIDATOR_METADATA CRC and selected validation paths applied");
    }
}
