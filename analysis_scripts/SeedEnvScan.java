// Signatures for sector traversal, lookup callbacks and reservation policy.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEnvScan extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0xcc];currentProgram.getMemory().getBytes(toAddr(0x80c0cb16L),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("b8378e0ea7dd1f5ccb9010649e8e0218eb040d6a477976ade5d170594539ee7e"))throw new IllegalStateException("Unrecognized reservation policy");
        for(long[] row:new long[][]{{0x80c0c364L,1,1},{0x80c0c818L,3,1},{0x80c0c44cL,2,1},
            {0x80c0c54cL,3,1},{0x80c0c59cL,3,1},{0x80c0c6d4L,3,1},{0x80c0c9feL,6,0},
            {0x80c0ca72L,2,1},{0x80c0cb7aL,2,1},{0x80c0cb16L,0,0},{0x80c0c392L,2,1},{0x80c0cd82L,4,0}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed environment scan function");
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(row[2]!=0?UnsignedIntegerDataType.dataType:VoidDataType.dataType,SourceType.USER_DEFINED);
            f.setNoReturn(false);f.setInline(false);Parameter[] p=new Parameter[(int)row[1]];
            for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("ENV_SCAN_METADATA applied");
    }
}
