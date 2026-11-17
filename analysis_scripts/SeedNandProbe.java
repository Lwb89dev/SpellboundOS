// Guarded NAND identification, operation init and driver registration metadata.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedNandProbe extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0x314];currentProgram.getMemory().getBytes(toAddr(0x80c2874aL),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("bb970f21e8765d548b5877e39ac81ebeac3266c7fb66b1a8857cd2872019dd74"))throw new IllegalStateException("Unrecognized NAND probe");
        for(long[] row:new long[][]{{0x80c1dee4L,2},{0x80c1e046L,1},{0x80c1df76L,1},{0x80c164aaL,1},
            {0x80c1d13aL,1},{0x80c27d48L,2},{0x80c27ce8L,2},{0x80c29f5cL,0},{0x80c28422L,0},
            {0x80c2785aL,3},{0x80c2ceccL,3},{0x80c28318L,3},{0x80c2819eL,2},{0x80c281fcL,0},
            {0x80c2874aL,0},{0x80c27aacL,0},{0x80c27524L,1},{0x80c29d4cL,0},
            {0x80c026a6L,2},{0x80c025d4L,2}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed NAND probe boundary");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        println("NAND_PROBE_METADATA applied");
    }
}
