// QSPI platform/command metadata only; imported bytes remain unchanged.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedNandBus extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0x16e];currentProgram.getMemory().getBytes(toAddr(0x80c10580L),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("69fd28f411b9e8f4e447870d0b38a1cc677c4811aa5ac73bf06cf85abef7706e"))throw new IllegalStateException("Unrecognized NAND bus init");
        for(long[] row:new long[][]{{0x80df928cL,3},{0x80df93c4L,3},{0x80df94bcL,3},{0x80df951cL,3},{0x80df960cL,3},
            {0x80c10580L,1},{0x80c12298L,0},{0x80c102f0L,1},{0x80c106f0L,2},
            {0x80c27ce8L,2},{0x80c27d48L,2},{0x80c27db0L,0},{0x80c27e0eL,1},
            {0x80c27e70L,3},{0x80c27ed6L,4},{0x80c27f3eL,4},{0x80c27fa8L,1},
            {0x80c2806cL,4},{0x80c280d0L,4},{0x80c28136L,1},{0x80c2836eL,2},{0x80c286b2L,2}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed NAND bus boundary");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
            if(row[0]==0x80c106f0L)println("BUS_TRANSFER_BODY "+f.getBody());
        }
        println("NAND_BUS_METADATA applied");
    }
}
