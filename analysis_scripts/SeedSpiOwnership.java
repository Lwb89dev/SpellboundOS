// Restore selected sensor SPI ownership/operation prototypes; analysis metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedSpiOwnership extends GhidraScript {
    private void signature(long value,int count) throws Exception {
        var address=toAddr(value); disassemble(address);
        var f=getFunctionAt(address);
        if(f==null) f=createFunction(address,"candidate_"+Long.toHexString(value));
        if(f==null) throw new IllegalStateException("Cannot create ownership function");
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(IntegerDataType.dataType,SourceType.USER_DEFINED); f.setNoReturn(false);
        Parameter[] params=new Parameter[count];
        for(int i=0;i<count;++i) params[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
    }
    public void run() throws Exception {
        byte[] bytes=new byte[36]; currentProgram.getMemory().getBytes(toAddr(0x80f1589cL),bytes);
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if(!hash.equals("f3d2d26656d566ba5fc722b14a9492ce52f81ffe5da7c4cd70e2102bf90194d4"))
            throw new IllegalStateException("Unrecognized sensor SPI operation table");
        var address=toAddr(0x91003000L); var block=currentProgram.getMemory().getBlock(address);
        if(block==null) block=currentProgram.getMemory().createUninitializedBlock("spi_gpio_mmio",address,0x1000,false);
        if(!block.getStart().equals(address) || block.getSize()!=0x1000) throw new IllegalStateException("Unexpected GPIO window");
        block.setRead(true); block.setWrite(true); block.setExecute(false); block.setVolatile(true);
        for(long a:new long[]{0x80f8965cL,0x80f896d8L,0x80f899aaL,0x80f89a6aL,
                0x80f7b404L,0x80f7b3e8L,0x80f7b328L,0x80f7b2d4L}) signature(a,1);
        signature(0x80f89756L,2); signature(0x80f7b2c0L,2); signature(0x80f7bdbcL,3);
        signature(0x80f7304cL,2); signature(0x80f73152L,2);
        println("SPI_OWNERSHIP_METADATA exact operation-table guard and argument widths applied");
    }
}
