// Guard the reviewed sensor SPI adapter and preserve transfer argument widths.
// Analysis metadata only. Does not configure the watch or emulate a bus.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedOpticalSpi extends GhidraScript {
    private void signature(long value, int count) throws Exception {
        var address = toAddr(value); disassemble(address);
        var f = getFunctionAt(address);
        if (f == null) f = createFunction(address,"candidate_" + Long.toHexString(value));
        if (f == null) throw new IllegalStateException("Cannot create SPI function");
        f.setNoReturn(false);
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(IntegerDataType.dataType,SourceType.USER_DEFINED);
        Parameter[] params = new Parameter[count];
        for (int i = 0; i < count; ++i)
            params[i] = new ParameterImpl("arg" + i,UnsignedIntegerDataType.dataType,currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
    }
    public void run() throws Exception {
        byte[] bytes = new byte[0x34]; currentProgram.getMemory().getBytes(toAddr(0x80f7b36cL),bytes);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals("b9d75e291da80ac65979421aab1d4e89b0ea0c8cf6807cb04ddb32d3478030cb"))
            throw new IllegalStateException("Unrecognized SPI adapter");
        for (long base : new long[]{0x90004000L,0x90005000L,0x9a000000L}) {
            var address = toAddr(base); var block = currentProgram.getMemory().getBlock(address);
            if (block == null) block = currentProgram.getMemory().createUninitializedBlock("spi_mmio_" + Long.toHexString(base),address,0x1000,false);
            if (!block.getStart().equals(address) || block.getSize() != 0x1000) throw new IllegalStateException("Unexpected SPI window");
            block.setRead(true); block.setWrite(true); block.setExecute(false); block.setVolatile(true);
        }
        signature(0x80f7eb60L,1); signature(0x80f7b36cL,2);
        for (long a : new long[]{0x80f7ee38L,0x80f7eeccL,0x80f7b3d0L,0x80f7b3b8L,0x80f897bcL}) signature(a,4);
        for (long a : new long[]{0x80f7ed84L,0x80f7b3a0L,0x80f898aeL}) signature(a,5);
        println("OPTICAL_SPI_METADATA selected argument widths and volatile windows applied");
    }
}
