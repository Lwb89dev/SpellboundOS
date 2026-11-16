// Restore reviewed wide clock signatures and volatile clock/CSR semantics.
// Changes Ghidra analysis metadata only.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedClockCache extends GhidraScript {
    private Function function(long value) throws Exception {
        var address = toAddr(value);
        disassemble(address);
        var f = getFunctionAt(address);
        if (f == null) f = createFunction(address, "candidate_" + Long.toHexString(value));
        if (f == null) throw new IllegalStateException("Cannot create function " + address);
        f.setNoReturn(false);
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        return f;
    }
    public void run() throws Exception {
        byte[] bytes = new byte[0x26];
        currentProgram.getMemory().getBytes(toAddr(0x80d45464L), bytes);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals("43196df4f0cc2097e5d10bb271df73e18a49be725fbc3157b1a9d75f6bfd6c15"))
            throw new IllegalStateException("Unrecognized clock reader");
        var csrSpace = currentProgram.getAddressFactory().getAddressSpace("csreg");
        var csr = currentProgram.getMemory().getBlock(csrSpace.getAddress(0));
        if (csr == null || csr.getStart().getOffset() != 0 || csr.getSize() != 0x4000)
            throw new IllegalStateException("Unexpected CSR memory block");
        csr.setVolatile(true);
        var address = toAddr(0x9a000000L);
        var clocks = currentProgram.getMemory().getBlock(address);
        if (clocks == null)
            clocks = currentProgram.getMemory().createUninitializedBlock("clock_mmio", address, 0x1000, false);
        if (!clocks.getStart().equals(address) || clocks.getSize() != 0x1000)
            throw new IllegalStateException("Unexpected clock MMIO block");
        clocks.setRead(true); clocks.setWrite(true); clocks.setExecute(false); clocks.setVolatile(true);
        var u64 = UnsignedLongLongDataType.dataType;
        for (long value : new long[]{0x80d45464L, 0x80d4548cL, 0x80d4549cL}) {
            var f = function(value);
            f.setReturnType(u64, SourceType.USER_DEFINED);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
        }
        var divide = function(0x70945b3cL);
        divide.setReturnType(u64, SourceType.USER_DEFINED);
        divide.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("numerator", u64, currentProgram),
            new ParameterImpl("denominator", u64, currentProgram));
        for (long value : new long[]{0x80d454b0L, 0x80d413a8L, 0x80d41338L,
                                    0x80d412a8L, 0x80d412f0L}) {
            var f = function(value);
            f.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
        }
        println("CLOCK_CACHE_METADATA csr_volatile=" + csr.isVolatile() + " clock_mmio_volatile=" + clocks.isVolatile());
        println("CLOCK_DIVIDE_SIGNATURE " + divide.getSignature());
    }
}
