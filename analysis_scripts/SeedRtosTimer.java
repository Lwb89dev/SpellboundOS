// Guard selected main/sensor timer paths and restore raw-reader signatures.
// Changes analysis metadata only; does not set hardware frequency or registers.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedRtosTimer extends GhidraScript {
    private void signature(long value, DataType result, int arguments) throws Exception {
        var address = toAddr(value);
        disassemble(address);
        var f = getFunctionAt(address);
        if (f == null) f = createFunction(address, "candidate_" + Long.toHexString(value));
        if (f == null) throw new IllegalStateException("Cannot create " + address);
        f.setNoReturn(false);
        f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
        f.setReturnType(result, SourceType.USER_DEFINED);
        Parameter[] params = new Parameter[arguments];
        for (int i = 0; i < arguments; ++i)
            params[i] = new ParameterImpl("arg" + i, UnsignedIntegerDataType.dataType, currentProgram);
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, params);
    }
    public void run() throws Exception {
        boolean sensor = getScriptArgs().length == 1 && getScriptArgs()[0].equals("sensor");
        if (getScriptArgs().length > 0 && !sensor) throw new IllegalArgumentException("optional sensor");
        long entry = sensor ? 0x80f80e42L : 0x80d37e14L;
        byte[] bytes = new byte[sensor ? 0x62 : 0x52];
        currentProgram.getMemory().getBytes(toAddr(entry), bytes);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        String expected = sensor ? "1722b1fc3e455bf16ac6b8551a9258aa8e2da55d26453ce92b59c01460235193"
            : "936430accc0369f177732ef790dc8da0b99535bf5ff7c81d92fed4dd0889420e";
        if (!hash.equals(expected)) throw new IllegalStateException("Unrecognized timer setup: " + hash);
        var csreg = currentProgram.getAddressFactory().getAddressSpace("csreg");
        var block = currentProgram.getMemory().getBlock(csreg.getAddress(0));
        if (block == null || block.getSize() != 0x4000) throw new IllegalStateException("Unexpected CSR block");
        block.setVolatile(true);
        var aonAddress = toAddr(0x91001000L);
        var aon = currentProgram.getMemory().getBlock(aonAddress);
        if (aon == null) aon = currentProgram.getMemory().createUninitializedBlock("aon_mmio", aonAddress, 0x1000, false);
        if (!aon.getStart().equals(aonAddress) || aon.getSize() != 0x1000)
            throw new IllegalStateException("Unexpected AON block");
        aon.setRead(true); aon.setWrite(true); aon.setExecute(false); aon.setVolatile(true);
        long[] readers = sensor ? new long[]{0x80f7b594L,0x80f7b5b8L,0x80f7b5c8L,0x80f80fe0L}
            : new long[]{0x80d45464L,0x80d4548cL,0x80d4549cL,0x80d37fa6L};
        for (long reader : readers) signature(reader, UnsignedLongLongDataType.dataType, 0);
        signature(sensor ? 0x80f7e7b4L : 0x702a2bb0L, UnsignedLongLongDataType.dataType, 0);
        signature(sensor ? 0x80fd2c3eL : 0x80d33720L, VoidDataType.dataType, 2);
        signature(sensor ? 0x80fd3e34L : 0x80d35c6cL, VoidDataType.dataType, 3);
        signature(sensor ? 0x80fd3d94L : 0x80d35bccL, VoidDataType.dataType, 1);
        signature(sensor ? 0x80f826e2L : 0x80d3974eL, UnsignedIntegerDataType.dataType, 0);
        signature(sensor ? 0x80f8286aL : 0x80d398d6L, VoidDataType.dataType, 0);
        signature(sensor ? 0x80f81008L : 0x80d37fceL, VoidDataType.dataType, 1);
        println("RTOS_TIMER_SEED sensor=" + sensor + " csr_volatile=" + block.isVolatile());
    }
}
