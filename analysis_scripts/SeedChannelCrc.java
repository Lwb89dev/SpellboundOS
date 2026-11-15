// Restore the CRC accumulator return that inferred void types erase.
// Analysis metadata only; guard the exact reviewed native loop bytes.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedChannelCrc extends GhidraScript {
    public void run() throws Exception {
        var address = toAddr(0x70161360L);
        byte[] bytes = new byte[0x26];
        currentProgram.getMemory().getBytes(address, bytes);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals("82666efb8aecf1c3c3a4e1834306b1827d0bf6003c7ef65f852de46eb1876610"))
            throw new IllegalStateException("Unrecognized CRC loop: " + hash);
        disassemble(address);
        var function = getFunctionAt(address);
        if (function == null) function = createFunction(address, "candidate_channel_crc_update");
        function.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("accumulator", UnsignedIntegerDataType.dataType, currentProgram),
            new ParameterImpl("data", new PointerDataType(ByteDataType.dataType), currentProgram),
            new ParameterImpl("size", UnsignedIntegerDataType.dataType, currentProgram));
        println("CHANNEL_CRC_SIGNATURE " + function.getSignature());
    }
}
