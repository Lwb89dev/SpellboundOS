// Redisassemble only the fingerprinted division helper after the local DSP fix.
// No image bytes are modified. Previous export directories remain untouched.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedTimerArithmetic extends GhidraScript {
    public void run() throws Exception {
        var start = toAddr(0x70945b3cL);
        byte[] bytes = new byte[0x3a4];
        currentProgram.getMemory().getBytes(start, bytes);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals("fb9c031f6bd2d49123fc951bdb2dc1aa7446c55fb356a3a18ef385a761440717"))
            throw new IllegalStateException("Unrecognized arithmetic helper");
        var previous = getFunctionAt(start);
        if (previous != null) removeFunction(previous);
        clearListing(start, start.add(bytes.length - 1));
        disassemble(start);
        if (createFunction(start, "candidate_udiv64") == null)
            throw new IllegalStateException("Cannot recreate helper");
        for (long value : new long[]{0x70945bd4L, 0x70945e48L}) {
            var instruction = getInstructionAt(toAddr(value));
            String expected = value == 0x70945bd4L ? "pkbb16" : "maddr32";
            if (instruction == null || !instruction.getMnemonicString().equals(expected))
                throw new IllegalStateException("DSP language repair missing at " + Long.toHexString(value));
            println("TIMER_DSP " + instruction.getAddress() + " " + instruction);
            for (var operation : instruction.getPcode()) println("  " + operation);
        }
    }
}
