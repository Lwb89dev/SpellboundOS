// Host-only execution of fingerprinted firmware through corrected SLEIGH p-code.
// Each invocation is bounded and compared with Java's independent unsigned /
// oracle. No device connection, physical time or live register state is used.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateTimerArithmetic extends GhidraScript {
    private static final long ENTRY = 0x70945b3cL, READER = 0x80d45464L, RETURN = 0x70000000L;
    private static final String[] REGS = {"ra","sp","gp","tp","t0","t1","t2","s0","s1",
        "a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5","s6",
        "s7","s8","s9","s10","s11","t3","t4","t5","t6"};
    private final Set<Long> covered = new TreeSet<>();
    private final Set<String> edges = new TreeSet<>();
    private final Map<Long, Long> dsp = new TreeMap<>();
    private int cases, readerCases, maxSteps;
    private long totalSteps;

    private void guard(long address, int size, String expected) throws Exception {
        byte[] bytes = new byte[size];
        currentProgram.getMemory().getBytes(toAddr(address), bytes);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals(expected)) throw new IllegalStateException("Unrecognized bytes at " + Long.toHexString(address));
    }

    private void check(EmulatorHelper emu, long numerator, long denominator, boolean reader) throws Exception {
        // Vary scratch/callee-saved state; ensure input values are the only operands.
        long initial = numerator ^ denominator ^ 0x91e10da5L;
        for (int i = 0; i < REGS.length; ++i) emu.writeRegister(REGS[i], (initial + 0x1020304L * i) & 0xffffffffL);
        emu.writeRegister("ra", RETURN);
        emu.writeRegister("sp", 0x81001000L); // synthetic host memory, no physical stack
        emu.writeRegister("a0", numerator & 0xffffffffL);
        emu.writeRegister("a1", numerator >>> 32);
        emu.writeRegister("a2", denominator & 0xffffffffL);
        emu.writeRegister("a3", denominator >>> 32);
        if (reader) emu.writeMemoryValue(toAddr(0xe6000000L), 8, numerator);
        emu.writeRegister(emu.getPCRegister(), reader ? READER : ENTRY);
        int steps = 0;
        while (emu.getExecutionAddress().getOffset() != RETURN) {
            long pc = emu.getExecutionAddress().getOffset();
            boolean inHelper = pc >= ENTRY && pc < ENTRY + 0x3a4;
            if ((!inHelper && !(reader && pc >= READER && pc < READER + 0x26)) || ++steps > 512)
                throw new IllegalStateException("Execution escaped bound at " + Long.toHexString(pc));
            monitor.checkCancelled();
            covered.add(pc);
            var instruction = getInstructionAt(toAddr(pc));
            if (instruction == null) throw new IllegalStateException("Undecoded instruction at " + Long.toHexString(pc));
            String mnemonic = instruction.getMnemonicString();
            if (mnemonic.equals("pkbb16") || mnemonic.equals("maddr32")) dsp.merge(pc, 1L, Long::sum);
            if (!emu.step(monitor)) throw new IllegalStateException("Emulation failed: " + emu.getLastError());
            if (instruction.getFlowType().isConditional())
                edges.add(String.format("%08x:%08x", pc, emu.getExecutionAddress().getOffset()));
        }
        long result = (emu.readRegister("a1").longValue() << 32) | (emu.readRegister("a0").longValue() & 0xffffffffL);
        long expected = Long.divideUnsigned(numerator, reader ? 1000 : denominator);
        if (result != expected)
            throw new IllegalStateException("Mismatch " + Long.toUnsignedString(numerator) + "/" +
                Long.toUnsignedString(denominator) + ": " + Long.toUnsignedString(result) + " != " + Long.toUnsignedString(expected));
        if (emu.readRegister("sp").longValue() != 0x81001000L || emu.readRegister("ra").longValue() != RETURN)
            throw new IllegalStateException("Return/stack contract violated");
        if (reader) ++readerCases; else ++cases;
        totalSteps += steps;
        maxSteps = Math.max(maxSteps, steps);
    }

    private String addresses(Collection<Long> values) {
        return values.stream().map(a -> String.format("\"%08x\"", a)).toList().toString();
    }

    public void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("report-path");
        guard(ENTRY, 0x3a4, "fb9c031f6bd2d49123fc951bdb2dc1aa7446c55fb356a3a18ef385a761440717");
        guard(0x709babf8L, 256, "14a5d850c255623f9472e3c650abce0c78d32f0276b315b3a276a0462d97a1ac");
        guard(READER, 0x26, "43196df4f0cc2097e5d10bb271df73e18a49be725fbc3157b1a9d75f6bfd6c15");
        Set<Long> values = new LinkedHashSet<>(List.of(0L, 1L, 2L, 3L, -1L));
        for (int bit = 0; bit < 64; ++bit) {
            long p = 1L << bit;
            values.add(p - 1); values.add(p); values.add(p + 1);
        }
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            for (long n : values) for (long d : values) if (d != 0) check(emu, n, d, false);
            Random random = new Random(0x5350454c4cL);
            for (int i = 0; i < 4096; ++i) {
                long n = random.nextLong(), d = random.nextLong();
                if (d != 0) check(emu, n, d, false);
                d &= 0xffffffffL;
                if (d != 0) check(emu, n, d, false);
                check(emu, n, 1000, false);
                // Exercise normalized high-word divisors with large quotients,
                // which uniformly random 64-bit divisors rarely reach.
                d = random.nextLong() >>> (i & 63);
                check(emu, n, d == 0 ? 1 : d, false);
            }
            for (long n : values) check(emu, n, 1000, true);
            // Boundary phase of floor(raw/1000), including near 64-bit wrap.
            for (long n : new long[]{998,999,1000,1001,999999,1000000,1000001,-1001,-1000,-999})
                check(emu, n, 1000, true);
        } finally { emu.dispose(); }
        StringBuilder hits = new StringBuilder("{");
        for (var e : dsp.entrySet()) {
            if (hits.length() > 1) hits.append(',');
            hits.append(String.format("\"%08x\":%d", e.getKey(), e.getValue()));
        }
        hits.append('}');
        String report = "{\n  \"oracle\": \"Java Long.divideUnsigned; nonzero divisors\",\n" +
            "  \"random_seed_hex\": \"5350454c4c\",\n  \"division_cases\": " + cases +
            ",\n  \"reader_cases\": " + readerCases + ",\n  \"instruction_steps\": " + totalSteps +
            ",\n  \"max_steps_per_case\": " + maxSteps + ",\n  \"covered_addresses\": " + addresses(covered) +
            ",\n  \"conditional_edges\": " + edges.stream().map(s -> "\"" + s + "\"").toList() +
            ",\n  \"dsp_execution_counts\": " + hits +
            ",\n  \"limitations\": [\"Corrected SLEIGH p-code on host, not silicon execution\", " +
            "\"Synthetic stable counter and stack; no elapsed-time or rollover-race measurement\", " +
            "\"Bounded vectors, not exhaustive proof; division by zero excluded\"]\n}\n";
        Files.writeString(Path.of(getScriptArgs()[0]), report);
        println("TIMER_VALIDATION division=" + cases + " reader=" + readerCases + " maxSteps=" + maxSteps);
    }
}
