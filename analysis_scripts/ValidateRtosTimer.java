// Host-only execution of reviewed timer setup/ISR prefixes and AON snapshots.
// Stops before scheduler/IRQ-registration calls; no physical hardware accessed.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateRtosTimer extends GhidraScript {
    private class Helper extends EmulatorHelper {
        private Emulator core;
        Helper(Program p) { super(p); }
        @Override protected Emulator newEmulator() { core = super.newEmulator(); return core; }
        void filter(MemoryAccessFilter f) { core.addMemoryAccessFilter(f); }
    }
    private class Access extends MemoryAccessFilter {
        final List<String> writes = new ArrayList<>();
        long[] samples;
        int sampleIndex;
        @Override protected void processRead(AddressSpace space, long offset, int size, byte[] values) {
            if (samples != null && space.getName().equals("ram") && (offset == 0x910012f8L || offset == 0x910012fcL)) {
                if (size != 4 || sampleIndex >= samples.length || offset != 0x910012f8L + (sampleIndex & 1)*4)
                    throw new IllegalStateException("Unexpected AON read");
                long value = samples[sampleIndex++];
                for (int i = 0; i < 4; ++i) values[i] = (byte)(value >>> (i * 8));
            }
        }
        @Override protected void processWrite(AddressSpace space, long offset, int size, byte[] values) {
            if (space.getName().equals("ram") && offset >= 0xe6000000L && offset < 0xe6000010L) {
                if (size != 4) throw new IllegalStateException("Unexpected timer store width");
                long value = 0;
                for (int i = 0; i < 4; ++i) value |= (values[i] & 255L) << (8 * i);
                writes.add(String.format("%08x:%08x", offset, value));
            }
        }
    }
    private void guard(long address, int size, String expected) throws Exception {
        byte[] bytes = new byte[size]; currentProgram.getMemory().getBytes(toAddr(address), bytes);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals(expected)) throw new IllegalStateException("Unrecognized native bytes at " + Long.toHexString(address));
    }
    private void execute(Helper emu, long entry, long stop, long low, long high) throws Exception {
        emu.writeRegister("sp", 0x81001000L); emu.writeRegister("ra", stop);
        emu.writeRegister(emu.getPCRegister(), entry);
        int steps = 0;
        while (emu.getExecutionAddress().getOffset() != stop) {
            long pc = emu.getExecutionAddress().getOffset();
            if (pc < low || pc >= high || ++steps > 512) throw new IllegalStateException("Execution escaped prefix at " + Long.toHexString(pc));
            if (!emu.step(monitor)) throw new IllegalStateException(emu.getLastError());
        }
    }
    private String store(long address, long value) { return String.format("%08x:%08x", address, value & 0xffffffffL); }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !(args[0].equals("main") || args[0].equals("sensor")))
            throw new IllegalArgumentException("main|sensor report-path");
        boolean sensor = args[0].equals("sensor");
        long setup = sensor ? 0x80f80e42L : 0x80d37e14L, setupStop = sensor ? 0x80f80e86L : 0x80d37e58L;
        long isr = sensor ? 0x80f80f7cL : 0x80d37f42L, isrStop = sensor ? 0x80f80fb2L : 0x80d37f78L;
        long state = sensor ? 0x80f17168L : 0x80c07de8L, period = sensor ? 33 : 1000;
        long aon = sensor ? 0x80f7e7b4L : 0x702a2bb0L;
        guard(setup, sensor ? 0x62 : 0x52, sensor ? "1722b1fc3e455bf16ac6b8551a9258aa8e2da55d26453ce92b59c01460235193" : "936430accc0369f177732ef790dc8da0b99535bf5ff7c81d92fed4dd0889420e");
        guard(isr, 0x4a, sensor ? "d8afeb374f608cdd88ccd6637b34c898c8fd39376e9b7d71e1085481bde41bab" : "895359a9f0fba3c2780e8243e9ae9282cebaeb9986d272faa8014b40b201da0a");
        guard(aon, 0x1e, "aebeb8d2be1fa9fc6e7696e480eb2ea173725542605cd74d7928c6d8eac5944d");
        var csr = currentProgram.getAddressFactory().getAddressSpace("csreg").getAddress(0x304 * 4);
        int setupCases = 0, isrCases = 0, snapshotCases = 0, dispatchCases = 0;
        long[] values = {0,1,32,33,999,1000,0xfffffff0L,0xffffffffL,0x100000000L,Long.MAX_VALUE,-1001,-34,-1};
        for (long n : values) {
            Helper emu = new Helper(currentProgram);
            try {
                emu.writeMemoryValue(toAddr(0xe6000000L), 8, n);
                Access access = new Access(); emu.filter(access);
                execute(emu, setup, setupStop, setup, setupStop);
                long compare = n + period, next = n + period * 2;
                if (!access.writes.equals(List.of(store(0xe6000008L,compare), store(0xe600000cL,compare >>> 32))))
                    throw new IllegalStateException("Setup write order/result differs: " + access.writes);
                if (emu.readMemory(toAddr(state),8).length != 8) throw new IllegalStateException("No state");
                byte[] raw = emu.readMemory(toAddr(state),8);
                long observed = 0; for (int i = 0; i < 8; ++i) observed |= (raw[i] & 255L) << (8 * i);
                if (observed != next) throw new IllegalStateException("Setup next compare differs");
                ++setupCases;
            } finally { emu.dispose(); }
            for (long mie : new long[]{0xa5a58000L,0xa5a58080L}) {
                emu = new Helper(currentProgram);
                try {
                    emu.writeMemoryValue(toAddr(state),8,n); emu.writeMemoryValue(csr,4,mie);
                    Access access = new Access(); emu.filter(access);
                    execute(emu,isr,isrStop,isr,isrStop);
                    if (!access.writes.equals(List.of(store(0xe6000008L,0),store(0xe600000cL,n >>> 32),store(0xe6000008L,n))))
                        throw new IllegalStateException("ISR write order/result differs: " + access.writes);
                    long observed = 0; byte[] raw = emu.readMemory(toAddr(state),8);
                    for (int i = 0; i < 8; ++i) observed |= (raw[i] & 255L) << (8 * i);
                    if (observed != n + period) throw new IllegalStateException("ISR next compare differs");
                    raw = emu.readMemory(csr,4); long flags = 0;
                    for (int i = 0; i < 4; ++i) flags |= (raw[i] & 255L) << (8 * i);
                    if (flags != (mie | 0x80)) throw new IllegalStateException("MTIE contract differs: " + Long.toHexString(flags));
                    ++isrCases;
                } finally { emu.dispose(); }
            }
        }
        for (long[] samples : new long[][]{{7,3,7,3},{0xffffffffL,3,0,4,2,4,2,4},{7,3,7,4,8,4,8,4}}) {
            Helper emu = new Helper(currentProgram);
            try {
                emu.writeMemoryValue(toAddr(0x910012f8L),8,0);
                Access access = new Access(); access.samples = samples; emu.filter(access);
                execute(emu,aon,0x70000000L,aon,aon+0x1e);
                long actual = (emu.readRegister("a1").longValue() << 32) | emu.readRegister("a0").longValue();
                long expected = samples[samples.length-3] << 32 | samples[samples.length-4];
                if (actual != expected || access.sampleIndex != samples.length) throw new IllegalStateException("AON retry contract differs");
                ++snapshotCases;
            } finally { emu.dispose(); }
        }
        long dispatcher = sensor ? 0x80fd3d18L : 0x80d35b10L;
        long table = sensor ? 0x80f15914L : 0x80c009f4L;
        guard(dispatcher,0x14,sensor ? "317caefb3c4694e5ce9d054bd3807e7ac118c3a704c71a5f1011bda0158b7011"
            : "88bb46b86233ba7f778a2cea4b4a33f4fb86f3da0671fbf7eab83f80653e018b");
        for (int cause : new int[]{3,7,11}) {
            long record=table+cause*16;
            long callback=currentProgram.getMemory().getInt(toAddr(record)) & 0xffffffffL;
            long argument=currentProgram.getMemory().getInt(toAddr(record+4)) & 0xffffffffL;
            Helper emu=new Helper(currentProgram);
            try {
                emu.writeRegister("a0",cause);
                execute(emu,dispatcher,callback,dispatcher,dispatcher+0x14);
                if (emu.readRegister("a0").longValue()!=argument) throw new IllegalStateException("Dispatch argument differs");
                ++dispatchCases;
            } finally { emu.dispose(); }
        }
        Files.writeString(Path.of(args[1]), String.format("{\n  \"domain\":\"%s\",\n  \"period_raw\":%d,\n  \"setup_cases\":%d,\n  \"isr_prefix_cases\":%d,\n  \"aon_snapshot_cases\":%d,\n  \"dispatch_cases\":%d,\n  \"bound_per_call\":512,\n  \"hardware_execution\":false\n}\n",args[0],period,setupCases,isrCases,snapshotCases,dispatchCases));
        println("RTOS_VALIDATION " + args[0] + " setup=" + setupCases + " isr=" + isrCases + " aon=" + snapshotCases + " dispatch=" + dispatchCases);
    }
}
