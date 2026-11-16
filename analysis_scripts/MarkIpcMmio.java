// Preserve IPC register side effects during native decompilation.
// Analysis metadata only; no firmware or device writes.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import java.security.MessageDigest;
import java.util.HexFormat;

public class MarkIpcMmio extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        boolean sensor = args.length == 1 && args[0].equals("sensor");
        if (args.length > 0 && !sensor) throw new IllegalArgumentException("Only optional argument: sensor");
        byte[] code = new byte[sensor ? 0x116 : 0x12a];
        currentProgram.getMemory().getBytes(toAddr(sensor ? 0x80fa6ad6L : 0x707bf7e0L), code);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(code));
        String expected = sensor ? "738f62e11ea413c293b39c5260b44848ba86ffe682fb62c8248c52e78e3ebe22"
            : "49f4e144a55122620a62ce1846362a2775f47669bdfca952248b9943d8d5d226";
        if (!hash.equals(expected))
            throw new IllegalStateException("Unrecognized IPC notify routine: " + hash);
        long[][] ranges = {{0x90008000L, 0x1000}, {0x91000000L, 0x1000},
                           {0xe4000000L, 0x4000}, {0xe6000000L, 0x1000}};
        for (long[] range : ranges) {
            var address = toAddr(range[0]);
            var block = currentProgram.getMemory().getBlock(address);
            if (block == null)
                block = currentProgram.getMemory().createUninitializedBlock(
                    "ipc_mmio_" + Long.toHexString(range[0]), address, range[1], false);
            if (!block.getStart().equals(address) || block.getSize() != range[1])
                throw new IllegalStateException("Unexpected existing MMIO block at " + address);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(false);
            block.setVolatile(true);
            println("IPC_MMIO " + address + " bytes=" + range[1] + " volatile=" + block.isVolatile());
        }
    }
}
