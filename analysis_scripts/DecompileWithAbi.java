// Targeted analysis on a fresh startup-aware main ELF, with the verified
// four verified save/restore pairs modeled as p-code call fixups. Analysis metadata
// only: the imported image bytes are never patched.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.listing.*;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;
import java.nio.file.*;

public class DecompileWithAbi extends GhidraScript {
    private Function ensure(long value, String name) throws Exception {
        var address = toAddr(value);
        disassemble(address);
        var function = getFunctionAt(address);
        return function != null ? function : createFunction(address, name);
    }
    private void fixup(long address, String name, String body) throws Exception {
        String xml = "<callfixup name=\"" + name + "\"><pcode><body><![CDATA[" +
            body + "]]></body></pcode></callfixup>";
        new SpecExtension(currentProgram).addReplaceCompilerSpecExtension(xml, monitor);
        var function = ensure(address, name);
        if (function == null) throw new IllegalStateException("No stub function");
        function.setCallFixup(name);
        function.setNoReturn(false);
    }
    private void pair(long save, long restore, int frame, String[] registers) throws Exception {
        StringBuilder push = new StringBuilder("sp = sp - " + frame + ";");
        if (frame != 16) push.append("t1 = " + (frame - 64) + ";");
        StringBuilder pop = new StringBuilder();
        int first = frame - registers.length * 4;
        for (int index = 0; index < registers.length; index++) {
            String slot = "*:4 (sp + " + (first + index * 4) + ")";
            push.append(slot + " = " + registers[index] + ";");
            pop.append(registers[index] + " = " + slot + ";");
        }
        pop.append("sp = sp + " + frame + "; return [ra];");
        fixup(save, "spellbound_save" + frame, push.toString());
        fixup(restore, "spellbound_restore" + frame, pop.toString());
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("output-directory addresses...");
        Path output = Paths.get(args[0]);
        Files.createDirectories(output);
        byte[] stubs = new byte[0x60];
        currentProgram.getMemory().getBytes(toAddr(0x70946264L), stubs);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(stubs));
        if (!hash.equals("aa642d9b6e2215e62610b7f18db4155db6eb4b7585f3b43ef80a676ccb82074e"))
            throw new IllegalStateException("Unrecognized save/restore bytes: " + hash);
        pair(0x70946264L, 0x709462a0L, 64,
            new String[]{"s11","s10","s9","s8","s7","s6","s5","s4","s3","s2","s1","s0","ra"});
        pair(0x7094626cL, 0x709462a4L, 48,
            new String[]{"s10","s9","s8","s7","s6","s5","s4","s3","s2","s1","s0","ra"});
        pair(0x7094627aL, 0x709462aeL, 32,
            new String[]{"s6","s5","s4","s3","s2","s1","s0","ra"});
        pair(0x70946294L, 0x709462b8L, 16, new String[]{"s2","s1","s0","ra"});
        Set<Long> restores = Set.of(0x709462a0L,0x709462a4L,0x709462aeL,0x709462b8L);
        var logger = ensure(0x702b38a2L, "candidate_logger");
        if (logger != null) logger.setNoReturn(false);
        for (int index = 1; index < args.length; index++) {
            long value = Long.decode(args[index]);
            var function = ensure(value, "candidate_" + Long.toHexString(value));
            if (function == null) throw new IllegalStateException("Cannot create " + args[index]);
            // A direct tail jump into the restore helper must use the same
            // injected stack/return effects as a recognized call.
            var instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                var instruction = instructions.next();
                for (var target : instruction.getFlows()) {
                    if (restores.contains(target.getOffset()) && instruction.getFlowType().isJump())
                        instruction.setFlowOverride(FlowOverride.CALL_RETURN);
                }
            }
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (int index = 1; index < args.length; index++) {
                long value = Long.decode(args[index]);
                var function = getFunctionAt(toAddr(value));
                var result = decompiler.decompileFunction(function, 60, monitor);
                String prefix = String.format("%08x", value);
                Files.writeString(output.resolve(prefix + (result.decompileCompleted() ? ".c" : ".error.txt")),
                    result.decompileCompleted() ? result.getDecompiledFunction().getC() : result.getErrorMessage());
                println("ABI_EXPORT " + prefix + " completed=" + result.decompileCompleted());
            }
        } finally { decompiler.dispose(); }
    }
}
