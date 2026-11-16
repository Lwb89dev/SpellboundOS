// Targeted export with explicit logger return metadata; no save/restore fixups.
// Use only where the selected entry/call instructions have been reviewed.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import java.nio.file.*;

public class DecompileWithLogger extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) throw new IllegalArgumentException("output-directory logger-address targets...");
        Path output = Paths.get(args[0]);
        Files.createDirectories(output);
        var loggerAddress = toAddr(Long.decode(args[1]));
        disassemble(loggerAddress);
        var logger = getFunctionAt(loggerAddress);
        if (logger == null) logger = createFunction(loggerAddress, "candidate_logger");
        if (logger == null) throw new IllegalStateException("Cannot create logger");
        logger.setNoReturn(false);
        for (int i = 2; i < args.length; i++) {
            var address = toAddr(Long.decode(args[i]));
            disassemble(address);
            if (getFunctionAt(address) == null && createFunction(address, "candidate_" + args[i].substring(2)) == null)
                throw new IllegalStateException("Cannot create target " + args[i]);
        }
        var decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (int i = 2; i < args.length; i++) {
                long value = Long.decode(args[i]);
                var result = decompiler.decompileFunction(getFunctionAt(toAddr(value)), 60, monitor);
                if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
                Files.writeString(output.resolve(String.format("%08x.c", value)), result.getDecompiledFunction().getC());
                println("LOGGER_EXPORT " + args[i] + " completed=true");
            }
        } finally { decompiler.dispose(); }
    }
}
