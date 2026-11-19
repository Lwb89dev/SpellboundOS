// Read-only: decompiles the code at each given entry address, creating an
// in-memory function first when none exists (the project is opened read-only,
// so nothing is saved). Prints the full decompiled C for each entry.
//@category SpellboundOS
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;

public class DecompileNativeAt extends GhidraScript {
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String value : getScriptArgs()) {
            var entry = toAddr(Long.decode(value));
            if (getInstructionAt(entry) == null) {
                disassemble(entry);
            }
            var function = getFunctionAt(entry);
            if (function == null) {
                function = createFunction(entry, null);
            }
            if (function == null) {
                println("DECOMP " + entry + " create=failed");
                continue;
            }
            var result = decompiler.decompileFunction(function, 180, monitor);
            if (result == null || !result.decompileCompleted()) {
                println("DECOMP " + entry + " decompile=failed");
                continue;
            }
            println("DECOMP " + entry + " BEGIN");
            for (String line : result.getDecompiledFunction().getC().split("\n")) {
                println("C| " + line);
            }
            println("DECOMP " + entry + " END");
        }
        decompiler.dispose();
    }
}
