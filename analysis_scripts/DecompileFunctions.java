// Decompile explicit candidate function starts in a raw Ghidra program.
// Run with -noanalysis and one or more hexadecimal addresses as script arguments.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileFunctions extends GhidraScript {
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length == 0) throw new IllegalArgumentException("Supply hexadecimal candidate addresses");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (String argument : arguments) {
                Address address = toAddr(Long.decode(argument));
                println("CANDIDATE " + address);
                disassemble(address);
                Function function = getFunctionAt(address);
                if (function == null) function = createFunction(address, "candidate_" + address.toString().replace(':', '_'));
                if (function == null) { println("Cannot create candidate function"); continue; }
                DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
                println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : "INCOMPLETE: " + result.getErrorMessage());
            }
        } finally { decompiler.dispose(); }
    }
}
