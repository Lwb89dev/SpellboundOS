// Ghidra post-script: bounded references and pseudocode for integrity strings.
//@category SpellboundFit
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class ReportBoot extends GhidraScript {
    public void run() throws Exception {
        long[] offsets = {0x3310c, 0x33130, 0x33188, 0x331a4, 0x3321c, 0x3710c, 0x371c8};
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (long originalOffset : offsets) {
            Address target = toAddr(0x80c00000L + originalOffset - 0x400);
            println("STRING file_offset=0x" + Long.toHexString(originalOffset) + " candidate_address=" + target);
            Reference[] refs = getReferencesTo(target);
            int count = 0;
            for (Reference ref : refs) {
                if (count++ >= 10 || monitor.isCancelled()) break;
                Function f = getFunctionContaining(ref.getFromAddress());
                println("XREF " + ref.getFromAddress() + " function=" + (f == null ? "unknown" : f.getEntryPoint()));
                if (f != null) {
                    DecompileResults result = decompiler.decompileFunction(f, 20, monitor);
                    if (result.decompileCompleted()) println(result.getDecompiledFunction().getC());
                    else println("Decompilation incomplete: " + result.getErrorMessage());
                }
            }
            if (count == 0) println("No references found under this mapping and analysis.");
        }
        decompiler.dispose();
    }
}
