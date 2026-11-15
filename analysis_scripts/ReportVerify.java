// Ghidra post-script. Addresses depend on the candidate boot image mapping.
//@category SpellboundFit
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;

public class ReportVerify extends GhidraScript {
    public void run() throws Exception {
        long[] addresses = {0x80c0e6eaL, 0x80c0e7e0L};
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        for (long address : addresses) {
            Function f = getFunctionContaining(toAddr(address));
            println("CANDIDATE " + Long.toHexString(address));
            if (f == null) { println("No function found"); continue; }
            DecompileResults r = d.decompileFunction(f, 30, monitor);
            println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : r.getErrorMessage());
        }
        d.dispose();
    }
}
