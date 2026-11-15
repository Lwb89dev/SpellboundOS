// Bounded, manually seeded decompilation; addresses assume raw base 0x70160000.
// Function starts are hypotheses derived from nearby RISC-V prologues.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompilePeripheralLoad extends GhidraScript {
    public void run() throws Exception {
        long[] addresses = {0x70163860L, 0x702c2682L, 0x702c2842L, 0x702c50b0L, 0x703cd15aL, 0x707241faL};
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        for (long value : addresses) {
            Address address = toAddr(value);
            println("CANDIDATE " + address);
            disassemble(address);
            Function f = getFunctionAt(address);
            if (f == null) f = createFunction(address, "candidate_" + Long.toHexString(value));
            if (f == null) { println("Cannot create candidate function"); continue; }
            DecompileResults result = d.decompileFunction(f, 45, monitor);
            println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : "INCOMPLETE: " + result.getErrorMessage());
        }
        d.dispose();
    }
}
