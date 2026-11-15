// Ghidra pre-script. Mapping is a hypothesis based on the HDRZ header.
//@category SpellboundFit
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SeedBoot extends GhidraScript {
    public void run() throws Exception {
        Address entry = toAddr(0x80c0022cL);
        println("Hypothetical entry: " + entry);
        disassemble(entry);
        createFunction(entry, "candidate_boot_entry");
    }
}
