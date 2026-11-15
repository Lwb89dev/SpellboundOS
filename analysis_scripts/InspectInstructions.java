// Print selected decoded instructions and p-code to a private headless log.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
public class InspectInstructions extends GhidraScript {
    public void run() throws Exception {
        for (String value : getScriptArgs()) {
            var address = toAddr(Long.decode(value));
            disassemble(address);
            var instruction = getInstructionAt(address);
            if (instruction == null) throw new IllegalStateException("No instruction at " + value);
            println(address + " " + instruction);
            for (var operation : instruction.getPcode()) println("  " + operation);
        }
    }
}
