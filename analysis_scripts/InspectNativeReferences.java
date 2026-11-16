// Read-only references and instruction windows for selected native addresses.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;

public class InspectNativeReferences extends GhidraScript {
    public void run() throws Exception {
        for (String value : getScriptArgs()) {
            var address = toAddr(Long.decode(value));
            var function = getFunctionContaining(address);
            println("NATIVE_TARGET " + address + " function=" + (function == null ? "none" : function.getEntryPoint()));
            for (var reference : getReferencesTo(address)) {
                var from = reference.getFromAddress();
                var owner = getFunctionContaining(from);
                println("NATIVE_REF " + from + " type=" + reference.getReferenceType() +
                    " owner=" + (owner == null ? "none" : owner.getEntryPoint()));
            }
            var instruction = getInstructionAt(address);
            for (int i = 0; instruction != null && i < 8; ++i) {
                println("NATIVE_INSTR " + instruction.getAddress() + " " + instruction);
                instruction = instruction.getNext();
            }
        }
    }
}
