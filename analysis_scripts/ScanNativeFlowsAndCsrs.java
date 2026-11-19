// Read-only scan: instruction flows into target addresses and CSR/trap instructions.
// Arguments: hex flow targets. Reports flow sources (jal/j/branch/call), every
// csr access (with CSR number), and every mret/uret/sret/wfi instruction.
// Ghidra reference metadata can be incomplete without analysis; results are
// candidates to be confirmed against raw control flow.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.util.HashSet;
import java.util.Set;

public class ScanNativeFlowsAndCsrs extends GhidraScript {
    public void run() throws Exception {
        Set<Address> targets = new HashSet<>();
        for (String value : getScriptArgs()) {
            targets.add(toAddr(Long.decode(value)));
        }
        var it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            var in = it.next();
            for (Address flow : in.getFlows()) {
                if (targets.contains(flow)) {
                    var owner = getFunctionContaining(in.getAddress());
                    println("FLOW_REF " + in.getAddress() + " -> " + flow + " owner=" +
                        (owner == null ? "none" : owner.getEntryPoint()) + " " + in);
                }
            }
            String m = in.getMnemonicString();
            if (m.startsWith("csr") || m.equals("mret") || m.equals("uret") || m.equals("sret") ||
                m.equals("wfi") || m.equals("ecall") || m.equals("ebreak")) {
                var owner = getFunctionContaining(in.getAddress());
                println("CSR_SITE " + in.getAddress() + " owner=" +
                    (owner == null ? "none" : owner.getEntryPoint()) + " " + in);
            }
        }
    }
}
