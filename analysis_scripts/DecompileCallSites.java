// Read-only: decompiles the functions containing the given addresses and prints
// the decompiled lines mentioning any of the given callee tokens.
// Arguments: comma-separated callee tokens (e.g. "80d35c6c,80d35bcc"), then
// hex call-site addresses. A site outside any function is reported as such.
//@category SpellboundOS
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import java.util.HashSet;
import java.util.Set;

public class DecompileCallSites extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String[] tokens = args[0].split(",");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> done = new HashSet<>();
        for (int i = 1; i < args.length; ++i) {
            var site = toAddr(Long.decode(args[i]));
            var function = getFunctionContaining(site);
            if (function == null) {
                println("CALLSITE " + site + " function=none");
                continue;
            }
            String key = function.getEntryPoint().toString();
            if (!done.add(key)) {
                continue;
            }
            var result = decompiler.decompileFunction(function, 120, monitor);
            if (result == null || !result.decompileCompleted()) {
                println("CALLSITE " + site + " function=" + key + " decompile=failed");
                continue;
            }
            String c = result.getDecompiledFunction().getC();
            println("CALLSITE " + site + " function=" + key + " name=" + function.getName());
            for (String line : c.split("\n")) {
                for (String token : tokens) {
                    if (line.contains(token)) {
                        println("CALLLINE " + key + " " + line.trim());
                        break;
                    }
                }
            }
        }
        decompiler.dispose();
    }
}
