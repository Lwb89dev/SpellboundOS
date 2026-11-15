// Export inferred functions locally with explicit decompiler status and coverage.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.io.*;
public class ExportFunctions extends GhidraScript {
    public void run() throws Exception {
        Path output = Paths.get(getScriptArgs()[0]);
        Files.createDirectories(output);
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        try (PrintWriter index = new PrintWriter(Files.newBufferedWriter(output.resolve("functions.tsv")))) {
            index.println("address\tname\tstatus\tbytes");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function f = functions.next();
                DecompileResults result = d.decompileFunction(f, 10, monitor);
                String status = result.decompileCompleted() ? "completed" : "incomplete";
                index.println(f.getEntryPoint() + "\t" + f.getName() + "\t" + status + "\t" + f.getBody().getNumAddresses());
                index.flush();
                if (result.decompileCompleted()) Files.writeString(output.resolve(f.getEntryPoint().toString().replace(':','_') + ".c"), result.getDecompiledFunction().getC());
                else Files.writeString(output.resolve(f.getEntryPoint().toString().replace(':','_') + ".error.txt"), result.getErrorMessage());
            }
        } finally { d.dispose(); }
    }
}
