//@category SpellboundOS
import ghidra.app.script.GhidraScript;
public class SeedEntry extends GhidraScript {
    public void run() throws Exception {
        var entry = toAddr(Long.decode(getScriptArgs()[0]));
        disassemble(entry);
        createFunction(entry, "candidate_image_entry");
    }
}
