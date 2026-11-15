// Metadata correction for the observed OTA boot reset helper. Keep this
// distinct from the logger, which does return. No firmware bytes are patched.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
public class SeedBootFlow extends GhidraScript {
    public void run() throws Exception {
        if ((currentProgram.getMemory().getShort(toAddr(0x80c007d8L)) & 0xffff) != 0xa001)
            throw new IllegalStateException("Expected reset-helper terminal self-loop is absent");
        var entry = toAddr(0x80c007b0L);
        disassemble(entry);
        var function = getFunctionAt(entry);
        if (function == null) function = createFunction(entry, "candidate_reset_no_return");
        if (function == null) throw new IllegalStateException("Cannot create reset helper");
        function.setNoReturn(true);
        var logger = getFunctionAt(toAddr(0x80c1cd7aL));
        if (logger != null) logger.setNoReturn(false);
        println("Verified terminal C.J self-loop; reset helper marked non-returning");
    }
}
