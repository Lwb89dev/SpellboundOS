// Disassembles address ranges in memory (read-only project, nothing is saved) and
// prints a linear listing. Arguments: <start> <end> [<start> <end> ...] in hex.
// Use to inspect code regions that analysis has not disassembled.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;

public class DisassembleNativeRange extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        for (int i = 0; i + 1 < args.length; i += 2) {
            long start = Long.decode(args[i]);
            long end = Long.decode(args[i + 1]);
            println("RANGE " + args[i] + " " + args[i + 1]);
            long cursor = start;
            while (cursor < end) {
                var address = toAddr(cursor);
                var instruction = getInstructionAt(address);
                if (instruction == null) {
                    disassemble(address);
                    instruction = getInstructionAt(address);
                }
                if (instruction == null) {
                    println(String.format("DIS %08x <undecoded %02x%02x>", cursor,
                        getByte(address.add(1)) & 0xff, getByte(address) & 0xff));
                    cursor += 2;
                    continue;
                }
                println(String.format("DIS %08x %s", cursor, instruction));
                cursor += instruction.getLength();
            }
        }
    }
}
