// Read-only scan for instruction-level and pointer-word references to addresses.
// Resolves lui/auipc/li/addi/mv constant chains linearly (reset at function entry
// and unconditional control flow) and reports loads, stores and address
// materializations whose effective address falls inside [target, target+size).
// Also reports aligned memory words equal to a target (function pointers/tables).
// Arguments: pairs "<hex address>:<size>" or plain "<hex address>" (size 4).
// Results are candidates: confirm control flow and register lifetimes manually.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import java.util.HashMap;
import java.util.Map;

public class ScanNativeDataReferences extends GhidraScript {
    private static long scalar(Instruction in, int op) {
        for (Object o : in.getOpObjects(op)) {
            if (o instanceof Scalar) {
                return ((Scalar) o).getSignedValue();
            }
        }
        return Long.MIN_VALUE;
    }

    private static Register reg(Instruction in, int op) {
        for (Object o : in.getOpObjects(op)) {
            if (o instanceof Register) {
                return (Register) o;
            }
        }
        return null;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        long[] base = new long[args.length];
        long[] size = new long[args.length];
        for (int i = 0; i < args.length; ++i) {
            String[] parts = args[i].split(":");
            base[i] = Long.decode(parts[0]);
            size[i] = parts.length > 1 ? Long.decode(parts[1]) : 4;
        }
        Map<Register, Long> known = new HashMap<>();
        var it = currentProgram.getListing().getInstructions(true);
        Address previousEnd = null;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction in = it.next();
            if (previousEnd == null || !previousEnd.equals(in.getAddress())) {
                known.clear();
            }
            previousEnd = in.getMaxAddress().add(1);
            String m = in.getMnemonicString();
            Long effective = null;
            String kind = null;
            Register dst = in.getNumOperands() > 0 ? reg(in, 0) : null;
            switch (m) {
                case "auipc":
                case "c.auipc": {
                    long imm = scalar(in, 1);
                    if (dst != null && imm != Long.MIN_VALUE) {
                        long v = (in.getAddress().getOffset() + (imm << 12)) & 0xffffffffL;
                        known.put(dst, v);
                        effective = v;
                        kind = "auipc";
                    }
                    break;
                }
                case "lui":
                case "c.lui": {
                    long imm = scalar(in, 1);
                    if (dst != null && imm != Long.MIN_VALUE) {
                        long v = (imm << 12) & 0xffffffffL;
                        known.put(dst, v);
                        effective = v;
                        kind = "lui";
                    }
                    break;
                }
                case "li":
                case "c.li": {
                    long imm = scalar(in, 1);
                    if (dst != null && imm != Long.MIN_VALUE) {
                        known.put(dst, imm & 0xffffffffL);
                    }
                    break;
                }
                case "mv":
                case "c.mv": {
                    Register src = in.getNumOperands() > 1 ? reg(in, 1) : null;
                    if (dst != null && src != null && known.containsKey(src)) {
                        known.put(dst, known.get(src));
                    } else if (dst != null) {
                        known.remove(dst);
                    }
                    break;
                }
                case "addi":
                case "c.addi": {
                    Register src = in.getNumOperands() > 2 ? reg(in, 1) : dst;
                    long imm = scalar(in, in.getNumOperands() - 1);
                    if (dst != null && src != null && known.containsKey(src) && imm != Long.MIN_VALUE) {
                        long v = (known.get(src) + imm) & 0xffffffffL;
                        known.put(dst, v);
                        effective = v;
                        kind = "addi";
                    } else if (dst != null) {
                        known.remove(dst);
                    }
                    break;
                }
                case "lw": case "lh": case "lhu": case "lb": case "lbu":
                case "sw": case "sh": case "sb":
                case "c.lw": case "c.sw": case "c.lwsp": case "c.swsp": {
                    boolean store = m.startsWith("s") || m.startsWith("c.sw");
                    Register b = null;
                    long off = 0;
                    for (int op = 1; op < in.getNumOperands(); ++op) {
                        for (Object o : in.getOpObjects(op)) {
                            if (o instanceof Register) {
                                b = (Register) o;
                            } else if (o instanceof Scalar) {
                                off = ((Scalar) o).getSignedValue();
                            }
                        }
                    }
                    if (b != null && known.containsKey(b)) {
                        effective = (known.get(b) + off) & 0xffffffffL;
                        kind = store ? "store" : "load";
                    }
                    if (!store && dst != null) {
                        known.remove(dst);
                    }
                    break;
                }
                default:
                    if (dst != null && in.getFlowType().isFallthrough() && !m.startsWith("s")
                        && !m.startsWith("c.s") && !m.startsWith("b") && !m.startsWith("c.b")) {
                        known.remove(dst);
                    }
                    break;
            }
            var flow = in.getFlowType();
            if (flow.isTerminal() || flow.isCall() || (flow.isJump() && !flow.isConditional())) {
                known.clear();
            }
            if (effective != null) {
                for (int i = 0; i < base.length; ++i) {
                    if (effective >= base[i] && effective < base[i] + size[i]) {
                        var owner = getFunctionContaining(in.getAddress());
                        println(String.format("SCAN_REF target=0x%x at=%s kind=%s eff=0x%x owner=%s %s",
                            base[i], in.getAddress(), kind, effective,
                            owner == null ? "none" : owner.getEntryPoint().toString(), in));
                    }
                }
            }
        }
        // Pointer words in initialized memory.
        for (var block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }
            Address a = block.getStart();
            Address end = block.getEnd().subtract(3);
            while (a.compareTo(end) <= 0 && !monitor.isCancelled()) {
                long w = getInt(a) & 0xffffffffL;
                for (int i = 0; i < base.length; ++i) {
                    if (w >= base[i] && w < base[i] + size[i] && (a.getOffset() & 3) == 0) {
                        println(String.format("SCAN_WORD target=0x%x word_at=%s value=0x%x block=%s",
                            base[i], a, w, block.getName()));
                    }
                }
                a = a.add(4);
            }
        }
    }
}
