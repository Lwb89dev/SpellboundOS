// Generic bounded native-scope runner (program-agnostic): executes original bodies over
// authored state with typed stubs (return/store/capture/memcpy/memset/spi/bus/fcvt_wu_s),
// records calls, captured bytes and non-quiet RAM writes, and compares them with the
// independent model's expected actions. Project opened read-only; nothing is saved.
//@category SpellboundOS
import com.google.gson.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.memstate.MemoryState;
import ghidra.app.emulator.Emulator;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

public class ValidateNativeScope extends GhidraScript {
    static final long END = 0x70000000L;
    static final int MAX_BOUND = 50000;
    private int bound;
    static final String[] X = {"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1",
        "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
        "t3", "t4", "t5", "t6"};
    static final String[] F = {"ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0",
        "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8",
        "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11"};

    private JsonObject c;
    private JsonArray actions;
    private int steps;
    private Helper e;
    private Io io;
    private java.util.Map<Long, Integer> storeCount;
    private AddressSpace csr;

    private class Helper extends EmulatorHelper {
        private Emulator core;
        Helper(Program p) { super(p); }
        @Override protected Emulator newEmulator() { core = super.newEmulator(); return core; }
        void filter(MemoryAccessFilter f) { core.addMemoryAccessFilter(f); }
    }

    private static long value(byte[] b, int n) {
        long v = 0;
        for (int i = 0; i < n; i++) v |= (b[i] & 255L) << (8 * i);
        return v;
    }

    private boolean inRanges(JsonArray ranges, long p) {
        for (JsonElement r : ranges) {
            long lo = r.getAsJsonArray().get(0).getAsLong(), hi = r.getAsJsonArray().get(1).getAsLong();
            if (p >= lo && p < hi) return true;
        }
        return false;
    }

    private class Io extends MemoryAccessFilter {
        boolean active;
        Map<Long, Integer> used = new HashMap<>();
        @Override protected void processRead(AddressSpace space, long offset, int size, byte[] data) {
            if (!active || !space.getName().equals("ram")) return;
            JsonObject supplied = c.getAsJsonObject("supplied");
            String key = Long.toString(offset);
            if (!supplied.has(key)) return;
            JsonArray seq = supplied.getAsJsonArray(key);
            int n = used.getOrDefault(offset, 0);
            if (size != 4 || n >= seq.size()) throw new IllegalStateException("Supplied read bound " + key);
            long v = seq.get(n).getAsLong();
            used.put(offset, n + 1);
            for (int i = 0; i < 4; i++) data[i] = (byte) (v >>> (8 * i));
            actions.add("r:" + offset + ":" + size + ":" + v);
        }
        @Override protected void processWrite(AddressSpace space, long offset, int size, byte[] data) {
            if (!active || !space.getName().equals("ram")) return;
            if (inRanges(c.getAsJsonArray("quiet"), offset)) return;
            actions.add("w:" + offset + ":" + size + ":" + value(data, size));
        }
    }

    private long reg(String name) { return e.readRegister(name).longValue() & 0xffffffffL; }
    private long csrValue(long num) {
        byte[] b = e.readMemory(csr.getAddress(num * 4), 4);
        return value(b, 4);
    }

    private Instruction instruction(long pc) throws Exception {
        var at = toAddr(pc);
        Instruction in = getInstructionAt(at);
        if (in == null) {
            disassemble(at);
            in = getInstructionAt(at);
        }
        if (in == null) throw new IllegalStateException("Undecodable pc " + Long.toHexString(pc));
        return in;
    }

    private TreeSet<Long> csrsOf(Instruction in) {
        TreeSet<Long> out = new TreeSet<>();
        for (PcodeOp op : in.getPcode()) {
            List<Varnode> nodes = new ArrayList<>(Arrays.asList(op.getInputs()));
            if (op.getOutput() != null) nodes.add(op.getOutput());
            for (Varnode v : nodes) {
                if (v.getAddress().getAddressSpace().getName().equals("csreg")) out.add(v.getOffset() / 4);
            }
        }
        return out;
    }

    private JsonObject stub(long pc) {
        JsonObject stubs = c.getAsJsonObject("stubs");
        String key = Long.toString(pc);
        return stubs.has(key) ? stubs.getAsJsonObject(key) : null;
    }

    private String stop(long pc) {
        JsonObject stops = c.getAsJsonObject("stops");
        String key = Long.toString(pc);
        return stops.has(key) ? stops.get(key).getAsString() : null;
    }

    // Applies a supplied callee; returns a stop label or null to continue at ra.
    private String applyStub(long pc, JsonObject s) throws Exception {
        String kind = s.get("kind").getAsString();
        if (kind.equals("fcvt_wu_s")) {
            // Repair: Ghidra 12.1.2 RV32 SLEIGH computes fcvt.wu.s into a temporary and never writes rd.
            // Apply the RISC-V semantics (round toward zero, saturating) and step over the 4-byte instruction.
            float f = Float.intBitsToFloat((int) (e.readRegister(s.get("fs").getAsString()).longValue() & 0xffffffffL));
            long v;
            if (Float.isNaN(f) || f >= 4294967296.0f) v = 0xffffffffL;
            else if (f <= -1.0f) v = 0;
            else v = (long) f & 0xffffffffL;
            e.writeRegister(s.get("rd").getAsString(), v);
            actions.add("fix:" + pc + ":" + v);
            e.writeRegister(e.getPCRegister(), pc + 4);
            return null;
        }
        if (kind.equals("bus")) {
            // Bus transfer helper(a0 handle, a1 address, buf, len, a4): a write records up to 16 bytes of buf,
            // a read fills buf with scripted bytes; each call consumes one {status, rx?} entry.
            long buf = reg("a" + s.get("buf_arg").getAsInt()), len = reg("a" + s.get("len_arg").getAsInt());
            if (len < 0 || len > 0x1000) throw new IllegalStateException("bus length");
            boolean write = s.get("write").getAsBoolean();
            String tx = write ? HexFormat.of().formatHex(e.readMemory(toAddr(buf), (int) Math.min(len, 16))) : "";
            if (s.has("cmd_arg")) {
                // A read can also carry a command buffer: record it in place of the (empty) write bytes.
                long cmd = reg("a" + s.get("cmd_arg").getAsInt()), clen = reg("a" + s.get("cmd_len_arg").getAsInt());
                if (clen < 0 || clen > 16) throw new IllegalStateException("bus command length");
                tx = HexFormat.of().formatHex(e.readMemory(toAddr(cmd), (int) clen));
            }
            if (s.has("rec")) {
                StringBuilder r = new StringBuilder("bus:" + pc);
                for (JsonElement i : s.getAsJsonArray("rec")) r.append(":").append(reg("a" + i.getAsInt()));
                actions.add(r.append(":").append(tx).toString());
            } else {
                actions.add("bus:" + pc + ":" + reg("a0") + ":" + reg("a1") + ":" + len + ":" + reg("a4") + ":" + tx);
            }
            JsonArray seq = s.getAsJsonArray("seq");
            int n = storeCount.getOrDefault(pc, 0);
            if (n >= seq.size()) throw new IllegalStateException("bus sequence bound");
            storeCount.put(pc, n + 1);
            JsonObject t = seq.get(n).getAsJsonObject();
            if (t.has("rx")) {
                byte[] r = HexFormat.of().parseHex(t.get("rx").getAsString());
                if (r.length != len) throw new IllegalStateException("bus rx length");
                e.writeMemory(toAddr(buf), r);
            }
            e.writeRegister("a0", t.get("status").getAsLong());
            e.writeRegister(e.getPCRegister(), reg("ra"));
            return null;
        }
        if (kind.equals("spi")) {
            // helper(handle, tx, rx, len, timeout): capture tx[0..len), fill rx, return status.
            long tx = reg("a1"), rx = reg("a2"), len = reg("a3");
            if (len < 1 || len > 0x1000) throw new IllegalStateException("spi length");
            // Records at most the first 16 transmitted bytes (all of them for register transfers).
            actions.add("spi:" + reg("a0") + ":" + len + ":" + reg("a4") + ":"
                + HexFormat.of().formatHex(e.readMemory(toAddr(tx), (int) Math.min(len, 16))));
            JsonArray seq = s.getAsJsonArray("seq");
            int n = storeCount.getOrDefault(pc, 0);
            if (n >= seq.size()) throw new IllegalStateException("spi sequence bound");
            storeCount.put(pc, n + 1);
            JsonObject t = seq.get(n).getAsJsonObject();
            byte[] r = HexFormat.of().parseHex(t.get("rx").getAsString());
            if (r.length != len) throw new IllegalStateException("spi rx length");
            e.writeMemory(toAddr(rx), r);
            e.writeRegister("a0", t.get("status").getAsLong());
            e.writeRegister(e.getPCRegister(), reg("ra"));
            return null;
        }
        StringBuilder call = new StringBuilder("call:" + pc);
        int count = s.has("args") ? s.get("args").getAsInt() : 0;
        for (int i = 0; i < count; i++) call.append(":").append(reg("a" + i));
        actions.add(call.toString());
        switch (kind) {
            case "return":
                if (s.has("seq")) {
                    JsonArray seq = s.getAsJsonArray("seq");
                    int n = storeCount.getOrDefault(pc, 0);
                    if (n >= seq.size()) throw new IllegalStateException("return sequence bound");
                    storeCount.put(pc, n + 1);
                    e.writeRegister("a0", seq.get(n).getAsLong());
                } else if (s.has("value")) e.writeRegister("a0", s.get("value").getAsLong());
                if (s.has("value_a1")) e.writeRegister("a1", s.get("value_a1").getAsLong());
                break;
            case "switch":
                if (s.has("current")) e.writeMemoryValue(toAddr(s.get("current_address").getAsLong()), 4,
                    s.get("current").getAsLong());
                break;
            case "memcpy": {
                long dst = reg("a0"), src = reg("a1"), n = reg("a2");
                if (n > 0x1000) throw new IllegalStateException("memcpy bound");
                e.writeMemory(toAddr(dst), e.readMemory(toAddr(src), (int) n));
                break;
            }
            case "memset": {
                long dst = reg("a0"), v = reg("a1"), n = reg("a2");
                if (n > 0x1000) throw new IllegalStateException("memset bound");
                byte[] b = new byte[(int) n];
                Arrays.fill(b, (byte) v);
                e.writeMemory(toAddr(dst), b);
                break;
            }
            case "store": {
                long out = reg("a" + s.get("out_arg").getAsInt());
                int size = s.has("size") ? s.get("size").getAsInt() : 1;
                long v;
                if (s.has("seq")) {
                    JsonArray seq = s.getAsJsonArray("seq");
                    int n = storeCount.getOrDefault(pc, 0);
                    if (n >= seq.size()) throw new IllegalStateException("Store seq bound");
                    v = seq.get(n).getAsLong();
                    byte[] fb = new byte[size];
                    for (int i = 0; i < size; i++) fb[i] = (byte) (v >>> (8 * i));
                    e.writeMemory(toAddr(out), fb);
                    long ret = 0;
                    if (s.has("ret_seq")) {
                        JsonArray rs = s.getAsJsonArray("ret_seq");
                        if (n < rs.size()) ret = rs.get(n).getAsLong();
                    } else if (s.has("value_ret")) ret = s.get("value_ret").getAsLong();
                    storeCount.put(pc, n + 1);
                    e.writeRegister("a0", ret);
                    break;
                }
                if (s.has("seqs")) {
                    long idx = reg("a" + s.get("index_arg").getAsInt());
                    JsonArray seq = s.getAsJsonObject("seqs").getAsJsonArray(Long.toString(idx));
                    int n = storeCount.getOrDefault(idx, 0);
                    if (n >= seq.size()) throw new IllegalStateException("Store sequence bound");
                    v = seq.get(n).getAsLong();
                    storeCount.put(idx, n + 1);
                } else {
                    v = s.get("value").getAsLong();
                }
                byte[] b = new byte[size];
                for (int i = 0; i < size; i++) b[i] = (byte) (v >>> (8 * i));
                e.writeMemory(toAddr(out), b);
                e.writeRegister("a0", s.has("value_ret") ? s.get("value_ret").getAsLong() : 0);
                break;
            }
            case "capture": {
                // Records size bytes at a pointer argument, then returns value.
                long ptr = reg("a" + s.get("ptr_arg").getAsInt());
                int size = s.get("size").getAsInt();
                if (size < 1 || size > 64) throw new IllegalStateException("capture bound");
                actions.add("cap:" + HexFormat.of().formatHex(e.readMemory(toAddr(ptr), size)));
                if (s.has("value")) e.writeRegister("a0", s.get("value").getAsLong());
                break;
            }
            case "stop":
                return s.get("label").getAsString();
            default:
                throw new IllegalStateException("Unknown stub kind " + kind);
        }
        e.writeRegister(e.getPCRegister(), reg("ra"));
        return null;
    }

    private String run(long entry) throws Exception {
        e.writeRegister(e.getPCRegister(), entry);
        JsonArray allowed = c.getAsJsonArray("ranges");
        JsonArray csrAllowed = c.getAsJsonArray("csr_allowed");
        while (true) {
            long pc = e.getExecutionAddress().getOffset();
            if (pc == END) return null;
            String label = stop(pc);
            if (label != null) return label;
            JsonObject s = stub(pc);
            if (s != null) {
                String stopped = applyStub(pc, s);
                if (stopped != null) return stopped;
                continue;
            }
            if (!inRanges(allowed, pc)) throw new IllegalStateException("Unreviewed pc " + Long.toHexString(pc));
            if (++steps > bound) throw new IllegalStateException("Instruction bound");
            Instruction in = instruction(pc);
            TreeSet<Long> touched = csrsOf(in);
            TreeMap<Long, Long> before = new TreeMap<>();
            for (long n : touched) {
                boolean ok = false;
                for (JsonElement a : csrAllowed) ok |= a.getAsLong() == n;
                if (!ok) throw new IllegalStateException("Unexpected CSR " + Long.toHexString(n));
                before.put(n, csrValue(n));
            }
            boolean ok;
            io.active = true;
            try { ok = e.step(monitor); } finally { io.active = false; }
            if (!ok) throw new IllegalStateException(e.getLastError());
            for (long n : touched) actions.add("csr:" + n + ":" + before.get(n) + ":" + csrValue(n));
        }
    }

    private JsonObject snapshot() {
        JsonObject out = new JsonObject();
        for (JsonElement item : c.getAsJsonArray("snapshot")) {
            long at = item.getAsJsonArray().get(0).getAsLong();
            int n = item.getAsJsonArray().get(1).getAsInt();
            out.addProperty(Long.toString(at), HexFormat.of().formatHex(e.readMemory(toAddr(at), n)));
        }
        return out;
    }

    private JsonObject execute(JsonObject input) throws Exception {
        c = input;
        steps = 0;
        actions = new JsonArray();
        e = new Helper(currentProgram);
        io = new Io();
        storeCount = new HashMap<>();
        csr = currentProgram.getAddressFactory().getAddressSpace("csreg");
        try {
            for (JsonElement item : c.getAsJsonArray("memory")) {
                JsonArray m = item.getAsJsonArray();
                e.writeMemory(toAddr(m.get(0).getAsLong()), HexFormat.of().parseHex(m.get(1).getAsString()));
            }
            for (var entry : c.getAsJsonObject("csrs").entrySet())
                e.writeMemoryValue(csr.getAddress(Long.parseLong(entry.getKey()) * 4), 4, entry.getValue().getAsLong());
            for (var entry : c.getAsJsonObject("registers").entrySet())
                e.writeRegister(entry.getKey(), entry.getValue().getAsLong());
            for (var entry : c.getAsJsonObject("fregisters").entrySet())
                e.writeRegister(entry.getKey(), new BigInteger(entry.getValue().getAsString(), 16));
            e.filter(io);
            JsonArray rows = new JsonArray();
            for (JsonElement item : c.getAsJsonArray("operations")) {
                JsonObject op = item.getAsJsonObject();
                if (op.get("call").getAsBoolean()) {
                    e.writeRegister("ra", END);
                    JsonArray args = op.getAsJsonArray("args");
                    for (int i = 0; i < args.size(); i++) e.writeRegister("a" + i, args.get(i).getAsLong());
                }
                actions.add("op:" + op.get("name").getAsString());
                String stopped = run(op.get("entry").getAsLong());
                JsonObject row = new JsonObject();
                row.add("stopped", stopped == null ? JsonNull.INSTANCE : new JsonPrimitive(stopped));
                JsonObject csrs = new JsonObject();
                for (JsonElement a : c.getAsJsonArray("csr_allowed")) csrs.addProperty(a.getAsString(), csrValue(a.getAsLong()));
                row.add("csrs", csrs);
                if (stopped == null && op.get("result").getAsBoolean()) {
                    row.addProperty("a0", reg("a0"));
                    if (op.get("result_high").getAsBoolean()) row.addProperty("a1", reg("a1"));
                }
                if (op.get("registers").getAsBoolean() && "mret".equals(stopped)) {
                    JsonObject regs = new JsonObject();
                    for (int i = 1; i < 32; i++) regs.addProperty(X[i], reg(X[i]));
                    JsonObject fregs = new JsonObject();
                    for (String f : F) fregs.addProperty(f, String.format("%016x", e.readRegister(f)));
                    row.add("registers", regs);
                    row.add("fregisters", fregs);
                }
                row.add("snapshot", snapshot());
                rows.add(row);
                if (stopped != null) break;
            }
            JsonObject observed = new JsonObject();
            observed.add("actions", actions);
            observed.add("rows", rows);
            if (!observed.equals(c.getAsJsonObject("expected"))) {
                Files.writeString(Path.of("firmware/native-scope-mismatch.json"), observed.toString());
                throw new IllegalStateException("Mismatch " + c.get("name").getAsString());
            }
            JsonObject result = new JsonObject();
            result.addProperty("name", c.get("name").getAsString());
            result.addProperty("steps", steps);
            result.add("observed", observed);
            return result;
        } finally {
            e.dispose();
        }
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("vectors report");
        JsonObject vectors = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        bound = vectors.get("bound_per_case").getAsInt();
        if (vectors.get("schema").getAsInt() != 1 || bound < 1 || bound > MAX_BOUND
            || vectors.getAsJsonArray("cases").size() > 128) throw new IllegalArgumentException("Vector bound");
        for (JsonElement item : vectors.getAsJsonArray("guards")) {
            JsonObject g = item.getAsJsonObject();
            byte[] b = new byte[g.get("size").getAsInt()];
            currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()), b);
            String h = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
            if (!h.equals(g.get("sha256").getAsString()))
                throw new IllegalStateException("Unrecognized body " + g.get("address").getAsLong());
        }
        JsonArray cases = new JsonArray();
        for (JsonElement item : vectors.getAsJsonArray("cases")) {
            try {
                cases.add(execute(item.getAsJsonObject()));
            } catch (IllegalStateException ex) {
                Files.writeString(Path.of("firmware/native-scope-mismatch.json"), actions == null ? "{}"
                    : "{\"case\":\"" + item.getAsJsonObject().get("name").getAsString() + "\",\"actions\":" + actions + "}");
                throw new IllegalStateException(ex.getMessage() + " in " + item.getAsJsonObject().get("name").getAsString(), ex);
            }
        }
        JsonObject report = new JsonObject();
        report.addProperty("schema", 1);
        report.addProperty("hardware_execution", false);
        report.addProperty("bound_per_case", bound);
        report.addProperty("case_count", cases.size());
        report.add("cases", cases);
        Files.writeString(Path.of(args[1]), new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(report) + "\n");
        println("NATIVE_SCOPE_VALIDATION cases=" + cases.size());
    }
}
