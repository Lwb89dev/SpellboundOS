// Host execution of guarded public SPI transfers and completion paths.
// Mutex, diagnostic, device-operation and user callbacks return synthetic values.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateSpiOwnership extends GhidraScript {
    private static final long D=0x81002000L,B=0x81003000L,S=0x81004000L,C=0x81005000L,
        O=0x81006000L,P=0x81007000L,TX=0x81008000L,RX=0x81009000L,END=0x70000000L;
    private final List<String> trace=new ArrayList<>();
    private int takeResult,opResult,releaseResult,mutexResult;
    private boolean full,dma;
    private int calls;
    private void equal(long observed,long expected,String message) {
        if(observed!=expected) throw new IllegalStateException(message+": "+Long.toHexString(observed));
    }
    private long reg(EmulatorHelper emu,int i) { return emu.readRegister("a"+i).longValue() & 0xffffffffL; }
    private void guard(long address,int size,String expected) throws Exception {
        byte[] bytes=new byte[size];currentProgram.getMemory().getBytes(toAddr(address),bytes);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(expected))
            throw new IllegalStateException("Unrecognized ownership bytes");
    }
    private void put(EmulatorHelper e,long address,long value) { e.writeMemoryValue(toAddr(address),4,value); }
    private long word(EmulatorHelper e,long address) {
        byte[] raw=e.readMemory(toAddr(address),4);long value=0;
        for(int i=0;i<4;++i)value|=(raw[i]&255L)<<(8*i);
        return value;
    }
    private void initialize(EmulatorHelper e,boolean ops,boolean callback,boolean cs) {
        e.writeMemory(toAddr(D),new byte[0x80]);e.writeMemory(toAddr(B),new byte[0x80]);
        e.writeMemory(toAddr(S),new byte[0x40]);e.writeMemory(toAddr(O),new byte[0x40]);
        put(e,D,B);put(e,D+4,cs?S:0);put(e,D+8,C);put(e,D+0x14,dma?1:0);
        put(e,D+0x5c,0x70000300L);put(e,D+0x60,0x12345678L);
        put(e,B,0x2468);put(e,B+0x24,ops?O:0);put(e,B+0x28,P);
        put(e,S+4,0x70000100L);put(e,S+8,0x70000110L);
        int offset=dma?(full?0x1c:0x14):(full?0x10:8);
        put(e,O+offset,callback?0x70000200L:0);
    }
    private boolean stub(EmulatorHelper e,long pc) {
        long result=0;
        if(pc==0x80f802deL) {
            equal(reg(e,0),0x2468,"mutex handle");equal(reg(e,1),0xffffffffL,"mutex wait");
            trace.add("mutex_take");result=mutexResult;
        } else if(pc==0x80f80382L) {
            equal(reg(e,0),0x2468,"mutex release handle");trace.add("mutex_release");
        } else if(pc==0x70000100L || pc==0x70000110L) {
            equal(reg(e,0),C,"CS private argument");trace.add(pc==0x70000100L?"select":"deselect");
            result=pc==0x70000100L?takeResult:releaseResult;
        } else if(pc==0x70000200L) {
            equal(reg(e,0),P,"bus private argument");equal(reg(e,1),TX,"TX buffer");
            if(full) {equal(reg(e,2),RX,"RX buffer");equal(reg(e,3),3,"length");equal(reg(e,4),1000,"timeout");}
            else {equal(reg(e,2),3,"length");equal(reg(e,3),1000,"timeout");}
            trace.add(dma?"dma_operation":"poll_operation");result=opResult;
        } else if(pc==0x70000300L) {
            equal(reg(e,0),0x55,"completion event");equal(reg(e,1),0x12345678L,"user callback argument");
            trace.add("user_callback");
        } else if(pc==0x80f80aa2L) {
            put(e,reg(e,0),8);trace.add("critical_enter");
        } else if(pc==0x80f80aceL) {
            equal(reg(e,0),8,"critical token");trace.add("critical_exit");
        } else if(pc==0x70000310L || pc==0x70000320L) {
            trace.add(pc==0x70000310L?"resource_enable":"resource_disable");
        } else if(pc!=0x80f86d34L) return false; // diagnostic logger only
        e.writeRegister("a0",result & 0xffffffffL);
        e.writeRegister(e.getPCRegister(),e.readRegister("ra"));
        return true;
    }
    private long run(EmulatorHelper e,long entry,long...args) throws Exception {
        e.writeRegister("sp",0x81001000L);e.writeRegister("ra",END);
        for(int i=0;i<12;++i)e.writeRegister("s"+i,0x51510000L+i);
        for(int i=0;i<args.length;++i)e.writeRegister("a"+i,args[i]);
        e.writeRegister(e.getPCRegister(),entry);
        int steps=0;
        while(e.getExecutionAddress().getOffset()!=END) {
            if(++steps>3000)throw new IllegalStateException("Ownership execution bound");
            long pc=e.getExecutionAddress().getOffset();
            if(stub(e,pc))continue;
            if(!((pc>=0x80f8965cL && pc<0x80f899aaL) || (pc>=0x80f7b2d4L && pc<0x80f7b36cL)
                    || (pc>=0x80f7b3e8L && pc<0x80f7b420L) || (pc>=0x80f7bdbcL && pc<0x80f7bdcaL)))
                throw new IllegalStateException("Escaped ownership path: "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(e.getLastError());
        }
        equal(e.readRegister("sp").longValue(),0x81001000L,"stack restoration");
        for(int i=0;i<12;++i)equal(e.readRegister("s"+i).longValue(),0x51510000L+i,"callee-saved register");
        ++calls;return reg(e,0);
    }
    private void caseOf(String name,boolean isFull,boolean isDma,int take,int operation,int release,int mutex,
                        boolean ops,boolean callback,boolean cs,long result,List<String> expected,int completionMode) throws Exception {
        full=isFull;dma=isDma;takeResult=take;opResult=operation;releaseResult=release;mutexResult=mutex;
        trace.clear();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try {
            initialize(e,ops,callback,cs);
            long actual=full?run(e,0x80f898aeL,D,TX,RX,3,1000):run(e,0x80f897bcL,D,TX,3,1000);
            equal(actual,result & 0xffffffffL,name+" result");
            if(!trace.equals(expected))throw new IllegalStateException(name+" trace: "+trace+" expected "+expected);
            if(completionMode>0) {
                trace.clear();if(completionMode==2)put(e,D+0x14,0);
                equal(run(e,0x80f89756L,0x55,D),0,"completion result");
                List<String> completion=completionMode==2?List.of("user_callback"):
                    List.of("deselect","mutex_release","user_callback");
                if(!trace.equals(completion))throw new IllegalStateException(name+" completion ordering: "+trace);
                if(completionMode==3) {
                    trace.clear();run(e,0x80f89756L,0x55,D);
                    if(!trace.equals(completion))throw new IllegalStateException("Repeated callback behavior differs");
                }
            }
        }finally{e.dispose();}
    }
    public void run() throws Exception {
        if(getScriptArgs().length!=1)throw new IllegalArgumentException("report-path");
        guard(0x80f8965cL,0x34e,"0c9fe44af7d6dbc29c0363ae54729d568f5e950bbaa3be40f93cc58545c6a91e");
        guard(0x80f7b2d4L,0x98,"64ec0cc26aa1a622b896eb5be81f0cff118bd2bc71073c657a8ef3314f2e54bf");
        guard(0x80f7b3e8L,0x38,"130bf3eaa32a50f8444fcb3e24854dbdd8ab64d186660c10d22bb9053e1b9642");
        guard(0x80f7bdbcL,0xe,"0c779278011a9524660c57136188feacc70bffd6f804bf047d7604bf686a5944");
        for(boolean f:new boolean[]{false,true}) {
            List<String> poll=List.of("mutex_take","select","poll_operation","deselect","mutex_release");
            List<String> failedTake=List.of("mutex_take","select","deselect","mutex_release");
            caseOf("poll_ok",f,false,0,0,0,0,true,true,true,0,poll,0);
            caseOf("poll_error",f,false,0,2,0,0,true,true,true,-14,poll,0);
            caseOf("select_error",f,false,2,0,0,0,true,true,true,-14,failedTake,0);
            caseOf("release_error_ignored",f,false,0,0,2,0,true,true,true,0,poll,0);
            caseOf("mutex_error_ignored",f,false,0,0,0,-2,true,true,true,0,poll,0);
            caseOf("no_bus_ops",f,false,0,0,0,0,false,true,true,0,List.of(),0);
            caseOf("no_operation",f,false,0,0,0,0,true,false,true,0,List.of(),0);
            caseOf("no_cs_ops",f,false,0,0,0,0,true,true,false,0,List.of("mutex_take","poll_operation","mutex_release"),0);
            caseOf("dma_pending",f,true,0,0,0,0,true,true,true,0,List.of("mutex_take","select","dma_operation"),1);
            caseOf("dma_error",f,true,0,2,0,0,true,true,true,-14,List.of("mutex_take","select","dma_operation","deselect","mutex_release"),0);
            caseOf("dma_missing_operation",f,true,0,0,0,0,true,false,true,0,List.of(),0);
            caseOf("dma_flag_changed",f,true,0,0,0,0,true,true,true,0,List.of("mutex_take","select","dma_operation"),2);
            caseOf("dma_repeat_callback",f,true,0,0,0,0,true,true,true,0,List.of("mutex_take","select","dma_operation"),3);
        }
        EmulatorHelper gpio=new EmulatorHelper(currentProgram);
        try {
            put(gpio,C,0x91003000L);put(gpio,C+4,0x200);put(gpio,0x91003010L,0xface);put(gpio,0x91003014L,0xbeef);
            equal(run(gpio,0x80f7b404L,C),0,"GPIO select result");
            equal(word(gpio,0x91003014L),0x200,"GPIO select mask");
            equal(word(gpio,0x91003010L),0xface,"GPIO other register unchanged");
            equal(run(gpio,0x80f7b3e8L,C),0,"GPIO release result");
            equal(word(gpio,0x91003010L),0x200,"GPIO release mask");
            equal(word(gpio,0x91003014L),0x200,"GPIO select register preserved");
        }finally{gpio.dispose();}
        int refs=0;
        for(int count:new int[]{0,1,2,65535})for(boolean enable:new boolean[]{false,true})for(boolean callback:new boolean[]{false,true}) {
            if(!callback && count!=0 && count!=1)continue;
            EmulatorHelper e=new EmulatorHelper(currentProgram);trace.clear();
            try {
                e.writeMemory(toAddr(B),new byte[0x80]);put(e,C+8,B);e.writeMemoryValue(toAddr(B+0x4c),2,count);
                put(e,B+0x50,callback?0x70000311L:0);put(e,B+0x54,callback?0x70000320L:0);
                equal(run(e,enable?0x80f7b328L:0x80f7b2d4L,C),0,"resource result");
                int updated=enable?(count+1)&65535:Math.max(0,count-1);
                byte[] raw=e.readMemory(toAddr(B+0x4c),2);equal((raw[0]&255)|((raw[1]&255)<<8),updated,"reference count");
                List<String> expected=new ArrayList<>(List.of("critical_enter","critical_exit"));
                if(callback && (enable?updated!=0:updated==0))expected.add(enable?"resource_enable":"resource_disable");
                if(!trace.equals(expected))throw new IllegalStateException("Reference callback condition differs: "+trace);
                ++refs;
            }finally{e.dispose();}
        }
        Files.writeString(Path.of(getScriptArgs()[0]),String.format("{\n  \"public_transfer_cases\":26,\n  \"completion_calls\":8,\n  \"chip_select_calls\":2,\n  \"reference_cases\":%d,\n  \"native_invocations\":%d,\n  \"mutex_and_operation_callbacks\":\"synthetic\",\n  \"hardware_execution\":false\n}\n",refs,calls));
        println("SPI_OWNERSHIP_VALIDATION native invocations="+calls);
    }
}
