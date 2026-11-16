// Native sensor flush routing and packet allocation/rebinding, with synthetic I/O.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateSensorPackets extends GhidraScript {
    private static final long END=0x70000000L,HEAP=0x81020000L,MOVED=0x81200000L,TICK=0x12345678abcdef01L;
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void guard(long a,int n,String expected)throws Exception {
        byte[] b=new byte[n];currentProgram.getMemory().getBytes(toAddr(a),b);
        if(!hash(b).equals(expected))throw new IllegalStateException("Unrecognized code "+Long.toHexString(a));
    }
    private long reg(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long a,int n,long v){e.writeMemoryValue(toAddr(a),n,v);}
    private long read(EmulatorHelper e,long a,int n){long v=0;byte[] b=e.readMemory(toAddr(a),n);
        for(int i=0;i<n;++i)v|=(b[i]&255L)<<(8*i);return v;}
    private void ret(EmulatorHelper e,long value){e.writeRegister("a0",value&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void enter(EmulatorHelper e,long a,long a0,long a1){
        e.writeRegister("ra",END);e.writeRegister("a0",a0);e.writeRegister("a1",a1);e.writeRegister(e.getPCRegister(),a);
    }
    private boolean range(long pc,long start,long end){return pc>=start&&pc<end;}
    private JsonObject optical(EmulatorHelper e){JsonObject o=new JsonObject();
        String[] names={"count","write","read","frame","last_tick"};long[] addresses={0x80f1705cL,0x80f1705eL,0x80f17060L,0x80f17062L,0x80f17050L};
        for(int i=0;i<names.length;++i)o.addProperty(names[i],read(e,addresses[i],i==4?4:2));return o;
    }
    private JsonObject execute(JsonObject c)throws Exception {
        String kind=c.get("kind").getAsString(),name=c.get("name").getAsString();boolean flush=kind.equals("flush");
        boolean consumer=kind.equals("consumer");
        if(!flush&&!consumer&&!kind.equals("packet"))throw new IllegalArgumentException("Unknown kind");
        EmulatorHelper e=new EmulatorHelper(currentProgram);JsonArray actions=new JsonArray();int steps=0,heapSize=0;boolean rebound=false;
        JsonElement heapHash=JsonNull.INSTANCE,movedHash=JsonNull.INSTANCE;long returned=0;
        try {
            e.writeRegister("sp",0x81001000L);for(int i=0;i<12;++i)e.writeRegister("s"+i,0x45670000L+i);
            if(flush){
                byte[] window=new byte[512];Arrays.fill(window,(byte)0xa5);e.writeMemory(toAddr(0x80f4fb20L),window);
                put(e,0x80f4fd1cL,4,c.get("flags").getAsLong());int sensor=c.get("sensor").getAsInt();
                for(int identifier=1;identifier<=257;++identifier){
                    if(identifier>35&&identifier!=257)continue;
                    long record=0x81010000L+64L*identifier;
                    put(e,0x80f4f9d8L+8L*identifier,4,identifier==sensor&&!c.get("present").getAsBoolean()?0:record);
                    put(e,record+32,4,identifier==sensor&&!c.get("callback").getAsBoolean()?0:
                        identifier==6?0x80f763beL:0x70001000L+4L*identifier);
                }
                put(e,0x80f17091L,1,c.get("enabled").getAsBoolean()?1:0);put(e,0x80f16b30L,1,3);
                put(e,0x80f1705cL,2,4);put(e,0x80f1705eL,2,7);put(e,0x80f17060L,2,3);
                put(e,0x80f17062L,2,4);put(e,0x80f17050L,4,10);
                enter(e,0x80f64238L,sensor,129);e.writeRegister("a2",0);e.writeRegister("a3",0);
            }else if(consumer){
                put(e,0x80f17091L,1,c.get("enabled").getAsBoolean()?1:0);put(e,0x80f17094L,4,4660);
                put(e,0x80f1706eL,1,1);put(e,0x80f17065L,1,0);put(e,0x80f1706dL,1,2);
                put(e,0x80f17062L,2,2);put(e,0x80f17070L,2,1);put(e,0x80f17086L,1,c.get("secondary").getAsInt());
                put(e,0x80f1707cL,2,c.get("rate").getAsInt());put(e,0x80f17048L,4,c.get("dac").getAsLong());
                put(e,0x80f17059L,1,0);put(e,0x80f17066L,2,7);put(e,0x80f17068L,4,5);
                JsonArray words=c.getAsJsonArray("words");int index=c.get("read").getAsInt();
                put(e,0x80f1705cL,2,words.size());put(e,0x80f17060L,2,index);
                for(int i=0;i<1000;++i)put(e,0x80f5073cL+4L*i,4,0xdeadbeefL);
                for(int i=0;i<words.size();++i)put(e,0x80f5073cL+4L*((index+i)%1000),4,words.get(i).getAsLong());
                enter(e,0x80f747c0L,0,0);
            }else enter(e,0x80f6453eL,c.get("count").getAsLong(),c.get("stride").getAsLong());
            while(true){
                long pc=e.getExecutionAddress().getOffset();
                if(pc==END){
                    if(!flush&&!rebound&&heapSize>0){
                        returned=reg(e,0);heapHash=new JsonPrimitive(hash(e.readMemory(toAddr(HEAP),heapSize)));
                        if(!consumer&&c.get("rebind").getAsBoolean()){
                            e.writeMemory(toAddr(MOVED),e.readMemory(toAddr(HEAP),heapSize));
                            // Rebinding also resets the reference field, so seed a non-one value.
                            put(e,MOVED+16,4,7);rebound=true;enter(e,0x80f645e2L,MOVED,0);continue;
                        }
                    }else if(rebound)movedHash=new JsonPrimitive(hash(e.readMemory(toAddr(MOVED),heapSize)));
                    else returned=reg(e,0);
                    break;
                }
                if(++steps>100000)throw new IllegalStateException(name+" execution bound");
                if(pc==0x80f86d34L){if(!flush){
                    if(consumer&&reg(e,3)==0x80fd8f98L)actions.add("clamp_log");
                    else if(consumer&&reg(e,3)==0x80fd8d80L)actions.add("sample_tag_log");
                    else if(reg(e,3)==0x80fd4b4cL)actions.add("allocation_log");
                    else throw new IllegalStateException("Unexpected log "+Long.toHexString(reg(e,3)));
                }ret(e,0);continue;}
                if(pc==0x80f63302L){long tick=consumer?c.get("tick").getAsLong():TICK;
                    actions.add("clock");e.writeRegister("a1",tick>>>32);ret(e,tick);continue;}
                if(consumer&&pc==0x80f73014L){actions.add("lock:"+reg(e,0));ret(e,c.get("locked").getAsBoolean()?1:0);continue;}
                if(consumer&&pc==0x80f80382L){actions.add("unlock:"+reg(e,0));ret(e,0);continue;}
                if(flush&&range(pc,0x70001000L,0x70002000L)){
                    actions.add("callback:"+((pc-0x70001000L)/4)+":"+reg(e,0)+":"+reg(e,1)+":"+reg(e,2));ret(e,0xdeadbeefL);continue;
                }
                if(flush&&pc==0x80f763beL)actions.add("callback:6:"+reg(e,0)+":"+reg(e,1)+":"+reg(e,2));
                if(flush&&pc==0x80f7304cL){long r=reg(e,0);if(r!=9&&r!=13)throw new IllegalStateException("Unexpected read");
                    actions.add("read:"+r);put(e,reg(e,1),1,r==9?5:16);ret(e,0);continue;}
                if(flush&&pc==0x80f73152L){actions.add("write:"+reg(e,0)+":"+(reg(e,1)&255));ret(e,0);continue;}
                if(!flush&&pc==0x80f84ceeL){
                    if(reg(e,0)!=4||reg(e,1)!=0x80fd4868L||reg(e,3)!=4)throw new IllegalStateException("Unexpected allocation arguments");
                    long size=reg(e,2);actions.add("alloc:4:"+size+":4");
                    if(c.get("allocated").getAsBoolean()){
                        if(size>262144)throw new IllegalArgumentException("Host heap bound");
                        heapSize=(int)size;byte[] bytes=new byte[heapSize];Arrays.fill(bytes,(byte)0xa5);e.writeMemory(toAddr(HEAP),bytes);ret(e,HEAP);
                    }else ret(e,0);continue;
                }
                if(!flush&&pc==0x80fcdfccL){
                    if(reg(e,0)!=HEAP||reg(e,1)!=0||reg(e,2)!=heapSize)throw new IllegalStateException("Unexpected memset");
                    actions.add("zero:"+heapSize);e.writeMemory(toAddr(HEAP),new byte[heapSize]);ret(e,HEAP);continue;
                }
                boolean allowed=flush?(range(pc,0x80f632dcL,0x80f63300L)||range(pc,0x80f64216L,0x80f6453eL)
                    ||range(pc,0x80f65cd6L,0x80f65cfaL)||range(pc,0x80f65e2eL,0x80f65fd0L)||range(pc,0x80f66298L,0x80f66326L)
                    ||range(pc,0x80f763beL,0x80f76448L)||range(pc,0x80f7667aL,0x80f766b2L)
                    ||range(pc,0x80f72e86L,0x80f72ea4L)||range(pc,0x80f738beL,0x80f73948L)):
                    (range(pc,0x80f6453eL,0x80f64622L)||(consumer&&(range(pc,0x80f747c0L,0x80f75bf6L)||range(pc,0x80f72ea4L,0x80f72f60L))));
                if(!allowed)throw new IllegalStateException(name+" escaped at "+Long.toHexString(pc));
                if(!e.step(monitor))throw new IllegalStateException(name+": "+e.getLastError());
            }
            if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");
            for(int i=0;i<12;++i)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("ABI mismatch");
            JsonObject observed=new JsonObject();observed.addProperty("returned",returned);observed.add("actions",actions);
            if(flush){observed.addProperty("fusion_sha256",hash(e.readMemory(toAddr(0x80f4fb20L),512)));observed.add("optical",optical(e));}
            else if(consumer){
                JsonObject state=new JsonObject();state.addProperty("count",read(e,0x80f1705cL,2));state.addProperty("read",read(e,0x80f17060L,2));
                state.addProperty("auxiliary",read(e,0x80f17066L,2));state.addProperty("counter",read(e,0x80f17068L,4));
                observed.add("state",state);observed.add("heap_sha256",heapHash);observed.addProperty("ring_sha256",hash(e.readMemory(toAddr(0x80f5073cL),4000)));
            }else {observed.add("heap_sha256",heapHash);observed.add("relocated_sha256",movedHash);}
            if(!observed.equals(c.getAsJsonObject("expected"))){
                if(flush)Files.write(Path.of("firmware/sensor-packets-mismatch.bin"),e.readMemory(toAddr(0x80f4fb20L),512));
                else if(heapSize>0)Files.write(Path.of("firmware/sensor-packets-mismatch.bin"),e.readMemory(toAddr(HEAP),heapSize));
                throw new IllegalStateException(name+" observed="+observed+" expected="+c.get("expected"));
            }
            JsonObject row=new JsonObject();row.addProperty("name",name);row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");
        guard(0x80f632dcL,0x24,"24186f291aae90c382d3d88780f720e91323505d458dc4cf35891da9d5a0e0ff");
        guard(0x80f64216L,0x328,"c176f482cbc962cb4a446da9500ea67c1021c0bd10fb27f61eea3deb9427ae6f");
        guard(0x80f65cd6L,0x24,"484be53f9a1d7db49c1e0bb8db58ae008b6c1d463dbd81aff5a7b07497f9168a");
        guard(0x80f65e2eL,0x1a2,"b79af3ac1462c1ac20d4e3f888b1e62d113de1df34b725962c0b792804575de2");
        guard(0x80f66298L,0x8e,"ff9a78b9e3cc032235751dfe2f82530cf7ad4a6559b002d43c2a445ed2b0aeeb");
        guard(0x80f763beL,0x8fc,"a6d6664143e84c5aeb3093660cb86a1e31c53ffaa3ecb0461be8f658d1c19349");
        guard(0x80f6453eL,0xe4,"bae54c31f544b2e9aa8d932c271b85a6f47af177280eab66c468ef875e15ad67");
        guard(0x80f72e86L,0xda,"144bac09340c6d9c88e175034a4682fe5449533b230c1955b12217f45adf5527");
        guard(0x80f738beL,0x8a,"e3e1c41c50337b45eb3d850844d360b6b8851414629def94e105e1c9b8b382fa");
        guard(0x80f73906L,0x42,"8f26515b505908687b371057304fc30b3bd463e70fba0f7ee47622480e5c379d");
        guard(0x80f747c0L,0x1436,"fe225471740c916d1cc8e2bf7460bf668bedd07fdfff4c53ce094f46bf3e8cbb");
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>1024)throw new IllegalArgumentException("Unsupported vector set");
        JsonArray rows=new JsonArray();for(JsonElement c:input.getAsJsonArray("cases"))rows.add(execute(c.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("case_count",rows.size());report.addProperty("hardware_execution",false);
        report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");
        println("SENSOR_PACKETS_VALIDATION cases="+rows.size());
    }
}
