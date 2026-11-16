// Execute packet reference, fanout and cache queue code with synthetic inputs.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateSensorDelivery extends GhidraScript {
    private static final long END=0x70000000L,CB_END=0x70000010L,P0=0x81020000L,P1=0x81030000L,
        QUEUE=0x81050000L,NODE=0x81051000L,OUT=0x81052000L,TASK=0x81070000L;
    private JsonObject c;private String kind;private JsonArray actions;private int steps;
    private final List<Long> leases=new ArrayList<>();
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void guard(long a,int n,String expected)throws Exception {byte[] b=new byte[n];currentProgram.getMemory().getBytes(toAddr(a),b);
        if(!hash(b).equals(expected))throw new IllegalStateException("Unrecognized code "+Long.toHexString(a));}
    private long reg(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long a,int n,long v){e.writeMemoryValue(toAddr(a),n,v);}
    private long read(EmulatorHelper e,long a,int n){long v=0;byte[] b=e.readMemory(toAddr(a),n);for(int i=0;i<n;++i)v|=(b[i]&255L)<<(8*i);return v;}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private boolean range(long pc,long start,long end){return pc>=start&&pc<end;}
    private String label(long p){if(p==P0)return "p0";if(p==P1)return "p1";throw new IllegalStateException("Unknown packet");}
    private long status(EmulatorHelper e){byte[] b=e.readMemory(currentProgram.getAddressFactory().getAddressSpace("csreg").getAddress(0x300*4),4);
        long v=0;for(int i=0;i<4;++i)v|=(b[i]&255L)<<(8*i);return v;}
    private JsonObject summary(EmulatorHelper e,long p)throws Exception {JsonObject o=new JsonObject();o.addProperty("refs",read(e,p+16,4));
        o.addProperty("descriptor",read(e,p+20,4));o.addProperty("sha256",hash(e.readMemory(toAddr(p),68)));return o;}
    private void packet(EmulatorHelper e,long p,long refs,int sensor,int privateType,int frames){
        e.writeMemory(toAddr(p),new byte[68]);put(e,p,2,1);put(e,p+2,2,4);put(e,p+4,2,sensor);put(e,p+6,2,privateType);
        put(e,p+8,4,0x8000);put(e,p+16,4,refs);put(e,p+20,4,p+24);put(e,p+24,4,0x8000);
        put(e,p+32,8,0x12345678abcdef01L);put(e,p+44,2,frames);put(e,p+46,2,10);put(e,p+48,2,20);
        put(e,p+56,4,p+64);put(e,p+64,4,0x12345678);
    }
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");
        for(int i=0;i<12;++i)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("ABI mismatch");}
    private void runEntry(EmulatorHelper e,long entry,long a0,long a1,long a2,long a3)throws Exception {
        e.writeRegister("ra",END);e.writeRegister("a0",a0);e.writeRegister("a1",a1);e.writeRegister("a2",a2);e.writeRegister("a3",a3);
        e.writeRegister(e.getPCRegister(),entry);long callbackReturn=0;
        while(e.getExecutionAddress().getOffset()!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");long pc=e.getExecutionAddress().getOffset();
            if(pc==CB_END){e.writeRegister("ra",callbackReturn);e.writeRegister(e.getPCRegister(),callbackReturn);continue;}
            if(pc==0x80f64622L&&reg(e,0)!=0)actions.add("retain:"+label(reg(e,0)));
            if(pc==0x80f6462cL&&reg(e,0)!=0)actions.add("release:"+label(reg(e,0)));
            if(pc==0x80f7f5e4L){ret(e,kind.equals("refs")?c.get("context").getAsInt():1);continue;}
            if(pc==0x80f809a0L||pc==0x80f809b2L||pc==0x80f80974L){ret(e,kind.equals("fanout")&&c.get("thread").getAsBoolean()?0:1);continue;}
            if(pc==0x80f84d24L){
                if(reg(e,0)==4){long p=reg(e,2);if(reg(e,1)!=0x80fd4868L||read(e,p+20,4)!=0)throw new IllegalStateException("Packet free contract");actions.add("free:"+label(p));}
                else if(reg(e,0)==0x26&&reg(e,1)==0x80fe5124L&&reg(e,2)==NODE)actions.add("free:node");
                else throw new IllegalStateException("Unexpected free");ret(e,0);continue;
            }
            if(kind.equals("fanout")){
                if(pc==0x80f648dcL){actions.add("read");ret(e,c.get("source").getAsBoolean()?P0:0);continue;}
                if(pc==0x80f63d74L){actions.add("sync");ret(e,0);continue;}
                if(pc==0x80f66326L){if(reg(e,0)!=P0)throw new IllegalStateException("Fusion input");actions.add("fusion");ret(e,c.get("fusion").getAsString().equals("none")?0:P1);continue;}
                if(pc==0x80f65a0eL){actions.add("cache:"+label(reg(e,0)));ret(e,0);continue;}
                if(range(pc,0x70001000L,0x70001100L)){
                    int index=(int)((pc-0x70001000L)/4);long p=reg(e,0);actions.add("callback:"+index+":"+label(p));
                    if(c.getAsJsonArray("listeners").get(index).getAsJsonArray().get(1).getAsBoolean()){
                        leases.add(p);callbackReturn=e.readRegister("ra").longValue();e.writeRegister("ra",CB_END);e.writeRegister(e.getPCRegister(),0x80f64622L);
                    }else ret(e,0xdeadbeefL);continue;
                }
            }
            if(pc==0x80f802deL||pc==0x80f80382L){
                String prefix=kind.equals("fanout")?"listener_":"queue_";
                if(reg(e,0)!=(kind.equals("fanout")?0x4444:0x3333))throw new IllegalStateException("Unexpected lock");
                if(pc==0x80f802deL&&reg(e,1)!=0xffffffffL)throw new IllegalStateException("Lock timeout");
                actions.add(prefix+(pc==0x80f802deL?"lock":"unlock"));ret(e,0);continue;
            }
            if(kind.equals("cache")){
                if(pc==0x80f84cbeL){if(reg(e,0)!=0x26||reg(e,1)!=0x80fe5124L||reg(e,2)!=24)throw new IllegalStateException("Queue allocation");
                    actions.add("queue_alloc");ret(e,c.get("allocated").getAsBoolean()?NODE:0);continue;}
                if(pc==0x80fcddf0L){int n=(int)reg(e,2);if(n!=8)throw new IllegalStateException("Unexpected copy size");
                    e.writeMemory(toAddr(reg(e,0)),e.readMemory(toAddr(reg(e,1)),n));ret(e,reg(e,0));continue;}
                if(pc==0x80f84a8cL){ret(e,c.get("free_memory").getAsLong());continue;}
                if(pc==0x80f65920L){actions.add("cache_flush");ret(e,0);continue;}
                if(pc==0x80f86d34L){long fmt=reg(e,3);
                    if(fmt==0x80fd51c0L)actions.add("cache_failure_log");else if(fmt==0x80fd51e0L)actions.add("pressure_log");
                    else if(fmt==0x80fe51f0L)actions.add("queue_short_log");else throw new IllegalStateException("Unexpected log "+Long.toHexString(fmt));
                    ret(e,0);continue;
                }
            }
            boolean common=range(pc,0x80f64622L,0x80f64660L)||range(pc,0x80f85cbeL,0x80f85ce8L)||range(pc,0x80f85d14L,0x80f85d42L)
                ||range(pc,0x80f80aa2L,0x80f80ae6L)||range(pc,0x80f82fb8L,0x80f83026L)||range(pc,0x80fd2c3eL,0x80fd2c58L);
            boolean allowed=common||(kind.equals("fanout")&&(range(pc,0x80f649beL,0x80f64a18L)||range(pc,0x80f635faL,0x80f6374eL)
                ||range(pc,0x80f637dcL,0x80f63886L)||range(pc,0x80f63f7aL,0x80f63fb6L)))
                ||(kind.equals("cache")&&(range(pc,0x80f65a0eL,0x80f65c6eL)||range(pc,0x80f655f8L,0x80f65602L)
                ||range(pc,0x80fa6028L,0x80fa60e4L)||range(pc,0x80fa60e4L,0x80fa61caL)));
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(e.getLastError());
        }
        abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;kind=c.get("kind").getAsString();actions=new JsonArray();steps=0;leases.clear();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);
            e.writeRegister("sp",0x81001000L);for(int i=0;i<12;++i)e.writeRegister("s"+i,0x45670000L+i);
            put(e,0x80f16f78L,1,0);put(e,0x80f1719cL,4,kind.equals("refs")&&!c.get("started").getAsBoolean()?0:1);
            put(e,0x80f171bcL,4,TASK);put(e,TASK+0x50,4,kind.equals("refs")?c.get("depth").getAsLong():0);
            e.writeMemoryValue(currentProgram.getAddressFactory().getAddressSpace("csreg").getAddress(0x300*4),4,kind.equals("refs")?c.get("mstatus").getAsLong():0x1888);
            int sensor=kind.equals("fanout")?c.get("sensor").getAsInt():6,privateType=kind.equals("fanout")?c.get("private").getAsInt():0;
            packet(e,P0,kind.equals("refs")?c.get("refs").getAsLong():1,sensor,privateType,1);
            packet(e,P1,1,sensor,privateType,kind.equals("fanout")&&c.get("fusion").getAsString().equals("empty")?0:1);
            JsonObject observed=new JsonObject();
            if(kind.equals("refs")){
                JsonArray rows=new JsonArray();for(JsonElement op:c.getAsJsonArray("operations")){
                    runEntry(e,op.getAsString().equals("retain")?0x80f64622L:0x80f6462cL,c.get("null").getAsBoolean()?0:P0,0,0,0);
                    JsonObject row=new JsonObject();row.addProperty("refs",read(e,P0+16,4));row.addProperty("descriptor",read(e,P0+20,4));
                    row.addProperty("depth",read(e,TASK+0x50,4));row.addProperty("mstatus",status(e));rows.add(row);
                }
                observed.add("operations",rows);observed.add("packet",summary(e,P0));observed.addProperty("depth",read(e,TASK+0x50,4));observed.addProperty("mstatus",status(e));
            }else if(kind.equals("fanout")){
                put(e,0x80f16f9cL,4,0x4444);JsonArray listeners=c.getAsJsonArray("listeners");
                for(long head:new long[]{0x80f4faf8L,0x80f4fb00L}){
                    long base=head==0x80f4faf8L?0x81060000L:0x81061000L;
                    put(e,head,4,listeners.size()==0?head:base);put(e,head+4,4,listeners.size()==0?head:base+16L*(listeners.size()-1));
                    for(int i=0;i<listeners.size();++i){long node=base+16L*i;
                        put(e,node,4,i==listeners.size()-1?head:node+16);put(e,node+4,4,i==0?head:node-16);
                        put(e,node+8,4,listeners.get(i).getAsJsonArray().get(0).getAsLong());put(e,node+12,4,0x70001000L+4L*i);
                    }
                }
                runEntry(e,0x80f649beL,0,0,0,0);for(long p:leases)runEntry(e,0x80f6462cL,p,0,0,0);
                JsonArray packets=new JsonArray();packets.add(summary(e,P0));packets.add(summary(e,P1));observed.add("packets",packets);
            }else if(kind.equals("cache")){
                put(e,0x80f16fccL,4,c.get("enabled").getAsBoolean()?QUEUE:0);
                put(e,0x80f16fd0L,4,c.get("selected").getAsBoolean()?0xffffffffL:0);put(e,0x80f16fd4L,4,0);
                put(e,0x80f16fd8L,4,c.get("cached").getAsLong());put(e,QUEUE,4,QUEUE);put(e,QUEUE+4,4,QUEUE);
                put(e,QUEUE+8,4,0x3333);put(e,QUEUE+12,4,c.get("magic").getAsBoolean()?0x5a6a7a8aL:0);put(e,QUEUE+16,4,0);
                byte[] node=new byte[24];Arrays.fill(node,(byte)0xa5);e.writeMemory(toAddr(NODE),node);
                byte[] out=new byte[8];Arrays.fill(out,(byte)0xa5);e.writeMemory(toAddr(OUT),out);
                runEntry(e,0x80f65a0eL,P0,0,0,0);runEntry(e,0x80f6462cL,P0,0,0,0);JsonElement getResult=JsonNull.INSTANCE;
                String drain=c.get("drain").getAsString();
                if(read(e,QUEUE+16,4)!=0&&!drain.equals("none")){
                    runEntry(e,0x80fa60e4L,QUEUE,OUT,drain.equals("short")?4:8,0);getResult=new JsonPrimitive(reg(e,0));
                    if(drain.equals("take"))runEntry(e,0x80f655f8L,OUT,0,0,0);
                }
                observed.add("packet",summary(e,P0));observed.addProperty("cached",read(e,0x80f16fd8L,4));observed.add("get_result",getResult);
                JsonObject queue=new JsonObject();queue.addProperty("head",read(e,QUEUE,4));queue.addProperty("tail",read(e,QUEUE+4,4));queue.addProperty("count",read(e,QUEUE+16,4));
                observed.add("queue",queue);observed.addProperty("node_sha256",hash(e.readMemory(toAddr(NODE),24)));observed.addProperty("output_hex",HexFormat.of().formatHex(e.readMemory(toAddr(OUT),8)));
            }else throw new IllegalArgumentException("Unknown case kind");
            observed.add("actions",actions);
            if(!observed.equals(c.getAsJsonObject("expected")))throw new IllegalStateException(c.get("name")+" observed="+observed+" expected="+c.get("expected"));
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");
        guard(0x80f64622L,0x3e,"b9835d6c053d9c13fbe4e599a8e9bbf43f61a2d4e96b672598489376025cfcb5");
        guard(0x80f85cbeL,0x2a,"c17387081f2ddfbc269895b568de6df4dee772448e84fbb9e1b923df2337a197");
        guard(0x80f85d14L,0x2e,"2f433e93934eec35d30cac5be783e0b278a010b2984a22c4717d3955a5c5f63b");
        guard(0x80f80aa2L,0x44,"a370c614222b8f603d0ca1c5a042b4ed57635edb383f3227a43ced901ad62bd1");
        guard(0x80f82fb8L,0x6e,"ac27f44a8de79360f5f586734856fc47dcdd5fd307401e0a14fbd2cc508fbc6e");
        guard(0x80fd2c3eL,0x1a,"f207acf3996babc0dcd3fa1eac67c084a1ecf94216a884b882550ec4f7a31e3c");
        guard(0x80f649beL,0x5a,"cdd1ce8f1d199f9bc130d363a6fd1064e667fcb36dece997659bbc6f2d561e46");
        guard(0x80f635faL,0x154,"9148f2d51b4966e145dcdf3a815eaa0c891d00bc690b53d03a178df68088617c");
        guard(0x80f637dcL,0xaa,"38c4bd7a2b8f291c872169ddf141f0fe97987feeb2b1c9b4e1cf5bb9c7bf3456");
        guard(0x80f63f7aL,0x1c,"f465b2ed549c8b455f1b667c6ba3ff927addd9240ed2c980764418cef6874a24");
        guard(0x80f63f96L,0x20,"c4487f623ef4bf52f2fb6a355d57af7a16b8a7ef630119fc7aad4f690cfc1319");
        guard(0x80f655f8L,0xa,"72b217c0812ec91bbfa9340dc31ea5fe08e293da994a782cb86f2788a0e25b20");
        guard(0x80f65a0eL,0x260,"85f1aa71f12e06d0626f434f8c8153a043ec3cffb84695e26a518b184a834783");
        guard(0x80fa6028L,0xbc,"dbb2171320e7c641e2e7b99f09a4de840a781d0452e6caeb1f3d2aa4f488bcb1");
        guard(0x80fa60e4L,0xe6,"d3ebf9ae2d77dc4363e0fdd98edb515cfcc10c5910e04388128e9c5f25275ca9");
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>512)throw new IllegalArgumentException("Unsupported vectors");
        JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("case_count",rows.size());report.addProperty("hardware_execution",false);
        report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");
        println("SENSOR_DELIVERY_VALIDATION cases="+rows.size());
    }
}
