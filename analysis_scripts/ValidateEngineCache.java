// Register native cache listeners and execute receive -> engine event -> HR policy.
// Allocation/copy/OS queue/critical sections and algorithm math are supplied.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateEngineCache extends GhidraScript {
    private static final String CONFIG="{\"recv\":1886518624,\"parser\":1886522048,\"handler\":1886519538,\"cleanup\":1886530200,\"init\":1882381114,\"remain\":1882381230,\"byte\":1882381478,\"word\":1882381580,\"pointer\":1882381738,\"valid\":1881033952,\"alloc\":1881034500,\"retain\":1881034620,\"release\":1881034662,\"fixup\":1881034736,\"reset\":1881029816,\"dispatch\":1881027342,\"bridge\":1886514580,\"initializer\":1886521828,\"malloc\":2161361700,\"free\":2161361754,\"copy\":1888779020,\"zero\":1888779496,\"increment\":2161366434,\"subtract\":2161366562,\"critical_enter\":2161342958,\"critical_exit\":2161343002,\"context\":2161342678,\"logger\":1881880738,\"table\":1895653388,\"callback\":1895653380,\"head\":1895377184,\"pool\":5,\"tag\":1889339884,\"logs\":{\"1892323784\":\"parse_cache\",\"1892322728\":\"receive_parse\",\"1889342112\":\"buffer_alloc\",\"1892322820\":\"receive_alloc\",\"1889339852\":\"reg_duplicate\",\"1889339900\":\"reg_alloc\",\"1889339936\":\"unreg_missing\",\"1891642048\":\"event_alloc\",\"1891643540\":\"algorithm_missing\",\"1891643596\":\"algorithm_error\",\"1889810000\":\"period_success\",\"1889809976\":\"manual_success\"},\"ranges\":[[1886518624,458],[1886522048,3296],[1886519538,116],[1886530200,140],[1882381114,682],[1881033952,38],[1881034500,326],[1881029816,64],[1881027342,166],[1886514580,8],[1884051570,32],[2161366434,174],[1881024728,422],[1881027086,256],[1881035696,94],[1884044946,814],[1884042048,8],[1884042614,168],[1884046310,30],[1884041724,28],[1884038462,32],[1882280180,56],[1882278820,1360],[1884048708,188],[1884048396,88],[1884051562,40]],\"reg\":1881027086,\"unreg\":1881027214,\"event_listener\":1884044968,\"event_handler\":1884045114,\"event_destructor\":1884042048,\"event_alloc\":1882210910,\"event_post\":1882212962,\"walk\":1881035696,\"gate\":1884045640,\"hr_packet\":1882280180,\"hr_descriptor\":1882278820,\"algorithm_dispatch\":1884048708,\"guards\":[{\"address\":1886518624,\"size\":458,\"sha256\":\"ae2e806a62dc907aa218cd0e04ba0c654f4bc8ce774c4234a3c0e3f7f17c0bf5\"},{\"address\":1886522048,\"size\":3296,\"sha256\":\"f736b76c64b922cff338b0b215da63f2023b06cc251f5c35f40245d747e5c484\"},{\"address\":1886519538,\"size\":116,\"sha256\":\"ddab4174fc63c4e9dfe9dbd95df4b3173a24a2e9138947219e187b0d9ab3e9c1\"},{\"address\":1886530200,\"size\":140,\"sha256\":\"20f9202e4c234f0822f0731226dc24a3b3b95eeefd4b696ff0fb832d2e45ca5f\"},{\"address\":1882381114,\"size\":682,\"sha256\":\"afb626ff23bd5ac1b68190b3bec7bdc9076aab241ad50cae86c48884de29fb94\"},{\"address\":1881033952,\"size\":38,\"sha256\":\"e1c2b796a0aac0d76d696e27a3bb9ca5b075406c280c06e195d6ef2e82645667\"},{\"address\":1881034500,\"size\":326,\"sha256\":\"23b661794a014a553bbc0df310c1584608c26cc65c67e2099f3273b3e7cad49c\"},{\"address\":1881029816,\"size\":64,\"sha256\":\"0b4826e32a27e6fc52163b9123c6d931a7e92a75647902905451c237a9b139f3\"},{\"address\":1881027342,\"size\":166,\"sha256\":\"61f89caa36338c3a2dfd70750b5d24b481e7f8ab61406517b06e92779503dd2c\"},{\"address\":1886514580,\"size\":8,\"sha256\":\"55740b83652ae2f67f6685cba1cfe74f12a71a707ee6381fa3c24e46a9cbb107\"},{\"address\":1884051570,\"size\":32,\"sha256\":\"8d3b44c965517c2f921eeae10513d040f513ee4ac0ee38e4716e0f09896366ab\"},{\"address\":2161366434,\"size\":174,\"sha256\":\"bbc939341f56ef45daa4e8e9e8b2a2217f1742e6c8a3331055560f7d9b56b941\"},{\"address\":1881024728,\"size\":422,\"sha256\":\"2c017358e0478f930388e2f8499ad28de254eb52cb22f6ad3728bbb5d4e5a2ab\"},{\"address\":1881027086,\"size\":256,\"sha256\":\"6c3e2d8a6ebfdf0ac79645c9cca0cad81e2aa6fb7752263b72847557ec8aae5d\"},{\"address\":1881035696,\"size\":94,\"sha256\":\"47658c2a8ae67c3bd5e1b660d232325691360220eb365274f87a60d5804998da\"},{\"address\":1884044946,\"size\":814,\"sha256\":\"c90329d4721160082863a61798573923b5c91e39c364dae82f35d77d64e8882a\"},{\"address\":1884042048,\"size\":8,\"sha256\":\"4067d7c96748803547585c1f46e214055c3e601ad7051988499a0a5a8f31d26a\"},{\"address\":1884042614,\"size\":168,\"sha256\":\"813bfefd56a5c194405dacac8d3f59e093bca59b770949a22de853d9c0628db7\"},{\"address\":1884046310,\"size\":30,\"sha256\":\"7c9a45dba6ec14eda8df272645544fb4cd187315eeb8398f5f9b5f56b5545eda\"},{\"address\":1884041724,\"size\":28,\"sha256\":\"771720a5ff886f62c9f513e9a40e35454728822a1b5a768cbedc9100dde935b6\"},{\"address\":1884038462,\"size\":32,\"sha256\":\"491dfb3f2ae1ded0c2808eb89ce2ab8de742b8a4e906f6d3b52fe90ed346df27\"},{\"address\":1882280180,\"size\":56,\"sha256\":\"a7ab4d1fe1bf35e807c698af59a41ca9c735b544e34148403968a288da167399\"},{\"address\":1882278820,\"size\":1360,\"sha256\":\"9a76d5e5854eef9e2eb811add30dc3468b3a6290b589a01dc3b27ee5ea91476b\"},{\"address\":1884048708,\"size\":188,\"sha256\":\"1a428d89d34ee9f9ab942ba74d30211ea72f0d2b2bbf8a19c1ade0e9a0105700\"},{\"address\":1884048396,\"size\":88,\"sha256\":\"83251693e2d82e791c87b592ff1c0b756ce6ab7ae45c90410b0fdd4bc42295d0\"},{\"address\":1884051562,\"size\":40,\"sha256\":\"69ab5e67dbd3bf4f4cd4d827dd54fc4ad871baf053543e5cc39d77e69d9f05f4\"}]}";
    private static final long END=0x70000000L,CB=0x70000100L,ENGINE_CB=0x70000200L,ALGORITHM=0x70000300L,
        NODES=0x81008000L,WIRE=0x81010000L,HEAP=0x81200000L,EVENT=0x81050000L,RECORDS=0x81400000L,HANDLES=0x81500000L,ALG=0x81600000L;
    private JsonObject cfg,c;private JsonArray actions,deliveries,calls;private int steps,heapSize,nodeAttempt;private boolean posted;
    private final List<Long> nodes=new ArrayList<>();
    private long a(String key){return cfg.get(key).getAsLong();}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void put(EmulatorHelper e,long at,int n,long value){e.writeMemoryValue(toAddr(at),n,value);}
    private long read(EmulatorHelper e,long at,int n){byte[] b=e.readMemory(toAddr(at),n);long v=0;for(int i=0;i<n;++i)v|=(b[i]&255L)<<(8*i);return v;}
    private long reg(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void ret(EmulatorHelper e,long value){e.writeRegister("a0",value&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private JsonObject snapshot(EmulatorHelper e)throws Exception {JsonObject o=new JsonObject();o.addProperty("refs",read(e,HEAP,4));o.addProperty("magic",read(e,HEAP+4,4));
        o.addProperty("sha256",hash(e.readMemory(toAddr(HEAP),heapSize)));o.addProperty("guard_sha256",hash(e.readMemory(toAddr(HEAP+heapSize),128)));return o;}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");
        for(int i=0;i<12;++i)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("ABI mismatch");}
    private JsonArray active(EmulatorHelper e){JsonArray out=new JsonArray();long node=read(e,a("head"),4),previous=a("head");int count=0;
        while(node!=a("head")){if(++count>8||read(e,node+4,4)!=previous||read(e,node+8,4)!=0)throw new IllegalStateException("Listener list invariant");out.add(read(e,node+12,4));previous=node;node=read(e,node,4);}
        if(read(e,a("head")+4,4)!=previous)throw new IllegalStateException("Listener tail invariant");return out;}
    private void delivery(EmulatorHelper e){long record=reg(e,0),packet=reg(e,1);int index=(int)((record-RECORDS)/0x100);int at=(int)(packet-HEAP);
        actions.add("engine:"+index+":"+at);JsonObject d=new JsonObject();d.addProperty("engine",index);d.addProperty("packet",packet);deliveries.add(d);}
    private void runEntry(EmulatorHelper e,long entry,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;++i)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),entry);
        while(e.getExecutionAddress().getOffset()!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");long pc=e.getExecutionAddress().getOffset();
            if(pc==a("context")){ret(e,1);continue;}
            if(pc==a("critical_enter")){put(e,reg(e,0),4,0);ret(e,0);continue;}
            if(pc==a("critical_exit")){ret(e,0);continue;}
            if(pc==a("malloc")){
                if(reg(e,0)!=5||reg(e,1)!=a("tag")||reg(e,3)!=4)throw new IllegalStateException("Allocation arguments");int size=(int)reg(e,2);
                if(size==16){boolean ok;
                    if(c.get("kind").getAsString().equals("registry")){JsonArray values=c.getAsJsonArray("allocations");ok=nodeAttempt>=values.size()||values.get(nodeAttempt).getAsBoolean();}
                    else ok=c.get("register_allocated").getAsBoolean();
                    long node=NODES+0x100L*nodeAttempt;actions.add((ok?"node_alloc:":"node_alloc_fail:")+nodeAttempt++);
                    if(ok){nodes.add(node);e.writeMemory(toAddr(node),new byte[16]);}ret(e,ok?node:0);
                }else{if(size<16||size>8192)throw new IllegalStateException("Heap bound");heapSize=size;actions.add("buffer_alloc:"+size);
                    byte[] bytes=new byte[size+128];Arrays.fill(bytes,(byte)0xa5);e.writeMemory(toAddr(HEAP),bytes);ret(e,HEAP);}
                continue;
            }
            if(pc==a("zero")){int n=(int)reg(e,2);if(n<0||n>8192||reg(e,1)!=0)throw new IllegalStateException("Memset bound");
                e.writeMemory(toAddr(reg(e,0)),new byte[n]);ret(e,reg(e,0));continue;}
            if(pc==a("copy")){int n=(int)reg(e,2);if(n<0||n>8192)throw new IllegalStateException("Copy bound");e.writeMemory(toAddr(reg(e,0)),e.readMemory(toAddr(reg(e,1)),n));ret(e,reg(e,0));continue;}
            if(pc==a("free")){if(reg(e,0)!=5||reg(e,1)!=a("tag"))throw new IllegalStateException("Free arguments");long at=reg(e,2);
                if(at==HEAP){if(read(e,HEAP,4)!=0||read(e,HEAP+4,4)!=0)throw new IllegalStateException("Buffer free before clear");actions.add("free:buffer");}
                else{if(!nodes.contains(at)||read(e,at,4)!=at||read(e,at+4,4)!=at)throw new IllegalStateException("Unlinked node free");actions.add("free:node"+((at-NODES)/0x100));}
                ret(e,0);continue;
            }
            if(pc==a("logger")){JsonElement message=cfg.getAsJsonObject("logs").get(Long.toString(reg(e,3)));
                if(message==null)throw new IllegalStateException("Unexpected log "+Long.toHexString(reg(e,3)));actions.add("log:"+message.getAsString());ret(e,0);continue;}
            if(pc>=CB&&pc<CB+8){actions.add("listener:"+((pc-CB)/4));ret(e,0);continue;}
            if(pc==a("event_alloc")){if(reg(e,0)!=a("event_destructor"))throw new IllegalStateException("Event destructor");boolean ok=c.get("event_allocated").getAsBoolean();
                actions.add(ok?"event_alloc":"event_alloc_fail");if(ok)e.writeMemory(toAddr(EVENT),new byte[20]);ret(e,ok?EVENT:0);continue;}
            if(pc==a("event_post")){if(reg(e,0)!=0x1234||reg(e,1)!=39||reg(e,2)!=EVENT||read(e,EVENT+4,4)!=6||read(e,EVENT+16,4)!=HEAP+8)
                    throw new IllegalStateException("Engine event post contract");actions.add("post:39");posted=true;ret(e,1);continue;}
            if(pc==a("gate"))actions.add("packet:"+(reg(e,0)-HEAP));
            if(pc==a("hr_packet"))delivery(e);
            if(pc>=ENGINE_CB&&pc<ENGINE_CB+4*40){delivery(e);ret(e,0xdeadbeefL);continue;}
            if(pc==ALGORITHM){long desc=reg(e,0),output=reg(e,2);if(read(e,output+2,2)!=0x100d)throw new IllegalStateException("Algorithm output tag");
                actions.add("algorithm:"+(desc-HEAP));JsonObject row=new JsonObject();row.addProperty("descriptor",desc);row.addProperty("type",read(e,desc,8));
                row.addProperty("payload",read(e,desc+32,4));row.addProperty("tag",read(e,output+2,2));calls.add(row);
                put(e,output,1,c.get("ready").getAsBoolean()?1:0);put(e,output+8,1,c.get("pulse").getAsInt());put(e,output+9,1,c.get("quality").getAsInt());
                ret(e,c.get("algorithm_error").getAsInt());continue;
            }
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(e.getLastError());
        }abi(e);
    }
    private void initializeHr(EmulatorHelper e){e.writeMemory(toAddr(0x70fa0680L),new byte[0xbc]);
        put(e,0x70fa06f5L,1,c.get("features").getAsInt());put(e,0x70fa06f4L,1,c.get("control").getAsInt());put(e,0x70fa06dcL,4,c.get("counter").getAsLong());
        put(e,0x70fa06e0L,4,c.get("limit").getAsLong());put(e,0x70fa06e4L,4,c.get("aggregate").getAsLong());put(e,0x70fa06e9L,1,255);put(e,0x70fa06ebL,1,255);}
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;actions=new JsonArray();deliveries=new JsonArray();calls=new JsonArray();steps=0;heapSize=0;nodeAttempt=0;posted=false;nodes.clear();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);
            for(int i=0;i<12;++i)e.writeRegister("s"+i,0x45670000L+i);put(e,a("head"),4,a("head"));put(e,a("head")+4,4,a("head"));initializeHr(e);
            JsonArray registry=new JsonArray(),nodeHashes=new JsonArray();JsonElement registration=JsonNull.INSTANCE,unregistration=JsonNull.INSTANCE,owner=JsonNull.INSTANCE,finalHeap=JsonNull.INSTANCE,
                receiverReturned=JsonNull.INSTANCE,eventReturned=JsonNull.INSTANCE;
            if(c.get("kind").getAsString().equals("registry")){
                for(JsonElement element:c.getAsJsonArray("operations")){String operation=element.getAsString();String[] op=operation.split(":");JsonElement returned=JsonNull.INSTANCE;
                    if(op[0].equals("dispatch"))runEntry(e,a("dispatch"),HEAP+8);
                    else{long callback=op[1].equals("null")?0:CB+(op[1].equals("b")?4:0);runEntry(e,op[0].equals("reg")?a("reg"):a("unreg"),callback);returned=new JsonPrimitive(reg(e,0));}
                    JsonObject row=new JsonObject();row.add("returned",returned);row.add("callbacks",active(e));registry.add(row);
                }
                for(long node:nodes)nodeHashes.add(hash(e.readMemory(toAddr(node),16)));
            }else{
                runEntry(e,a("reg"),a("event_listener"));registration=new JsonPrimitive(reg(e,0));active(e);
                e.writeMemory(toAddr(0x70fc1f1cL),new byte[40*4]);
                for(JsonElement element:c.getAsJsonArray("engines")){JsonObject card=element.getAsJsonObject();int id=card.get("index").getAsInt();if(id<0||id>39)throw new IllegalStateException("Engine index bound");
                    long record=RECORDS+0x100L*id,handle=HANDLES+0x100L*id;e.writeMemory(toAddr(record),new byte[0x80]);e.writeMemory(toAddr(handle),new byte[0x20]);
                    put(e,0x70fc1f1cL+4L*id,4,record);put(e,record+1,1,card.get("enabled").getAsInt());put(e,record+5,1,id);
                    long mask=card.get("mask").getAsLong();put(e,record+8,4,mask);put(e,record+12,4,mask>>>32);put(e,record+20,4,card.get("handle").getAsBoolean()?handle:0);
                    put(e,handle+12,1,card.get("state").getAsInt());put(e,handle+21,1,card.get("cache").getAsInt());put(e,record+44,4,card.get("callback").getAsBoolean()?(card.get("hr").getAsBoolean()?a("hr_packet"):ENGINE_CB+4L*id):0);
                }
                e.writeMemory(toAddr(ALG),new byte[0x28]);long mask=c.get("algorithm_mask").getAsLong();put(e,ALG+24,4,mask);put(e,ALG+28,4,mask>>>32);put(e,ALG+36,4,ALGORITHM);
                put(e,0x70fc2064L,4,c.get("algorithm_present").getAsBoolean()?ALG:0);put(e,0x70fc2068L,1,c.get("algorithm_active").getAsBoolean()?1:0);
                put(e,0x70fc1fe4L,4,0x1234);put(e,a("table")+21*4,4,a("handler"));put(e,a("callback"),4,a("bridge"));
                byte[] wire=HexFormat.of().parseHex(c.get("wire_hex").getAsString());e.writeMemory(toAddr(WIRE),wire);put(e,0x81002200L,1,165);
                runEntry(e,a("recv"),0x81004000L,WIRE,wire.length,0x81002200L);receiverReturned=new JsonPrimitive(reg(e,0));owner=snapshot(e);
                if(posted){runEntry(e,a("event_handler"),EVENT);eventReturned=new JsonPrimitive(reg(e,0));runEntry(e,a("event_destructor"),HEAP+8);}
                finalHeap=snapshot(e);if(!hash(wire).equals(hash(e.readMemory(toAddr(WIRE),wire.length))))throw new IllegalStateException("Input mutated");
                runEntry(e,a("unreg"),a("event_listener"));unregistration=new JsonPrimitive(reg(e,0));active(e);
            }
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("registry",registry);observed.add("node_sha256",nodeHashes);observed.add("registration",registration);observed.add("unregistration",unregistration);
            observed.add("owner_after",owner);observed.add("final_heap",finalHeap);observed.add("receiver_returned",receiverReturned);observed.add("event_returned",eventReturned);observed.add("deliveries",deliveries);observed.add("algorithm_calls",calls);
            observed.addProperty("hr_sha256",hash(e.readMemory(toAddr(0x70fa0680L),0xbc)));
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.write(Path.of("firmware/engine-cache-mismatch.bin"),e.readMemory(toAddr(0x70fa0680L),0xbc));
                throw new IllegalStateException(c.get("name")+" observed="+observed+" expected="+c.get("expected"));}
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement element:cfg.getAsJsonArray("guards")){JsonObject guard=element.getAsJsonObject();byte[] bytes=new byte[guard.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(guard.get("address").getAsLong()),bytes);
            if(!hash(bytes).equals(guard.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized engine cache code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");
        JsonArray rows=new JsonArray();for(JsonElement element:input.getAsJsonArray("cases"))rows.add(execute(element.getAsJsonObject()));JsonObject report=new JsonObject();
        report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("ENGINE_CACHE_VALIDATION cases="+rows.size());
    }
}
