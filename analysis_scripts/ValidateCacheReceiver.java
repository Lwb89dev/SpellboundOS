// Execute both cores' decoder/parser/receive/consumer-dispatch/cleanup paths.
// Registers, input, listeners and allocator/OS boundaries are synthetic.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateCacheReceiver extends GhidraScript {
    private static final long END=0x70000000L,RESUME=0x70000010L,CB=0x70000100L,WIRE=0x81010000L,
        HEAP=0x81200000L,ARGS=0x81002000L,OUTPUT=0x81002100L,ACK=0x81002200L,DECODER=0x81003000L;
    private static final String MAIN_CONFIG="{\"recv\":1886518624,\"parser\":1886522048,\"handler\":1886519538,\"cleanup\":1886530200,\"init\":1882381114,\"remain\":1882381230,\"byte\":1882381478,\"word\":1882381580,\"pointer\":1882381738,\"valid\":1881033952,\"alloc\":1881034500,\"retain\":1881034620,\"release\":1881034662,\"fixup\":1881034736,\"reset\":1881029816,\"dispatch\":1881027342,\"bridge\":1886514580,\"initializer\":1886521828,\"malloc\":2161361700,\"free\":2161361754,\"copy\":1888779020,\"zero\":1888779496,\"increment\":2161366434,\"subtract\":2161366562,\"critical_enter\":2161342958,\"critical_exit\":2161343002,\"context\":2161342678,\"logger\":1881880738,\"table\":1895653388,\"callback\":1895653380,\"head\":1895377184,\"pool\":5,\"tag\":1889339884,\"logs\":{\"1892323784\":\"parse_cache\",\"1892322728\":\"receive_parse\",\"1889342112\":\"buffer_alloc\",\"1892322820\":\"receive_alloc\"},\"ranges\":[[1886518624,458],[1886522048,3296],[1886519538,116],[1886530200,140],[1882381114,682],[1881033952,38],[1881034500,326],[1881029816,64],[1881027342,166],[1886514580,8],[1884051570,32],[2161366434,174]],\"guards\":[{\"address\":1886518624,\"size\":458,\"sha256\":\"ae2e806a62dc907aa218cd0e04ba0c654f4bc8ce774c4234a3c0e3f7f17c0bf5\"},{\"address\":1886522048,\"size\":3296,\"sha256\":\"f736b76c64b922cff338b0b215da63f2023b06cc251f5c35f40245d747e5c484\"},{\"address\":1886519538,\"size\":116,\"sha256\":\"ddab4174fc63c4e9dfe9dbd95df4b3173a24a2e9138947219e187b0d9ab3e9c1\"},{\"address\":1886530200,\"size\":140,\"sha256\":\"20f9202e4c234f0822f0731226dc24a3b3b95eeefd4b696ff0fb832d2e45ca5f\"},{\"address\":1882381114,\"size\":682,\"sha256\":\"afb626ff23bd5ac1b68190b3bec7bdc9076aab241ad50cae86c48884de29fb94\"},{\"address\":1881033952,\"size\":38,\"sha256\":\"e1c2b796a0aac0d76d696e27a3bb9ca5b075406c280c06e195d6ef2e82645667\"},{\"address\":1881034500,\"size\":326,\"sha256\":\"23b661794a014a553bbc0df310c1584608c26cc65c67e2099f3273b3e7cad49c\"},{\"address\":1881029816,\"size\":64,\"sha256\":\"0b4826e32a27e6fc52163b9123c6d931a7e92a75647902905451c237a9b139f3\"},{\"address\":1881027342,\"size\":166,\"sha256\":\"61f89caa36338c3a2dfd70750b5d24b481e7f8ab61406517b06e92779503dd2c\"},{\"address\":1886514580,\"size\":8,\"sha256\":\"55740b83652ae2f67f6685cba1cfe74f12a71a707ee6381fa3c24e46a9cbb107\"},{\"address\":1884051570,\"size\":32,\"sha256\":\"8d3b44c965517c2f921eeae10513d040f513ee4ac0ee38e4716e0f09896366ab\"},{\"address\":2161366434,\"size\":174,\"sha256\":\"bbc939341f56ef45daa4e8e9e8b2a2217f1742e6c8a3331055560f7d9b56b941\"}]}";
    private static final String SENSOR_CONFIG="{\"recv\":2163839952,\"parser\":2163842728,\"handler\":2163840740,\"cleanup\":2163847072,\"init\":2163890912,\"remain\":2163890984,\"byte\":2163891098,\"word\":2163891200,\"pointer\":2163891350,\"valid\":2163627474,\"alloc\":2163628014,\"retain\":2163628126,\"release\":2163628164,\"fixup\":2163628230,\"reset\":2163623394,\"dispatch\":2163620910,\"bridge\":2163837212,\"initializer\":2163842574,\"malloc\":2163756270,\"free\":2163756324,\"copy\":2164055536,\"zero\":2164056012,\"increment\":2163760318,\"subtract\":2163760404,\"critical_enter\":2163739298,\"critical_exit\":2163739342,\"context\":2163739040,\"logger\":2163764532,\"table\":2163564116,\"callback\":2163564108,\"head\":2163538704,\"pool\":4,\"tag\":2164082792,\"logs\":{\"2164136656\":\"parse_cache\",\"2164135832\":\"receive_parse\",\"2164085044\":\"buffer_alloc\",\"2164135960\":\"receive_alloc\"},\"ranges\":[[2163839952,290],[2163842728,1854],[2163840740,96],[2163847072,346],[2163890912,496],[2163627474,38],[2163628014,306],[2163623394,64],[2163620910,134],[2163837212,4],[2163877858,16],[2163760318,132]],\"guards\":[{\"address\":2163839952,\"size\":290,\"sha256\":\"fb12e987584d0060c95fca63d7c17d441a72e28209e8c3d2e086400e478e055f\"},{\"address\":2163842728,\"size\":1854,\"sha256\":\"937a1677dbd5e7586d6d2b42add93887e0d7c935eb8402d4437d971f22232eb2\"},{\"address\":2163840740,\"size\":96,\"sha256\":\"9f1c22d5edf7fb93362ab1ced0c730a9904d785e4895d431766f30300cf828e6\"},{\"address\":2163847072,\"size\":346,\"sha256\":\"99fe129dae7ccf17f5f8ff137942540a20bbf0626edc83c7a1d7aa39f1bfe871\"},{\"address\":2163890912,\"size\":496,\"sha256\":\"83e562dc0e12bf4430a63597c9d19fab1fc7cfd5bae171f4c3726bbc31dfa85b\"},{\"address\":2163627474,\"size\":38,\"sha256\":\"e1c2b796a0aac0d76d696e27a3bb9ca5b075406c280c06e195d6ef2e82645667\"},{\"address\":2163628014,\"size\":306,\"sha256\":\"f4fd9eaaa3563ef1c607fec6f0ad52bee5ed5ab2002ac1117f87cdba1ec91f1d\"},{\"address\":2163623394,\"size\":64,\"sha256\":\"0b4826e32a27e6fc52163b9123c6d931a7e92a75647902905451c237a9b139f3\"},{\"address\":2163620910,\"size\":134,\"sha256\":\"ae26d17613ea566f46b2e2003314109c1a201ca520fd22447c89fdba6eb8d362\"},{\"address\":2163837212,\"size\":4,\"sha256\":\"d3359a164168715ab5ae68ce31d573bc27d9fa8216d3f5c2e702351e20257d98\"},{\"address\":2163877858,\"size\":16,\"sha256\":\"ee2978f0afc84a840dd58d3ea96f53354c9353a76b7eae519c208ae26112841d\"},{\"address\":2163760318,\"size\":132,\"sha256\":\"3f023e9de23f5c7652b9e962afcb58dbb5bb874c925dbc811a38aa0f9d12102d\"}]}";
    private JsonObject cfg,c;private JsonArray actions,callbacks;private int steps,heapSize;private long parsedAddress;
    private long a(String key){return cfg.get(key).getAsLong();}
    private String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private void put(EmulatorHelper e,long at,int n,long value){e.writeMemoryValue(toAddr(at),n,value);}
    private long read(EmulatorHelper e,long at,int n){byte[] b=e.readMemory(toAddr(at),n);long v=0;for(int i=0;i<n;++i)v|=(b[i]&255L)<<(8*i);return v;}
    private long reg(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void ret(EmulatorHelper e,long value){e.writeRegister("a0",value&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private JsonObject snapshot(EmulatorHelper e)throws Exception {JsonObject o=new JsonObject();o.addProperty("refs",read(e,HEAP,4));o.addProperty("magic",read(e,HEAP+4,4));
        o.addProperty("sha256",hash(e.readMemory(toAddr(HEAP),heapSize)));o.addProperty("guard_sha256",hash(e.readMemory(toAddr(HEAP+heapSize),128)));return o;}
    private JsonObject parsed(EmulatorHelper e){JsonObject o=new JsonObject();o.addProperty("opcode",read(e,parsedAddress,1));o.addProperty("length",read(e,parsedAddress+4,4));o.addProperty("pointer",read(e,parsedAddress+8,4));return o;}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");
        for(int i=0;i<12;++i)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("ABI mismatch");}
    private void runEntry(EmulatorHelper e,long entry,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;++i)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),entry);long callbackReturn=0;
        while(e.getExecutionAddress().getOffset()!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");long pc=e.getExecutionAddress().getOffset();
            if(pc==RESUME){e.writeRegister("ra",callbackReturn);e.writeRegister(e.getPCRegister(),callbackReturn);continue;}
            if(pc==a("parser"))parsedAddress=reg(e,1);
            if(pc==a("context")){ret(e,1);continue;}
            if(pc==a("critical_enter")){put(e,reg(e,0),4,0);ret(e,0);continue;}
            if(pc==a("critical_exit")){ret(e,0);continue;}
            if(pc==a("malloc")){
                if(reg(e,0)!=a("pool")||reg(e,1)!=a("tag")||reg(e,3)!=4)throw new IllegalStateException("Allocation arguments");
                int size=(int)reg(e,2);if(size<16||size>8192)throw new IllegalStateException("Heap bound");
                boolean ok=c.get("allocated").getAsBoolean();actions.add((ok?"alloc:":"alloc_fail:")+size);
                if(ok){heapSize=size;byte[] data=new byte[size+128];Arrays.fill(data,(byte)0xa5);e.writeMemory(toAddr(HEAP),data);}ret(e,ok?HEAP:0);continue;
            }
            if(pc==a("zero")){if(reg(e,0)!=HEAP||reg(e,1)!=0||reg(e,2)!=heapSize)throw new IllegalStateException("Memset arguments");
                e.writeMemory(toAddr(HEAP),new byte[heapSize]);ret(e,HEAP);continue;}
            if(pc==a("copy")){int n=(int)reg(e,2);if(n<0||n>8192)throw new IllegalStateException("Copy bound");
                e.writeMemory(toAddr(reg(e,0)),e.readMemory(toAddr(reg(e,1)),n));ret(e,reg(e,0));continue;}
            if(pc==a("free")){if(reg(e,0)!=a("pool")||reg(e,1)!=a("tag")||reg(e,2)!=HEAP||read(e,HEAP+4,4)!=0||read(e,HEAP,4)!=0)
                    throw new IllegalStateException("Free-before-clear contract");actions.add("free:buffer");ret(e,0);continue;}
            if(pc==a("logger")){JsonElement name=cfg.getAsJsonObject("logs").get(Long.toString(reg(e,3)));
                if(name==null)throw new IllegalStateException("Unexpected log "+Long.toHexString(reg(e,3)));actions.add("log:"+name.getAsString());ret(e,0);continue;}
            if(pc>=CB&&pc<CB+64){
                int index=(int)((pc-CB)/4);if(reg(e,0)!=HEAP+8||index>=c.getAsJsonArray("listeners").size())throw new IllegalStateException("Listener input");
                actions.add("callback:"+index);JsonObject row=new JsonObject();row.addProperty("index",index);row.addProperty("refs",read(e,HEAP,4));
                row.addProperty("data_sha256",hash(e.readMemory(toAddr(HEAP+16),heapSize-16)));row.addProperty("guard_sha256",hash(e.readMemory(toAddr(HEAP+heapSize),128)));callbacks.add(row);
                if(c.getAsJsonArray("listeners").get(index).getAsBoolean()){
                    actions.add("retain:"+index);callbackReturn=e.readRegister("ra").longValue();e.writeRegister("ra",RESUME);e.writeRegister(e.getPCRegister(),a("retain"));
                }else ret(e,0xdeadbeefL);continue;
            }
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){JsonArray pair=span.getAsJsonArray();long first=pair.get(0).getAsLong();
                if(pc>=first&&pc<first+pair.get(1).getAsLong()){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;actions=new JsonArray();callbacks=new JsonArray();steps=0;heapSize=0;parsedAddress=OUTPUT;EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);
            e.writeRegister("sp",0x81001000L);for(int i=0;i<12;++i)e.writeRegister("s"+i,0x45670000L+i);
            byte[] raw=HexFormat.of().parseHex(c.get("wire_hex").getAsString());if(raw.length>8192)throw new IllegalStateException("Input bound");
            e.writeMemory(toAddr(WIRE),raw.length==0?new byte[1]:raw);e.writeMemory(toAddr(OUTPUT),new byte[16]);put(e,ACK,1,165);
            JsonArray decoderRows=new JsonArray();JsonElement parsed=JsonNull.INSTANCE,owner=JsonNull.INSTANCE,finalHeap=JsonNull.INSTANCE;long returned=0;
            String kind=c.get("kind").getAsString();
            if(kind.equals("decoder")){
                e.writeMemory(toAddr(DECODER),new byte[16]);runEntry(e,a("init"),DECODER,WIRE,raw.length);
                for(JsonElement element:c.getAsJsonArray("operations")){
                    String op=element.getAsString();long function=op.equals("byte")?a("byte"):op.equals("word")?a("word"):a("pointer");
                    long n=op.startsWith("data:")?Long.parseLong(op.substring(5)):0;runEntry(e,function,DECODER,n);returned=reg(e,0);
                    JsonObject row=new JsonObject();row.addProperty("operation",op);row.addProperty("returned",returned);row.addProperty("base",read(e,DECODER,4));
                    row.addProperty("length",read(e,DECODER+4,4));row.addProperty("cursor",read(e,DECODER+8,4));row.addProperty("error",read(e,DECODER+12,1));decoderRows.add(row);
                }
            }else if(kind.equals("parse")){
                put(e,ARGS,4,WIRE);put(e,ARGS+4,4,raw.length);runEntry(e,a("parser"),ARGS,OUTPUT);returned=reg(e,0);parsed=parsed(e);
            }else if(kind.equals("receive")){
                put(e,a("table")+21*4,4,c.get("handler").getAsBoolean()?a("handler"):0);put(e,a("callback"),4,a("bridge"));
                JsonArray listeners=c.getAsJsonArray("listeners");long head=a("head"),base=0x81008000L;
                put(e,head,4,listeners.size()==0?head:base);put(e,head+4,4,listeners.size()==0?head:base+16L*(listeners.size()-1));
                for(int i=0;i<listeners.size();++i){long node=base+16L*i;put(e,node,4,i==listeners.size()-1?head:node+16);put(e,node+4,4,i==0?head:node-16);
                    put(e,node+8,4,0);put(e,node+12,4,CB+4L*i);}
                runEntry(e,a("recv"),0x81004000L,WIRE,raw.length,ACK);returned=reg(e,0);parsed=parsed(e);
                if(heapSize>0){owner=snapshot(e);
                    for(int i=0;i<listeners.size();++i)if(listeners.get(i).getAsBoolean()){actions.add("drop:"+i);runEntry(e,a("release"),HEAP+8);}
                    finalHeap=snapshot(e);
                }
            }else throw new IllegalArgumentException("Unknown kind");
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.addProperty("returned",returned);observed.add("parsed",parsed);
            observed.addProperty("ack",read(e,ACK,1));observed.add("decoder",decoderRows);observed.add("callbacks",callbacks);observed.add("owner_after",owner);
            observed.add("final_heap",finalHeap);observed.addProperty("input_sha256",hash(raw.length==0?new byte[0]:e.readMemory(toAddr(WIRE),raw.length)));
            if(!observed.equals(c.getAsJsonObject("expected")))throw new IllegalStateException(c.get("name")+" observed="+observed+" expected="+c.get("expected"));
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=3)throw new IllegalArgumentException("vectors-path report-path main|sensor");String core=getScriptArgs()[2];
        if(!core.equals("main")&&!core.equals("sensor"))throw new IllegalArgumentException("Unknown core");
        cfg=JsonParser.parseString(core.equals("main")?MAIN_CONFIG:SENSOR_CONFIG).getAsJsonObject();
        for(JsonElement element:cfg.getAsJsonArray("guards")){JsonObject g=element.getAsJsonObject();byte[] bytes=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),bytes);
            if(!hash(bytes).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized receiver code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>256)throw new IllegalArgumentException("Unsupported vectors");
        JsonArray rows=new JsonArray();for(JsonElement element:input.getAsJsonArray("cases"))if(element.getAsJsonObject().get("platform").getAsString().equals(core))rows.add(execute(element.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("platform",core);report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("CACHE_RECEIVER_VALIDATION "+core+" cases="+rows.size());
    }
}
