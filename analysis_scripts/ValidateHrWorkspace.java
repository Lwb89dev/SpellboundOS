// Native HR outer workspace allocation/free and borrowed extension views.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateHrWorkspace extends GhidraScript {
    private static final String CONFIG="{\"init\":1888071114,\"exit\":1888072544,\"process\":1888073772,\"extension\":1888068178,\"alloc\":2161361290,\"free\":2161361386,\"zero\":1888779496,\"copy\":1888779272,\"copy2\":1888779020,\"setup\":1888097330,\"cleanup\":1888097988,\"logger\":1881880738,\"ranges\":[[1888068178,354],[1888071114,2658],[1888073772,6372],[1888097992,10]],\"logs\":{\"1892789104\":\"extension\",\"1892761212\":\"init\",\"1892786644\":\"backend_error\",\"1892789228\":\"ppg_alloc\",\"1892789252\":\"ppg_free\"},\"guards\":[{\"address\":1888068178,\"size\":354,\"sha256\":\"8227ed02cca548427a434d8fb552d7441c1cca80514518093d174fbe4eeb0a83\"},{\"address\":1888071114,\"size\":2658,\"sha256\":\"2801d6ce79767bafbfb0dc2d2b18548e7b71aec8ce5f617ab19da8881121f1e6\"},{\"address\":1888073772,\"size\":6372,\"sha256\":\"8b28504c39a389792228c7a572e78e5e7c7113c0f3d9a4572bfab81545af0805\"},{\"address\":1888097992,\"size\":10,\"sha256\":\"2f0f037a5c4cb094053c8d8d9c818f00ef4ead43fd9a1a135acbf7cd4e84e6fd\"}]}";
    private static final long END=0x70000000L,GLOBAL=0x80c46100L,EXT=0x80c45f50L,HEAP=0x81400000L,INPUT=0x82000000L,
        DESC=0x81020000L,WORK=0x81021000L,OUTPUT=0x81022000L;
    private JsonObject cfg,c;private JsonArray actions;private int steps;private final List<Long> pointers=new ArrayList<>();
    private final List<Integer> sizes=new ArrayList<>();private final Set<Long> freed=new HashSet<>();
    private long a(String key){return cfg.get(key).getAsLong();}
    private long value(JsonObject o,String key,long fallback){return o.has(key)?o.get(key).getAsLong():fallback;}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int size,long value){e.writeMemoryValue(toAddr(at),size,value);}
    private long read(EmulatorHelper e,long at,int size){long v=0;byte[] b=e.readMemory(toAddr(at),size);for(int i=0;i<size;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private String memoryHash(EmulatorHelper e,long at,int n)throws Exception{return hash(e.readMemory(toAddr(at),n));}
    private void ret(EmulatorHelper e,long value){e.writeRegister("a0",value&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");
        for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i||e.readRegister("fs"+i).longValue()!=0x12340000L+i)throw new IllegalStateException("Saved register mismatch");}
    private boolean heapRange(long ptr,long n){for(int i=0;i<pointers.size();i++)if(ptr>=pointers.get(i)&&ptr+n<=pointers.get(i)+sizes.get(i)&&!freed.contains(pointers.get(i)))return true;return false;}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);
        long pc;while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if(pc==a("logger")){JsonElement log=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));if(log==null)throw new IllegalStateException("Unexpected log "+Long.toHexString(r(e,3)));actions.add("log:"+log.getAsString());ret(e,0);continue;}
            if(pc==a("alloc")){if(r(e,0)!=0||r(e,2)!=4||r(e,1)>0x9dc4)throw new IllegalStateException("Allocation arguments");int n=(int)r(e,1);
                if(c.get("root_failure").getAsBoolean()){if(n!=0x9dc4||!pointers.isEmpty())throw new IllegalStateException("Root failure scope");actions.add("alloc_fail:"+n);ret(e,0);continue;}
                long ptr=HEAP+0x10000L*pointers.size();pointers.add(ptr);sizes.add(n);byte[] data=new byte[n+32];Arrays.fill(data,(byte)0xa5);e.writeMemory(toAddr(ptr),data);actions.add("alloc:"+n);ret(e,ptr);continue;}
            if(pc==a("free")){long ptr=r(e,1);if(r(e,0)!=0||!pointers.contains(ptr)||freed.contains(ptr))throw new IllegalStateException("Free arguments/ownership "+Long.toHexString(ptr));freed.add(ptr);actions.add("free:"+pointers.indexOf(ptr));ret(e,0);continue;}
            if(pc==a("zero")){long ptr=r(e,0),n=r(e,2);if(r(e,1)!=0||n>0x9dc4||!(heapRange(ptr,n)||(ptr==GLOBAL+0x58&&n==56)))throw new IllegalStateException("Zero bounds");e.writeMemory(toAddr(ptr),new byte[(int)n]);ret(e,ptr);continue;}
            if(pc==a("copy")||pc==a("copy2")){long ptr=r(e,0),src=r(e,1),n=r(e,2);
                if(!((ptr==EXT+4&&src>=INPUT&&src<INPUT+0x50000L&&n==4)||(src==GLOBAL+0x20&&ptr>=0x81000000L&&ptr+n<=0x81001000L&&n==56)))throw new IllegalStateException("Copy bounds");
                e.writeMemory(toAddr(ptr),e.readMemory(toAddr(src),(int)n));ret(e,ptr);continue;}
            if(pc==a("setup")||pc==a("cleanup")){if(r(e,0)!=read(e,GLOBAL+0x90,4))throw new IllegalStateException("Setup/cleanup root");actions.add(pc==a("setup")?"boundary:setup":"boundary:cleanup");ret(e,0);continue;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject snapshot(EmulatorHelper e)throws Exception {
        JsonObject row=new JsonObject();row.addProperty("returned",r(e,0));row.addProperty("state_sha256",memoryHash(e,GLOBAL,192));row.addProperty("extension_sha256",memoryHash(e,EXT,104));
        row.addProperty("aux",read(e,0x80c01c7cL,1));row.addProperty("output_sha256",memoryHash(e,OUTPUT,0x520));JsonArray allocations=new JsonArray();
        byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);
        for(int i=0;i<pointers.size();i++){long p=pointers.get(i);int size=sizes.get(i);if(!hash(guard).equals(memoryHash(e,p+size,32)))throw new IllegalStateException("Heap guard changed");
            JsonObject a=new JsonObject();a.addProperty("pointer",p);a.addProperty("size",size);a.addProperty("sha256",memoryHash(e,p,size));a.addProperty("freed",freed.contains(p));allocations.add(a);}
        row.add("allocations",allocations);return row;
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;actions=new JsonArray();pointers.clear();sizes.clear();freed.clear();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);
            for(int i=0;i<12;i++){e.writeRegister("s"+i,0x45670000L+i);e.writeRegister("fs"+i,0x12340000L+i);}
            byte[] state=new byte[192];Arrays.fill(state,(byte)0x5a);state[0x20]=(byte)c.get("mode").getAsInt();state[0xbe]=(byte)(c.get("already_initialized").getAsBoolean()?1:0);e.writeMemory(toAddr(GLOBAL),state);
            byte[] ext=new byte[104];Arrays.fill(ext,(byte)0x5a);e.writeMemory(toAddr(EXT),ext);put(e,0x80c01c7cL,1,165);
            byte[] output=new byte[0x520];Arrays.fill(output,(byte)0xa5);e.writeMemory(toAddr(OUTPUT),output);e.writeMemory(toAddr(WORK),new byte[44]);JsonArray rows=new JsonArray();
            for(JsonElement element:c.getAsJsonArray("operations")){JsonObject op=element.getAsJsonObject();String kind=op.get("op").getAsString();byte[] source=null;long base=0;
                if(kind.equals("extension")){base=value(op,"base",INPUT);source=new byte[0x1a1d0];Arrays.fill(source,(byte)0xa5);source[0]=(byte)255;source[1]=11;source[2]=22;source[3]=33;
                    e.writeMemory(toAddr(base),source);put(e,base+4,4,value(op,"header_size",0));source=e.readMemory(toAddr(base),source.length);entry(e,a(kind),base,value(op,"length",0));}
                else if(kind.equals("process")){e.writeMemory(toAddr(DESC),new byte[40]);put(e,DESC,8,op.get("type").getAsLong());entry(e,a(kind),DESC,WORK,OUTPUT);}
                else entry(e,a(kind));
                if(source!=null&&!hash(source).equals(memoryHash(e,base,source.length)))throw new IllegalStateException("Extension input mutated");
                rows.add(snapshot(e));
            }
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/hr-workspace-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement element:cfg.getAsJsonArray("guards")){JsonObject guard=element.getAsJsonObject();byte[] bytes=new byte[guard.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(guard.get("address").getAsLong()),bytes);
            if(!hash(bytes).equals(guard.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized HR code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");
        JsonArray rows=new JsonArray();for(JsonElement c:input.getAsJsonArray("cases"))rows.add(execute(c.getAsJsonObject()));JsonObject report=new JsonObject();
        report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("HR_WORKSPACE_VALIDATION cases="+rows.size());
    }
}
