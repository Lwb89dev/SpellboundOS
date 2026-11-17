// Execute actual HR setup/component allocation/nested cleanup instructions.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateHrSetup extends GhidraScript {
    private static final String CONFIG="{\"init\":1888071114,\"exit\":1888072544,\"setup\":1888097330,\"inner\":1888058438,\"cleanup\":1888058908,\"alloc\":2161361290,\"free\":2161361386,\"zero\":1888779496,\"copy\":1888779020,\"logger\":1881880738,\"component\":1888110616,\"ranges\":[[1888071114,2658],[1888097330,944],[1888058438,548],[1888055366,60],[1888057370,200],[1888103598,260],[1888091582,222]],\"logs\":{\"1892761212\":\"init\",\"1892786644\":\"backend_error\",\"1892789228\":\"ppg_alloc\",\"1892789252\":\"ppg_free\",\"1892788588\":\"extra_alloc_failed\"},\"children\":[[0,4096],[1,240],[2,240],[3,240],[4,240],[5,240],[6,240],[7,240],[8,240],[9,240],[10,240],[11,240],[12,50],[13,50],[14,50],[30,200],[31,200],[32,200],[33,200],[34,256],[35,256],[37,1024],[38,1024],[40,512],[41,256],[42,256],[100,30],[3871,256],[3872,256],[174,480],[178,400],[179,960],[220,100],[3976,1000],[3984,1000],[3968,1000],[3992,1024],[3977,1000],[3985,1000],[3969,1000],[3993,1024],[3978,1000],[3986,1000],[3970,1000],[3994,1024],[3979,1000],[3987,1000],[3971,1000],[3995,1024],[3980,1000],[3988,1000],[3972,1000],[3996,1024],[3981,1000],[3989,1000],[3973,1000],[3997,1024],[3982,1000],[3990,1000],[3974,1000],[3998,1024],[3983,1000],[3991,1000],[3975,1000],[3999,1024],[4000,1024]],\"clean_fields\":[15776,15780,15784,15788,15448,15452,3404,3412,3408,3416,39956],\"guards\":[{\"address\":1888071114,\"size\":2658,\"sha256\":\"2801d6ce79767bafbfb0dc2d2b18548e7b71aec8ce5f617ab19da8881121f1e6\"},{\"address\":1888097330,\"size\":944,\"sha256\":\"a69c23eab2cc22708e8af27d03e87e369a0bae654e8ce341793d741285a94267\"},{\"address\":1888058438,\"size\":548,\"sha256\":\"2951445994ff4260399c2eaaa43ec9bc05211214258555b3b750831ee445d895\"},{\"address\":1888055366,\"size\":60,\"sha256\":\"5370ee7c929eaa7a5dca39c73fa0d7b5d55ac20c35227628f85099473ea8339c\"},{\"address\":1888057370,\"size\":200,\"sha256\":\"c5380450c0e8eb5ba5c8a8492054db5e12f42985e154adecba2b50c67ba107c2\"},{\"address\":1888103598,\"size\":260,\"sha256\":\"3bbad1511a655e46dc894d14a80ded811557e85c51bac851d75a5ece5edbd88a\"},{\"address\":1888091582,\"size\":222,\"sha256\":\"e12fa16cca1ef4cc107509c48e87b16013381db043692f03c45051f8886fc5c2\"},{\"address\":1892788752,\"size\":16,\"sha256\":\"cbe793633ea09b05e3364790b67172cdb6858b8b096e52599cbcfc79baa2a40a\"},{\"address\":1889291900,\"size\":4,\"sha256\":\"c68830a25204a09f8e77aada6bc5807f607cccaaa0ebb2a7122d317584478a8b\"},{\"address\":1892788612,\"size\":4,\"sha256\":\"c957742e36e20cd727bf350c99142d2f92e98a09cf412361892ab2aedbc124dc\"},{\"address\":1890397824,\"size\":4,\"sha256\":\"a9354cb88a60330a1b2fa595e556bc765743d814b0117d54dc1ac52b34543f9b\"}]}";
    private static final long END=0x70000000L,GLOBAL=0x80c46100L,HEAP=0x81400000L;
    private JsonObject cfg,c;private JsonArray actions;private int steps;private final List<Long> pointers=new ArrayList<>();
    private final List<Integer> sizes=new ArrayList<>();private final Set<Long> freed=new HashSet<>();
    private long a(String key){return cfg.get(key).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int size,long value){e.writeMemoryValue(toAddr(at),size,value);}
    private long read(EmulatorHelper e,long at,int size){long v=0;byte[] b=e.readMemory(toAddr(at),size);for(int i=0;i<size;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private String memoryHash(EmulatorHelper e,long at,int n)throws Exception{return hash(n==0?new byte[0]:e.readMemory(toAddr(at),n));}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");
        for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i||e.readRegister("fs"+i).longValue()!=0x12340000L+i)throw new IllegalStateException("Saved register mismatch");}
    private long allocation(EmulatorHelper e,int n,boolean supplied){
        if(n<0||n>0x9dc4||pointers.size()>=256)throw new IllegalStateException("Allocation bound");
        if(!supplied&&n==0x1ffc&&c.get("extra_failure").getAsBoolean()){actions.add("alloc_fail:8188");return 0;}
        long ptr=HEAP+0x10000L*pointers.size();pointers.add(ptr);sizes.add(n);byte[] data=new byte[n+32];Arrays.fill(data,(byte)0xa5);e.writeMemory(toAddr(ptr),data);
        if(!supplied)actions.add("alloc:"+n);return ptr;
    }
    private boolean heapRange(long ptr,long n){for(int i=0;i<pointers.size();i++)if(ptr>=pointers.get(i)&&ptr+n<=pointers.get(i)+sizes.get(i)&&!freed.contains(pointers.get(i)))return true;return false;}
    private int[][] clears(int rate){List<int[]> rows=new ArrayList<>();rows.add(new int[]{0,4*(rate*512/25)});
        for(int i=12;i<=14;i++)rows.add(new int[]{i,rate*2});for(int i=1;i<12;i++)rows.add(new int[]{i,4*(rate*60/25)});
        for(int i=30;i<34;i++)rows.add(new int[]{i,rate*8});for(int i=34;i<=35;i++)rows.add(new int[]{i,4*(rate*64/25)});
        rows.add(new int[]{37,4*(rate*256/25)});rows.add(new int[]{38,8*(rate*128/25)});rows.add(new int[]{40,4*(rate*128/25)});
        rows.add(new int[]{41,4*(rate*64/25)});rows.add(new int[]{42,4*(rate*64/25)});rows.add(new int[]{100,rate*30/25});return rows.toArray(int[][]::new);}
    private void fixture(EmulatorHelper e){int rate=c.get("rate").getAsInt();long root=allocation(e,0x9dc4,true);byte[] raw=new byte[0x9dc4];Arrays.fill(raw,(byte)0x5a);e.writeMemory(toAddr(root),raw);put(e,root+0x15a,2,rate);put(e,GLOBAL+0x90,4,root);
        if(c.get("scope").getAsString().equals("cleanup")){int i=0,mask=c.get("mask").getAsInt();for(JsonElement at:cfg.getAsJsonArray("clean_fields"))put(e,root+at.getAsInt(),4,(mask&(1<<i++))!=0?allocation(e,64,true):0);}
        else{
            Map<Integer,Integer> lengths=new HashMap<>();for(int[] row:clears(rate))lengths.put(row[0],row[1]);
            for(JsonElement item:cfg.getAsJsonArray("children")){JsonArray child=item.getAsJsonArray();int index=child.get(0).getAsInt(),n=child.get(1).getAsInt();
                n=Math.max(n,lengths.getOrDefault(index,0));if(index==0xf1f||index==0xf20)n=Math.max(n,4*(rate*64/25));put(e,root+4L*index,4,allocation(e,n+16,true));}
        }
    }
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if(pc==a("alloc")){if(r(e,0)!=0||r(e,2)!=4)throw new IllegalStateException("Allocator arguments");ret(e,allocation(e,(int)r(e,1),false));continue;}
            if(pc==a("free")){long ptr=r(e,1);if(r(e,0)!=0)throw new IllegalStateException("Free pool");
                if(ptr==0)actions.add("free:null");else{int index=pointers.indexOf(ptr);if(index<0||freed.contains(ptr))throw new IllegalStateException("Unexpected/duplicate free");freed.add(ptr);actions.add("free:"+index);}ret(e,0);continue;}
            if(pc==a("zero")){long ptr=r(e,0),n=r(e,2);if(r(e,1)!=0||n>0x9dc4||!(heapRange(ptr,n)||(ptr==GLOBAL+0x58&&n==56)))throw new IllegalStateException("Zero bounds "+Long.toHexString(ptr)+" n="+n);
                actions.add("zero:"+Long.toHexString(ptr)+":"+n);e.writeMemory(toAddr(ptr),new byte[(int)n]);ret(e,ptr);continue;}
            if(pc==a("copy")){if(r(e,1)!=0x70d1aa10L||r(e,2)!=16||!heapRange(r(e,0),16))throw new IllegalStateException("Coefficient copy");
                actions.add("copy:coefficients");e.writeMemory(toAddr(r(e,0)),e.readMemory(toAddr(r(e,1)),16));ret(e,r(e,0));continue;}
            if(pc==a("logger")){JsonElement log=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));if(log==null)throw new IllegalStateException("Unexpected log "+Long.toHexString(r(e,3)));actions.add("log:"+log.getAsString());ret(e,0);continue;}
            if(pc==a("component")){if(r(e,0)!=read(e,GLOBAL+0x90,4)+0x218)throw new IllegalStateException("Component context");actions.add("boundary:component");ret(e,c.get("component_status").getAsLong());continue;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject snapshot(EmulatorHelper e,JsonElement returned)throws Exception {
        JsonObject row=new JsonObject();row.add("returned",returned);row.addProperty("state_sha256",memoryHash(e,GLOBAL,192));row.addProperty("aux",read(e,0x80c01c7cL,1));
        JsonArray hashes=new JsonArray(),released=new JsonArray();byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);
        for(int i=0;i<pointers.size();i++){long p=pointers.get(i);int n=sizes.get(i);if(!hash(guard).equals(memoryHash(e,p+n,32)))throw new IllegalStateException("Allocation guard changed");hashes.add(memoryHash(e,p,n));if(freed.contains(p))released.add(i);}
        row.add("allocation_sha256",hashes);row.add("freed",released);return row;
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;actions=new JsonArray();pointers.clear();sizes.clear();freed.clear();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);
            for(int i=0;i<12;i++){e.writeRegister("s"+i,0x45670000L+i);e.writeRegister("fs"+i,0x12340000L+i);}
            byte[] state=new byte[192];Arrays.fill(state,(byte)0x5a);state[0xbe]=0;state[0x20]=(byte)c.get("mode").getAsInt();e.writeMemory(toAddr(GLOBAL),state);put(e,0x80c01c7cL,1,165);
            if(!c.get("scope").getAsString().equals("owner"))fixture(e);JsonArray rows=new JsonArray();
            for(JsonElement element:c.getAsJsonArray("operations")){String op=element.getAsString();JsonElement returned=JsonNull.INSTANCE;
                if(op.equals("init")||op.equals("exit")){entry(e,a(op));returned=new JsonPrimitive(r(e,0));}
                else entry(e,a(op),read(e,GLOBAL+0x90,4));rows.add(snapshot(e,returned));
            }
            JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray lengths=new JsonArray();for(int n:sizes)lengths.add(n);observed.add("allocation_sizes",lengths);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/hr-setup-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement element:cfg.getAsJsonArray("guards")){JsonObject guard=element.getAsJsonObject();byte[] bytes=new byte[guard.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(guard.get("address").getAsLong()),bytes);
            if(!hash(bytes).equals(guard.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized HR setup code/constants");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");
        JsonArray rows=new JsonArray();for(JsonElement c:input.getAsJsonArray("cases"))rows.add(execute(c.getAsJsonObject()));JsonObject report=new JsonObject();
        report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("HR_SETUP_VALIDATION cases="+rows.size());
    }
}
