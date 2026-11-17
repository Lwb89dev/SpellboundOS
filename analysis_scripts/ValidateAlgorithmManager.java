// Actual main algorithm manager and HR adapters with supplied mathematical calls.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateAlgorithmManager extends GhidraScript {
    private static final String CONFIG="{\"base_reg\":1884047908,\"reg\":1884048566,\"enable\":1884048700,\"disable\":1884048704,\"lookup\":1884048442,\"active\":1884048396,\"dispatch\":1884048708,\"control\":1884048896,\"mask\":1884048984,\"hr_register\":1882272910,\"hr_process\":1888073772,\"hr_init\":1888071114,\"hr_exit\":1888072544,\"extension\":1888068178,\"copy\":1888779272,\"zero\":1888779496,\"logger\":1881880738,\"ranges\":[[1884047902,1130],[1882272838,90],[1888080144,604],[1888073772,184]],\"logs\":{\"1891643140\":\"reg_invalid\",\"1891643200\":\"reg_duplicate\",\"1891643396\":\"ops_invalid\",\"1891643452\":\"ops_reg_failed\",\"1891643252\":\"enable_missing\",\"1891643304\":\"enable_error\",\"1891643344\":\"disable_missing\",\"1891643484\":\"dispatch_invalid\",\"1891643540\":\"dispatch_missing\",\"1891643596\":\"dispatch_error\",\"1891643632\":\"control_error\",\"1892789556\":\"hr_config\",\"1892789584\":\"hr_config_array1\",\"1892789624\":\"hr_config_array0\",\"1892789668\":\"hr_config_array2\",\"1892789712\":\"hr_config_tail\",\"1892789724\":\"hr_extension_nonone\",\"1892789764\":\"hr_extension_absent\",\"1892786644\":\"hr_uninitialized\"},\"guards\":[{\"address\":1884047902,\"size\":1130,\"sha256\":\"c765b206b73ceb3e3574d088a756b741099e61a72acc846de7d4186e1581b23d\"},{\"address\":1882272838,\"size\":90,\"sha256\":\"d2004725c5c6d7a28f7aa27e503456b0c08fa425bb86563676663b60c7b97f4c\"},{\"address\":1888080144,\"size\":604,\"sha256\":\"30fd55938757529f1c8e29d289686bdb25d23888a8a92668475ad2559b70d639\"},{\"address\":1888073772,\"size\":184,\"sha256\":\"d3d61bbe8fe7934acabc5777cec25b516d43a4cb47efcd84194ac9ae149c8706\"},{\"address\":1895184608,\"size\":48,\"sha256\":\"31b95cbc4bc97f6ec5ca89a5ebc25f149de4ce96614d5531083d725c693b54ce\"}]}";
    private static final long END=0x70000000L,CB=0x70000100L,TABLE=0x70fc1ffcL,HR=0x70f638e0L,
        RECORDS=0x81010000L,DESC=0x81020000L,WORK=0x81021000L,OUTPUT=0x81022000L,CONTROL=0x81023000L,STATE=0x80c46120L;
    private JsonObject cfg,c,op;private JsonArray actions;private int steps;private long[] pointers;
    private long a(String key){return cfg.get(key).getAsLong();}
    private long value(JsonObject object,String key,long fallback){return object.has(key)?object.get(key).getAsLong():fallback;}
    private boolean flag(JsonObject object,String key,boolean fallback){return object.has(key)?object.get(key).getAsBoolean():fallback;}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int size,long v){e.writeMemoryValue(toAddr(at),size,v);}
    private long read(EmulatorHelper e,long at,int size){long v=0;byte[] bytes=e.readMemory(toAddr(at),size);for(int i=0;i<size;i++)v|=(bytes[i]&255L)<<(8*i);return v;}
    private String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private String memoryHash(EmulatorHelper e,long at,int n)throws Exception{return hash(e.readMemory(toAddr(at),n));}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");
        for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");
        for(int i=0;i<4;i++)if(e.readRegister("fs"+i).longValue()!=0x12340000L+i)throw new IllegalStateException("Saved FP register mismatch");}
    private void entry(EmulatorHelper e,long pc,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),pc);
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            long status=value(op,"status",0);
            if(pc==a("logger")){JsonElement log=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));
                if(log==null)throw new IllegalStateException("Unexpected log "+Long.toHexString(r(e,3)));actions.add("log:"+log.getAsString());ret(e,0);continue;}
            if(pc==a("copy")){if(r(e,2)!=10||r(e,0)<STATE||r(e,0)+10>STATE+56||r(e,1)<CONTROL||r(e,1)+10>CONTROL+48)
                    throw new IllegalStateException("HR copy arguments");e.writeMemory(toAddr(r(e,0)),e.readMemory(toAddr(r(e,1)),10));ret(e,r(e,0));continue;}
            if(pc==a("zero")){if(r(e,0)!=STATE||r(e,1)!=0||r(e,2)!=56)throw new IllegalStateException("HR zero arguments");e.writeMemory(toAddr(STATE),new byte[56]);ret(e,STATE);continue;}
            if(pc==a("extension")){if(r(e,0)!=0x81024000L||r(e,1)!=16)throw new IllegalStateException("Extension arguments");actions.add("backend:extension");ret(e,status);continue;}
            if(pc==a("hr_init")||pc==a("hr_exit")){actions.add(pc==a("hr_init")?"backend:init":"backend:exit");ret(e,status);continue;}
            if(pc==a("hr_process")&&!flag(op,"real_guard",false)){
                checkProcess(e);actions.add("backend:process");put(e,OUTPUT,1,flag(op,"ready",true)?1:0);put(e,OUTPUT+8,1,72);put(e,OUTPUT+9,1,4);ret(e,status);continue;}
            if(pc==a("hr_process")){checkProcess(e);actions.add("backend:process");if(read(e,STATE+0x9e,1)!=0)throw new IllegalStateException("Guard fixture must be uninitialized");}
            if(pc>=CB&&pc<=CB+12&&((pc-CB)&3)==0){
                int kind=(int)((pc-CB)/4);actions.add("callback:"+new String[]{"init","exit","process","control"}[kind]);
                if(kind==2){checkProcess(e);put(e,OUTPUT,1,flag(op,"ready",true)?1:0);put(e,OUTPUT+8,1,72);put(e,OUTPUT+9,1,4);}
                if(kind==3&&r(e,0)!=CONTROL)throw new IllegalStateException("Control callback argument");ret(e,status);continue;
            }
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long start=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=start&&pc<start+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private void checkProcess(EmulatorHelper e){long descriptor=op.has("type")&&op.get("type").isJsonNull()?0:DESC;
        if(r(e,0)!=descriptor||r(e,1)!=WORK||r(e,2)!=OUTPUT||read(e,OUTPUT,1)!=0||read(e,OUTPUT+2,2)!=(value(op,"id",0x100d)&65535))
            throw new IllegalStateException("Process arguments/output initialization");}
    private void record(EmulatorHelper e,int index,JsonObject d){long p=pointers[index];if(flag(d,"real",false))return;
        e.writeMemory(toAddr(p),new byte[48]);put(e,p+8,4,value(d,"id",0x100d));put(e,p+12,4,value(d,"refs",123));
        put(e,p+16,4,flag(d,"init",true)?CB:0);put(e,p+20,4,flag(d,"exit",true)?CB+4:0);
        put(e,p+24,8,value(d,"mask",0x10));put(e,p+36,4,flag(d,"process",true)?CB+8:0);put(e,p+40,4,flag(d,"control",true)?CB+12:0);}
    private JsonObject snapshot(EmulatorHelper e,JsonElement returned)throws Exception {
        JsonObject row=new JsonObject();row.add("returned",returned);row.addProperty("table_sha256",memoryHash(e,TABLE,58*8));
        JsonArray hashes=new JsonArray();for(long p:pointers)hashes.add(memoryHash(e,p,48));row.add("record_sha256",hashes);
        row.addProperty("output_sha256",memoryHash(e,OUTPUT,0x520));row.addProperty("state_sha256",memoryHash(e,STATE,160));return row;}
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;actions=new JsonArray();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);
            for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            for(int i=0;i<4;i++)e.writeRegister("fs"+i,0x12340000L+i);
            e.writeMemory(toAddr(TABLE),new byte[58*8]);byte[] state=new byte[160];Arrays.fill(state,(byte)0x5a);state[0x9e]=0;e.writeMemory(toAddr(STATE),state);
            byte[] out=new byte[0x520];Arrays.fill(out,(byte)0xa5);e.writeMemory(toAddr(OUTPUT),out);byte[] work=new byte[44];Arrays.fill(work,(byte)0x96);e.writeMemory(toAddr(WORK),work);
            JsonArray definitions=c.getAsJsonArray("records");pointers=new long[definitions.size()];
            for(int i=0;i<pointers.length;i++){JsonObject d=definitions.get(i).getAsJsonObject();pointers[i]=flag(d,"real",false)?HR:RECORDS+0x100L*i;record(e,i,d);}
            JsonArray rows=new JsonArray();
            for(JsonElement element:c.getAsJsonArray("operations")){op=element.getAsJsonObject();String kind=op.get("op").getAsString();long id=value(op,"id",0x100d);JsonElement returned=JsonNull.INSTANCE;
                byte[] source=null,descriptor=null;
                if(kind.equals("reg")||kind.equals("base_reg")||kind.equals("hr_register")){
                    long ptr=op.has("record")&&op.get("record").isJsonNull()?0:pointers[(int)value(op,"record",0)];
                    entry(e,a(kind),ptr);if(kind.equals("base_reg"))returned=new JsonPrimitive(r(e,0));
                }else if(kind.equals("seed")){
                    long p=read(e,TABLE+(id-0x1000)*8,4);if(p==0)throw new IllegalStateException("Seed missing record");
                    put(e,p+12,2,value(op,"refs",0));put(e,TABLE+(id-0x1000)*8+4,1,value(op,"enabled",0));actions.add("supplied:seed");
                }else if(kind.equals("dispatch")){
                    descriptor=new byte[40];e.writeMemory(toAddr(DESC),descriptor);if(!(op.has("type")&&op.get("type").isJsonNull()))put(e,DESC,8,value(op,"type",0x10));descriptor=e.readMemory(toAddr(DESC),40);
                    entry(e,a(kind),id,op.has("type")&&op.get("type").isJsonNull()?0:DESC,WORK,flag(op,"output",true)?OUTPUT:0);
                }else if(kind.equals("control")||kind.equals("direct_control")){
                    source=HexFormat.of().parseHex(op.get("control_hex").getAsString());if(source.length!=48)throw new IllegalStateException("Control length");e.writeMemory(toAddr(CONTROL),source);
                    if(kind.equals("direct_control")){entry(e,0x7089d110L,CONTROL);returned=new JsonPrimitive(r(e,0));}
                    else entry(e,a(kind),id,CONTROL);
                }else if(kind.equals("mask")){
                    long mask=value(op,"mask",0);entry(e,a(kind),id,mask&0xffffffffL,mask>>>32);
                }else{
                    entry(e,a(kind),id);if(kind.equals("enable")||kind.equals("lookup")||kind.equals("active"))returned=new JsonPrimitive(r(e,0));
                }
                if(source!=null&&!hash(source).equals(memoryHash(e,CONTROL,48)))throw new IllegalStateException("Control mutated");
                if(descriptor!=null&&!hash(descriptor).equals(memoryHash(e,DESC,40)))throw new IllegalStateException("Descriptor mutated");
                if(!hash(work).equals(memoryHash(e,WORK,44)))throw new IllegalStateException("Work mutated");
                rows.add(snapshot(e,returned));
            }
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected")))throw new IllegalStateException(c.get("name")+" observed="+observed+" expected="+c.get("expected"));
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path validation-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement element:cfg.getAsJsonArray("guards")){JsonObject guard=element.getAsJsonObject();byte[] bytes=new byte[guard.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(guard.get("address").getAsLong()),bytes);
            if(!hash(bytes).equals(guard.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized algorithm code/record");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");
        JsonArray rows=new JsonArray();for(JsonElement c:input.getAsJsonArray("cases"))rows.add(execute(c.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("ALGORITHM_MANAGER_VALIDATION cases="+rows.size());
    }
}
