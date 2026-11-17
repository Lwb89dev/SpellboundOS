// Actual environment wrappers and boot policy with supplied storage/board services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateBootEnvironment extends GhidraScript {
    private static final String CONFIG="{\"get\":2160120644,\"set\":2160120756,\"commit\":2160120976,\"reason\":2160127088,\"key\":2160067346,\"prefix\":2160067668,\"lock\":2160115958,\"unlock\":2160115976,\"find\":2160119286,\"read\":2160115544,\"reserve\":2160118650,\"append\":2160118730,\"remove\":2160119510,\"maintenance\":2160118550,\"strlen\":2160256380,\"warn\":2160116256,\"raw_reason\":2160140868,\"copy\":2160254520,\"keyboard_command\":2160251066,\"power\":2160203436,\"delay\":2160158852,\"zero\":2160254996,\"strncpy\":2160256644,\"logger\":2160184698,\"board_flag\":2160072776,\"display\":2160069154,\"hw\":2160182792,\"board_init\":2160073006,\"keyboard_register\":2160250438,\"keyboard_init\":2160250958,\"ranges\":[[2160120644,336],[2160127088,128],[2160067346,760],[2160072836,26]],\"logs\":{\"2160274088\":\"reason\",\"2160274112\":\"no_power\",\"2160274160\":\"press\",\"2160274136\":\"key_pass\",\"2160274184\":\"build\",\"2160274224\":\"hw\",\"2160274256\":\"backup_request\",\"2160274284\":\"fallback_reason\"},\"guards\":[{\"address\":2160120644,\"size\":336,\"sha256\":\"96ec9efd27e8cf5624341fde8eb92aa0cc739dc8ef16e3118e3dba715fe6f3b2\"},{\"address\":2160127088,\"size\":128,\"sha256\":\"0df72d90a387b0c6d5613af218e70d655251650c70d74f405e33d6bd689e9398\"},{\"address\":2160067346,\"size\":760,\"sha256\":\"9cc7e9af874aa56d31221bc7ee6f3bd1ef97da25c8f96946af0891d01887a46d\"},{\"address\":2160072836,\"size\":26,\"sha256\":\"a6c321b91f7117631f99fa891f4929e00b94f85f9fa0d9373cd98edbae2c2727\"}]}";
    private static final long END=0x70000000L,KEY=0x81200000L,DATA=0x81210000L,INPUT=0x81220000L,OUTPUT=0x81230000L,LENGTH=0x81240000L,
        CACHE=0x80de6294L,NEW=0x80de62ccL,READY=0x80d81d40L,MAINTENANCE=0x80d81d3fL,REASON=0x80d81afcL,RETAINED=0x80dff738L,KEYBOARD=0x80d81ce8L,STOP=0x80c005b8L;
    private JsonObject cfg,c,stopped;private JsonArray actions,appends;private int steps,polls;private boolean locked;private String operation;
    private long a(String key){return cfg.get(key).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private long read(EmulatorHelper e,long at,int n){long v=0;byte[] b=e.readMemory(toAddr(at),n);for(int i=0;i<n;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private byte[] memory(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private String memoryHash(EmulatorHelper e,long at,int n)throws Exception{return hash(memory(e,at,n));}
    private String string(EmulatorHelper e,long at){StringBuilder out=new StringBuilder();for(int i=0;i<64;i++){int v=(int)read(e,at+i,1);if(v==0)return out.toString();out.append((char)v);}throw new IllegalStateException("String bound");}
    private String expectedKey(){return operation.equals("prefix")?"upgrade":c.get("key_name").getAsString();}
    private void keyArgument(EmulatorHelper e,int index){if(!string(e,r(e,index)).equals(expectedKey()))throw new IllegalStateException("Environment key");}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");if(locked)throw new IllegalStateException("Unbalanced lock");}
    private boolean entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if(operation.equals("prefix")&&pc==STOP){
                long sp=e.readRegister("sp").longValue();if(sp!=0x81001000L-0x150||read(e,sp+0x14c,4)!=END||locked)throw new IllegalStateException("Stopped prefix frame");
                for(int i=0;i<3;i++)if(read(e,sp+0x148-4L*i,4)!=0x45670000L+i)throw new IllegalStateException("Prefix saved frame");
                if(e.readRegister("s1").longValue()!=0x80d81a78L||e.readRegister("s2").longValue()!=KEYBOARD)throw new IllegalStateException("Prefix live frame");
                for(int i=3;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Prefix saved register");
                stopped=new JsonObject();stopped.addProperty("pc",pc);stopped.addProperty("sp",sp);stopped.addProperty("key_result",e.readRegister("s0").longValue()&0xffffffffL);stopped.addProperty("record_sha256",memoryHash(e,sp+0x14,298));return true;
            }
            if(pc==a("lock")){if(locked)throw new IllegalStateException("Recursive lock");locked=true;actions.add("env:lock");ret(e,0);continue;}
            if(pc==a("unlock")){if(!locked)throw new IllegalStateException("Unlock without lock");locked=false;actions.add("env:unlock");ret(e,0);continue;}
            if(pc==a("warn")){if(r(e,0)!=0x80c3696cL)throw new IllegalStateException("Unexpected environment diagnostic");actions.add("env:uninitialized");ret(e,0);continue;}
            if(pc==a("find")){if(!locked)throw new IllegalStateException("Find outside lock");keyArgument(e,0);boolean ok=c.get("found").getAsBoolean();long target=r(e,1);
                if(!(target==CACHE||(target>=0x81000000L&&target+56<=0x81001000L)))throw new IllegalStateException("Descriptor bound");actions.add("env:find:"+(ok?1:0));
                if(ok){e.writeMemory(toAddr(target),new byte[56]);put(e,target+12,4,HexFormat.of().parseHex(c.get("stored_hex").getAsString()).length);put(e,target+52,4,DATA);}ret(e,ok?1:0);continue;}
            if(pc==a("read")){int n=(int)r(e,2),size=HexFormat.of().parseHex(c.get("stored_hex").getAsString()).length;long status=c.get("read_status").getAsLong();
                if(!locked||r(e,0)!=DATA||r(e,1)!=OUTPUT||n<0||n>size||n>1024)throw new IllegalStateException("Environment read arguments");actions.add("env:read:"+n+":"+status);if(status==0)e.writeMemory(toAddr(OUTPUT),memory(e,DATA,n));ret(e,status);continue;}
            if(pc==a("strlen")){keyArgument(e,0);ret(e,expectedKey().length());continue;}
            if(pc==a("reserve")){int payload=operation.equals("prefix")?298:HexFormat.of().parseHex(c.get("payload_hex").getAsString()).length;
                if(!locked||r(e,0)!=NEW||r(e,1)!=payload+28+expectedKey().length())throw new IllegalStateException("Reserve extent");actions.add("env:reserve:"+r(e,1));ret(e,c.get("reserve_result").getAsLong());continue;}
            if(pc==a("append")){if(!locked||r(e,0)!=NEW||r(e,3)>512)throw new IllegalStateException("Append bounds");keyArgument(e,1);long source=r(e,2);int n=(int)r(e,3);
                if(!(source==INPUT||(operation.equals("prefix")&&source>=0x81000000L&&source+n<=0x81001000L)))throw new IllegalStateException("Append source");long status=c.get("append_status").getAsLong();
                actions.add("env:append:"+status);JsonObject value=new JsonObject();value.addProperty("key",expectedKey());value.addProperty("size",n);value.addProperty("sha256",memoryHash(e,source,n));value.addProperty("status",status);appends.add(value);ret(e,status);continue;}
            if(pc==a("remove")){if(!locked)throw new IllegalStateException("Remove outside lock");keyArgument(e,0);String kind;
                if(r(e,1)==0&&r(e,2)==1)kind="direct";else if(r(e,1)==CACHE&&r(e,2)==0)kind="mark";else if(r(e,1)==CACHE&&r(e,2)==1)kind="final";else throw new IllegalStateException("Remove arguments");
                long status=c.get("remove_"+kind).getAsLong();actions.add("env:remove:"+kind+":"+status);ret(e,status);continue;}
            if(pc==a("maintenance")){if(!locked||read(e,MAINTENANCE,1)==0)throw new IllegalStateException("Maintenance flag");actions.add("env:maintenance");put(e,MAINTENANCE,1,0);ret(e,c.get("maintenance_status").getAsLong());continue;}
            if(pc==a("commit"))actions.add("commit:no_op");
            if(pc==a("raw_reason")){if(r(e,0)<0x81000000L||r(e,0)+4>0x81001000L)throw new IllegalStateException("Raw reason output");actions.add("reason:raw");put(e,r(e,0),4,c.get("raw_reason").getAsLong());ret(e,c.get("raw_reason").getAsLong());continue;}
            if(pc==a("copy")){if(r(e,1)!=RETAINED||r(e,2)!=32||r(e,0)<0x81000000L||r(e,0)+32>0x81001000L)throw new IllegalStateException("Retained copy");actions.add("reason:retained");e.writeMemory(toAddr(r(e,0)),memory(e,RETAINED,32));ret(e,r(e,0));continue;}
            if(pc==a("power")){if(r(e,0)<0x81000000L||r(e,0)+4>0x81001000L)throw new IllegalStateException("Power output");actions.add("power");put(e,r(e,0),4,c.get("power_present").getAsBoolean()?1:0);ret(e,c.get("power_status").getAsLong());continue;}
            if(pc==a("keyboard_command")){long handle=operation.equals("prefix")?read(e,KEYBOARD,4):c.get("handle").getAsLong();
                if(r(e,0)!=handle||r(e,1)!=6||r(e,2)>1||r(e,4)!=0||r(e,3)<0x81000000L||r(e,3)>=0x81001000L||polls>=c.getAsJsonArray("polls").size())throw new IllegalStateException("Keyboard arguments/trace bound");
                JsonArray sample=c.getAsJsonArray("polls").get(polls++).getAsJsonArray();if(r(e,2)!=sample.get(0).getAsInt())throw new IllegalStateException("Keyboard sample index");int index=sample.get(0).getAsInt(),value=sample.get(1).getAsInt();long status=sample.get(2).getAsLong();
                actions.add("key:"+index+":"+value+":"+status);put(e,r(e,3),1,value);ret(e,status);continue;}
            if(pc==a("delay")){if(r(e,0)!=50)throw new IllegalStateException("Delay argument");actions.add("delay:50");ret(e,0);continue;}
            if(pc==a("zero")){if(!operation.equals("prefix")||r(e,1)!=0||r(e,2)!=298||r(e,0)<0x81000000L||r(e,0)+298>0x81001000L)throw new IllegalStateException("Upgrade clear bound");e.writeMemory(toAddr(r(e,0)),new byte[298]);ret(e,r(e,0));continue;}
            if(pc==a("strncpy")){if(!operation.equals("prefix")||r(e,1)!=0x80c32c30L||r(e,2)!=254||r(e,0)<0x81000000L||r(e,0)+254>0x81001000L)throw new IllegalStateException("Backup path arguments");
                byte[] target=new byte[254],source=string(e,r(e,1)).getBytes(java.nio.charset.StandardCharsets.US_ASCII);System.arraycopy(source,0,target,0,source.length);e.writeMemory(toAddr(r(e,0)),target);ret(e,r(e,0));continue;}
            if(pc==a("logger")){JsonElement name=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));if(name==null)throw new IllegalStateException("Unknown boot diagnostic "+Long.toHexString(r(e,3)));actions.add("log:"+name.getAsString());ret(e,0);continue;}
            if(pc==a("board_flag")){if(r(e,0)<220||r(e,0)>222)throw new IllegalStateException("Board flag argument");actions.add("boundary:flag:"+r(e,0));ret(e,0);continue;}
            if(pc==a("display")||pc==a("hw")||pc==a("board_init")){actions.add(pc==a("display")?"boundary:display":pc==a("hw")?"boundary:hw":"boundary:board_init");ret(e,pc==a("hw")?0x21000000L:0);continue;}
            if(pc==a("keyboard_register")){if(!string(e,r(e,0)).equals("keyboard")||r(e,1)!=KEYBOARD)throw new IllegalStateException("Keyboard registration");actions.add("keyboard:register");long status=c.get("register_status").getAsLong();if(status==0)put(e,KEYBOARD,4,c.get("handle").getAsLong());ret(e,status);continue;}
            if(pc==a("keyboard_init")){if(r(e,0)!=read(e,KEYBOARD,4)||r(e,1)!=0)throw new IllegalStateException("Keyboard initialization");actions.add("keyboard:init");ret(e,c.get("keyboard_init_status").getAsLong());continue;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);return false;
    }
    private JsonObject snapshot(EmulatorHelper e,JsonElement returned)throws Exception {
        JsonObject row=new JsonObject();row.add("returned",returned);row.addProperty("buffer_sha256",memoryHash(e,OUTPUT,1024));row.addProperty("length_output",read(e,LENGTH,4));row.addProperty("descriptor_sha256",memoryHash(e,CACHE,56));
        row.addProperty("maintenance_flag",read(e,MAINTENANCE,1));row.addProperty("reason_cache",read(e,REASON,4));row.addProperty("keyboard",read(e,KEYBOARD,4));row.addProperty("polls_consumed",polls);row.add("appends",appends.deepCopy());row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);
        byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long at:new long[]{OUTPUT+1024,LENGTH+4})if(!hash(guard).equals(memoryHash(e,at,32)))throw new IllegalStateException("Output guard changed");return row;
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;polls=0;locked=false;stopped=null;actions=new JsonArray();appends=new JsonArray();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] key=(c.get("key_name").getAsString()+"\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII),stored=HexFormat.of().parseHex(c.get("stored_hex").getAsString()),payload=HexFormat.of().parseHex(c.get("payload_hex").getAsString());
            e.writeMemory(toAddr(KEY),key);e.writeMemory(toAddr(DATA),stored.length==0?new byte[1]:stored);e.writeMemory(toAddr(INPUT),payload.length==0?new byte[1]:payload);
            byte[] out=new byte[1056];Arrays.fill(out,(byte)0xa5);e.writeMemory(toAddr(OUTPUT),out);byte[] length=new byte[36];Arrays.fill(length,(byte)0xa5);e.writeMemory(toAddr(LENGTH),length);byte[] descriptors=new byte[112];Arrays.fill(descriptors,(byte)0xa5);e.writeMemory(toAddr(CACHE),descriptors);
            put(e,READY,1,c.get("ready").getAsBoolean()?1:0);put(e,MAINTENANCE,1,c.get("maintenance_required").getAsLong());put(e,REASON,4,c.get("cached_reason").getAsLong());put(e,KEYBOARD,4,c.get("keyboard_initial").getAsLong());
            byte[] retained=new byte[32];e.writeMemory(toAddr(RETAINED),retained);put(e,RETAINED,4,c.get("retained_magic").getAsLong());put(e,RETAINED+4,4,c.get("retained_reason").getAsLong());retained=memory(e,RETAINED,32);JsonArray rows=new JsonArray();
            for(JsonElement element:c.getAsJsonArray("operations")){operation=element.getAsString();JsonElement returned=JsonNull.INSTANCE;
                if(operation.equals("get")){entry(e,a(operation),KEY,c.get("has_output").getAsBoolean()?OUTPUT:0,c.get("capacity").getAsInt(),c.get("size_output").getAsBoolean()?LENGTH:0);returned=new JsonPrimitive(r(e,0));}
                else if(operation.equals("set")){entry(e,a(operation),KEY,c.get("delete").getAsBoolean()?0:INPUT,payload.length);returned=new JsonPrimitive(r(e,0));}
                else if(operation.equals("key")){entry(e,a(operation),c.get("handle").getAsLong());returned=new JsonPrimitive(r(e,0));}
                else{boolean stop=entry(e,a(operation));if(!stop)returned=new JsonPrimitive(r(e,0));}rows.add(snapshot(e,returned));
            }
            if(!hash(key).equals(memoryHash(e,KEY,key.length))||!hash(stored).equals(memoryHash(e,DATA,stored.length))||!hash(payload).equals(memoryHash(e,INPUT,payload.length))||!hash(retained).equals(memoryHash(e,RETAINED,32)))throw new IllegalStateException("Input changed");
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/boot-environment-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement element:cfg.getAsJsonArray("guards")){JsonObject g=element.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized boot environment code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");JsonArray rows=new JsonArray();
        for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("BOOT_ENVIRONMENT_VALIDATION cases="+rows.size());
    }
}
