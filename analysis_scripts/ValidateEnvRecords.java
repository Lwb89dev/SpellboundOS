// Native environment records over supplied synthetic storage and sector scan.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.CRC32;

public class ValidateEnvRecords extends GhidraScript {
    private static final String CONFIG="{\"append\":2160118730,\"decode\":2160117496,\"remove\":2160119510,\"get\":2160120644,\"set\":2160120756,\"read\":2160115544,\"write\":2160115682,\"status\":2160117196,\"strlen\":2160256380,\"memset\":2160254996,\"strncmp\":2160256488,\"read_service\":2160215110,\"write_service\":2160215298,\"reserve\":2160118650,\"scan\":2160119170,\"diagnostic\":2160116000,\"warn\":2160116256,\"logger\":2160184698,\"ranges\":[[2160115544,276],[2160115958,34],[2160116464,116],[2160116642,170],[2160117196,264],[2160117496,288],[2160118730,396],[2160119286,438],[2160120644,336],[2160121948,4],[2160069412,46]],\"guards\":[{\"address\":2160115544,\"size\":276,\"sha256\":\"21a1b4f5cd9656531ea80fdaa2a12a636292499104fc732d8bfbe8581c997cdb\"},{\"address\":2160115958,\"size\":34,\"sha256\":\"7076e3bafddb77bfe907f0e8071ef8f6310775756c59bc0ba895bb31b45ea3be\"},{\"address\":2160116464,\"size\":116,\"sha256\":\"1b2ca84d54a004229377b7e678c5d84f7ae480c062377993d3e058b8dcf84974\"},{\"address\":2160116642,\"size\":170,\"sha256\":\"330a84a951d47f46aa93b118c66704b90a6a6405ce54203afd00a02afcd539d1\"},{\"address\":2160117196,\"size\":264,\"sha256\":\"3c268f64fe00f3dd2fad4807df47b0773b5f11020e1037f7c3a2c67476fa04dc\"},{\"address\":2160117496,\"size\":288,\"sha256\":\"f22d289445ef5b2d88a5d995f7dae3e9dc89278c58b52572c6e288dc4520279c\"},{\"address\":2160118730,\"size\":396,\"sha256\":\"4eb6b0c15b4d694f7e12b5fac15dc443ce04812b509a53e2042070db3b9101fd\"},{\"address\":2160119286,\"size\":438,\"sha256\":\"fbbe29b33af05145ae0545f3888874c8ccd79187d2c1defb1b66729415ba2aba\"},{\"address\":2160120644,\"size\":336,\"sha256\":\"96ec9efd27e8cf5624341fde8eb92aa0cc739dc8ef16e3118e3dba715fe6f3b2\"},{\"address\":2160121948,\"size\":4,\"sha256\":\"f6b7ef06146c25d1eab3efa185a252b3158a3469ad935742c1ee264db32482f1\"},{\"address\":2160069412,\"size\":46,\"sha256\":\"08e0b6d64fe10875c94c5cb67b140355c1366be7b925e52f18d2b27dac4a6c1f\"},{\"address\":2160275084,\"size\":1024,\"sha256\":\"12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86\"}]}";
    private static final long END=0x70000000L,KEY=0x81200000L,INPUT=0x81210000L,OUTPUT=0x81220000L,LENGTH=0x81230000L,DESC=0x81240000L,CONTEXT=0x81250000L,
        CACHE=0x80de6304L,OLD=0x6014L,CURSOR=0x7014L,BASE=0x4000L;
    private JsonObject cfg,c;private JsonArray actions;private byte[] flash;private int steps,writes;
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private long read(EmulatorHelper e,long at,int n){byte[] b=e.readMemory(toAddr(at),n);long v=0;for(int i=0;i<n;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private byte[] mem(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private long crc(byte[] b){CRC32 crc=new CRC32();crc.update(b);return crc.getValue();}
    private void word(byte[] b,int at,long v){for(int i=0;i<4;i++)b[at+i]=(byte)(v>>(8*i));}
    private byte[] bytes(String field){return HexFormat.of().parseHex(c.get(field).getAsString());}
    private String string(EmulatorHelper e,long at){StringBuilder s=new StringBuilder();for(int i=0;i<34;i++){int v=(int)read(e,at+i,1);if(v==0)return s.toString();s.append((char)v);}throw new IllegalStateException("String bound");}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private byte[] storage(long at,int n){if(n==0)return new byte[0];int off=(int)(at-BASE);if(off<0||off+n>flash.length)throw new IllegalStateException("Storage bound "+Long.toHexString(at)+" "+n);return Arrays.copyOfRange(flash,off,off+n);}
    private void seed(long at,byte[] b){int off=(int)(at-BASE);if(off<0||off+b.length>flash.length)throw new IllegalStateException("Seed bound");System.arraycopy(b,0,flash,off,b.length);}
    private void context(EmulatorHelper e,long at){e.writeMemory(toAddr(at),new byte[24]);put(e,at+1,1,c.get("context_state").getAsInt());put(e,at+4,4,CURSOR&~0xfffL);put(e,at+16,4,c.get("free").getAsLong());put(e,at+20,4,c.get("cursor").getAsLong());}
    private boolean pointer(long at,int n){return at>=0x81000000L&&at+n<=0x81001000L||at>=KEY&&at+n<=KEY+34||at>=INPUT&&at+n<=INPUT+4077||at>=OUTPUT&&at+n<=OUTPUT+4096||at>=DESC&&at+n<=DESC+56||at>=0x80de6294L&&at+n<=0x80de6304L;}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>200000)throw new IllegalStateException("Execution bound");
            if(pc==a("memset")){int n=(int)r(e,2);if(n<0||!pointer(r(e,0),n))throw new IllegalStateException("Memset bound");byte[] b=new byte[n];Arrays.fill(b,(byte)r(e,1));e.writeMemory(toAddr(r(e,0)),b);ret(e,r(e,0));continue;}
            if(pc==a("strlen")){String key=string(e,r(e,0));if(!key.equals(c.get("key").getAsString()))throw new IllegalStateException("Key argument");ret(e,key.length());continue;}
            if(pc==a("strncmp")){int n=(int)r(e,2);if(r(e,0)!=KEY||n!=c.get("key").getAsString().length()||!pointer(r(e,1),n))throw new IllegalStateException("Name comparison");byte[] x=mem(e,r(e,0),n),y=mem(e,r(e,1),n);int value=0;for(int i=0;i<n;i++){value=(x[i]&255)-(y[i]&255);if(value!=0||x[i]==0)break;}ret(e,value);continue;}
            if(pc==a("read_service")||pc==a("write_service")){
                boolean writing=pc==a("write_service");long handle=r(e,0),offset=r(e,1),source=r(e,2);int n=(int)r(e,3);
                if(n<0||n>4096||!pointer(source,n))throw new IllegalStateException("Storage pointer bound");
                long physical=handle==17?offset+BASE:offset,result=n;
                if(writing){writes++;if(writes==c.get("fault_write").getAsInt())result=c.get("write_result").getAsLong();}
                else if(!c.get("read_result").isJsonNull())result=c.get("read_result").getAsLong();
                String action=(writing?"write:":"read:")+handle+":"+offset+":"+n+":"+result;
                if(writing){byte[] data=mem(e,source,n);action+=":"+hash(data);if(result>=0){int count=(int)Math.min(n,result);byte[] before=storage(physical,count);for(int i=0;i<count;i++)before[i]&=data[i];seed(physical,before);}}
                else if(result>=0){byte[] data=storage(physical,(int)Math.min(n,result));if(data.length!=0)e.writeMemory(toAddr(source),data);}
                actions.add(action);ret(e,result);continue;
            }
            if(pc==a("reserve")){long target=r(e,0),size=r(e,1);if(!(target==CONTEXT||target==0x80de62ccL)||size!=28+c.get("key").getAsString().length()+bytes("payload_hex").length)throw new IllegalStateException("Reservation arguments");
                actions.add("boundary:reserve:"+size);context(e,target);long result=c.get("reserve_result").getAsLong();put(e,target+20,4,result);ret(e,result);continue;}
            if(pc==0x80c0cd82L){if(r(e,1)!=KEY||r(e,3)!=0x80c0c54cL||!pointer(r(e,0),56)||!pointer(r(e,2),1))throw new IllegalStateException("Sector scan arguments");actions.add("boundary:scan_miss");ret(e,0);continue;}
            if(pc==0x80c0cb16L){if(read(e,0x80d81d3fL,1)==0)throw new IllegalStateException("Maintenance without flag");actions.add("boundary:maintenance");put(e,0x80d81d3fL,1,0);ret(e,0);continue;}
            if(pc==0x80c0c220L){long at=r(e,0);if(at==0x80c36740L)actions.add("warn:key_length");else if(at==0x80c3676cL)actions.add("warn:record_length");else throw new IllegalStateException("Unexpected warning");ret(e,0);continue;}
            if(pc==0x80c0c120L){long line=r(e,1);if(line!=0x68c&&line!=0x526)throw new IllegalStateException("Unexpected diagnostic "+Long.toHexString(line));actions.add("diagnostic:"+Long.toHexString(line));ret(e,0);continue;}
            if(pc==0x80c1cd7aL){long kind=r(e,7);if(kind==0x80c364c8L)actions.add("log:read_error");else if(kind==0x80c36498L)actions.add("log:write_error");else throw new IllegalStateException("Unexpected storage logger");ret(e,0);continue;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }
        if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");
    }
    private JsonObject snapshot(EmulatorHelper e,JsonElement returned)throws Exception {
        JsonObject row=new JsonObject();row.add("returned",returned);row.addProperty("flash_sha256",hash(flash));row.addProperty("output_sha256",hash(mem(e,OUTPUT,4096)));row.addProperty("descriptor_sha256",hash(mem(e,DESC,56)));
        row.addProperty("length_output",read(e,LENGTH,4));row.addProperty("key_cache_record",read(e,CACHE+4,4));row.addProperty("sector_cache_end",read(e,0x80de62e8L,4));row.addProperty("maintenance_flag",read(e,0x80d81d3fL,1));row.addProperty("pending_replace",read(e,0x80d81d3dL,1));
        byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long at:new long[]{OUTPUT+4096,LENGTH+4,DESC+56,CONTEXT+56})if(!hash(guard).equals(hash(mem(e,at,32))))throw new IllegalStateException("Output guard changed");return row;
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;writes=0;actions=new JsonArray();flash=new byte[0x8000];Arrays.fill(flash,(byte)0xff);EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            for(long sector:new long[]{0x6000L,0x7000L}){byte[] marker=new byte[]{(byte)0xff,(byte)0xff,(byte)0xff};int s=c.get("sector_state").getAsInt();if(s>0)marker[s-1]=0;seed(sector+3,marker);
                byte[] primary=new byte[]{(byte)0xff,(byte)0xff,(byte)0xff};int p=sector==0x7000L?c.get("context_state").getAsInt():2;if(p>0)primary[p-1]=0;seed(sector,primary);}
            byte[] name=c.get("key").getAsString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            if(c.get("existing").getAsBoolean()){
                byte[] old=bytes("old_hex"),value=new byte[28+name.length+old.length];Arrays.fill(value,(byte)0xff);value[0]=0;value[1]=0;
                System.arraycopy("KV40".getBytes(java.nio.charset.StandardCharsets.US_ASCII),0,value,8,4);word(value,12,value.length);value[20]=(byte)name.length;word(value,24,old.length);
                System.arraycopy(name,0,value,28,name.length);System.arraycopy(old,0,value,28+name.length,old.length);word(value,16,crc(Arrays.copyOfRange(value,20,value.length)));
                if(c.get("bad_crc").getAsBoolean())value[16]^=1;if(c.get("bad_magic").getAsBoolean())System.arraycopy(new byte[]{66,65,68,33},0,value,8,4);seed(OLD,value);
            }
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            e.writeMemory(toAddr(KEY),Arrays.copyOf(name,name.length+1));byte[] payload=bytes("payload_hex");e.writeMemory(toAddr(INPUT),payload.length==0?new byte[1]:payload);
            for(long at:new long[]{OUTPUT,LENGTH,DESC,CONTEXT}){int n=at==OUTPUT?4128:at==LENGTH?36:88;byte[] b=new byte[n];Arrays.fill(b,(byte)0xa5);e.writeMemory(toAddr(at),b);}
            e.writeMemory(toAddr(DESC),new byte[56]);put(e,DESC+48,4,OLD);context(e,CONTEXT);context(e,0x80de62ccL);e.writeMemory(toAddr(0x80de6294L),new byte[56]);
            byte[] index=new byte[128];Arrays.fill(index,(byte)0xff);e.writeMemory(toAddr(CACHE),index);byte[] sectorIndex=new byte[32];Arrays.fill(sectorIndex,(byte)0xff);e.writeMemory(toAddr(0x80de62e4L),sectorIndex);
            if(c.get("existing").getAsBoolean()){put(e,CACHE,2,crc(name)>>16);put(e,CACHE+2,2,0);put(e,CACHE+4,4,OLD);}
            put(e,0x80d81d28L,4,c.get("special").getAsLong());put(e,0x80d81d30L,4,c.get("general").getAsLong());put(e,0x80d81d34L,4,c.get("fallback").getAsLong());put(e,0x80d81d38L,4,0);
            put(e,0x80d81d3dL,1,0);put(e,0x80d81d3fL,1,0);put(e,0x80d81d40L,1,1);JsonArray rows=new JsonArray();
            for(JsonElement op:c.getAsJsonArray("operations")){String operation=op.getAsString();JsonElement returned=JsonNull.INSTANCE;
                if(operation.equals("append"))entry(e,a(operation),CONTEXT,KEY,INPUT,payload.length);
                else if(operation.equals("decode"))entry(e,a(operation),DESC);
                else if(operation.equals("remove"))entry(e,a(operation),KEY,0,c.get("final").getAsBoolean()?1:0);
                else if(operation.equals("get"))entry(e,a(operation),KEY,OUTPUT,c.get("capacity").getAsLong(),LENGTH);
                else if(operation.equals("set"))entry(e,a(operation),KEY,INPUT,payload.length);
                else if(operation.equals("read"))entry(e,a(operation),c.get("address").getAsLong(),OUTPUT,c.get("capacity").getAsLong());
                else if(operation.equals("write"))entry(e,a(operation),c.get("address").getAsLong(),INPUT,payload.length);
                else throw new IllegalStateException("Unknown operation");
                if(!operation.equals("decode"))returned=new JsonPrimitive(r(e,0));rows.add(snapshot(e,returned));
            }
            if(!hash(Arrays.copyOf(name,name.length+1)).equals(hash(mem(e,KEY,name.length+1)))||!hash(payload).equals(hash(mem(e,INPUT,payload.length))))throw new IllegalStateException("Input changed");
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/env-records-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized environment code/table");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");JsonArray rows=new JsonArray();
        for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",200000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("ENV_RECORD_VALIDATION cases="+rows.size());
    }
}
