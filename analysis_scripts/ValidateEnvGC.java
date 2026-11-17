// Actual record relocation, collection, sector formatting and defaults restore.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.CRC32;

public class ValidateEnvGC extends GhidraScript {
    private static final String CONFIG="{\"find\":2160119286,\"get\":2160120644,\"next\":2160116580,\"header\":2160117784,\"reserve\":2160118386,\"retry\":2160118650,\"maintenance\":2160118550,\"walk\":2160119170,\"strlen\":2160256380,\"strncmp\":2160256488,\"read_service\":2160215110,\"gc\":2160120446,\"logger\":2160184698,\"diagnostic\":2160116000,\"space\":2160117784,\"memset\":2160254996,\"write_service\":2160215298,\"warn\":2160116256,\"move\":2160119724,\"format\":2160120196,\"collect\":2160120446,\"defaults\":2160120980,\"erase_service\":2160215486,\"strncpy\":2160256644,\"ranges\":[[2160115544,138],[2160115958,34],[2160116464,116],[2160116580,62],[2160116642,554],[2160117460,36],[2160117496,288],[2160117784,946],[2160119170,340],[2160120644,112],[2160121948,4],[2160069412,46],[2160115682,138],[2160117196,148],[2160116082,174],[2160117344,116],[2160118730,396],[2160119510,686],[2160120196,448],[2160120980,250]],\"guards\":[{\"address\":2160115544,\"size\":138,\"sha256\":\"5df71ee1e5c1a95510b0d9ae24a48b6e8306d816f108eb7f99aa2ad54cb7b291\"},{\"address\":2160115958,\"size\":34,\"sha256\":\"7076e3bafddb77bfe907f0e8071ef8f6310775756c59bc0ba895bb31b45ea3be\"},{\"address\":2160116464,\"size\":116,\"sha256\":\"1b2ca84d54a004229377b7e678c5d84f7ae480c062377993d3e058b8dcf84974\"},{\"address\":2160116580,\"size\":62,\"sha256\":\"1cace28b59db3729e0fbc3b3461842a5d7570e251021196d71063e6e41b37177\"},{\"address\":2160116642,\"size\":554,\"sha256\":\"84a649085765686ac8c74fcbdc457422f9ca780408b42c62901250c138816630\"},{\"address\":2160117460,\"size\":36,\"sha256\":\"1efcdb8311e3734144512ce0696388e23320c1b7c618d8ec1b1301197fc962c9\"},{\"address\":2160117496,\"size\":288,\"sha256\":\"f22d289445ef5b2d88a5d995f7dae3e9dc89278c58b52572c6e288dc4520279c\"},{\"address\":2160117784,\"size\":946,\"sha256\":\"7a71bf0bc8ede34c0faeb66baa52e75f0ef2b845b5a0c388d8ab4abd38af90e0\"},{\"address\":2160119170,\"size\":340,\"sha256\":\"2e4b1c0abccddab31aff41becdd1e014f1466b4a767ea8ba5877e643e3dcdaab\"},{\"address\":2160120644,\"size\":112,\"sha256\":\"b1de8c005c9fc2d7616dc10d4cf2d76f6b52d6b0e82cdb26d0f15cb01555f443\"},{\"address\":2160121948,\"size\":4,\"sha256\":\"f6b7ef06146c25d1eab3efa185a252b3158a3469ad935742c1ee264db32482f1\"},{\"address\":2160069412,\"size\":46,\"sha256\":\"08e0b6d64fe10875c94c5cb67b140355c1366be7b925e52f18d2b27dac4a6c1f\"},{\"address\":2160115682,\"size\":138,\"sha256\":\"ad86f07ceca51852ab059eebcfe0eb6614ffac510716af38e62e936d9a9fa58d\"},{\"address\":2160117196,\"size\":148,\"sha256\":\"643357fd979ffc4cc70bde9d88ae0d5d1836bfbf4516699e5ba27a7f6479f779\"},{\"address\":2160116082,\"size\":174,\"sha256\":\"ba51f197ea5dfefe3d4d5ce463ea61ece57d32845427ec1dd181823be559dbb3\"},{\"address\":2160117344,\"size\":116,\"sha256\":\"c7625c1ddd7a87e0f292a856495be3e5a54b3a8eb78a576c9f3a1edc671dfec5\"},{\"address\":2160118730,\"size\":396,\"sha256\":\"4eb6b0c15b4d694f7e12b5fac15dc443ce04812b509a53e2042070db3b9101fd\"},{\"address\":2160119510,\"size\":686,\"sha256\":\"b4179edd19359f0682617450ff139614dae8cae084400ca5321021452437daf8\"},{\"address\":2160120196,\"size\":448,\"sha256\":\"c7314fb6c4f8a3d72176c4144aa18298fc84cb6148b30b375d6cb4fc976888a5\"},{\"address\":2160120980,\"size\":250,\"sha256\":\"f69b3e506f3705a49cc3b58deb408530e07bbc6ba9641074efc10c72496944fa\"},{\"address\":2160275084,\"size\":1024,\"sha256\":\"12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86\"}]}";
    private static final long END=0x70000000L,BASE=0L,KEY=0x81300000L,DESC=0x81210000L,OUTPUT=0x81220000L,
        LENGTH=0x81230000L,HEADER=0x81240000L,CONTEXT=0x81250000L,CACHE=0x80de6304L;
    private JsonObject cfg,c;private JsonArray actions;private byte[] flash;private int steps,writeCount,eraseCount;
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long value){e.writeMemoryValue(toAddr(at),n,value);}
    private long read(EmulatorHelper e,long at,int n){byte[] b=e.readMemory(toAddr(at),n);long v=0;for(int i=0;i<n;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private byte[] mem(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private long crc(byte[] b){CRC32 crc=new CRC32();crc.update(b);return crc.getValue();}
    private void word(byte[] b,int at,long v){for(int i=0;i<4;i++)b[at+i]=(byte)(v>>(8*i));}
    private boolean pointer(long p,int n){return p>=0x81000000L&&p+n<=0x81001000L||p>=0x81300000L&&p+n<=0x81350000L||p>=DESC&&p+n<=DESC+56||p>=OUTPUT&&p+n<=OUTPUT+256||p>=HEADER&&p+n<=HEADER+24||p>=CONTEXT&&p+n<=CONTEXT+24;}
    private String string(EmulatorHelper e,long p){StringBuilder s=new StringBuilder();for(int i=0;i<33;i++){int v=(int)read(e,p+i,1);if(v==0)return s.toString();s.append((char)v);}throw new IllegalStateException("Key bound");}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>1000000)throw new IllegalStateException("Execution bound");
            if(pc==a("memset")){int n=(int)r(e,2);if(n<0||!pointer(r(e,0),n))throw new IllegalStateException("Memset bound");byte[] b=new byte[n];Arrays.fill(b,(byte)r(e,1));e.writeMemory(toAddr(r(e,0)),b);ret(e,r(e,0));continue;}
            if(pc==a("write_service")){long address=r(e,1),source=r(e,2);int n=(int)r(e,3);if(r(e,0)!=34||n<0||n>128||address<0||address+n>flash.length||!pointer(source,n))throw new IllegalStateException("Write arguments");
                byte[] data=mem(e,source,n);++writeCount;long result=writeCount==c.get("fail_write").getAsInt()?-1:writeCount==c.get("short_write").getAsInt()?c.get("short_count").getAsInt():n;
                actions.add("write:"+address+":"+n+":"+result+":"+hash(data));if(result>=0)for(int i=0;i<Math.min(n,result);i++)flash[(int)address+i]&=data[i];ret(e,result);continue;}
            if(pc==a("erase_service")){long address=r(e,1);if(r(e,0)!=34||r(e,2)!=4096||address<0||address+4096>flash.length||(address&0xfff)!=0)throw new IllegalStateException("Erase arguments");
                ++eraseCount;long result=eraseCount==c.get("fail_erase").getAsInt()?-1:0;actions.add("erase:"+address+":4096:"+result);if(result>=0)Arrays.fill(flash,(int)address,(int)address+4096,(byte)0xff);ret(e,result);continue;}
            if(pc==a("strncpy")){int n=(int)r(e,2);if(n<0||n>32||!pointer(r(e,0),n)||!pointer(r(e,1),n))throw new IllegalStateException("Copy-name arguments");byte[] b=new byte[n],source=mem(e,r(e,1),n);for(int i=0;i<n&&source[i]!=0;i++)b[i]=source[i];e.writeMemory(toAddr(r(e,0)),b);ret(e,r(e,0));continue;}
            if(pc==a("warn")){if(r(e,0)!=0x80c36660L)throw new IllegalStateException("Unexpected record warning");actions.add("warn:record_integrity");ret(e,0);continue;}
            if(pc==a("logger")){long kind=r(e,7);if(kind==0x80c36498L)actions.add("log:write_error");else if(kind==0x80c364a8L)actions.add("log:erase_error");else throw new IllegalStateException("Unexpected storage diagnostic");ret(e,0);continue;}
            if(pc==a("read_service")){long address=r(e,1),target=r(e,2);int n=(int)r(e,3);
                if(r(e,0)!=34||n<0||n>256||address<BASE||address+n>BASE+flash.length||!pointer(target,n))throw new IllegalStateException("Read arguments");
                actions.add("read:"+address+":"+n);if(n>0)e.writeMemory(toAddr(target),Arrays.copyOfRange(flash,(int)(address-BASE),(int)(address-BASE)+n));ret(e,n);continue;}
            if(pc==a("strlen")){if(!pointer(r(e,0),1))throw new IllegalStateException("String pointer");ret(e,string(e,r(e,0)).length());continue;}
            if(pc==a("strncmp")){int n=(int)r(e,2);if(n<0||n>32||!pointer(r(e,0),n)||!pointer(r(e,1),n))throw new IllegalStateException("Compare arguments");
                byte[] x=mem(e,r(e,0),n),y=mem(e,r(e,1),n);int value=0;for(int i=0;i<n;i++){value=(x[i]&255)-(y[i]&255);if(value!=0||x[i]==0)break;}ret(e,value);continue;}
            if(pc==a("diagnostic")){long line=r(e,1);if(line!=0x506&&line!=0x603&&line!=0x5b4&&line!=0x283&&line!=0x5a4&&line!=0x5e9&&line!=0x5f0&&line!=0x68c)throw new IllegalStateException("Unexpected diagnostic "+Long.toHexString(line));actions.add("diagnostic:"+Long.toHexString(line));ret(e,0);continue;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long at=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=at&&pc<at+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }
        if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved-register mismatch");
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;writeCount=0;eraseCount=0;actions=new JsonArray();flash=new byte[0x4000];Arrays.fill(flash,(byte)0xff);
        for(int i=0;i<4;i++){
            JsonObject s=c.getAsJsonArray("sectors").get(i).getAsJsonObject();int at=i*4096,p=s.get("primary").getAsInt(),d=s.get("dirty").getAsInt();if(p>0)flash[at+p-1]=0;if(d>0)flash[at+3+d-1]=0;
            System.arraycopy((s.get("valid").getAsBoolean()?"EF40":"BAD!").getBytes(java.nio.charset.StandardCharsets.US_ASCII),0,flash,at+8,4);word(flash,at+12,s.get("link").getAsLong());
        }
        for(JsonElement item:c.getAsJsonArray("records")){
            JsonObject row=item.getAsJsonObject();byte[] name=row.get("key").getAsString().getBytes(java.nio.charset.StandardCharsets.US_ASCII),payload=HexFormat.of().parseHex(row.get("payload_hex").getAsString()),data=new byte[28+name.length+payload.length];Arrays.fill(data,(byte)0xff);
            int status=row.get("state").getAsInt();if(status>0)data[status-1]=0;System.arraycopy("KV40".getBytes(java.nio.charset.StandardCharsets.US_ASCII),0,data,8,4);word(data,12,data.length);data[20]=(byte)name.length;word(data,24,payload.length);
            System.arraycopy(name,0,data,28,name.length);System.arraycopy(payload,0,data,28+name.length,payload.length);word(data,16,crc(Arrays.copyOfRange(data,20,data.length)));if(row.get("bad_crc").getAsBoolean())data[16]^=1;if(!row.get("total_override").isJsonNull())word(data,12,row.get("total_override").getAsLong());
            int off=row.get("offset").getAsInt();System.arraycopy(data,0,flash,off,data.length);
        }
        for(JsonElement item:c.getAsJsonArray("patches")){JsonObject p=item.getAsJsonObject();byte[] data=HexFormat.of().parseHex(p.get("hex").getAsString());System.arraycopy(data,0,flash,p.get("offset").getAsInt(),data.length);}
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] key=(c.get("key").getAsString()+"\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII);e.writeMemory(toAddr(KEY),key);
            for(long at:new long[]{OUTPUT,LENGTH,DESC,HEADER,CONTEXT}){int n=at==OUTPUT?288:at==LENGTH?36:at==DESC?88:56;byte[] b=new byte[n];Arrays.fill(b,(byte)0xa5);e.writeMemory(toAddr(at),b);if(at!=OUTPUT&&at!=LENGTH)e.writeMemory(toAddr(at),new byte[n-32]);}
            byte[] index=new byte[128];Arrays.fill(index,(byte)0xff);e.writeMemory(toAddr(CACHE),index);byte[] sectors=new byte[32];Arrays.fill(sectors,(byte)0xff);e.writeMemory(toAddr(0x80de62e4L),sectors);
            for(JsonElement item:c.getAsJsonArray("warm_cache")){JsonObject row=item.getAsJsonObject();long p=0x80de62e4L+row.get("slot").getAsLong()*8;put(e,p,4,row.get("sector").getAsLong()*4096);put(e,p+4,4,row.get("cursor").getAsLong());}
            if(c.get("source_cache").getAsBoolean()){put(e,CACHE,2,crc("upgrade".getBytes(java.nio.charset.StandardCharsets.US_ASCII))>>16);put(e,CACHE+2,2,0);put(e,CACHE+4,4,20);}
            if(c.getAsJsonArray("records").size()>0){JsonObject first=c.getAsJsonArray("records").get(0).getAsJsonObject();byte[] name=first.get("key").getAsString().getBytes(java.nio.charset.StandardCharsets.US_ASCII),payload=HexFormat.of().parseHex(first.get("payload_hex").getAsString());long address=first.get("offset").getAsLong();
                put(e,DESC,1,first.get("state").getAsInt());put(e,DESC+1,1,1);put(e,DESC+2,1,name.length);put(e,DESC+8,4,28+name.length+payload.length);put(e,DESC+12,4,payload.length);e.writeMemory(toAddr(DESC+16),name);put(e,DESC+48,4,address);put(e,DESC+52,4,address+28+name.length);}
            JsonObject sourceSector=c.getAsJsonArray("sectors").get(0).getAsJsonObject();put(e,HEADER,1,c.get("source_valid").getAsBoolean()?1:0);put(e,HEADER+1,1,sourceSector.get("primary").getAsInt());put(e,HEADER+2,1,sourceSector.get("dirty").getAsInt());put(e,HEADER+4,4,0);
            int defaultCount=c.getAsJsonArray("defaults").size();byte[] defaultsBytes=new byte[defaultCount*12];int defaultIndex=0;
            for(JsonElement item:c.getAsJsonArray("defaults")){JsonObject d=item.getAsJsonObject();long k=0x81300100L+defaultIndex*64,v=0x81301000L+defaultIndex*64;
                e.writeMemory(toAddr(k),(d.get("key").getAsString()+"\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII));e.writeMemory(toAddr(v),(d.get("value").getAsString()+"\0").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                word(defaultsBytes,defaultIndex*12,k);word(defaultsBytes,defaultIndex*12+4,v);word(defaultsBytes,defaultIndex*12+8,d.get("length").getAsLong());defaultIndex++;}
            e.writeMemory(toAddr(0x81340000L),defaultsBytes);
            put(e,0x80d81d4cL,4,0);put(e,0x80d81d30L,4,34);put(e,0x80d81d38L,4,0);put(e,0x80d81d40L,1,1);put(e,0x80d81d3fL,1,c.get("maintenance_flag").getAsLong());
            put(e,0x80d81d3dL,1,c.get("pending").getAsLong());put(e,0x80d81d3eL,1,c.get("duplicate_guard").getAsBoolean()?1:0);put(e,0x80d81d44L,4,defaultCount);put(e,0x80d81d48L,4,0x81340000L);
            JsonArray snapshots=new JsonArray();
            for(JsonElement item:c.getAsJsonArray("operations")){String operation=item.getAsString();
                if(operation.equals("move"))entry(e,a(operation),DESC);
                else if(operation.equals("collect"))entry(e,a(operation),HEADER);
                else if(operation.equals("format"))entry(e,a(operation),c.get("format_sector").getAsLong()*4096);
                else if(operation.equals("maintenance")||operation.equals("defaults"))entry(e,a(operation));
                else throw new IllegalStateException("Unknown operation");
                JsonObject row=new JsonObject();row.add("returned",operation.equals("maintenance")?JsonNull.INSTANCE:new JsonPrimitive(r(e,0)));
                row.addProperty("flash_sha256",hash(flash));row.addProperty("sector_cache_sha256",hash(mem(e,0x80de62e4L,32)));row.addProperty("key_cache_sha256",hash(mem(e,CACHE,128)));
                row.addProperty("pending_replace",read(e,0x80d81d3dL,1));row.addProperty("maintenance_flag",read(e,0x80d81d3fL,1));snapshots.add(row);
            }
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",snapshots);
            byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long at:new long[]{OUTPUT+256,LENGTH+4,DESC+56,HEADER+24,CONTEXT+24})if(!hash(guard).equals(hash(mem(e,at,32))))throw new IllegalStateException("Output guard changed");
            if(!hash(key).equals(hash(mem(e,KEY,key.length))))throw new IllegalStateException("Key changed");
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/env-gc-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized scan code/table");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");JsonArray rows=new JsonArray();
        for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",1000000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("ENV_GC_VALIDATION cases="+rows.size());
    }
}
