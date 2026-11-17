// Read-only boot validation with synthetic partitions and supplied SHA/ECDSA services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateRecoveryValidator extends GhidraScript {
    private static final String CONFIG="{\"raw_crc\":2160069458,\"crc\":2160069412,\"metadata\":2160125304,\"image\":2160125674,\"partition\":2160125920,\"wrapper\":2160126402,\"signature\":2160124866,\"signature_callback\":2160124812,\"alloc\":2160173832,\"free\":2160173842,\"zero\":2160254996,\"copy\":2160254520,\"strncpy\":2160256644,\"strncmp\":2160256488,\"open\":2160113600,\"read\":2160113708,\"close\":2160113704,\"board_ota\":2160070776,\"board_hw\":2160070792,\"sha_init\":2160245042,\"sha_update\":2160245144,\"sha_final\":2160245276,\"crypto\":2160248244,\"clock\":2160157742,\"logger\":2160184698,\"key_sha256\":\"436da64f07264e8d1ddf568e7ec0edce6e52ea0f469af4ca54a36a2761aff547\",\"ranges\":[[2160069412,84],[2160124228,684],[2160125304,1108],[2160248234,10]],\"logs\":{\"2160291504\":\"ota_absent\",\"2160291576\":\"hw_unknown\",\"2160291536\":\"hw_compare\",\"2160291604\":\"magic\",\"2160291652\":\"product\",\"2160291120\":\"signature_short\",\"2160291032\":\"signature_alloc\",\"2160291084\":\"signature_rejected\"},\"guards\":[{\"address\":2160069412,\"size\":84,\"sha256\":\"4eb88ef657bf687d1f4f783909cdfdb382e2d1e448adb4099e6b2a28060a918d\"},{\"address\":2160124228,\"size\":684,\"sha256\":\"93ca276368ff8642b09a07f594bc7e78b48095796d006235eb35db56542a41f1\"},{\"address\":2160125304,\"size\":1108,\"sha256\":\"909f7190db39df3157b2464c8656f0b4ca8d11b5a398abee741a0ca1bc718665\"},{\"address\":2160248234,\"size\":10,\"sha256\":\"861b635a88f3c06e729b36f7fbc81130e516f6ba92affd0340a83e66a888f06c\"},{\"address\":2160275084,\"size\":1024,\"sha256\":\"12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86\"},{\"address\":2160290964,\"size\":64,\"sha256\":\"436da64f07264e8d1ddf568e7ec0edce6e52ea0f469af4ca54a36a2761aff547\"}]}";
    private static final long END=0x70000000L,PROGRESS=0x70000100L,FILE=0x81200000L,OUTPUT=0x81120000L,HEADER=0x81100000L,BUFFER=0x81110000L;
    private JsonObject cfg,c;private JsonArray actions,crypto;private byte[] file;private int steps;private long shaContext,signaturePointer;private MessageDigest sha;private boolean hashing;
    private final SortedMap<Integer,Boolean> allocations=new TreeMap<>();
    private long a(String key){return cfg.get(key).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private long read(EmulatorHelper e,long at,int n){long v=0;byte[] b=e.readMemory(toAddr(at),n);for(int i=0;i<n;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private byte[] memory(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private String memoryHash(EmulatorHelper e,long at,int n)throws Exception{return hash(memory(e,at,n));}
    private String string(EmulatorHelper e,long at){StringBuilder out=new StringBuilder();for(int i=0;i<64;i++){int ch=(int)read(e,at+i,1);if(ch==0)return out.toString();out.append((char)ch);}throw new IllegalStateException("String bound");}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if(pc==a("logger")){long message=r(e,3);
                if(message==0x80c36dfcL)actions.add("log:error:"+Long.toHexString(read(e,e.readRegister("sp").longValue(),4)));
                else if(message==0x80c36f80L)actions.add("log:image");
                else {JsonElement label=cfg.getAsJsonObject("logs").get(Long.toString(message));if(label==null)throw new IllegalStateException("Unexpected log "+Long.toHexString(message));actions.add("log:"+label.getAsString());}ret(e,0);continue;}
            if(pc==a("board_ota")||pc==a("board_hw")){boolean ota=pc==a("board_ota");actions.add(ota?"board:ota":"board:hw");ret(e,ota?(c.get("board_ota").getAsBoolean()?1:0):c.get("board_hw").getAsLong());continue;}
            if(pc==a("alloc")){int n=(int)r(e,0);if(n!=72&&n!=4096)throw new IllegalStateException("Allocator size");boolean ok=c.get("allocation_failure").getAsInt()!=n;
                actions.add((ok?"alloc:":"alloc_fail:")+n);long ptr=n==72?HEADER:BUFFER;if(ok){if(allocations.containsKey(n))throw new IllegalStateException("Repeated allocation");allocations.put(n,false);byte[] b=new byte[n+32];Arrays.fill(b,(byte)0xa5);e.writeMemory(toAddr(ptr),b);}ret(e,ok?ptr:0);continue;}
            if(pc==a("free")){long ptr=r(e,0);int n=ptr==HEADER?72:ptr==BUFFER?4096:0;if(n==0||!allocations.containsKey(n)||allocations.get(n))throw new IllegalStateException("Free ownership");allocations.put(n,true);actions.add("free:"+n);ret(e,0);continue;}
            if(pc==a("zero")){if(r(e,0)!=HEADER||r(e,1)!=0||r(e,2)!=72)throw new IllegalStateException("Header clear arguments");e.writeMemory(toAddr(HEADER),new byte[72]);ret(e,HEADER);continue;}
            if(pc==a("copy")){int n=(int)r(e,2);if(n<0||n>64)throw new IllegalStateException("Copy bound");e.writeMemory(toAddr(r(e,0)),memory(e,r(e,1),n));ret(e,r(e,0));continue;}
            if(pc==a("strncpy")){int n=(int)r(e,2);if(n<0||n>16)throw new IllegalStateException("Version copy bound");byte[] b=new byte[n];boolean end=false;for(int i=0;i<n;i++){int v=end?0:(int)read(e,r(e,1)+i,1);b[i]=(byte)v;if(v==0)end=true;}e.writeMemory(toAddr(r(e,0)),b);ret(e,r(e,0));continue;}
            if(pc==a("strncmp")){if(r(e,2)!=15)throw new IllegalStateException("Version comparison length");int result=0;for(int i=0;i<15;i++){int first=(int)read(e,r(e,0)+i,1),second=(int)read(e,r(e,1)+i,1);if(first!=second){result=first-second;break;}if(first==0)break;}ret(e,result);continue;}
            if(pc==a("open")){String name=string(e,r(e,0));if(!Set.of("recovery0","recovery1","recovery_ota").contains(name))throw new IllegalStateException("Partition name");actions.add("open:"+name);ret(e,c.get("open_failure").getAsBoolean()?0xffffffffL:3);continue;}
            if(pc==a("close")){if(r(e,0)!=3)throw new IllegalStateException("Close handle");actions.add("close");ret(e,0);continue;}
            if(pc==a("read")){int offset=(int)r(e,1),n=(int)r(e,3);if(r(e,0)!=3||offset<0||n<0||n>4096||offset+n>file.length)throw new IllegalStateException("Partition read bounds");
                String role=hashing?"body":offset==0&&n==72?"header":offset==4096+c.get("size").getAsInt()-112&&n==48?"metadata":"signature";
                int returned=n-(c.get("short_read").getAsString().equals(role)?1:0);if(returned<0)throw new IllegalStateException("Short read bound");
                actions.add("read:"+offset+":"+n+":"+returned);e.writeMemory(toAddr(r(e,2)),Arrays.copyOfRange(file,offset,offset+returned));if(role.equals("signature"))signaturePointer=r(e,2);ret(e,returned);continue;}
            if(pc==a("sha_init")){if(r(e,0)<0x81000000L||r(e,0)+616>0x81001000L)throw new IllegalStateException("SHA context bound");shaContext=r(e,0);e.writeMemory(toAddr(shaContext),new byte[616]);sha=MessageDigest.getInstance("SHA-256");hashing=true;actions.add("sha:init");ret(e,0);continue;}
            if(pc==a("sha_update")){int n=(int)r(e,2);if(r(e,0)!=shaContext||r(e,1)!=BUFFER||n<0||n>4096)throw new IllegalStateException("SHA update arguments");sha.update(memory(e,BUFFER,n));actions.add("sha:update:"+n);ret(e,0);continue;}
            if(pc==a("sha_final")){if(r(e,0)!=shaContext||r(e,1)<0x81000000L||r(e,1)+32>0x81001000L)throw new IllegalStateException("SHA output bound");e.writeMemory(toAddr(r(e,1)),sha.digest());actions.add("sha:final");ret(e,0);continue;}
            if(pc==a("crypto")){if(r(e,2)!=32||r(e,4)!=0x80c3f378L||r(e,3)!=signaturePointer||!memoryHash(e,r(e,0),64).equals(cfg.get("key_sha256").getAsString()))throw new IllegalStateException("ECDSA bridge arguments");
                JsonObject row=new JsonObject();row.addProperty("digest_hex",HexFormat.of().formatHex(memory(e,r(e,1),32)));row.addProperty("signature_sha256",memoryHash(e,r(e,3),64));row.addProperty("key_sha256",memoryHash(e,r(e,0),64));row.addProperty("curve",r(e,4));row.addProperty("length",r(e,2));crypto.add(row);actions.add("crypto");ret(e,c.get("crypto_result").getAsLong());continue;}
            if(pc==a("clock")){ret(e,1000);continue;}
            if(pc==PROGRESS){actions.add("progress:"+r(e,0)+":"+r(e,1));ret(e,0);continue;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;actions=new JsonArray();crypto=new JsonArray();allocations.clear();hashing=false;sha=null;signaturePointer=0;EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] output=new byte[96];Arrays.fill(output,(byte)0xa5);e.writeMemory(toAddr(OUTPUT),output);String scope=c.get("scope").getAsString();
            file=HexFormat.of().parseHex(c.get("input_hex").getAsString());byte[] backing=Arrays.copyOf(file,file.length+32);Arrays.fill(backing,file.length,backing.length,(byte)0xa5);e.writeMemory(toAddr(FILE),backing);
            long lo=c.get("magic_low").getAsLong(),hi=c.get("magic_high").getAsLong();
            if(scope.equals("crc"))entry(e,a(c.get("raw").getAsBoolean()?"raw_crc":"crc"),c.get("seed").getAsLong(),FILE,file.length);
            else if(scope.equals("metadata"))entry(e,a("metadata"),FILE,lo,hi);
            else if(scope.equals("signature")){if(c.get("callback").getAsBoolean())entry(e,a("signature_callback"),3,4096,c.get("size").getAsInt(),PROGRESS);else entry(e,a("signature"),3,4096,c.get("size").getAsInt());}
            else if(scope.equals("image"))entry(e,a("image"),3,4096,c.get("size").getAsInt(),c.get("has_output").getAsBoolean()?OUTPUT:0,c.get("version_len").getAsInt(),lo,hi,c.get("verify").getAsBoolean()?1:0);
            else if(scope.equals("partition")){if(c.get("wrapper").getAsBoolean())entry(e,a("wrapper"),c.get("selector").getAsInt());else entry(e,a("partition"),c.get("selector").getAsInt(),c.get("verify").getAsBoolean()?1:0,c.get("has_output").getAsBoolean()?OUTPUT:0,c.get("output_len").getAsInt());}
            else throw new IllegalArgumentException("Unsupported scope");
            if(!hash(backing).equals(memoryHash(e,FILE,backing.length)))throw new IllegalStateException("Input mutated");byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);
            if(!hash(guard).equals(memoryHash(e,OUTPUT+64,32)))throw new IllegalStateException("Output guard changed");
            JsonObject observed=new JsonObject();observed.addProperty("returned",r(e,0));observed.add("actions",actions);observed.addProperty("output_sha256",memoryHash(e,OUTPUT,64));observed.add("crypto",crypto);JsonArray allocated=new JsonArray();
            for(var item:allocations.entrySet()){int n=item.getKey();long ptr=n==72?HEADER:BUFFER;if(!hash(guard).equals(memoryHash(e,ptr+n,32)))throw new IllegalStateException("Heap guard changed");JsonObject row=new JsonObject();row.addProperty("size",n);row.addProperty("sha256",memoryHash(e,ptr,n));row.addProperty("freed",item.getValue());allocated.add(row);}observed.add("allocations",allocated);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/recovery-validator-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement element:cfg.getAsJsonArray("guards")){JsonObject guard=element.getAsJsonObject();byte[] bytes=new byte[guard.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(guard.get("address").getAsLong()),bytes);if(!hash(bytes).equals(guard.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized boot validation code/data");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");JsonArray rows=new JsonArray();
        for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("RECOVERY_VALIDATOR_VALIDATION cases="+rows.size());
    }
}
