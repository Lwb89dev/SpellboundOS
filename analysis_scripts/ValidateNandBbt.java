// Actual BBT verification/resume/remapping and CRC over authored storage.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateNandBbt extends GhidraScript {
    private static final String CONFIG="{\"verify\":2160227938,\"resume\":2160228442,\"block\":2160228824,\"page\":2160228888,\"active\":2160228984,\"crc\":2160069412,\"bad_check\":2160234562,\"read\":2160233112,\"write\":2160233478,\"erase\":2160234982,\"zero\":2160254996,\"copy\":2160254520,\"format\":2160255464,\"logger\":2160184698,\"assertion\":2160157974,\"ranges\":[[2160227938,504],[2160228442,382],[2160228824,64],[2160228888,96],[2160228984,24],[2160069412,46]],\"logs\":{\"2160316952\":\"record\",\"2160317036\":\"magic_error\",\"2160317084\":\"count_error\",\"2160317128\":\"crc_error\",\"2160317188\":\"loaded\",\"2160317224\":\"entries\",\"2160317248\":\"too_many_bad\",\"2160317280\":\"repair_failed\",\"2160317316\":\"no_bbt\"},\"guards\":[{\"address\":2160227938,\"size\":504,\"sha256\":\"67c2bdad43087d25f9063303a9b989bc452717ad3924c25a11c0841a630727cf\"},{\"address\":2160228442,\"size\":382,\"sha256\":\"2e7ee54a742ebc46999ecdd53bcd7c5a6207379a0895c7cd8cf6e112beeacdca\"},{\"address\":2160228824,\"size\":64,\"sha256\":\"2ce1d78c21e8c515ae5cecc8cde1e2d792ef3d10a8043712d76171be680039f6\"},{\"address\":2160228888,\"size\":96,\"sha256\":\"e3a36c868b1c4e9ab4247450a8e552beebdfffbdfc75749fd718d3e578331223\"},{\"address\":2160228984,\"size\":24,\"sha256\":\"d66a3e5a83fdb0c1c7a78617ceef0c106a24dfdf9de626b3349e06ee3b8dc912\"},{\"address\":2160069412,\"size\":46,\"sha256\":\"08e0b6d64fe10875c94c5cb67b140355c1366be7b925e52f18d2b27dac4a6c1f\"},{\"address\":2160275084,\"size\":1024,\"sha256\":\"12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86\"},{\"address\":2160317220,\"size\":4,\"sha256\":\"9d2fbb7d019778a2cea264523a3dd94a63bf002b7ca1c5855ed19f379a08efbd\"}]}";
    private static final long END=0x70000000L,BASE=0x80df42ccL,OUTPUT=0x81300000L;
    private JsonObject cfg,c,stopped;private JsonArray actions;private int steps,reads;
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private byte[] mem(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private long word(EmulatorHelper e,long at){byte[] b=mem(e,at,4);long v=0;for(int i=0;i<4;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private boolean stack(long p,int n){return n>=0&&p>=0x81000000L&&p+n<=0x81001000L;}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        stopped=null;e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if(pc==a("crc")){
                int n=(int)r(e,2);if(r(e,0)!=0||n<0||n>128||!stack(r(e,1),n))throw new IllegalStateException("CRC argument bound");
                actions.add("crc:"+n+":"+hash(mem(e,r(e,1),n)));
            }
            if(pc==a("bad_check")){
                long block=r(e,0);if(r(e,1)!=1||block>=c.get("blocks").getAsLong())throw new IllegalStateException("Bad-block query bound");
                boolean good=false;for(JsonElement item:c.getAsJsonArray("good_blocks"))if(item.getAsLong()==block)good=true;
                int status=good?0:103;actions.add("bad_check:"+block+":1:"+status);ret(e,status);continue;
            }
            if(pc==a("read")){
                long out=r(e,0),page=r(e,1),ppb=word(e,BASE+148),block=page/ppb;
                if(!stack(out,140)||r(e,2)!=0||r(e,3)!=140||r(e,4)!=1||page%ppb!=0)throw new IllegalStateException("BBT read arguments");
                JsonObject spec=c.getAsJsonObject("records").getAsJsonObject(Long.toString(block));
                int status=spec!=null&&spec.has("read_status")?spec.get("read_status").getAsInt():0;
                if(reads++==2)status=c.get("reread_status").getAsInt();
                actions.add("read:"+page+":140:"+word(e,BASE)+":"+status);
                if(status==0){
                    byte[] b=new byte[140];Arrays.fill(b,(byte)0xff);Arrays.fill(b,0,12,(byte)0);
                    JsonElement hex=c.getAsJsonObject("record_hex").get(Long.toString(block));if(hex!=null)b=HexFormat.of().parseHex(hex.getAsString());
                    if(b.length!=140)throw new IllegalStateException("Record size");e.writeMemory(toAddr(out),b);
                }ret(e,status);continue;
            }
            if(pc==a("erase")){
                if(r(e,0)!=word(e,BASE+156)||r(e,1)!=1)throw new IllegalStateException("BBT erase arguments");
                int status=c.get("erase_status").getAsInt();actions.add("erase:"+r(e,0)+":1:"+word(e,BASE)+":"+status);ret(e,status);continue;
            }
            if(pc==a("write")){
                if(!stack(r(e,0),140)||r(e,1)!=(word(e,BASE+156)*word(e,BASE+148)&0xffffffffL)||r(e,2)!=0||r(e,3)!=140||r(e,4)!=1)throw new IllegalStateException("BBT write arguments");
                int status=c.get("write_status").getAsInt();actions.add("write:"+r(e,1)+":140:"+word(e,BASE)+":"+hash(mem(e,r(e,0),140))+":"+status);ret(e,status);continue;
            }
            if(pc==a("zero")){
                long out=r(e,0);int n=(int)r(e,2);if(r(e,1)!=0||!(out==BASE&&n==164||stack(out,n)&&n<=140))throw new IllegalStateException("Zero bound");
                e.writeMemory(toAddr(out),new byte[n]);ret(e,out);continue;
            }
            if(pc==a("copy")){
                if(r(e,0)!=BASE||r(e,2)!=140||!stack(r(e,1),140))throw new IllegalStateException("BBT publish arguments");
                e.writeMemory(toAddr(BASE),mem(e,r(e,1),140));actions.add("publish:140");ret(e,BASE);continue;
            }
            if(pc==a("format")){
                long value=r(e,3);if(value>65535||r(e,1)!=128||r(e,2)!=0x80c3d324L)throw new IllegalStateException("BBT format arguments");
                byte[] text=(Long.toString(value)+" ").getBytes(java.nio.charset.StandardCharsets.US_ASCII);if(!stack(r(e,0),text.length+1))throw new IllegalStateException("Format output bound");
                e.writeMemory(toAddr(r(e,0)),Arrays.copyOf(text,text.length+1));actions.add("format:"+value);ret(e,text.length);continue;
            }
            if(pc==a("logger")){
                JsonElement tag=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));if(tag==null)throw new IllegalStateException("Unknown BBT log "+Long.toHexString(r(e,3)));
                actions.add("log:"+tag.getAsString());ret(e,0);continue;
            }
            if(pc==a("assertion")){stopped=new JsonObject();stopped.addProperty("kind","assertion");stopped.addProperty("owner",r(e,1));stopped.addProperty("line",r(e,2));return;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject snapshot(EmulatorHelper e){
        JsonObject row=new JsonObject();row.add("returned",stopped==null?new JsonPrimitive(r(e,0)):JsonNull.INSTANCE);row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);
        row.addProperty("state_hex",HexFormat.of().formatHex(mem(e,BASE,164)));row.addProperty("output",word(e,OUTPUT));return row;
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;reads=0;actions=new JsonArray();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] state=HexFormat.of().parseHex(c.get("initial_hex").getAsString());if(state.length!=164)throw new IllegalStateException("State size");
            e.writeMemory(toAddr(BASE-32),Arrays.copyOf(sentinel,228));e.writeMemory(toAddr(BASE),state);e.writeMemory(toAddr(OUTPUT-32),Arrays.copyOf(sentinel,68));
            String mode=c.get("mode").getAsString();long value=c.get("value").getAsLong();
            if(mode.startsWith("resume"))entry(e,a("resume"),c.get("blocks").getAsLong(),c.get("page_size").getAsLong(),c.get("ppb").getAsLong());
            else if(mode.startsWith("verify"))entry(e,a("verify"),c.get("verify_block").getAsLong());
            else if(mode.equals("active"))entry(e,a("active"));
            else entry(e,a(mode),value,OUTPUT);
            JsonArray rows=new JsonArray();rows.add(snapshot(e));
            if(mode.endsWith("_map")&&stopped==null){entry(e,a(c.get("map_page").getAsBoolean()?"page":"block"),value,OUTPUT);rows.add(snapshot(e));}
            byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{BASE-32,BASE+164,OUTPUT-32,OUTPUT+4})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("BBT memory guard changed");
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/nand-bbt-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized BBT code/data");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>96)throw new IllegalArgumentException("Vector bound");
        JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("NAND_BBT_VALIDATION cases="+rows.size());
    }
}
