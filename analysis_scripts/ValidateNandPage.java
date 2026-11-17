// Actual page policy and busy loops; command/remap/workaround services supplied.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateNandPage extends GhidraScript {
    private static final String CONFIG="{\"read\":2160233112,\"write\":2160233478,\"copy_page\":2160233850,\"copy_oob\":2160234180,\"erase\":2160234982,\"busy\":2160231278,\"erase_busy\":2160232114,\"wait\":2160132848,\"remap_page\":2160228888,\"remap_block\":2160228824,\"load\":2160229902,\"enable\":2160229808,\"program\":2160230312,\"erase_command\":2160230710,\"cache_read_bounce\":2160230206,\"cache_read_direct\":2160230102,\"cache_write_bounce\":2160230608,\"cache_write_direct\":2160230508,\"cache_write_oob\":2160230410,\"workaround\":2160238190,\"feature\":2160229608,\"delay\":2160140628,\"sleep\":2160158852,\"logger\":2160184698,\"ranges\":[[2160233112,366],[2160233478,372],[2160233850,330],[2160234180,382],[2160234982,264],[2160231278,180],[2160232114,152],[2160132848,20]],\"logs\":{\"2160318632\":\"page_result\",\"2160318712\":\"page_guard\",\"2160318584\":\"workaround_ok\",\"2160318780\":\"copy_result\",\"2160319052\":\"block_guard\",\"2160319120\":\"erase_result\",\"2160318116\":\"busy_timeout\",\"2160318088\":\"feature_error\"},\"guards\":[{\"address\":2160233112,\"size\":366,\"sha256\":\"21fe4647132a935ccaedfab627ff2c61d6429bfc6850afd0e1ce641c2911a16b\"},{\"address\":2160233478,\"size\":372,\"sha256\":\"206bc02f96f0b59bbb21a908ae2a50cb60a1404307c45593179040c00d03896a\"},{\"address\":2160233850,\"size\":330,\"sha256\":\"8d311b41c9557e9c6c45fd718a8945d5bc707a419998804515bfa2eeb9c9a16e\"},{\"address\":2160234180,\"size\":382,\"sha256\":\"53828d54bddaf8ad89283fe08e600376845d710bea0099950336b7a4b397aa98\"},{\"address\":2160234982,\"size\":264,\"sha256\":\"94a755e20b330b1f93e678e2e3f83e57e4238a6fed2499f5dd34520ac23ee52c\"},{\"address\":2160231278,\"size\":180,\"sha256\":\"c23248ed66048f16a449b0a16bac624f9da5bb43ac00fa3fca9d97e72d519836\"},{\"address\":2160232114,\"size\":152,\"sha256\":\"eb07a88e83d912f61370824888d06cb00252e8c3987e56c54bf4dc746df9e739\"},{\"address\":2160132848,\"size\":20,\"sha256\":\"088330a65e8b216c30d4a672c74d98806b12f38cc51620ec322280add4cc5ecd\"},{\"address\":2160321816,\"size\":184,\"sha256\":\"8ff794d0bd1806c93cf2eeab8b03a7b72b951b3021ec67311396a0bd295c39ee\"},{\"address\":2161646336,\"size\":4,\"sha256\":\"4b0501c77bf148c63c954e4aa8941e14678947a7ee018c32fb6b33ac2774e53a\"},{\"address\":2161641896,\"size\":16,\"sha256\":\"81772459228c4e018935677595f2f511a59d157684239146e872f0ce18584de7\"}]}";
    private static final long END=0x70000000L,BUFFER=0x81300000L,CHIP=0x81302000L;
    private JsonObject cfg,c;private JsonArray actions;private int steps,reads,maps;
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private byte[] mem(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private int item(String key,int index){JsonArray row=c.getAsJsonArray(key);return row.get(Math.min(index,row.size()-1)).getAsInt();}
    private int fault(String key){JsonElement v=c.getAsJsonObject("faults").get(key);return v==null?0:v.getAsInt();}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>300000)throw new IllegalStateException("Execution bound");
            if(pc==a("remap_page")||pc==a("remap_block")){
                long out=r(e,1),value=r(e,0),mapped=(value+c.get("map_delta").getAsLong())&0xffffffffL;
                if(out<0x81000000L||out+4>0x81001000L)throw new IllegalStateException("Remap output bound");
                int status=item("map_status",maps++);actions.add((pc==a("remap_page")?"remap_page:":"remap_block:")+value+":"+mapped+":"+status);
                if(status==0)put(e,out,4,mapped);ret(e,status);continue;
            }
            String stage=null;for(String name:new String[]{"load","enable","program","erase_command","workaround"})if(pc==a(name))stage=name;
            if(stage!=null){int status=fault(stage);actions.add(stage+(stage.equals("enable")?"":":"+r(e,0))+":"+status);ret(e,status);continue;}
            for(String name:new String[]{"cache_read_bounce","cache_read_direct","cache_write_bounce","cache_write_direct","cache_write_oob"})if(pc==a(name))stage=name;
            if(stage!=null){
                int n=(int)r(e,2);if(r(e,1)!=BUFFER||n<0||n>512)throw new IllegalStateException("Cache data bound");
                if(stage.endsWith("bounce")&&r(e,3)!=0x80c28316L)throw new IllegalStateException("Cache callback argument");
                int status=fault(stage);boolean write=stage.startsWith("cache_write");
                actions.add(stage+":"+r(e,0)+":"+n+(write?":"+hash(mem(e,BUFFER,n)):"")+":"+status);
                if(!write&&status==0){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(0x5a+i*7);if(n>0)e.writeMemory(toAddr(BUFFER),b);}
                ret(e,status);continue;
            }
            if(pc==a("feature")){
                long out=r(e,1);if(r(e,0)!=192||out<0x81000000L||out>=0x81001000L)throw new IllegalStateException("Status feature arguments");
                int v=item("responses",reads),status=item("feature_status",reads++);actions.add("feature:192:"+v+":"+status);
                if(status==0)put(e,out,1,v);ret(e,status);continue;
            }
            if(pc==a("delay")||pc==a("sleep")){
                long v=r(e,0);if(v!=(pc==a("delay")?5:1))throw new IllegalStateException("Busy delay argument");
                actions.add((pc==a("delay")?"delay:":"sleep:")+v);ret(e,0);continue;
            }
            if(pc==a("logger")){
                JsonElement tag=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));
                if(tag==null)throw new IllegalStateException("Unknown page log "+Long.toHexString(r(e,3)));
                actions.add("log:"+tag.getAsString());ret(e,0);continue;
            }
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;reads=0;maps=0;actions=new JsonArray();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] buffer=Arrays.copyOf(sentinel,544);for(int i=0;i<512;i++)buffer[i]=(byte)(i*3+1);e.writeMemory(toAddr(BUFFER-32),Arrays.copyOf(sentinel,32));e.writeMemory(toAddr(BUFFER),buffer);
            byte[] descriptor=new byte[184];currentProgram.getMemory().getBytes(toAddr(0x80c3e518L),descriptor);descriptor[0x96]=(byte)(c.get("plane").getAsBoolean()?1:0);
            e.writeMemory(toAddr(CHIP),descriptor);e.writeMemory(toAddr(CHIP+184),Arrays.copyOf(sentinel,32));
            put(e,0x80d81f28L,4,c.get("chip").getAsBoolean()?CHIP:0);put(e,0x80d81b2cL,1,c.get("guard").getAsBoolean()?1:0);put(e,0x80d81f20L,4,512);put(e,0x80d81f1cL,4,8);
            String mode=c.get("mode").getAsString();long page=c.get("page").getAsLong(),dest=c.get("dest").getAsLong(),size=c.get("size").getAsLong();
            long pointer=c.get("buffer").getAsBoolean()?BUFFER:0,blocking=c.get("blocking").getAsBoolean()?1:0;
            if(mode.equals("read")||mode.equals("write"))entry(e,a(mode),pointer,page,c.get("column").getAsLong(),size,blocking);
            else if(mode.equals("copy_page"))entry(e,a(mode),page,dest);
            else if(mode.equals("copy_oob"))entry(e,a(mode),page,dest,BUFFER,size);
            else if(mode.equals("erase"))entry(e,a(mode),c.get("block").getAsLong(),blocking);
            else throw new IllegalArgumentException("Unknown mode");
            byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{BUFFER-32,BUFFER+512,CHIP+184})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Page guard changed");
            if(!Arrays.equals(descriptor,mem(e,CHIP,184)))throw new IllegalStateException("Page descriptor changed");
            JsonObject row=new JsonObject();row.addProperty("returned",r(e,0));row.addProperty("buffer_sha256",hash(mem(e,BUFFER,512)));row.addProperty("feature_reads",reads);
            JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray rows=new JsonArray();rows.add(row);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/nand-page-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized page code/data");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Vector bound");
        JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",300000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("NAND_PAGE_VALIDATION cases="+rows.size());
    }
}
