// Actual mapping resume/checksum over supplied bad-block/erase/OOB services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateEftlResume extends GhidraScript {
    private static final String CONFIG="{\"resume\":2160074122,\"checksum\":2160073226,\"bad\":2160077016,\"erase\":2160076842,\"oob\":2160076720,\"logger\":2160184698,\"ranges\":[[2160074122,352],[2160073226,80]],\"logs\":{\"2160279728\":\"bad_block\",\"2160279760\":\"oob_read_error\",\"2160279400\":\"checksum_error\"},\"guards\":[{\"address\":2160074122,\"size\":352,\"sha256\":\"627b6414298e79230eb17db6291f05d99573c740082fe86d720f61b914e1b2f4\"},{\"address\":2160073226,\"size\":80,\"sha256\":\"eae8f359810bcc1382c84110bb2c4b4ee0b893a9a279491618fd314994a019be\"}]}";
    private static final long END=0x70000000L,CONTEXT=0x81300000L,FLAGS=0x81301000L,MAP=0x81302000L,OOB=0x81303000L;
    private JsonObject cfg,c;private JsonArray actions;private int steps;
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(EmulatorHelper e,int n){return e.readRegister("a"+n).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private byte[] mem(EmulatorHelper e,long at,int n){return e.readMemory(toAddr(at),n);}
    private long value(EmulatorHelper e,long at,int n){byte[] b=mem(e,at,n);long v=0;for(int i=0;i<n;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private byte[] record(JsonObject b){int logical=b.get("logical").getAsInt(),tag=b.get("tag").getAsInt();byte[] result={(byte)logical,(byte)(logical>>8),(byte)tag,0};result[3]=(byte)((result[0]&255)+(result[1]&255)+tag+(b.get("corrupt").getAsBoolean()?1:0));return result;}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if(pc==a("bad")||pc==a("erase")||pc==a("oob")){
                if(r(e,0)!=CONTEXT)throw new IllegalStateException("Service context");boolean oob=pc==a("oob");long index=r(e,1),pages=c.get("pages_per_block").getAsLong();if(oob){if(pages==0||index%pages!=0)throw new IllegalStateException("OOB first page");index/=pages;}
                if(index>=c.get("block_count").getAsInt())throw new IllegalStateException("Block backing bound");JsonObject block=c.getAsJsonArray("blocks").get((int)index).getAsJsonObject();String op=oob?"read":pc==a("bad")?"bad":"erase";int result=block.get(op).getAsInt();
                if(oob){byte[] data=record(block);long out=r(e,2);if(out<0x81000000L||out+4>0x81001000L)throw new IllegalStateException("OOB output pointer");actions.add("oob:"+r(e,1)+":"+result+":"+HexFormat.of().formatHex(data));if(result==0)e.writeMemory(toAddr(out),data);}
                else actions.add(op+":"+index+":"+result);ret(e,result);continue;
            }
            if(pc==a("logger")){JsonElement tag=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));long owner=r(e,4);if(tag==null||(owner!=0x80c34324L&&owner!=0x80c34384L))throw new IllegalStateException("Unexpected resume log");actions.add("log:"+tag.getAsString());ret(e,0);continue;}
            boolean allowed=false;for(JsonElement item:cfg.getAsJsonArray("ranges")){long first=item.getAsJsonArray().get(0).getAsLong(),n=item.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject snapshot(EmulatorHelper e)throws Exception {
        JsonObject row=new JsonObject();row.addProperty("returned",r(e,0));row.addProperty("marker",value(e,CONTEXT+4,1));row.addProperty("free",value(e,CONTEXT+56,2));row.addProperty("used",value(e,CONTEXT+58,2));row.addProperty("reserved",value(e,CONTEXT+60,2));row.addProperty("flags",HexFormat.of().formatHex(mem(e,FLAGS,8)));JsonArray mapping=new JsonArray();for(int i=0;i<8;i++)mapping.add(value(e,MAP+2*i,2));row.add("mapping",mapping);row.addProperty("context_sha256",hash(mem(e,CONTEXT,64)));return row;
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;actions=new JsonArray();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] guard=new byte[96];Arrays.fill(guard,(byte)0xa5);for(long at:new long[]{CONTEXT,FLAGS,MAP,OOB})e.writeMemory(toAddr(at),guard);e.writeMemory(toAddr(CONTEXT),new byte[64]);put(e,CONTEXT+4,1,c.get("marker").getAsLong());put(e,CONTEXT+8,4,c.get("pages_per_block").getAsLong());put(e,CONTEXT+16,4,c.get("block_count").getAsLong());put(e,CONTEXT+44,4,FLAGS);put(e,CONTEXT+48,4,MAP);
            for(int i=0;i<3;i++)put(e,CONTEXT+56+2*i,2,c.getAsJsonArray("counters").get(i).getAsLong());for(int i=0;i<8;i++){put(e,FLAGS+i,1,c.getAsJsonArray("flags").get(i).getAsLong());put(e,MAP+2*i,2,c.getAsJsonArray("mapping").get(i).getAsLong());}byte[] data=record(c.getAsJsonArray("blocks").get(0).getAsJsonObject());e.writeMemory(toAddr(OOB),data);
            JsonArray rows=new JsonArray();for(int iteration=0;iteration<c.get("repeat").getAsInt();iteration++){
                if(c.get("mode").getAsString().equals("checksum"))entry(e,a("checksum"),OOB);else entry(e,a("resume"),CONTEXT,c.get("repair").getAsLong());rows.add(snapshot(e));}
            byte[] g=Arrays.copyOf(guard,32);for(long at:new long[]{CONTEXT+64,FLAGS+8,MAP+16,OOB+4})if(!Arrays.equals(g,mem(e,at,32)))throw new IllegalStateException("Output guard changed");if(!Arrays.equals(data,mem(e,OOB,4)))throw new IllegalStateException("Checksum input changed");
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/eftl-resume-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized resume code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>64)throw new IllegalArgumentException("Vector bound");JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("EFTL_RESUME_VALIDATION cases="+rows.size());
    }
}
