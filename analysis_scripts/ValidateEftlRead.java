// Actual EFTL translation, read wrapper and page adapter, synthetic page services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateEftlRead extends GhidraScript {
    private static final String CONFIG="{\"map_read\":2160075162,\"wrapper\":2160210514,\"page\":2160076682,\"generic\":2160235826,\"fast\":2160233112,\"memset\":2160254996,\"logger\":2160184698,\"ranges\":[[2160075162,254],[2160210514,78],[2160076682,38]],\"logs\":{\"2160280132\":\"unmapped_block\",\"2160280156\":\"page_read_error\"},\"guards\":[{\"address\":2160075162,\"size\":254,\"sha256\":\"3298dbbdd33a76b06d90a940376431281bf0fefe6149262226156ff6f90d16dc\"},{\"address\":2160210514,\"size\":78,\"sha256\":\"0a69990c6e1b2273d246d277c1302ce0e2366d79fccd911e4768241fc991d972\"},{\"address\":2160076682,\"size\":38,\"sha256\":\"25ac27a5214407304c10fe7fa30a50d0e2ca097172c8c30b6aebf28228338f4b\"}]}";
    private static final long END=0x70000000L,CONTEXT=0x80de5fb8L,MAP=0x81300000L,BUFFER=0x81301000L,NAND=0x81230000L;
    private JsonObject cfg,c;private JsonArray actions;private int steps,calls;
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(EmulatorHelper e,int n){return e.readRegister("a"+n).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private byte[] mem(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if(pc==a("generic")||pc==a("fast")){
                boolean fast=pc==a("fast");long out=r(e,fast?0:1),ppn=r(e,fast?1:2),column=r(e,fast?2:3),count=r(e,fast?3:4);
                if(fast!=c.get("fast").getAsBoolean()||(!fast&&r(e,0)!=NAND)||(fast&&r(e,4)!=1)||out<BUFFER||out+count>BUFFER+512||count>512)throw new IllegalStateException("Page service arguments");
                int status=++calls==c.get("fail_at").getAsInt()?c.get("driver_error").getAsInt():c.get("driver_status").getAsInt();int wrote=status<0?0:(int)Math.min(count,c.get("copy_limit").getAsInt());
                actions.add("physical:"+(fast?"fast":"generic")+":"+ppn+":"+column+":"+count+":"+status+":"+wrote);
                if(wrote>0){byte[] b=new byte[wrote];for(int j=0;j<wrote;j++)b[j]=(byte)(ppn*19+(column+j)*3);e.writeMemory(toAddr(out),b);}ret(e,status);continue;
            }
            if(pc==a("memset")){long out=r(e,0);int n=(int)r(e,2);if(r(e,1)!=255||n<0||out<BUFFER||out+n>BUFFER+512)throw new IllegalStateException("Unmapped fill bound");byte[] b=new byte[n];Arrays.fill(b,(byte)0xff);if(n>0)e.writeMemory(toAddr(out),b);ret(e,out);continue;}
            if(pc==a("logger")){JsonElement tag=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));if(tag==null||r(e,4)!=0x80c34344L)throw new IllegalStateException("Unexpected EFTL log");actions.add("log:"+tag.getAsString());ret(e,0);continue;}
            boolean allowed=false;for(JsonElement item:cfg.getAsJsonArray("ranges")){long first=item.getAsJsonArray().get(0).getAsLong(),n=item.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;calls=0;actions=new JsonArray();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            e.writeMemory(toAddr(CONTEXT),new byte[64]);put(e,CONTEXT,4,NAND);put(e,CONTEXT+6,1,c.get("fast").getAsBoolean()?1:0);put(e,CONTEXT+8,4,c.get("pages_per_block").getAsLong());put(e,CONTEXT+12,4,c.get("page_size").getAsLong());put(e,CONTEXT+24,4,c.get("base_page").getAsLong());put(e,CONTEXT+48,4,MAP);
            for(int i=0;i<8;i++)put(e,MAP+i*2,2,c.getAsJsonArray("mapping").get(i).getAsLong());put(e,0x80d81ea2L,1,1);
            byte[] output=new byte[1056];Arrays.fill(output,(byte)0xa5);e.writeMemory(toAddr(BUFFER),output);byte[] context=mem(e,CONTEXT,64),mapping=mem(e,MAP,16);
            JsonArray rows=new JsonArray();String mode=c.get("mode").getAsString();for(int iteration=0;iteration<c.get("repeat").getAsInt();iteration++){
                if(mode.equals("page"))entry(e,a(mode),CONTEXT,BUFFER,c.get("page").getAsLong(),c.get("column").getAsLong(),c.get("size").getAsLong());
                else if(mode.equals("wrapper"))entry(e,a(mode),c.get("offset").getAsLong(),BUFFER,c.get("size").getAsLong());
                else entry(e,a(mode),CONTEXT,BUFFER,c.get("offset").getAsLong(),c.get("size").getAsLong());
                JsonObject row=new JsonObject();row.addProperty("returned",r(e,0));row.addProperty("buffer_sha256",hash(mem(e,BUFFER,1024)));rows.add(row);
            }
            if(!Arrays.equals(context,mem(e,CONTEXT,64))||!Arrays.equals(mapping,mem(e,MAP,16)))throw new IllegalStateException("Translation inputs changed");byte[] guard=Arrays.copyOf(output,32);if(!Arrays.equals(guard,mem(e,BUFFER+1024,32)))throw new IllegalStateException("Output guard changed");
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/eftl-read-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized EFTL code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>64)throw new IllegalArgumentException("Vector bound");JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("EFTL_READ_VALIDATION cases="+rows.size());
    }
}
