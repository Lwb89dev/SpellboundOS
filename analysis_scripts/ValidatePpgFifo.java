// Execute guarded FIFO/recovery/pop/sample code against independent host-model vectors.
// SPI/context/control outcomes and listener registration are synthetic; no hardware access.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidatePpgFifo extends GhidraScript {
    private static final long RING=0x80f5073cL,STAGE=0x80f4ff38L,FLAGS=0x81003000L,NODE=0x81004000L,HEAD=0x80f4fb08L,END=0x70000000L;
    private String hash(byte[] data)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));}
    private void guard(long address,int size,String expected)throws Exception{
        byte[] bytes=new byte[size];currentProgram.getMemory().getBytes(toAddr(address),bytes);
        if(!hash(bytes).equals(expected))throw new IllegalStateException("Unrecognized optical code: "+Long.toHexString(address));
    }
    private long address(String field){return switch(field){
        case "count"->0x80f1705cL;case "write"->0x80f1705eL;case "read"->0x80f17060L;
        case "frame"->0x80f17062L;case "auxiliary"->0x80f17066L;case "mode"->0x80f17070L;
        case "policy"->0x80f1706dL;case "last_tick"->0x80f17050L;case "limit"->0x80f1704cL;
        case "frame_total"->0x80f17054L;case "enabled"->0x80f17091L;case "base_frame"->0x80f16b30L;
        default->throw new IllegalArgumentException("Unknown state field");};}
    private int width(String field){return switch(field){case "policy","enabled","base_frame"->1;
        case "last_tick","limit","frame_total"->4;default->2;};}
    private long read(EmulatorHelper e,long at,int size){byte[] data=e.readMemory(toAddr(at),size);long result=0;
        for(int i=0;i<size;++i)result|=(data[i]&255L)<<(8*i);return result;}
    private void put(EmulatorHelper e,long at,int size,long value){e.writeMemoryValue(toAddr(at),size,value);}
    private long reg(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void stubReturn(EmulatorHelper e,long value){e.writeRegister("a0",value&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private JsonObject state(EmulatorHelper e,JsonObject template){JsonObject out=new JsonObject();
        for(String key:template.keySet()){long value=read(e,address(key),width(key));
            if(key.equals("enabled"))out.addProperty(key,value!=0);else out.addProperty(key,value);}
        return out;}
    private JsonObject execute(JsonObject c)throws Exception{
        String name=c.get("name").getAsString(),kind=c.get("kind").getAsString();
        JsonObject initial=c.getAsJsonObject("state"),expected=c.getAsJsonObject("expected");
        JsonArray actions=new JsonArray();EmulatorHelper e=new EmulatorHelper(currentProgram);int steps=0;
        try{
            for(String field:initial.keySet())put(e,address(field),width(field),field.equals("enabled")?
                (initial.get(field).getAsBoolean()?1:0):initial.get(field).getAsLong());
            byte[] ring=new byte[4000];Arrays.fill(ring,(byte)0);
            for(int i=0;i<1000;++i){long word=0xdeadbeefL;for(int b=0;b<4;++b)ring[4*i+b]=(byte)(word>>>(8*b));}
            e.writeMemory(toAddr(RING),ring);
            for(var entry:c.getAsJsonObject("ring_overrides").entrySet())put(e,RING+4L*Integer.parseInt(entry.getKey()),4,entry.getValue().getAsLong());
            byte[] stage=new byte[2052];Arrays.fill(stage,(byte)0xa5);stage[0]=0x55;stage[1]=(byte)0xaa;
            JsonArray words=c.getAsJsonArray("initial_words");
            for(int i=0;i<words.size();++i){long word=words.get(i).getAsLong();for(int b=0;b<4;++b)stage[2+4*i+b]=(byte)(word>>>(24-8*b));}
            e.writeMemory(toAddr(STAGE),stage);put(e,0x80f1709cL,4,0x1234);put(e,FLAGS,1,c.get("flags").getAsInt());
            put(e,0x80f171a4L,4,c.get("now").getAsLong());
            boolean registered=c.get("registered").getAsBoolean();
            put(e,HEAD,4,registered?NODE:HEAD);put(e,HEAD+4,4,registered?NODE:HEAD);
            put(e,NODE,4,HEAD);put(e,NODE+4,4,HEAD);put(e,NODE+8,4,2);put(e,NODE+12,4,0x80fa40b0L);
            e.writeRegister("sp",0x81001000L);e.writeRegister("ra",END);
            for(int i=0;i<12;++i)e.writeRegister("s"+i,0x45670000L+i);
            long entry=switch(kind){case "fifo"->0x80f74526L;case "recovery"->0x80f73906L;
                case "reset"->0x80f72e86L;case "pop"->0x80f72ea4L;case "sample"->0x80f72f18L;
                default->throw new IllegalArgumentException("Unknown case kind");};
            e.writeRegister("a0",kind.equals("pop")?FLAGS:kind.equals("recovery")?(c.get("notify").getAsBoolean()?1:0):c.get("index").getAsLong());
            e.writeRegister("a1",c.get("word").getAsLong());e.writeRegister(e.getPCRegister(),entry);
            while(e.getExecutionAddress().getOffset()!=END){
                if(++steps>100000)throw new IllegalStateException(name+" execution bound");
                long pc=e.getExecutionAddress().getOffset();
                if(pc==0x80f7f5e4L){stubReturn(e,c.get("context").getAsInt());continue;}
                if(pc==0x80f809a0L){stubReturn(e,1);continue;} // selected nonlocking dispatcher branch
                if(pc==0x80f86d34L){if(kind.equals("sample"))actions.add("sample_tag_log");stubReturn(e,0);continue;}
                if(pc==0x80f7304cL){
                    int register=(int)reg(e,0);actions.add("read:"+register);
                    JsonElement value=c.getAsJsonObject("registers").get(Integer.toString(register));
                    if(value==null)throw new IllegalStateException("Unexpected register read");
                    if(!value.isJsonNull()){put(e,reg(e,1),1,value.getAsInt());stubReturn(e,0);}else stubReturn(e,0xfffffff2L);
                    continue;
                }
                if(pc==0x80f73152L){actions.add("write:"+reg(e,0)+":"+(reg(e,1)&255));stubReturn(e,0);continue;}
                if(pc==0x80f898aeL){
                    long size=reg(e,3);
                    if(reg(e,0)!=0x1234 || reg(e,1)!=STAGE || reg(e,2)!=STAGE || reg(e,4)!=1000 || read(e,STAGE,2)!=0x8008)
                        throw new IllegalStateException("Unexpected FIFO transfer arguments");
                    byte[] response=HexFormat.of().parseHex(c.get("response_hex").getAsString());
                    if(response.length>size)throw new IllegalStateException("Response exceeds request");
                    actions.add("bulk:"+size);if(response.length>0)e.writeMemory(toAddr(STAGE),response);
                    stubReturn(e,c.get("bulk_result").getAsLong());continue;
                }
                if(pc==0x80f63f6cL)actions.add("event:"+HexFormat.of().formatHex(e.readMemory(toAddr(reg(e,0)),8)));
                if(pc==0x80fa286aL){actions.add("control:"+reg(e,0)+":"+reg(e,1)+":"+reg(e,2)+":"+reg(e,3));stubReturn(e,1);continue;}
                boolean allowed=(pc>=0x80f74526L&&pc<0x80f74798L)||(pc>=0x80f72e86L&&pc<0x80f72f60L)
                    ||(pc>=0x80f738beL&&pc<0x80f73948L)||(pc>=0x80f7f958L&&pc<0x80f7f972L)
                    ||(pc>=0x80f8263eL&&pc<0x80f82652L)||(pc>=0x80f80aa0L&&pc<0x80f80aa2L)
                    ||(pc>=0x80f63aa6L&&pc<0x80f63b6eL)||(pc>=0x80f63f6cL&&pc<0x80f63f7aL)
                    ||(pc>=0x80fa40b0L&&pc<0x80fa40c4L);
                if(!allowed)throw new IllegalStateException(name+" escaped at "+Long.toHexString(pc));
                if(!e.step(monitor))throw new IllegalStateException(name+": "+e.getLastError());
            }
            JsonObject observed=state(e,initial);String ringHash=hash(e.readMemory(toAddr(RING),4000)),stageHash=hash(e.readMemory(toAddr(STAGE),2052));
            long flags=read(e,FLAGS,1);
            JsonElement returned=expected.get("returned").isJsonNull()?JsonNull.INSTANCE:
                new JsonPrimitive(e.readRegister("a0").longValue()&0xffffffffL);
            if(!observed.equals(expected.getAsJsonObject("state")) || !ringHash.equals(expected.get("ring_sha256").getAsString())
                || !stageHash.equals(expected.get("stage_sha256").getAsString()) || !actions.equals(expected.getAsJsonArray("actions"))
                || flags!=expected.get("flags").getAsLong() || !returned.equals(expected.get("returned")))
                throw new IllegalStateException(name+" mismatch: state="+observed+" actions="+actions+" expected="+expected);
            if(!expected.get("returned").isJsonNull()&&reg(e,0)!=expected.get("returned").getAsLong())throw new IllegalStateException(name+" return mismatch");
            if(read(e,FLAGS,1)!=expected.get("flags").getAsInt())throw new IllegalStateException(name+" flags mismatch");
            if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException(name+" stack mismatch");
            for(int i=0;i<12;++i)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException(name+" preserved register mismatch");
            JsonObject row=new JsonObject();row.addProperty("name",name);row.addProperty("kind",kind);row.addProperty("steps",steps);
            row.add("state",observed);row.add("actions",actions);row.addProperty("ring_sha256",ringHash);row.addProperty("stage_sha256",stageHash);
            row.add("returned",returned);row.addProperty("flags",flags);
            row.add("returned",expected.get("returned"));row.addProperty("flags",read(e,FLAGS,1));return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception{
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");
        guard(0x80f74526L,0x272,"98b23e61205b0483933b6d19d41e48df208ad1235e181c2e65b4fa6a4f582e91");
        guard(0x80f72e86L,0xda,"144bac09340c6d9c88e175034a4682fe5449533b230c1955b12217f45adf5527");
        guard(0x80f738beL,0x8a,"e3e1c41c50337b45eb3d850844d360b6b8851414629def94e105e1c9b8b382fa");
        guard(0x80f7f958L,0x1a,"ce75a6c73072e2051687b5b98ab0cbe95dbd292fdd7a89826b63d745184218e3");
        guard(0x80f8263eL,0x14,"5a65cbca233574fcc3d51f8f96ff00b4f78926c24f0f2df94cfab8b1b090395d");
        guard(0x80f80aa0L,2,"7529d4e6ceb037815e2664a7277abb404b02f0bf9ddbf5c11658f52448221cba");
        guard(0x80f63aa6L,0xc8,"033701dd09e14f26b22979b56ec46eae80e8151e98764a72a5a7a89b44313944");
        guard(0x80f63f6cL,0xe,"6d92fd44f71c812d9a7f0e4a26fea11cddde2dd3ee90abff0d808129c9eb9f8a");
        guard(0x80fa40b0L,0x14,"39d5c6d8d55c4466137cd1d5730fdbd3594697016a8aa15d6fbb70912d1a06d1");
        JsonObject vectors=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        if(vectors.get("schema").getAsInt()!=1 || vectors.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vector set");
        JsonArray rows=new JsonArray();for(JsonElement c:vectors.getAsJsonArray("cases"))rows.add(execute(c.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("case_count",rows.size());report.addProperty("hardware_execution",false);
        report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");
        println("PPG_FIFO_VALIDATION cases="+rows.size());
    }
}
