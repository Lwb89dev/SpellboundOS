// Synthetic partition/header writes, actual selection/prepare/finish and stopped handoff.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateRecoveryLifecycle extends GhidraScript {
    private static final String CONFIG="{\"get\":2160124984,\"set\":2160125136,\"select\":2160126412,\"prepare\":2160126630,\"finish\":2160126932,\"handoff\":2160068682,\"launch\":2160069004,\"validate\":2160126402,\"open\":2160113600,\"read\":2160113708,\"write\":2160113780,\"close\":2160113704,\"base\":2160113884,\"zero\":2160254996,\"strcmp\":2160255960,\"logger\":2160184698,\"printf\":2160183158,\"console_close\":2160156844,\"interrupts\":2160157516,\"teardown\":2160145344,\"ranges\":[[2160069458,38],[2160124984,320],[2160126412,674],[2160068618,34],[2160068682,44],[2160069004,150],[2160157508,8]],\"logs\":{\"2160291372\":\"open_error\",\"2160291416\":\"read_error\",\"2160291460\":\"write_error\",\"2160291816\":\"selected\",\"2160291860\":\"counters\",\"2160291908\":\"finish\",\"2160274824\":\"launch\",\"2160274852\":\"jump\"},\"guards\":[{\"address\":2160069458,\"size\":38,\"sha256\":\"9c46c270026616b7f5d480618fb95112f9c400064a7a170d5b10944f144c5cf0\"},{\"address\":2160124984,\"size\":320,\"sha256\":\"973f6c8b3467b28ca1cbd01e70a30268e153c3b5a5e622ad8a3ed89a3101e15f\"},{\"address\":2160126412,\"size\":674,\"sha256\":\"e0b542290231f0112999e76adcfd082d06bd5e8fd4865f4df78d698d31e69ff2\"},{\"address\":2160068618,\"size\":34,\"sha256\":\"866cc31c043cb86eb6032e50f7559b338784fc23f27a0a31eafb6f597f5c073c\"},{\"address\":2160068682,\"size\":44,\"sha256\":\"1a6a6507b4c988ab79f95ce68fa538e4c8639eace870c97d465f96cd9bb6f5ba\"},{\"address\":2160069004,\"size\":150,\"sha256\":\"fc56db9564a9c10657f96d5d2fc813cc7c105bc54a65a232d7d3bff08718f6f4\"},{\"address\":2160157508,\"size\":8,\"sha256\":\"141b14ba598565535bdba37e8debb03bd96b34a7859b493d890ed88f28c8cd9e\"},{\"address\":2160275084,\"size\":1024,\"sha256\":\"12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86\"},{\"address\":2160126402,\"size\":10,\"sha256\":\"c44bf2a6b602e1e5fea6d4d40a56a6ef8a3c5a55fb495840d1112d0dce27b5eb\"}]}";
    private static final long END=0x70000000L,RAM=0x80d00000L,HEADER=0x81100000L,MAPPED=0x81110000L,FLAG=0x80d81cecL;
    private static final String[] NAMES={"recovery0","recovery1","recovery_ota"};
    private JsonObject cfg,c,jump;private JsonArray actions;private byte[][] files,initial;private int steps,nextFd;private String operation;
    private final SortedMap<Integer,Integer> handles=new TreeMap<>();private final Map<String,Integer> calls=new HashMap<>();
    private long a(String key){return cfg.get(key).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private long read(EmulatorHelper e,long at,int n){long v=0;byte[] b=e.readMemory(toAddr(at),n);for(int i=0;i<n;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private long status(EmulatorHelper e){byte[] b=e.readMemory(currentProgram.getAddressFactory().getAddressSpace("csreg").getAddress(0x300*4),4);long v=0;for(int i=0;i<4;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private String memoryHash(EmulatorHelper e,long at,int n)throws Exception{return hash(e.readMemory(toAddr(at),n));}
    private long word(byte[] b,int at){return (b[at]&255L)|((b[at+1]&255L)<<8)|((b[at+2]&255L)<<16)|((b[at+3]&255L)<<24);}
    private long crc(byte[] b){long v=0xffffffffL;for(int i=0;i<68;i++){v^=b[i]&255L;for(int j=0;j<8;j++)v=(v>>>1)^((v&1)!=0?0xedb88320L:0);}return v;}
    private String string(EmulatorHelper e,long at){StringBuilder out=new StringBuilder();for(int i=0;i<64;i++){int v=(int)read(e,at+i,1);if(v==0)return out.toString();out.append((char)v);}throw new IllegalStateException("String bound");}
    private int index(String name){for(int i=0;i<3;i++)if(NAMES[i].equals(name))return i;throw new IllegalStateException("Unknown partition "+name);}
    private int count(String service,int index){String key=service+":"+index;int next=calls.getOrDefault(key,0)+1;calls.put(key,next);return next;}
    private boolean fault(String key,int index,int ordinal){JsonArray f=c.getAsJsonArray(key);return f.size()==2&&f.get(0).getAsInt()==index&&f.get(1).getAsInt()==ordinal;}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(EmulatorHelper e,boolean stopped){long expected=0x81001000L-(stopped&&operation.equals("launch")?16:0);
        if(e.readRegister("sp").longValue()!=expected)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private boolean entry(EmulatorHelper e,long start,long... args)throws Exception {
        e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if(pc==RAM&&c.get("trampoline").getAsBoolean()){
                if(read(e,RAM,4)!=0x22c0006fL)throw new IllegalStateException("Entry jump fixture");
                if(!e.step(monitor))throw new IllegalStateException(e.getLastError());continue;
            }
            if(pc==(c.get("trampoline").getAsBoolean()?RAM+0x22c:RAM)){jump=new JsonObject();jump.addProperty("pc",pc);jump.addProperty("sp",e.readRegister("sp").longValue());jump.addProperty("ra",e.readRegister("ra").longValue()&0xffffffffL);jump.addProperty("first_word",read(e,RAM,4));actions.add("handoff:stopped");abi(e,true);return true;}
            if(pc==a("validate")){int selector=(int)r(e,0),i=selector==0?0:selector==1?1:selector==8?2:-1;if(i<0)throw new IllegalStateException("Validator selector");boolean ok=c.getAsJsonArray("available").get(i).getAsBoolean();actions.add("validate:"+selector+":"+(ok?1:0));ret(e,ok?1:0);continue;}
            if(pc==a("open")){int i=index(string(e,r(e,0))),ordinal=count("open",i);actions.add("open:"+i+":"+ordinal);
                if(fault("open_failure",i,ordinal))ret(e,0xffffffffL);else{int fd=nextFd++;handles.put(fd,i);ret(e,fd);}continue;}
            if(pc==a("close")){Integer i=handles.remove((int)r(e,0));if(i==null)throw new IllegalStateException("Close unknown handle");actions.add("close:"+i);ret(e,0);continue;}
            if(pc==a("read")){Integer i=handles.get((int)r(e,0));int offset=(int)r(e,1),n=(int)r(e,3);long target=r(e,2);
                if(i==null||n<0||n>4096||offset<0||offset+n>files[i].length||!((offset==0&&n==72&&(target==HEADER||(target>=0x81000000L&&target+n<=0x81001000L)))||(offset==4096&&target==RAM)))throw new IllegalStateException("Read bounds");
                int returned=n-(fault("read_short",i,count("read",i))?1:0);actions.add("read:"+i+":"+offset+":"+n+":"+returned);e.writeMemory(toAddr(target),Arrays.copyOfRange(files[i],offset,offset+returned));ret(e,returned);continue;}
            if(pc==a("write")){Integer i=handles.get((int)r(e,0));long source=r(e,2);if(i==null||r(e,1)!=0||r(e,3)!=72||!(source==HEADER||(source>=0x81000000L&&source+72<=0x81001000L)))throw new IllegalStateException("Write bounds");
                int returned=72-(fault("write_short",i,count("write",i))?1:0);actions.add("write:"+i+":72:"+returned);System.arraycopy(e.readMemory(toAddr(source),returned),0,files[i],0,returned);ret(e,returned);continue;}
            if(pc==a("base")){Integer i=handles.get((int)r(e,0));if(i==null)throw new IllegalStateException("Base handle");actions.add("base:"+i);ret(e,c.getAsJsonArray("parts").get(i).getAsJsonObject().get("base").getAsLong());continue;}
            if(pc==a("zero")){long ptr=r(e,0);if(r(e,1)!=0||r(e,2)!=72||ptr<0x81000000L||ptr+72>0x81001000L)throw new IllegalStateException("Header zero bounds");e.writeMemory(toAddr(ptr),new byte[72]);ret(e,ptr);continue;}
            if(pc==a("strcmp")){ret(e,string(e,r(e,0)).compareTo(string(e,r(e,1))));continue;}
            if(pc==a("logger")){long message=r(e,3);if(message==0x80c36dfcL)actions.add("log:error:"+Long.toHexString(read(e,e.readRegister("sp").longValue(),4)));
                else if(message==0x80c32dbcL)actions.add("log:launch_error:"+Long.toHexString(r(e,5)));
                else{JsonElement name=cfg.getAsJsonObject("logs").get(Long.toString(message));if(name==null)throw new IllegalStateException("Unknown log "+Long.toHexString(message));actions.add("log:"+name.getAsString());}ret(e,0);continue;}
            if(pc==a("printf")){if(r(e,0)!=0x80c32c9cL||r(e,1)!=RAM||r(e,2)!=read(e,RAM,4))throw new IllegalStateException("Handoff print arguments");actions.add("print:entry");ret(e,0);continue;}
            if(pc==a("console_close")||pc==a("interrupts")||pc==a("teardown")){actions.add(pc==a("console_close")?"boundary:console_close":pc==a("interrupts")?"boundary:interrupts":"boundary:teardown");ret(e,0);continue;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e,false);return false;
    }
    private JsonObject snapshot(EmulatorHelper e,JsonElement returned)throws Exception {
        JsonObject row=new JsonObject();row.add("returned",returned);row.addProperty("header_sha256",memoryHash(e,HEADER,72));row.addProperty("header_crc_valid",crc(e.readMemory(toAddr(HEADER),72))==read(e,HEADER+68,4));
        row.addProperty("ram_sha256",memoryHash(e,RAM,4096));row.addProperty("mapped",read(e,MAPPED,4));row.addProperty("console",read(e,FLAG,1));row.addProperty("mstatus",status(e));row.add("handoff",jump==null?JsonNull.INSTANCE:jump);
        JsonArray partitions=new JsonArray(),open=new JsonArray();for(byte[] data:files){JsonObject p=new JsonObject();p.addProperty("sha256",hash(data));p.addProperty("bootup",word(data,8));p.addProperty("complete",word(data,12));p.addProperty("magic_hex",HexFormat.of().formatHex(Arrays.copyOf(data,4)));p.addProperty("crc_valid",crc(data)==word(data,68));partitions.add(p);}row.add("partitions",partitions);
        for(var item:handles.entrySet()){JsonObject handle=new JsonObject();handle.addProperty("fd",item.getKey());handle.addProperty("partition",NAMES[item.getValue()]);open.add(handle);}row.add("open_handles",open);
        byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long at:new long[]{HEADER+72,MAPPED+4,RAM+4096})if(!hash(guard).equals(memoryHash(e,at,32)))throw new IllegalStateException("Output guard changed");
        return row;
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;nextFd=100;jump=null;actions=new JsonArray();handles.clear();calls.clear();files=new byte[3][];initial=new byte[3][];EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            for(int i=0;i<3;i++){files[i]=HexFormat.of().parseHex(c.getAsJsonArray("files_hex").get(i).getAsString());initial[i]=files[i].clone();}
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] ram=new byte[4096+32];Arrays.fill(ram,(byte)0xa5);e.writeMemory(toAddr(RAM),ram);put(e,RAM,4,c.get("entry_word").getAsLong());
            byte[] header=new byte[72+32];Arrays.fill(header,(byte)0xa5);System.arraycopy(HexFormat.of().parseHex(c.get("source_header_hex").getAsString()),0,header,0,72);e.writeMemory(toAddr(HEADER),header);
            byte[] mapped=new byte[36];Arrays.fill(mapped,(byte)0xa5);e.writeMemory(toAddr(MAPPED),mapped);put(e,FLAG,1,c.get("console").getAsLong());
            e.writeMemoryValue(currentProgram.getAddressFactory().getAddressSpace("csreg").getAddress(0x300*4),4,c.get("mstatus").getAsLong());JsonArray rows=new JsonArray();
            for(JsonElement element:c.getAsJsonArray("operations")){operation=element.getAsString();JsonElement returned=JsonNull.INSTANCE;boolean stopped;
                if(operation.equals("get")||operation.equals("set")){long[] names={0x80c36fc0L,0x80c36fccL,0x80c36fd8L};stopped=entry(e,a(operation),names[c.get("target").getAsInt()],HEADER);if(operation.equals("get"))returned=new JsonPrimitive(r(e,0));}
                else if(operation.equals("prepare")){stopped=entry(e,a(operation),c.get("ram_output").getAsBoolean()?RAM:0,c.get("mapped_output").getAsBoolean()?MAPPED:0);returned=new JsonPrimitive(r(e,0));}
                else if(operation.equals("finish")){stopped=entry(e,a(operation),c.get("finish_all").getAsBoolean()?1:0);returned=new JsonPrimitive(r(e,0));}
                else if(operation.equals("handoff"))stopped=entry(e,a(operation),RAM);
                else{stopped=entry(e,a(operation));if(!stopped)returned=new JsonPrimitive(r(e,0));}
                rows.add(snapshot(e,returned));
            }
            for(int i=0;i<3;i++)if(!Arrays.equals(Arrays.copyOfRange(files[i],72,files[i].length),Arrays.copyOfRange(initial[i],72,initial[i].length)))throw new IllegalStateException("Write outside synthetic header");
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/recovery-lifecycle-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();
        for(JsonElement element:cfg.getAsJsonArray("guards")){JsonObject g=element.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized recovery lifecycle code/data");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");JsonArray rows=new JsonArray();
        for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("RECOVERY_LIFECYCLE_VALIDATION cases="+rows.size());
    }
}
