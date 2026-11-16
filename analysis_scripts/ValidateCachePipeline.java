// Native cache filtering, buffer packing/rebasing, dispatch and opcode-21 send.
// OS allocation/copy/locks/context/event scheduling and send are synthetic.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateCachePipeline extends GhidraScript {
    private static final long END=0x70000000L,CLONE=0x81030000L,BUF=0x81100000L,Q=0x81050000L,
        NODES=0x81060000L,OPS=0x81090000L,CB=0x70001000L,ROUTE=0x70000100L,
        WIRE_ALLOC=0x70000110L,SEND=0x70000120L,POST=0x70000130L;
    private JsonObject c;private JsonArray actions,wires;private String kind;private int steps,currentEvent;
    private int cloneSize,nodeAllocations;private final List<Long> sourceAddresses=new ArrayList<>();
    private final List<Integer> sourceSizes=new ArrayList<>(),bufferSizes=new ArrayList<>();
    private final List<Long> eventAddresses=new ArrayList<>(),eventBuffers=new ArrayList<>();
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private long reg(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private long read(EmulatorHelper e,long at,int n){long v=0;byte[] b=e.readMemory(toAddr(at),n);for(int i=0;i<n;++i)v|=(b[i]&255L)<<(8*i);return v;}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private long buffer(int index){return BUF+0x10000L*index;}
    private int bufferIndex(long view){int i=(int)((view-BUF)/0x10000L);if(i<0||i>=bufferSizes.size()||view!=buffer(i)+8)throw new IllegalStateException("Unknown buffer view");return i;}
    private String label(long address){if(address==CLONE&&cloneSize>0)return "clone";
        int index=sourceAddresses.indexOf(address);if(index>=0)return "p"+index;
        for(int i=0;i<bufferSizes.size();++i)if(address==buffer(i))return "b"+i;
        throw new IllegalStateException("Unknown allocation "+Long.toHexString(address));}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");
        for(int i=0;i<12;++i)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("ABI mismatch");}
    private boolean range(long pc,long a,long n){return pc>=a&&pc<a+n;}
    private void runEntry(EmulatorHelper e,long entry,long a0)throws Exception {
        e.writeRegister("ra",END);e.writeRegister("a0",a0);e.writeRegister(e.getPCRegister(),entry);
        while(e.getExecutionAddress().getOffset()!=END){
            if(++steps>200000)throw new IllegalStateException("Execution bound");long pc=e.getExecutionAddress().getOffset();
            if(pc==0x80f7f5e4L||pc==0x80f809a0L||pc==0x80f809b2L||pc==0x80f80974L){ret(e,1);continue;}
            if(pc==0x80f802deL||pc==0x80f80382L){if(reg(e,0)!=0x3333)throw new IllegalStateException("Unexpected OS lock");ret(e,0);continue;}
            if(pc==0x80f63302L){e.writeRegister("a1",0x12345678);ret(e,0xabcdef01L);continue;}
            if(pc==0x80f84a8cL){ret(e,200000);continue;}
            if(pc==0x80f84ceeL){
                if(reg(e,0)!=4||reg(e,1)!=0x80fd4868L||reg(e,3)!=4)throw new IllegalStateException("Allocation args");
                int size=(int)reg(e,2);boolean isClone=kind.equals("filter")&&size!=4016;
                if(isClone){boolean ok=c.get("clone_allocated").getAsBoolean();actions.add((ok?"alloc:":"alloc_fail:")+"clone:"+size);
                    if(ok){if(size>4096)throw new IllegalStateException("Clone bound");cloneSize=size;e.writeMemory(toAddr(CLONE),new byte[size]);}ret(e,ok?CLONE:0);
                }else{
                    int index=bufferSizes.size();boolean ok=kind.equals("buffer")?c.get("allocated").getAsBoolean():index<c.get("buffer_limit").getAsInt();
                    actions.add((ok?"alloc:":"alloc_fail:")+"b"+index+":"+size);
                    if(ok){if(index>7||size<16||size>4016)throw new IllegalStateException("Buffer bound");bufferSizes.add(size);e.writeMemory(toAddr(buffer(index)),new byte[size]);}
                    ret(e,ok?buffer(index):0);
                }continue;
            }
            if(pc==0x80f84cbeL){if(reg(e,0)!=0x26||reg(e,1)!=0x80fe5124L||reg(e,2)!=24)throw new IllegalStateException("Queue allocation args");
                actions.add("alloc_node:"+nodeAllocations);long node=NODES+0x100L*nodeAllocations++;e.writeMemory(toAddr(node),new byte[24]);
                ret(e,c.get("node_allocated").getAsBoolean()?node:0);continue;}
            if(pc==0x80fcdfccL){int n=(int)reg(e,2);if(n>4016||reg(e,1)!=0)throw new IllegalStateException("Memset bound");
                e.writeMemory(toAddr(reg(e,0)),new byte[n]);ret(e,reg(e,0));continue;}
            if(pc==0x80fcddf0L){int n=(int)reg(e,2);if(n<0||n>4016)throw new IllegalStateException("Copy bound");
                e.writeMemory(toAddr(reg(e,0)),e.readMemory(toAddr(reg(e,1)),n));ret(e,reg(e,0));continue;}
            if(pc==0x80f84d24L){
                if(reg(e,0)==4){String name=label(reg(e,2));long at=reg(e,2);
                    if(name.startsWith("b")?read(e,at+4,4)!=0:read(e,at+20,4)!=0)throw new IllegalStateException("Free before pointer/tag clear");actions.add("free:"+name);
                }else if(reg(e,0)==0x26){long node=reg(e,2);if(node<NODES||(node-NODES)%0x100!=0)throw new IllegalStateException("Unknown node");actions.add("free:n"+((node-NODES)/0x100));}
                else throw new IllegalStateException("Unknown free pool");ret(e,0);continue;
            }
            if(pc==0x80f86d34L){actions.add("log:"+Long.toHexString(reg(e,3)));ret(e,0);continue;}
            if(pc==0x80f7fa90L)throw new IllegalStateException("Native assertion "+Long.toHexString(reg(e,1))+":"+reg(e,2));
            if(pc==0x80f63c2eL){int index=bufferIndex(reg(e,0));actions.add("dispatch:"+index+":"+read(e,reg(e,0),4));}
            if(pc==CB){ret(e,0);continue;}
            if(pc==0x80f8e38cL){if(reg(e,0)!=0x80f9b34eL)throw new IllegalStateException("Event destructor");
                int index=eventAddresses.size();long at=0x810a0000L+0x100L*index;actions.add("event:"+index);eventAddresses.add(at);e.writeMemory(toAddr(at),new byte[20]);ret(e,at);continue;}
            if(pc==0x80f95226L){ret(e,OPS);continue;}
            if(pc==POST){long at=reg(e,1);int index=eventAddresses.indexOf(at);
                if(reg(e,0)!=2||index<0||read(e,at,4)!=0x80fe1380L||read(e,at+4,4)!=3)throw new IllegalStateException("Event post");
                eventBuffers.add(read(e,at+16,4));actions.add("post:"+index);ret(e,0);continue;}
            if(pc==ROUTE){if(reg(e,0)!=0)throw new IllegalStateException("Route argument");ret(e,1);continue;}
            if(pc==WIRE_ALLOC){int size=(int)reg(e,0);if(size<5||size>4005)throw new IllegalStateException("Wire bound");
                actions.add("wire_alloc:"+size);long at=0x81300000L+0x10000L*currentEvent;e.writeMemory(toAddr(at),new byte[size]);ret(e,at);continue;}
            if(pc==SEND){int size=(int)reg(e,2);if(size>4005||reg(e,3)!=1200)throw new IllegalStateException("Send arguments");
                byte[] raw=e.readMemory(toAddr(reg(e,1)),size);JsonObject wire=new JsonObject();wire.addProperty("header_hex",HexFormat.of().formatHex(e.readMemory(toAddr(reg(e,0)),3)));
                wire.addProperty("length",size);wire.addProperty("sha256",hash(raw));wire.addProperty("prefix_hex",HexFormat.of().formatHex(Arrays.copyOf(raw,Math.min(21,raw.length))));wires.add(wire);
                actions.add("send:"+currentEvent+":"+size);ret(e,c.get("send_result").getAsInt());continue;
            }
            boolean allowed=range(pc,0x80f6453eL,0x122)||range(pc,0x80f655d2L,0x30)||range(pc,0x80f657eeL,0x480)
                ||range(pc,0x80f63c2eL,0x86)||range(pc,0x80f85cbeL,0x84)||range(pc,0x80f80aa2L,0x44)||range(pc,0x80fd2c3eL,0x1a)
                ||range(pc,0x80fa5d1eL,0x5b2)||range(pc,0x80f9b34eL,0xb0)||range(pc,0x80f9ba6eL,0x27c)
                ||range(pc,0x80f99c26L,0xdc)||range(pc,0x80f9a5e6L,0xa20)||range(pc,0x80fa27e6L,8);
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;kind=c.get("kind").getAsString();actions=new JsonArray();wires=new JsonArray();steps=0;cloneSize=0;nodeAllocations=0;currentEvent=0;
        sourceAddresses.clear();sourceSizes.clear();bufferSizes.clear();eventAddresses.clear();eventBuffers.clear();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);
            e.writeRegister("sp",0x81001000L);for(int i=0;i<12;++i)e.writeRegister("s"+i,0x45670000L+i);
            put(e,0x80f16f78L,1,0);put(e,0x80f16fccL,4,Q);put(e,0x80f16fd8L,4,c.has("cached")?c.get("cached").getAsLong():123);put(e,0x80f16fdcL,4,7);
            put(e,Q,4,Q);put(e,Q+4,4,Q);put(e,Q+8,4,0x3333);put(e,Q+12,4,0x5a6a7a8aL);put(e,Q+16,4,0);
            if(c.has("packets"))for(JsonElement element:c.getAsJsonArray("packets")){
                JsonObject packet=element.getAsJsonObject();long at=packet.get("address").getAsLong();byte[] data=HexFormat.of().parseHex(packet.get("hex").getAsString());
                if(data.length>4096)throw new IllegalStateException("Packet bound");e.writeMemory(toAddr(at),data);sourceAddresses.add(at);sourceSizes.add(data.length);
            }
            long head=0x80f4fb10L,node=0x81078000L;put(e,head,4,node);put(e,head+4,4,node);put(e,node,4,head);put(e,node+4,4,head);
            put(e,node+8,4,0);put(e,node+12,4,c.has("bridge")&&c.get("bridge").getAsBoolean()?0x80f9b390L:CB);
            put(e,OPS+4,4,ROUTE);put(e,OPS+8,4,WIRE_ALLOC);put(e,OPS+16,4,SEND);put(e,OPS+32,4,POST);put(e,0x80f55f50L,1,1);
            JsonArray statuses=new JsonArray();JsonElement returned=JsonNull.INSTANCE;
            if(kind.equals("buffer")){
                runEntry(e,0x80f657eeL,c.get("capacity").getAsLong());returned=new JsonPrimitive(reg(e,0));
                if(reg(e,0)!=0){long view=reg(e,0);byte[] blob=HexFormat.of().parseHex(c.get("blob_hex").getAsString());e.writeMemory(toAddr(BUF+16),blob);
                    put(e,view,4,c.get("used").getAsLong());if(!c.get("magic").getAsBoolean())put(e,BUF+4,4,0);if(!c.get("pointer").getAsBoolean())put(e,view+4,4,0);
                    for(long entry:new long[]{0x80f655d2L,0x80f658c6L,0x80f6585eL,0x80f65884L,0x80f65884L,0x80f65884L}){
                        runEntry(e,entry,view);statuses.add(reg(e,0));}
                }
            }else{
                if(kind.equals("filter")){
                    long mask=c.get("mask").getAsLong();put(e,0x80f16fd0L,4,mask);put(e,0x80f16fd4L,4,mask>>>32);
                    runEntry(e,0x80f65a0eL,sourceAddresses.get(0));runEntry(e,0x80f6462cL,sourceAddresses.get(0));
                }else if(kind.equals("flush")){
                    int count=sourceAddresses.size();put(e,Q,4,count==0?Q:NODES);put(e,Q+4,4,count==0?Q:NODES+0x100L*(count-1));put(e,Q+16,4,count);
                    for(int i=0;i<count;++i){long at=NODES+0x100L*i;put(e,at,4,i==count-1?Q:at+0x100);put(e,at+4,4,i==0?Q:at-0x100);
                        put(e,at+8,4,0x80f655f8L);put(e,at+12,4,8);put(e,at+16,4,sourceSizes.get(i));put(e,at+20,4,sourceAddresses.get(i));}
                }else throw new IllegalArgumentException("Unknown case kind");
                runEntry(e,0x80f65920L,0);
                for(currentEvent=0;currentEvent<eventAddresses.size();++currentEvent){runEntry(e,0x80f9ba6eL,eventAddresses.get(currentEvent));runEntry(e,0x80f9b34eL,eventBuffers.get(currentEvent));}
            }
            JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray packetHashes=new JsonArray();
            for(int i=0;i<sourceAddresses.size();++i)packetHashes.add(hash(e.readMemory(toAddr(sourceAddresses.get(i)),sourceSizes.get(i))));observed.add("packets_sha256",packetHashes);
            observed.add("clone_sha256",cloneSize==0?JsonNull.INSTANCE:new JsonPrimitive(hash(e.readMemory(toAddr(CLONE),cloneSize))));JsonArray buffers=new JsonArray();
            for(int i=0;i<bufferSizes.size();++i){long at=buffer(i);JsonObject b=new JsonObject();b.addProperty("base",at);b.addProperty("used",read(e,at+8,4));
                b.addProperty("refs",read(e,at,4));b.addProperty("magic",read(e,at+4,4));b.addProperty("sha256",hash(e.readMemory(toAddr(at),bufferSizes.get(i))));buffers.add(b);}
            observed.add("buffers",buffers);observed.add("wires",wires);observed.addProperty("queue_count",read(e,Q+16,4));observed.addProperty("cached",read(e,0x80f16fd8L,4));observed.addProperty("motion",read(e,0x80f16fdcL,4));
            observed.add("statuses",statuses);observed.add("returned",returned);
            if(!observed.equals(c.getAsJsonObject("expected")))throw new IllegalStateException(c.get("name")+" observed="+observed+" expected="+c.get("expected"));
            JsonObject row=new JsonObject();row.addProperty("name",c.get("name").getAsString());row.addProperty("steps",steps);row.add("observed",observed);return row;
        }finally{e.dispose();}
    }
    private void guard(long at,int n,String expected)throws Exception {byte[] data=new byte[n];currentProgram.getMemory().getBytes(toAddr(at),data);
        if(!hash(data).equals(expected))throw new IllegalStateException("Unrecognized cache code");}
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors-path report-path");
        guard(0x80f6453eL,0x122,"3045b1263a0db4ace34d9bf2f107cc65173a737397ab8914b43c45b6d898bb96");
        guard(0x80f655d2L,0x30,"629e4712e7dfe729c334016cc1705016190c20d7684f900958c37dcf3673eded");
        guard(0x80f657eeL,0x480,"578bdc5ab8723367b9712f7e49a5b303675bf55b7fa632dc9f1d2a7c512e7158");
        guard(0x80f63c2eL,0x86,"ae26d17613ea566f46b2e2003314109c1a201ca520fd22447c89fdba6eb8d362");
        guard(0x80f85cbeL,0x84,"3f023e9de23f5c7652b9e962afcb58dbb5bb874c925dbc811a38aa0f9d12102d");
        guard(0x80f80aa2L,0x44,"a370c614222b8f603d0ca1c5a042b4ed57635edb383f3227a43ced901ad62bd1");
        guard(0x80fd2c3eL,0x1a,"f207acf3996babc0dcd3fa1eac67c084a1ecf94216a884b882550ec4f7a31e3c");
        guard(0x80fa5d1eL,0x5b2,"7d9f59af4b06f0d6050c9801c59cbe385fa029989b86faf89c5da1a6e23bd16c");
        guard(0x80f9b34eL,0xb0,"de001823b4f4051e3465d276d665db520c11aed8de4aff6327c9071326660f31");
        guard(0x80f9ba6eL,0x27c,"378b49fb315e99b0623e2cf35c3459daa7a0bfac781a8048902176f2ce1d463a");
        guard(0x80f99c26L,0xdc,"3d3311eb0afded3a99c94dfa739aa3ef97de398e4b7a77190086cad30e0c55d0");
        guard(0x80f9a5e6L,0xa20,"ee03a002d5d3796cd37ef9f1aa25dd1fe0de93c81accd85b678697a3f4a99de8");
        guard(0x80fa27e6L,0x8,"f365460cd199682c0a44a933f351e89847cff60d0227df3c4c7de88c79be49dc");
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();
        if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Unsupported vectors");
        JsonArray rows=new JsonArray();for(JsonElement element:input.getAsJsonArray("cases"))rows.add(execute(element.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("case_count",rows.size());report.addProperty("hardware_execution",false);report.addProperty("bound_per_case",200000);report.add("cases",rows);
        Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("CACHE_PIPELINE_VALIDATION cases="+rows.size());
    }
}
