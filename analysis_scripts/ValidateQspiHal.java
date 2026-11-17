// Actual QSPI HAL with authored MMIO, timestamps and DMA services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import com.google.gson.*;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateQspiHal extends GhidraScript {
    private static final String CONFIG="{\"init\":2162135584,\"command\":2162135692,\"receive\":2162136004,\"receive_dma\":2162136252,\"transmit\":2162136348,\"transmit_dma\":2162136588,\"pack\":2162134840,\"complete\":2162135040,\"wait_receive\":2162135192,\"wait_transmit\":2162135352,\"tx_count\":2162135512,\"rx_count\":2162135548,\"clock\":2162139008,\"tick\":2160140824,\"frequency\":2160140844,\"dma_setup\":2160141864,\"dma_wait\":2160142048,\"bus\":2160133872,\"feature_read\":2160229608,\"feature_write\":2160229704,\"cache_read\":2160230000,\"cache_write\":2160230508,\"write_enable\":2160229808,\"version\":2160140952,\"logger\":2160184698,\"diagnostic\":2160132868,\"assertion\":2160157974,\"ranges\":[[2162135584,108],[2162135692,204],[2162136004,248],[2162136252,96],[2162136348,240],[2162136588,88],[2162134840,100],[2162135040,152],[2162135192,160],[2162135352,160],[2162135512,36],[2162135548,36],[2162139008,52],[2160133872,886],[2160229608,96],[2160229704,104],[2160230000,102],[2160230508,100],[2160229808,94]],\"guards\":[{\"address\":2162135584,\"size\":108,\"sha256\":\"00754e5d66f0e683b7574bfe16e58619d92ad41b9f5860c63ed5741d81bea4c3\"},{\"address\":2162135692,\"size\":204,\"sha256\":\"a1c08672020fd6b42ac6d1b852bf1fa25324b51155195b8874ac50355029cf6e\"},{\"address\":2162136004,\"size\":248,\"sha256\":\"cf0b858c19fc1abe1f9dd971a2092a1f70f34cf1d891b875ab3778953e5f6ca0\"},{\"address\":2162136252,\"size\":96,\"sha256\":\"9133bab78dc6a4b3a1bdd3c931eaab7d8cee2ccd15a659bc2dd9123b8758f24f\"},{\"address\":2162136348,\"size\":240,\"sha256\":\"0966f523fba54b2ecace5a0ea517192f39af5b05ba6447e0c35db03513b4a4b2\"},{\"address\":2162136588,\"size\":88,\"sha256\":\"96431deb8412fc45a4b405daa5936f73444e1f1c86df52a40f599e02af01f631\"},{\"address\":2162134840,\"size\":100,\"sha256\":\"d81728d94ec968a8022bdf7cd2c799cdd65fdbe9c81fe3e8279b0f1750187ca8\"},{\"address\":2162135040,\"size\":152,\"sha256\":\"5e3259ee308e7647a7df2e3cb4a472029fd2f49be162466fa3e7a823f8f9f694\"},{\"address\":2162135192,\"size\":160,\"sha256\":\"6aa9e076be56cc89f1917b42a275a6e4ac4d20a23e43bb88ebed2030ffd8c046\"},{\"address\":2162135352,\"size\":160,\"sha256\":\"084d605e2524d044a2b4c98514598e0a7dfe3e8286dd2af6eb0c8bbea6a88662\"},{\"address\":2162135512,\"size\":36,\"sha256\":\"23f0432a05059b34c075ae3b853d8042bb22a71cd30f0ee056f8eff3f02b715e\"},{\"address\":2162135548,\"size\":36,\"sha256\":\"42c4cd8a20418deeb8f7f9c7568c4df0993e9e95ff0957530f69f313c01f79e8\"},{\"address\":2162139008,\"size\":52,\"sha256\":\"da2211e78c9062b051bb9a378882c767596ec7f01c5b6c470bee83ddad1e207a\"},{\"address\":2160133872,\"size\":886,\"sha256\":\"e2ae939cfa8cdeefa0e0672c87e9fb5894fa6fc1d65507d305239a7bd054ab59\"},{\"address\":2160229608,\"size\":96,\"sha256\":\"2fec1eff293a04a76ac7b393c32edfa35c907acfceb78ad3b8d200a5100c1afe\"},{\"address\":2160229704,\"size\":104,\"sha256\":\"db25a8f625930987d4de9167e93c764a9d7bc8d50be4fdd13f84f3e61fda4274\"},{\"address\":2160230000,\"size\":102,\"sha256\":\"083d5c97de97dfdffc36089019e1f5f6851ff794d94c547ff6abcd4ff9d20345\"},{\"address\":2160230508,\"size\":100,\"sha256\":\"daf0b6127f69fa6583f5afe6dcfe20f0081bfca1fd68983192c4334bc5847302\"},{\"address\":2160229808,\"size\":94,\"sha256\":\"d52e2947976b3c2b24f6fafa40ecedd9ef3a2f533374ec97374d57b893a5a57a\"},{\"address\":2161646336,\"size\":4,\"sha256\":\"4b0501c77bf148c63c954e4aa8941e14678947a7ee018c32fb6b33ac2774e53a\"},{\"address\":2161641896,\"size\":16,\"sha256\":\"81772459228c4e018935677595f2f511a59d157684239146e872f0ce18584de7\"},{\"address\":2160321816,\"size\":184,\"sha256\":\"8ff794d0bd1806c93cf2eeab8b03a7b72b951b3021ec67311396a0bd295c39ee\"}]}";
    private static final long END=0x70000000L,CTRL=0x80dfb880L,BUFFER=0x81301000L,FRAME=0x81302000L,
        DMA0=0x81304000L,DMA1=0x81305000L,CLOCK=0x9a000024L,SHADOW=0x80de67dcL;
    private JsonObject cfg,c,stopped;private JsonArray actions;private int steps,ticks,chunks;private Io io;
    private class Helper extends EmulatorHelper {
        private Emulator core;
        Helper(Program p){super(p);}
        @Override protected Emulator newEmulator(){core=super.newEmulator();return core;}
        void filter(MemoryAccessFilter f){core.addMemoryAccessFilter(f);}
    }
    private class Io extends MemoryAccessFilter {
        boolean active,reset;int rx;long base,clock;
        TreeMap<Long,Long> regs=new TreeMap<>();Map<String,Integer> indices=new HashMap<>();
        ByteArrayOutputStream tx=new ByteArrayOutputStream();
        long next(String key){JsonArray values=c.getAsJsonArray(key);int i=indices.getOrDefault(key,0);indices.put(key,i+1);return values.get(Math.min(i,values.size()-1)).getAsLong();}
        long decode(byte[] data){long v=0;for(int i=0;i<data.length;i++)v|=(data[i]&255L)<<(8*i);return v;}
        @Override protected void processRead(AddressSpace space,long offset,int size,byte[] data){
            if(!active||!space.getName().equals("ram"))return;long value;
            if(offset==CLOCK){if(size!=4)throw new IllegalStateException("Clock read width");value=clock;actions.add("clock_read:"+value);}
            else if(offset>=base&&offset<base+0x104){
                long at=offset-base;
                if(at==0x100){if(size!=1&&size!=4||rx+size>512)throw new IllegalStateException("FIFO read bound");value=0;for(int i=0;i<size;i++)value|=((0x5a+(rx+i)*7)&255L)<<(8*i);rx+=size;}
                else{
                    if(size!=4||!regs.containsKey(at))throw new IllegalStateException("Unknown QSPI read "+Long.toHexString(offset));
                    if(at==0x10&&reset){value=next("reset_reads");regs.put(at,value);if((value&0x100)==0)reset=false;}
                    else if(at==0x18){value=next("ready");regs.put(at,value);}
                    else if(at==0x24){value=next("done");regs.put(at,value);}
                    else value=regs.get(at);
                }actions.add("r:"+at+":"+size+":"+value);
            }else return;
            for(int i=0;i<size;i++)data[i]=(byte)(value>>>(8*i));
        }
        @Override protected void processWrite(AddressSpace space,long offset,int size,byte[] data){
            if(!active||!space.getName().equals("ram"))return;long value=decode(data);
            if(offset==CLOCK){if(size!=4)throw new IllegalStateException("Clock write width");clock=value;actions.add("clock_write:"+value);return;}
            if(offset>=base&&offset<base+0x104){
                long at=offset-base;
                if(at==0x100){if(size!=1&&size!=4)throw new IllegalStateException("FIFO write width");tx.writeBytes(data);}
                else{
                    if(size!=4||!regs.containsKey(at))throw new IllegalStateException("Unknown QSPI write "+Long.toHexString(offset));
                    regs.put(at,at==0x24&&value==1?0:value);if(at==0x10&&(value&0x100)!=0)reset=true;
                }actions.add("w:"+at+":"+size+":"+value);
            }
        }
    }
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(Helper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(Helper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private byte[] mem(Helper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private long word(Helper e,long at){byte[] b=mem(e,at,4);long v=0;for(int i=0;i<4;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(Helper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private void abi(Helper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(Helper e,long start,long... args)throws Exception {
        stopped=null;e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>100000)throw new IllegalStateException("Execution bound");
            if((pc==a("wait_receive")||pc==a("wait_transmit"))&&c.get("stop_chunks").getAsInt()>0&&++chunks>c.get("stop_chunks").getAsInt()){
                actions.add("stop_no_progress:"+(chunks-1));stopped=new JsonObject();stopped.addProperty("kind","bounded_prefix");stopped.addProperty("chunks",chunks-1);return;
            }
            if(pc==a("tick")){
                JsonArray values=c.getAsJsonArray("ticks");long v=values.get(Math.min(ticks++,values.size()-1)).getAsLong();actions.add("tick:"+Long.toUnsignedString(v));
                e.writeRegister("a0",v&0xffffffffL);e.writeRegister("a1",v>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
            }
            if(pc==a("frequency")){long v=c.get("frequency").getAsLong();actions.add("frequency:"+v);ret(e,v);continue;}
            if(pc==a("version")){actions.add("version:2");ret(e,2);continue;}
            if(pc==a("diagnostic")){actions.add("diagnostic");ret(e,0);continue;}
            if(pc==a("logger")){
                String name=switch((int)r(e,3)){case 0x80c37a64->"command_error";case 0x80c37b14->"receive_poll_error";case 0x80c37b54->"transmit_poll_error";default->throw new IllegalStateException("Unexpected HAL bus log");};
                actions.add("log:"+name);ret(e,0);continue;
            }
            if(pc==a("assertion")){stopped=new JsonObject();stopped.addProperty("kind","assertion");stopped.addProperty("owner",r(e,1));stopped.addProperty("line",r(e,2));return;}
            if(pc==a("dma_setup")){
                boolean receive=c.get("mode").getAsString().contains("receive");long n=word(e,CTRL+20),data=BUFFER+c.get("alignment").getAsLong();
                if(n>64||r(e,0)!=(receive?DMA1:DMA0)||r(e,1)!=(receive?io.base+0x100:data)||r(e,2)!=(receive?data:io.base+0x100)||r(e,3)!=n)throw new IllegalStateException("DMA setup arguments");
                int status=c.get("dma_setup_status").getAsInt();byte[] payload=receive?new byte[0]:mem(e,data,(int)n);
                actions.add("dma_setup:"+(receive?"receive":"transmit")+":"+n+":"+io.regs.get(32L)+":"+status+":"+hash(payload));
                if(receive&&status==0&&c.get("dma_copy").getAsBoolean()&&n>0){byte[] b=new byte[(int)n];for(int i=0;i<n;i++)b[i]=(byte)(0x5a+i*7);e.writeMemory(toAddr(data),b);}ret(e,status);continue;
            }
            if(pc==a("dma_wait")){
                boolean receive=c.get("mode").getAsString().contains("receive");if(r(e,0)!=(receive?DMA1:DMA0)||r(e,1)!=c.get("timeout").getAsLong())throw new IllegalStateException("DMA wait arguments");
                int status=c.get("dma_wait_status").getAsInt();actions.add("dma_wait:"+r(e,1)+":"+io.regs.get(32L)+":"+status);ret(e,status);continue;
            }
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            boolean ok;io.active=true;try{ok=e.step(monitor);}finally{io.active=false;}
            if(!ok)throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=ticks=chunks=0;actions=new JsonArray();Helper e=new Helper(currentProgram);io=new Io();io.base=c.get("base").getAsLong();io.clock=c.get("clock_word").getAsLong();
        try{
            byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            e.writeMemory(toAddr(CTRL-32),Arrays.copyOf(sentinel,128));
            for(long[] f:new long[][]{{0,c.get("base_present").getAsBoolean()?io.base:0},{8,c.getAsJsonArray("flags").get(0).getAsLong()},{12,c.getAsJsonArray("flags").get(1).getAsLong()},
                {16,c.get("controller_mode").getAsLong()},{20,c.get("count").getAsLong()},{32,DMA0},{36,DMA1}})put(e,CTRL+f[0],4,f[1]);
            byte[] ctx=mem(e,CTRL,64),buffer=Arrays.copyOf(sentinel,544);for(int i=0;i<512;i++)buffer[i]=(byte)(i*3+1);e.writeMemory(toAddr(BUFFER-32),Arrays.copyOf(sentinel,32));e.writeMemory(toAddr(BUFFER),buffer);
            e.writeMemory(toAddr(FRAME),Arrays.copyOf(sentinel,76));for(int i=0;i<11;i++)put(e,FRAME+i*4,4,c.getAsJsonArray("frame").get(i).getAsLong());byte[] frame=mem(e,FRAME,76);
            for(long[] f:new long[][]{{0,0x11111111L},{4,0x22222222L},{8,0x33333333L},{12,0x44444444L},{16,0x55555555L},{24,0},{32,c.get("control").getAsLong()},{36,0},{52,0x101},{84,c.get("fifo").getAsLong()}}){io.regs.put(f[0],f[1]);put(e,io.base+f[0],4,f[1]);}
            put(e,CLOCK,4,io.clock);put(e,SHADOW,4,0xa5a5a5a5L);e.filter(io);
            put(e,0x80d81f28L,4,0x80c3e518L);put(e,0x80d81d6cL,1,0);
            String mode=c.get("mode").getAsString();long controller=c.get("context_present").getAsBoolean()?CTRL:0,timeout=c.get("timeout").getAsLong(),data=BUFFER+c.get("alignment").getAsLong();
            if(mode.equals("clock"))entry(e,a(mode),c.get("clock_select").getAsLong());
            else if(mode.equals("init"))entry(e,a(mode),controller);
            else if(mode.equals("pack"))entry(e,a(mode),FRAME);
            else if(mode.equals("rx_count")||mode.equals("tx_count"))entry(e,a(mode),io.base);
            else if(mode.equals("complete")||mode.equals("wait_receive")||mode.equals("wait_transmit"))entry(e,a(mode),controller,timeout);
            else if(mode.equals("feature_read"))entry(e,a(mode),c.get("feature_register").getAsLong(),data);
            else if(mode.equals("feature_write"))entry(e,a(mode),c.get("feature_register").getAsLong(),c.get("feature_value").getAsLong());
            else if(mode.equals("cache_read")||mode.equals("cache_write"))entry(e,a(mode),c.get("address").getAsLong(),data,c.get("count").getAsLong(),0);
            else if(mode.equals("write_enable"))entry(e,a(mode));
            else{
                if(mode.startsWith("command"))entry(e,a("command"),controller,c.get("frame_present").getAsBoolean()?FRAME:0,timeout);
                if(!mode.equals("command")&&(!mode.startsWith("command")||r(e,0)==0))entry(e,a(mode.replace("command_","")),controller,data,timeout);
            }
            byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{CTRL-32,CTRL+64,BUFFER-32,BUFFER+512})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("HAL guard changed");
            byte[] endCtx=mem(e,CTRL,64);System.arraycopy(ctx,20,endCtx,20,4);if(!Arrays.equals(ctx,endCtx)||!Arrays.equals(frame,mem(e,FRAME,76)))throw new IllegalStateException("HAL input changed");
            JsonObject row=new JsonObject();row.add("returned",stopped==null?new JsonPrimitive(r(e,0)):JsonNull.INSTANCE);row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);row.addProperty("context_hex",HexFormat.of().formatHex(mem(e,CTRL,64)));row.addProperty("buffer_sha256",hash(mem(e,BUFFER,512)));row.addProperty("tx_hex",HexFormat.of().formatHex(io.tx.toByteArray()));row.addProperty("rx_bytes",io.rx);
            JsonObject mmio=new JsonObject();for(var item:io.regs.entrySet())mmio.addProperty(Long.toString(item.getKey()),item.getValue());row.add("mmio",mmio);row.addProperty("clock_word",io.clock);row.addProperty("clock_shadow",word(e,SHADOW));
            JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray rows=new JsonArray();rows.add(row);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/qspi-hal-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized QSPI HAL code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Vector bound");JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",100000);report.add("cases",rows);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("QSPI_HAL_VALIDATION cases="+rows.size());
    }
}
