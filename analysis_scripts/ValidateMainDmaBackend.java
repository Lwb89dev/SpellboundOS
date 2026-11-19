// Actual DMA init/setup/wait/cancel/IRQ with authored peripheral/cache services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateMainDmaBackend extends GhidraScript {
    private static final String CONFIG="{\"init\":1881800760,\"setup_irq\":1881801152,\"cancel\":1881801316,\"setup\":1881801376,\"remaining\":1881801528,\"wait\":1881801560,\"tick\":2161398884,\"prepare\":1881800352,\"finish\":1881800452,\"callback_a\":1879052288,\"callback_b\":1879056384,\"ranges\":[[1881800760,388],[1881801152,162],[1881801316,58],[1881801376,150],[1881801528,28],[1881801560,194]],\"guards\":[{\"address\":1881800760,\"size\":388,\"sha256\":\"62cbd9af6fae44f8b5742c2e6ea363fcd109e8054bfaeb3302e5a74947069ec2\"},{\"address\":1881801152,\"size\":162,\"sha256\":\"b3a179a5e9265500297bb1071f1190bcca1c98817aa3117a9a7340adc7834efe\"},{\"address\":1881801316,\"size\":58,\"sha256\":\"af24620efafac4d7870df9f3dddfaa2b04da08fd8e6e9d739ee052663ba6018a\"},{\"address\":1881801376,\"size\":150,\"sha256\":\"cfce33a095142823ac3765bd40f6c73a758432dc84030c34d4063fd78dd1a5ef\"},{\"address\":1881801528,\"size\":28,\"sha256\":\"f4108ec707a7124c2625c29db37bf0da941d15205408364520929a78018b8be2\"},{\"address\":1881801560,\"size\":194,\"sha256\":\"9985aae8a70d67cb9b9810ca3d6be4381d12c09cb2b8dd4b85454cd4a0551c0c\"}]}";
    private static final long END=0x70000000L,D=0x81300000L,SOURCE=0x81301000L,DEST=0x81302000L,OUT=0x81303000L,TABLE=0x80c11738L;
    private JsonObject cfg,c,stopped;private JsonArray actions;private int steps,ticks;private Io io;
    private class Helper extends EmulatorHelper {
        private Emulator core;
        Helper(Program p){super(p);}
        @Override protected Emulator newEmulator(){core=super.newEmulator();return core;}
        void filter(MemoryAccessFilter f){core.addMemoryAccessFilter(f);}
    }
    private class Io extends MemoryAccessFilter {
        boolean active;long base;TreeMap<Long,Long> regs=new TreeMap<>();Map<String,Integer> indices=new HashMap<>();
        @Override protected void processRead(AddressSpace space,long address,int size,byte[] data){
            if(!active||!space.getName().equals("ram")||address<base||address>=base+0x200)return;
            long at=address-base;if(size!=4||!regs.containsKey(at))throw new IllegalStateException("Unexpected DMA read "+Long.toHexString(address));
            long value=regs.get(at);
            if(at==20||at==24){String key=at==20?"status_a":"status_b";JsonArray values=c.getAsJsonArray(key);int i=indices.getOrDefault(key,0);indices.put(key,i+1);value=values.get(Math.min(i,values.size()-1)).getAsLong();regs.put(at,value);}
            actions.add("r:"+at+":"+value);for(int i=0;i<4;i++)data[i]=(byte)(value>>>(8*i));
        }
        @Override protected void processWrite(AddressSpace space,long address,int size,byte[] data){
            if(!active||!space.getName().equals("ram")||address<base||address>=base+0x200)return;
            long at=address-base;if(size!=4||!regs.containsKey(at))throw new IllegalStateException("Unexpected DMA write "+Long.toHexString(address));
            long value=0;for(int i=0;i<4;i++)value|=(data[i]&255L)<<(8*i);regs.put(at,value);actions.add("w:"+at+":"+value);
        }
    }
    private long a(String key){return cfg.get(key).getAsLong();}
    private long r(Helper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(Helper e,long at,int n,long value){e.writeMemoryValue(toAddr(at),n,value);}
    private byte[] mem(Helper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private long word(Helper e,long at){byte[] b=mem(e,at,4);long v=0;for(int i=0;i<4;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(Helper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    protected int bank(long base){if(base==0x92000000L)return 0;if(base==0x93000000L)return 7;if(base==0x93040000L)return 14;if(base==0x93080000L)return 21;return -1;}
    protected String configuration(){return CONFIG;}
    protected boolean supplyCacheServices(JsonObject input){return true;}
    private void abi(Helper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(Helper e,long start,long... args)throws Exception {
        stopped=null;e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>10000)throw new IllegalStateException("Execution bound");
            if(pc==a("tick")){
                JsonArray values=c.getAsJsonArray("ticks");long v=values.get(Math.min(ticks++,values.size()-1)).getAsLong();actions.add("tick:"+Long.toUnsignedString(v));
                e.writeRegister("a0",v&0xffffffffL);e.writeRegister("a1",v>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
            }
            if(pc==a("prepare")||pc==a("finish")){
                long address=r(e,0),n=r(e,1);if(!(address==SOURCE||address==DEST||address==0)||n>64)throw new IllegalStateException("DMA cache boundary arguments");
                actions.add((pc==a("prepare")?"cache_prepare:":"cache_finish:")+address+":"+n);if(supplyCacheServices(c)){ret(e,0);continue;}
            }
            if(pc==a("callback_a")||pc==a("callback_b")){
                long p=r(e,0);int n=c.getAsJsonArray("slots").size();if(p<D||p>=D+n*256||((p-D)&255)!=0)throw new IllegalStateException("DMA callback descriptor");
                actions.add((pc==a("callback_a")?"callback_a:":"callback_b:")+word(e,p+36)+":"+word(e,p+60)+":"+word(e,p+64));ret(e,0);continue;
            }
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            boolean ok;io.active=true;try{ok=e.step(monitor);}finally{io.active=false;}
            if(!ok)throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=ticks=0;actions=new JsonArray();Helper e=new Helper(currentProgram);io=new Io();io.base=c.get("base").getAsLong();
        try{
            byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            e.writeMemory(toAddr(TABLE-32),Arrays.copyOf(sentinel,204));e.writeMemory(toAddr(TABLE),new byte[140]);JsonArray slots=c.getAsJsonArray("slots"),initial=c.getAsJsonArray("context_hex");
            for(int i=0;i<slots.size();i++){
                long p=D+i*256;byte[] b=HexFormat.of().parseHex(initial.get(i).getAsString());if(b.length!=80)throw new IllegalStateException("DMA descriptor size");
                e.writeMemory(toAddr(p-32),Arrays.copyOf(sentinel,144));e.writeMemory(toAddr(p),b);int channel=slots.get(i).getAsInt();
                if(c.get("registered").getAsBoolean()&&bank(io.base)>=0&&channel<7)put(e,TABLE+(bank(io.base)+channel)*4,4,p);
            }
            byte[] source=Arrays.copyOf(sentinel,160),dest=Arrays.copyOf(sentinel,160);for(int i=0;i<128;i++)source[i]=(byte)(i*3+1);
            e.writeMemory(toAddr(SOURCE),source);e.writeMemory(toAddr(DEST),dest);e.writeMemory(toAddr(OUT-32),Arrays.copyOf(sentinel,68));
            for(long[] f:new long[][]{{4,c.get("irq_a").getAsLong()},{8,0x100},{12,c.get("irq_b").getAsLong()},{16,0x200},{20,0},{24,0},{36,c.get("enabled").getAsLong()}})io.regs.put(f[0],f[1]);
            for(int ch=0;ch<7;ch++)for(long[] f:new long[][]{{0x100,0x12340001},{0x104,0xffff},{0x108,0x11111111},{0x10c,0x22222222},{0x110,0x33333333},{0x114,0x44444444}})io.regs.put(ch*32+f[0],f[1]);
            for(var item:io.regs.entrySet())put(e,io.base+item.getKey(),4,item.getValue());e.filter(io);
            String mode=c.get("mode").getAsString();long size=c.get("size").getAsLong(),timeout=c.get("timeout").getAsLong();
            if(mode.startsWith("init")){
                entry(e,a("init"),D);
                if(stopped==null&&r(e,0)==0&&!mode.equals("init"))entry(e,a(mode.equals("init_setup_irq")?"setup_irq":"setup"),D,SOURCE,DEST,size);
                if(stopped==null&&r(e,0)==0&&mode.equals("init_setup_wait"))entry(e,a("wait"),D,timeout);
                else if(stopped==null&&r(e,0)==0&&mode.equals("init_setup_irq"))entry(e,a("irq"),io.base);
            }else if(mode.equals("setup")||mode.equals("setup_irq"))entry(e,a(mode),D,SOURCE,DEST,size);
            else if(mode.equals("wait"))entry(e,a(mode),D,timeout);
            else if(mode.equals("remaining"))entry(e,a(mode),c.get("context_present").getAsBoolean()?D:0,c.get("output_present").getAsBoolean()?OUT:0);
            else if(mode.equals("irq"))entry(e,a(mode),io.base);
            else entry(e,a(mode),D);
            byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{TABLE-32,TABLE+140,OUT-32,OUT+4})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("DMA guard changed");
            JsonArray contexts=new JsonArray();for(int i=0;i<slots.size();i++){
                long p=D+i*256;byte[] b=mem(e,p,80),original=HexFormat.of().parseHex(initial.get(i).getAsString());contexts.add(HexFormat.of().formatHex(b));
                System.arraycopy(original,60,b,60,8);if(!Arrays.equals(original,b)||!Arrays.equals(guard,mem(e,p-32,32))||!Arrays.equals(guard,mem(e,p+80,32)))throw new IllegalStateException("DMA descriptor input/guard changed");
            }
            if(!Arrays.equals(source,mem(e,SOURCE,160))||!Arrays.equals(dest,mem(e,DEST,160)))throw new IllegalStateException("DMA fixture payload changed");
            JsonObject row=new JsonObject();boolean noReturn=mode.equals("irq")||mode.equals("init_setup_irq");row.add("returned",stopped!=null||noReturn?JsonNull.INSTANCE:new JsonPrimitive(r(e,0)));row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);row.addProperty("output",word(e,OUT));row.add("contexts_hex",contexts);
            JsonArray registry=new JsonArray();for(int i=0;i<35;i++)registry.add(word(e,TABLE+i*4));row.add("registry",registry);JsonObject mmio=new JsonObject();for(var item:io.regs.entrySet())mmio.addProperty(Long.toString(item.getKey()),item.getValue());row.add("mmio",mmio);
            JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray rows=new JsonArray();rows.add(row);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/main-dma-backend-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(configuration()).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized DMA backend code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.get("bound_per_case").getAsInt()!=10000||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Vector bound");JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",10000);report.add("cases",rows);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("MAIN_DMA_BACKEND_VALIDATION cases="+rows.size());
    }
}
