// Original main platform/transfer/feature packets over supplied revision and HAL services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateMainNandBus extends GhidraScript {
    private static final String CONFIG="{\"init\":1881762480,\"transfer\":1881762852,\"read_feature\":1882021290,\"write_feature\":1882021390,\"version\":2161399148,\"clock_select\":2161334284,\"pinmux\":2161392164,\"gpio\":2161328888,\"controller_init\":2161330884,\"dma_init\":1881800760,\"command\":2161330992,\"receive_poll\":2161331304,\"receive_bounce\":2161331552,\"transmit_poll\":2161331648,\"transmit_bounce\":2161331888,\"copy\":1888779020,\"diagnostic\":1881761844,\"logger\":1881880738,\"assertion\":2161337594,\"ranges\":[[1881762480,370],[1881762852,938],[1882021290,100],[1882021390,108]],\"logs\":{\"1889647476\":\"command_error\",\"1889647512\":\"receive_bounce_error\",\"1889647580\":\"transmit_bounce_error\",\"1889647652\":\"receive_poll_error\",\"1889647716\":\"transmit_poll_error\"},\"guards\":[{\"address\":1881762480,\"size\":370,\"sha256\":\"cd883f10874ffa0d0a0c0a61a9bcc5b9f5e97da4bc15704a9b767fd0076abbc7\"},{\"address\":1881762852,\"size\":938,\"sha256\":\"1e8f2570ed783b41497de82112e94798920bb9ffbd745d81e85c304737d237ce\"},{\"address\":1882021290,\"size\":100,\"sha256\":\"eeb3306b86c99b76c1881aed97dcebaf93411af971d08ed975dd8e58874ef177\"},{\"address\":1882021390,\"size\":108,\"sha256\":\"490dbfa98ddfa99a2ff0375a38a4dbf0b778eb00527b6e587dedb39f59a9d3d9\"},{\"address\":2160068548,\"size\":20,\"sha256\":\"0052a47961a0f941dd3d97beca4b258b8be0cbd7553cf4e8ee92e8f735f65074\"},{\"address\":1889738828,\"size\":184,\"sha256\":\"2e1217166b3942f8e42486bd55379b45b87f2f51085d04688b626452159c89dd\"}],\"data_guards\":[{\"address\":2160068548,\"size\":20,\"sha256\":\"0052a47961a0f941dd3d97beca4b258b8be0cbd7553cf4e8ee92e8f735f65074\"},{\"address\":1889738828,\"size\":184,\"sha256\":\"2e1217166b3942f8e42486bd55379b45b87f2f51085d04688b626452159c89dd\"}]}";
    private static final long END=0x70000000L,BUFFER=0x81300000L,PACKET=0x81301000L,COPY=0x81302000L,
        CTRL=0x80d94a60L,BOUNCE=0x80d93960L,DMA0=0x80c10df4L,DMA1=0x80c10db0L;
    private JsonObject cfg,c,stopped;private JsonArray actions;private int steps,dataCount,reads;
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private byte[] mem(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private long value(EmulatorHelper e,long at,int n){byte[] b=mem(e,at,n);long v=0;for(int i=0;i<n;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private boolean dataPointer(long p,int n){return n>=0&&(p>=BUFFER&&p+n<=BUFFER+512||p>=BOUNCE&&p+n<=BOUNCE+512||p>=0x81000000L&&p+n<=0x81001000L);}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        stopped=null;e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>10000)throw new IllegalStateException("Execution bound");
            if(pc==a("version")){actions.add("version_query");ret(e,c.get("rom_revision").getAsLong());continue;}
            if(pc==a("clock_select")){if(r(e,0)!=1&&r(e,0)!=2)throw new IllegalStateException("Clock selection argument");actions.add("clock_select:"+r(e,0));ret(e,c.get("init_status").getAsInt());continue;}
            if(pc==a("pinmux")){if(r(e,0)!=0||r(e,1)!=127||r(e,2)!=63)throw new IllegalStateException("Pinmux arguments");actions.add("pinmux:0:127:63");ret(e,c.get("init_status").getAsInt());continue;}
            if(pc==a("gpio")){if(r(e,0)!=0||r(e,1)!=127||r(e,2)!=1)throw new IllegalStateException("GPIO arguments");actions.add("gpio:0:127:1");ret(e,c.get("init_status").getAsInt());continue;}
            if(pc==a("controller_init")){if(r(e,0)!=CTRL)throw new IllegalStateException("Controller argument");actions.add("controller_init:"+c.get("init_status").getAsInt());ret(e,c.get("init_status").getAsInt());continue;}
            if(pc==a("dma_init")){long p=r(e,0);if(p!=DMA0&&p!=DMA1)throw new IllegalStateException("DMA config pointer");actions.add("dma_init:"+(p==DMA0?0:1)+":"+hash(mem(e,p,44))+":"+c.get("init_status").getAsInt());ret(e,c.get("init_status").getAsInt());continue;}
            if(pc==a("command")){long p=r(e,1);if(r(e,0)!=CTRL||r(e,2)!=1000||p<0x81000000L||p+44>0x81001000L)throw new IllegalStateException("HAL command arguments");String action="command";for(int i=0;i<11;i++)action+=":"+value(e,p+i*4,4);dataCount=(int)value(e,p+36,4);if(dataCount<0||dataCount>512)throw new IllegalStateException("HAL count bound");int status=c.get("command_status").getAsInt();actions.add(action+":"+status);ret(e,status);continue;}
            String stage=null;for(String name:new String[]{"receive_poll","receive_bounce","transmit_poll","transmit_bounce"})if(pc==a(name))stage=name;
            if(stage!=null){long p=r(e,1);if(r(e,0)!=CTRL||r(e,2)!=1000||!dataPointer(p,dataCount)||(stage.endsWith("bounce")&&p!=BOUNCE))throw new IllegalStateException("HAL data arguments");boolean write=stage.startsWith("transmit");int status=c.get(write?"write_status":"read_status").getAsInt();String action=stage+":"+dataCount;if(write)action+=":"+hash(mem(e,p,dataCount));actions.add(action+":"+status);if(!write){JsonArray response=c.getAsJsonArray("responses");int first=response.get(Math.min(reads++,response.size()-1)).getAsInt();if(status==0){int n=Math.min(dataCount,c.get("copy_limit").getAsInt());byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(first+i*7);if(n>0)e.writeMemory(toAddr(p),b);}}ret(e,status);continue;}
            if(pc==a("copy")){long out=r(e,0),source=r(e,1);int n=(int)r(e,2);if(n<0||n>512||!dataPointer(out,n)||!dataPointer(source,n))throw new IllegalStateException("Bounce copy bound");if(out==BOUNCE)actions.add("copy_to_bounce:"+n);else if(source==BOUNCE)actions.add("copy_from_bounce:"+n);else throw new IllegalStateException("Unexpected copy");if(n>0)e.writeMemory(toAddr(out),mem(e,source,n));ret(e,out);continue;}
            if(pc==a("diagnostic")){actions.add("diagnostic");ret(e,0);continue;}
            if(pc==a("logger")){JsonElement tag=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));if(tag==null)throw new IllegalStateException("Unexpected NAND bus log "+Long.toHexString(r(e,3)));actions.add("log:"+tag.getAsString());ret(e,0);continue;}
            if(pc==a("assertion")){stopped=new JsonObject();stopped.addProperty("kind","assertion");stopped.addProperty("owner",r(e,1));stopped.addProperty("line",r(e,2));return;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));var instruction=getInstructionAt(toAddr(pc));if(instruction!=null&&instruction.getMnemonicString().startsWith("fence")){actions.add("fence");e.writeRegister(e.getPCRegister(),pc+instruction.getLength());continue;}
            if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=0;dataCount=0;reads=0;actions=new JsonArray();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] stack=new byte[4096];Arrays.fill(stack,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),stack);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] buffer=new byte[544];for(int i=0;i<512;i++)buffer[i]=(byte)(i*3+1);Arrays.fill(buffer,512,544,(byte)0xa5);e.writeMemory(toAddr(BUFFER),buffer);byte[] sentinel=new byte[544];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(CTRL-32),Arrays.copyOf(sentinel,128));e.writeMemory(toAddr(BOUNCE),sentinel);e.writeMemory(toAddr(DMA1),Arrays.copyOf(sentinel,68));e.writeMemory(toAddr(DMA0),Arrays.copyOf(sentinel,80));
            put(e,0x9a000004L,4,c.getAsJsonArray("mmio").get(0).getAsLong());put(e,0x9a00000cL,4,c.getAsJsonArray("mmio").get(1).getAsLong());put(e,0x80c10e38L,1,c.get("reinit").getAsBoolean()?1:0);put(e,0x70f8e6f8L,4,COPY);put(e,0x80c10e39L,1,c.get("disabled").getAsBoolean()?1:0);
            byte[] descriptor=new byte[0xb8];currentProgram.getMemory().getBytes(toAddr(0x70a3204cL),descriptor);for(int i=0;i<4;i++)descriptor[12+i]=(byte)(c.get("bus_word").getAsLong()>>(8*i));e.writeMemory(toAddr(COPY),descriptor);e.writeMemory(toAddr(COPY+0xb8),Arrays.copyOf(sentinel,32));
            byte[] packet=new byte[68];Arrays.fill(packet,(byte)0xa5);e.writeMemory(toAddr(PACKET),packet);for(Object[] f:new Object[][]{{0,"write_byte",1},{1,"dummy_byte",1},{2,"force_block",1},{4,"command_lines",1},{8,"opcode",4},{12,"address_bytes",1},{16,"address",4},{24,"size",4},{28,"data_lines",1}})put(e,PACKET+(int)f[0],(int)f[2],c.get((String)f[1]).getAsLong());put(e,PACKET+20,4,BUFFER);put(e,PACKET+32,4,0x11223344L);packet=mem(e,PACKET,68);
            String mode=c.get("mode").getAsString();long address=c.get("address").getAsLong(),size=c.get("size").getAsLong();
            if(mode.equals("init"))entry(e,a(mode),COPY);
            else if(mode.equals("transfer"))entry(e,a(mode),COPY,PACKET);
            else if(mode.equals("read_feature"))entry(e,a(mode),c.get("feature_register").getAsLong(),BUFFER);
            else if(mode.equals("write_feature"))entry(e,a(mode),c.get("feature_register").getAsLong(),c.get("feature_value").getAsLong());
            else throw new IllegalStateException("Main bus entry");
            JsonObject row=new JsonObject();row.add("returned",stopped==null?new JsonPrimitive(r(e,0)):JsonNull.INSTANCE);row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);row.addProperty("reinit",value(e,0x80c10e38L,1));row.addProperty("disabled",value(e,0x80c10e39L,1));JsonArray mmio=new JsonArray();for(long at:new long[]{0x9a000004L,0x9a00000cL})mmio.add(value(e,at,4));row.add("mmio",mmio);row.addProperty("buffer_sha256",hash(mem(e,BUFFER,512)));row.addProperty("bounce_sha256",hash(mem(e,BOUNCE,512)));row.addProperty("controller_hex",HexFormat.of().formatHex(mem(e,CTRL,64)));JsonArray dma=new JsonArray();for(long at:new long[]{DMA0,DMA1})dma.add(hash(mem(e,at,48)));row.add("dma_sha256",dma);
            byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{BUFFER+512,BOUNCE+512,CTRL-32,CTRL+64,COPY+0xb8})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("NAND bus guard");if(!Arrays.equals(Arrays.copyOf(sentinel,20),mem(e,DMA0+48,20))||!Arrays.equals(Arrays.copyOf(sentinel,10),mem(e,DMA0+70,10))||!Arrays.equals(Arrays.copyOf(sentinel,20),mem(e,DMA1+48,20))||!Arrays.equals(descriptor,mem(e,COPY,0xb8))||!Arrays.equals(packet,mem(e,PACKET,68)))throw new IllegalStateException("NAND bus input changed");
            for(JsonElement item:cfg.getAsJsonArray("data_guards")){JsonObject g=item.getAsJsonObject();if(!hash(mem(e,g.get("address").getAsLong(),g.get("size").getAsInt())).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Original main bus source changed");}
            JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray rows=new JsonArray();rows.add(row);observed.add("rows",rows);if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/main-nand-bus-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized NAND bus code/data");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.get("bound_per_case").getAsInt()!=10000||input.getAsJsonArray("cases").size()>64)throw new IllegalArgumentException("Vector bound");JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",10000);report.add("cases",rows);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("MAIN_NAND_BUS_VALIDATION cases="+rows.size());
    }
}
