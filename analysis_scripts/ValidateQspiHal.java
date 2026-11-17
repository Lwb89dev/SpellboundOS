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
    private static final String CONFIG="{\"init\":2162135584,\"command\":2162135692,\"receive\":2162136004,\"receive_dma\":2162136252,\"transmit\":2162136348,\"transmit_dma\":2162136588,\"pack\":2162134840,\"complete\":2162135040,\"wait_receive\":2162135192,\"wait_transmit\":2162135352,\"tx_count\":2162135512,\"rx_count\":2162135548,\"clock\":2162139008,\"tick\":2160140824,\"frequency\":2160140844,\"dma_setup\":2160141864,\"dma_wait\":2160142048,\"bus\":2160133872,\"feature_read\":2160229608,\"feature_write\":2160229704,\"cache_read\":2160230000,\"cache_write\":2160230508,\"write_enable\":2160229808,\"version\":2160140952,\"logger\":2160184698,\"diagnostic\":2160132868,\"assertion\":2160157974,\"ranges\":[[2162135584,108],[2162135692,204],[2162136004,248],[2162136252,96],[2162136348,240],[2162136588,88],[2162134840,100],[2162135040,152],[2162135192,160],[2162135352,160],[2162135512,36],[2162135548,36],[2162139008,52],[2160133872,886],[2160229608,96],[2160229704,104],[2160230000,102],[2160230508,100],[2160229808,94]],\"guards\":[{\"address\":2162135584,\"size\":108,\"sha256\":\"00754e5d66f0e683b7574bfe16e58619d92ad41b9f5860c63ed5741d81bea4c3\"},{\"address\":2162135692,\"size\":204,\"sha256\":\"a1c08672020fd6b42ac6d1b852bf1fa25324b51155195b8874ac50355029cf6e\"},{\"address\":2162136004,\"size\":248,\"sha256\":\"cf0b858c19fc1abe1f9dd971a2092a1f70f34cf1d891b875ab3778953e5f6ca0\"},{\"address\":2162136252,\"size\":96,\"sha256\":\"9133bab78dc6a4b3a1bdd3c931eaab7d8cee2ccd15a659bc2dd9123b8758f24f\"},{\"address\":2162136348,\"size\":240,\"sha256\":\"0966f523fba54b2ecace5a0ea517192f39af5b05ba6447e0c35db03513b4a4b2\"},{\"address\":2162136588,\"size\":88,\"sha256\":\"96431deb8412fc45a4b405daa5936f73444e1f1c86df52a40f599e02af01f631\"},{\"address\":2162134840,\"size\":100,\"sha256\":\"d81728d94ec968a8022bdf7cd2c799cdd65fdbe9c81fe3e8279b0f1750187ca8\"},{\"address\":2162135040,\"size\":152,\"sha256\":\"5e3259ee308e7647a7df2e3cb4a472029fd2f49be162466fa3e7a823f8f9f694\"},{\"address\":2162135192,\"size\":160,\"sha256\":\"6aa9e076be56cc89f1917b42a275a6e4ac4d20a23e43bb88ebed2030ffd8c046\"},{\"address\":2162135352,\"size\":160,\"sha256\":\"084d605e2524d044a2b4c98514598e0a7dfe3e8286dd2af6eb0c8bbea6a88662\"},{\"address\":2162135512,\"size\":36,\"sha256\":\"23f0432a05059b34c075ae3b853d8042bb22a71cd30f0ee056f8eff3f02b715e\"},{\"address\":2162135548,\"size\":36,\"sha256\":\"42c4cd8a20418deeb8f7f9c7568c4df0993e9e95ff0957530f69f313c01f79e8\"},{\"address\":2162139008,\"size\":52,\"sha256\":\"da2211e78c9062b051bb9a378882c767596ec7f01c5b6c470bee83ddad1e207a\"},{\"address\":2160133872,\"size\":886,\"sha256\":\"e2ae939cfa8cdeefa0e0672c87e9fb5894fa6fc1d65507d305239a7bd054ab59\"},{\"address\":2160229608,\"size\":96,\"sha256\":\"2fec1eff293a04a76ac7b393c32edfa35c907acfceb78ad3b8d200a5100c1afe\"},{\"address\":2160229704,\"size\":104,\"sha256\":\"db25a8f625930987d4de9167e93c764a9d7bc8d50be4fdd13f84f3e61fda4274\"},{\"address\":2160230000,\"size\":102,\"sha256\":\"083d5c97de97dfdffc36089019e1f5f6851ff794d94c547ff6abcd4ff9d20345\"},{\"address\":2160230508,\"size\":100,\"sha256\":\"daf0b6127f69fa6583f5afe6dcfe20f0081bfca1fd68983192c4334bc5847302\"},{\"address\":2160229808,\"size\":94,\"sha256\":\"d52e2947976b3c2b24f6fafa40ecedd9ef3a2f533374ec97374d57b893a5a57a\"},{\"address\":2161646336,\"size\":4,\"sha256\":\"4b0501c77bf148c63c954e4aa8941e14678947a7ee018c32fb6b33ac2774e53a\"},{\"address\":2161641896,\"size\":16,\"sha256\":\"81772459228c4e018935677595f2f511a59d157684239146e872f0ce18584de7\"},{\"address\":2160321816,\"size\":184,\"sha256\":\"8ff794d0bd1806c93cf2eeab8b03a7b72b951b3021ec67311396a0bd295c39ee\"}],\"dma_init\":2160141228,\"dma_tick\":2160140772,\"dma_prepare\":2160141044,\"dma_finish\":2160141136,\"cache_read_bounce\":2160230206,\"cache_write_bounce\":2160230608,\"copy\":2160254520,\"native_dma_ranges\":[[2160141228,408],[2160141864,150],[2160142048,186],[2160230206,106],[2160230608,102]],\"native_dma_guards\":[{\"address\":2160141228,\"size\":408,\"sha256\":\"015a3c0dd1dc248097d4e49c2b79ff045025b7d67506449b160083c7201f5f43\"},{\"address\":2160141864,\"size\":150,\"sha256\":\"f0b33f8e12dc67cc8fe23b42a8c4da3aded10baf6449775b8e6627e09937fbdf\"},{\"address\":2160142048,\"size\":186,\"sha256\":\"24642ea6a207babf06794ea2be566e59972a8d51d0d500871222a85feb57e128\"},{\"address\":2160230206,\"size\":106,\"sha256\":\"e0ba22b249a1572b27516b1b17c0f97527330ae00521c4dea6a888a3a9986ce7\"},{\"address\":2160230608,\"size\":102,\"sha256\":\"3a2f774dc1ddb356b498444480ddf4f938170c4c48a8d93ca7b254028a114cf2\"}],\"platform_init\":2160133504,\"pinmux\":2160145416,\"pin_function\":2162134676,\"platform_ranges\":[[2160133504,366],[2160145416,646],[2162134676,164],[2162134420,144]],\"platform_guards\":[{\"address\":2160133504,\"size\":366,\"sha256\":\"69fd28f411b9e8f4e447870d0b38a1cc677c4811aa5ac73bf06cf85abef7706e\"},{\"address\":2160145416,\"size\":646,\"sha256\":\"6a455fa5a9c95b43cec588b9ac0ab405faa2b5a6f5d00047562028beb3ce6e94\"},{\"address\":2162134676,\"size\":164,\"sha256\":\"987ded0cdd1149b3a7ea09d452d91ff35c4dc25c9b5454a06bfc41a2a512edde\"},{\"address\":2162134420,\"size\":144,\"sha256\":\"8f37b4147dc0ae556fff5af91e9f625ca69f31d50a55d9f0b322e9123e87f3ac\"},{\"address\":2161646640,\"size\":184,\"sha256\":\"17b573beccd13a7fbabc3c12675435de2add3e8aa8d9d8e0ee1bf97eedc00620\"},{\"address\":2160067204,\"size\":8,\"sha256\":\"9d6c527a6a93b654949c546a06a2fdb93abeb0b230e88a67d53aae8b57d2ef12\"}],\"page_read\":2160233112,\"remap_page\":2160228888,\"remap_block\":2160228824,\"page_delay\":2160140628,\"page_compare\":2160256488,\"page_ranges\":[[2160233112,366],[2160228824,64],[2160228888,96],[2160229902,98],[2160231278,180],[2160132848,20],[2160230102,104],[2160238190,238],[2160237900,72]],\"page_guards\":[{\"address\":2160233112,\"size\":366,\"sha256\":\"21fe4647132a935ccaedfab627ff2c61d6429bfc6850afd0e1ce641c2911a16b\"},{\"address\":2160228824,\"size\":64,\"sha256\":\"2ce1d78c21e8c515ae5cecc8cde1e2d792ef3d10a8043712d76171be680039f6\"},{\"address\":2160228888,\"size\":96,\"sha256\":\"e3a36c868b1c4e9ab4247450a8e552beebdfffbdfc75749fd718d3e578331223\"},{\"address\":2160229902,\"size\":98,\"sha256\":\"46e9abe616332fcdbfc12b6d60f23bd021543b3762f7234b90a30984ebbc9c1d\"},{\"address\":2160231278,\"size\":180,\"sha256\":\"c23248ed66048f16a449b0a16bac624f9da5bb43ac00fa3fca9d97e72d519836\"},{\"address\":2160132848,\"size\":20,\"sha256\":\"088330a65e8b216c30d4a672c74d98806b12f38cc51620ec322280add4cc5ecd\"},{\"address\":2160230102,\"size\":104,\"sha256\":\"c63146f005884eca61348d6b26e26ab65a0b1f52d92c908341233d1b078f098e\"},{\"address\":2160238190,\"size\":238,\"sha256\":\"c97829ee76b97c4ee9c40c2c017a018183b2f6a0ce506bcb64ecf195c313aa22\"},{\"address\":2160237900,\"size\":72,\"sha256\":\"04093b1b9d368004296b8da508d08bfe9242d1c2ced22bac32bc0e67db03569f\"},{\"address\":2160319952,\"size\":20,\"sha256\":\"878c2808d3decb4cd6ba7ff75b2f04f8ccc928f24062efd4d529d009caf3d0fe\"},{\"address\":2160322660,\"size\":20,\"sha256\":\"0eee04242e68d13a4a8d4618a7a4e22b57d00a9541d8a8ec1ff0b396077e1d19\"},{\"address\":2160319740,\"size\":20,\"sha256\":\"ec2eec5e971cc1add06ef5f5a34bd159ea6c850d7292b3ca479d171cfa50fb84\"}],\"page_write\":2160233478,\"program_ranges\":[[2160233478,372],[2160230312,98]],\"program_guards\":[{\"address\":2160233478,\"size\":372,\"sha256\":\"206bc02f96f0b59bbb21a908ae2a50cb60a1404307c45593179040c00d03896a\"},{\"address\":2160230312,\"size\":98,\"sha256\":\"0ca2b00fa3eb68273c3c640455eca08be20ce6b66a55a03d30827fb8deb10b4a\"}],\"erase\":2160234982,\"copy_page\":2160233850,\"copy_oob\":2160234180,\"maintenance_sleep\":2160158852,\"maintenance_ranges\":[[2160234982,264],[2160233850,330],[2160234180,382],[2160230710,104],[2160232114,152],[2160230410,98]],\"maintenance_guards\":[{\"address\":2160234982,\"size\":264,\"sha256\":\"94a755e20b330b1f93e678e2e3f83e57e4238a6fed2499f5dd34520ac23ee52c\"},{\"address\":2160233850,\"size\":330,\"sha256\":\"8d311b41c9557e9c6c45fd718a8945d5bc707a419998804515bfa2eeb9c9a16e\"},{\"address\":2160234180,\"size\":382,\"sha256\":\"53828d54bddaf8ad89283fe08e600376845d710bea0099950336b7a4b397aa98\"},{\"address\":2160230710,\"size\":104,\"sha256\":\"ac2a060dff15bde10a546abff681df1b4a9e13dea9afbc7a0834d0a3b76bd2ff\"},{\"address\":2160232114,\"size\":152,\"sha256\":\"eb07a88e83d912f61370824888d06cb00252e8c3987e56c54bf4dc746df9e739\"},{\"address\":2160230410,\"size\":98,\"sha256\":\"302022a1363436da0e40d2c08abc49f960745ed12eda8d4fb56f8cde99e78ca4\"}]}";
    private static final long END=0x70000000L,CTRL=0x80dfb880L,BUFFER=0x81301000L,FRAME=0x81302000L,
        DMA0=0x81304000L,DMA1=0x81305000L,CLOCK=0x9a000024L,SHADOW=0x80de67dcL,BOUNCE=0x80dfb8c0L,TABLE=0x80de65ecL;
    private int executionBound=100000;
    private boolean nativeMaintenance(){return c.has("native_maintenance")&&c.get("native_maintenance").getAsBoolean();}
    private boolean nativeProgram(){return c.has("native_program")&&c.get("native_program").getAsBoolean();}
    private boolean nativePage(){return c.has("native_page")&&c.get("native_page").getAsBoolean();}
    private JsonObject cfg,c,stopped;private JsonArray actions;private int steps,ticks,chunks,dmaTicks;private Io io;
    private boolean nativeDma(){return c.has("native_dma")&&c.get("native_dma").getAsBoolean();}
    private boolean nativePlatform(){return c.has("native_platform")&&c.get("native_platform").getAsBoolean();}
    private boolean fullPlatform(){return nativePlatform()&&c.get("full_platform").getAsBoolean();}
    private long dmaPointer(int i){return fullPlatform()?(i==0?0x80de64a0L:0x80de645cL):(i==0?DMA0:DMA1);}
    private class Helper extends EmulatorHelper {
        private Emulator core;
        Helper(Program p){super(p);}
        @Override protected Emulator newEmulator(){core=super.newEmulator();return core;}
        void filter(MemoryAccessFilter f){core.addMemoryAccessFilter(f);}
    }
    private class Io extends MemoryAccessFilter {
        boolean active,reset;int rx,featureReads,payloadRx;long base,clock;
        TreeMap<Long,Long> regs=new TreeMap<>();Map<String,Integer> indices=new HashMap<>();
        TreeMap<Long,Long> dmaRegs=new TreeMap<>();Map<String,Integer> dmaIndices=new HashMap<>();long dmaBase;
        TreeMap<Long,Long> boardRegs=new TreeMap<>();
        ByteArrayOutputStream tx=new ByteArrayOutputStream();
        long next(String key){JsonArray values=c.getAsJsonArray(key);int i=indices.getOrDefault(key,0);indices.put(key,i+1);return values.get(Math.min(i,values.size()-1)).getAsLong();}
        long decode(byte[] data){long v=0;for(int i=0;i<data.length;i++)v|=(data[i]&255L)<<(8*i);return v;}
        @Override protected void processRead(AddressSpace space,long offset,int size,byte[] data){
            if(!active||!space.getName().equals("ram"))return;long value;
            if(nativePlatform()&&boardRegs.containsKey(offset)){if(size!=4)throw new IllegalStateException("Board read width");value=boardRegs.get(offset);actions.add("board_r:"+offset+":"+value);}
            else if(nativeDma()&&offset>=dmaBase&&offset<dmaBase+0x200){
                long at=offset-dmaBase;if(size!=4||!dmaRegs.containsKey(at))throw new IllegalStateException("Unexpected connected DMA read");value=dmaRegs.get(at);
                if(at==20||at==24){String key=at==20?"status_a":"status_b";JsonObject p=c.getAsJsonObject(c.get("mode").getAsString().contains("receive")||c.get("mode").getAsString().contains("read")?"dma_rx":"dma_tx");JsonArray values=p.getAsJsonArray(key);int i=dmaIndices.getOrDefault(key,0);dmaIndices.put(key,i+1);value=values.get(Math.min(i,values.size()-1)).getAsLong();dmaRegs.put(at,value);}
                actions.add("dma_r:"+at+":"+value);
            }else if(offset==CLOCK){if(size!=4)throw new IllegalStateException("Clock read width");value=clock;actions.add("clock_read:"+value);}
            else if(offset>=base&&offset<base+0x104){
                long at=offset-base;
                if(at==0x100){if(size!=1&&size!=4||rx+size>(nativePage()?4096:512))throw new IllegalStateException("FIFO read bound");value=0;
                    if(nativePage()&&(regs.get(12L)>>>24)==0x0f){
                        if(size!=1)throw new IllegalStateException("Status FIFO width");JsonArray values=c.getAsJsonArray("responses");value=values.get(Math.min(featureReads++,values.size()-1)).getAsLong();
                    }else{for(int i=0;i<size;i++)value|=((0x5a+((nativePage()?payloadRx:rx)+i)*7)&255L)<<(8*i);payloadRx+=size;}rx+=size;}
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
            if(nativePlatform()&&boardRegs.containsKey(offset)){if(size!=4)throw new IllegalStateException("Board write width");boardRegs.put(offset,value);actions.add("board_w:"+offset+":"+value);return;}
            if(nativeDma()&&offset>=dmaBase&&offset<dmaBase+0x200){long at=offset-dmaBase;if(size!=4||!dmaRegs.containsKey(at))throw new IllegalStateException("Unexpected connected DMA write");dmaRegs.put(at,value);actions.add("dma_w:"+at+":"+value);return;}
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
            if(++steps>executionBound)throw new IllegalStateException("Execution bound");
            if((pc==a("wait_receive")||pc==a("wait_transmit"))&&c.get("stop_chunks").getAsInt()>0&&++chunks>c.get("stop_chunks").getAsInt()){
                actions.add("stop_no_progress:"+(chunks-1));stopped=new JsonObject();stopped.addProperty("kind","bounded_prefix");stopped.addProperty("chunks",chunks-1);return;
            }
            if(nativePage()&&(pc==a("remap_page")||pc==a("remap_block")))actions.add((pc==a("remap_page")?"native_remap_page:":"native_remap_block:")+r(e,0));
            if(nativePage()&&pc==a("page_delay")){if(r(e,0)!=5)throw new IllegalStateException("Page delay argument");actions.add("delay:5");ret(e,0);continue;}
            if(nativeMaintenance()&&pc==a("maintenance_sleep")){if(r(e,0)!=1)throw new IllegalStateException("Erase sleep argument");actions.add("sleep:1");ret(e,0);continue;}
            if(nativePage()&&pc==a("page_compare")){
                if(r(e,0)!=0x80c3ddd0L||(r(e,1)!=0x80c3e864L&&r(e,1)!=0x80c3dcfcL)||r(e,2)!=20)throw new IllegalStateException("Read retry comparison arguments");
                byte[] left=mem(e,r(e,0),20),right=mem(e,r(e,1),20);int v=0;for(int i=0;i<20;i++){int x=left[i]&255,y=right[i]&255;if(x!=y){v=x<y?-1:1;break;}if(x==0)break;}actions.add("compare20:"+v);ret(e,v);continue;
            }
            if(pc==a("tick")){
                JsonArray values=c.getAsJsonArray("ticks");long v=values.get(Math.min(ticks++,values.size()-1)).getAsLong();actions.add("tick:"+Long.toUnsignedString(v));
                e.writeRegister("a0",v&0xffffffffL);e.writeRegister("a1",v>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
            }
            if(pc==a("frequency")){long v=c.get("frequency").getAsLong();actions.add("frequency:"+v);ret(e,v);continue;}
            if(nativeDma()&&pc==a("dma_tick")){
                JsonObject p=c.getAsJsonObject(c.get("mode").getAsString().contains("receive")||c.get("mode").getAsString().contains("read")?"dma_rx":"dma_tx");JsonArray values=p.getAsJsonArray("ticks");long v=values.get(Math.min(dmaTicks++,values.size()-1)).getAsLong();actions.add("dma_tick:"+Long.toUnsignedString(v));
                e.writeRegister("a0",v&0xffffffffL);e.writeRegister("a1",v>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
            }
            if(nativeDma()&&(pc==a("dma_prepare")||pc==a("dma_finish"))){
                long p=r(e,0),n=r(e,1);if(n>64||!(p==0||p==BOUNCE||p==BUFFER||p==BUFFER+1||p==io.base+0x100))throw new IllegalStateException("Connected DMA cache arguments");
                actions.add((pc==a("dma_prepare")?"dma_cache_prepare:":"dma_cache_finish:")+p+":"+n);ret(e,0);continue;
            }
            if(nativeDma()&&pc==a("copy")){
                long out=r(e,0),in=r(e,1);int n=(int)r(e,2);if(n<0||n>64||!((out==BOUNCE&&in==BUFFER)||(out==BUFFER&&in==BOUNCE)))throw new IllegalStateException("Private-buffer copy arguments");
                if(n>0)e.writeMemory(toAddr(out),mem(e,in,n));actions.add((out==BOUNCE?"copy_to_bounce:":"copy_from_bounce:")+n);ret(e,out);continue;
            }
            if(pc==a("version")){actions.add("version:2");ret(e,2);continue;}
            if(pc==a("diagnostic")){actions.add("diagnostic");ret(e,0);continue;}
            if(pc==a("logger")){
                String name=switch((int)r(e,3)){case 0x80c37a64->"command_error";case 0x80c37b14->"receive_poll_error";case 0x80c37b54->"transmit_poll_error";case 0x80c37a88->"receive_bounce_error";case 0x80c37acc->"transmit_bounce_error";case 0x80c3d8a8->"page_result";case 0x80c3d6a4->"busy_timeout";case 0x80c3d8f8->"page_guard";case 0x80c3d93c->"copy_result";case 0x80c3da4c->"block_guard";case 0x80c3da90->"erase_result";default->throw new IllegalStateException("Unexpected HAL bus log");};
                actions.add("log:"+name);ret(e,0);continue;
            }
            if(pc==a("assertion")){stopped=new JsonObject();stopped.addProperty("kind","assertion");stopped.addProperty("owner",r(e,1));stopped.addProperty("line",r(e,2));return;}
            if(!nativeDma()&&pc==a("dma_setup")){
                boolean receive=c.get("mode").getAsString().contains("receive");long n=word(e,CTRL+20),data=BUFFER+c.get("alignment").getAsLong();
                if(n>64||r(e,0)!=(receive?DMA1:DMA0)||r(e,1)!=(receive?io.base+0x100:data)||r(e,2)!=(receive?data:io.base+0x100)||r(e,3)!=n)throw new IllegalStateException("DMA setup arguments");
                int status=c.get("dma_setup_status").getAsInt();byte[] payload=receive?new byte[0]:mem(e,data,(int)n);
                actions.add("dma_setup:"+(receive?"receive":"transmit")+":"+n+":"+io.regs.get(32L)+":"+status+":"+hash(payload));
                if(receive&&status==0&&c.get("dma_copy").getAsBoolean()&&n>0){byte[] b=new byte[(int)n];for(int i=0;i<n;i++)b[i]=(byte)(0x5a+i*7);e.writeMemory(toAddr(data),b);}ret(e,status);continue;
            }
            if(!nativeDma()&&pc==a("dma_wait")){
                boolean receive=c.get("mode").getAsString().contains("receive");if(r(e,0)!=(receive?DMA1:DMA0)||r(e,1)!=c.get("timeout").getAsLong())throw new IllegalStateException("DMA wait arguments");
                int status=c.get("dma_wait_status").getAsInt();actions.add("dma_wait:"+r(e,1)+":"+io.regs.get(32L)+":"+status);ret(e,status);continue;
            }
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeDma())for(JsonElement span:cfg.getAsJsonArray("native_dma_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativePlatform())for(JsonElement span:cfg.getAsJsonArray("platform_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativePage())for(JsonElement span:cfg.getAsJsonArray("page_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeProgram())for(JsonElement span:cfg.getAsJsonArray("program_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(nativeMaintenance())for(JsonElement span:cfg.getAsJsonArray("maintenance_ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(fullPlatform()){
                var instruction=getInstructionAt(toAddr(pc));if(instruction!=null&&instruction.getMnemonicString().startsWith("fence")){actions.add("fence");e.writeRegister(e.getPCRegister(),pc+instruction.getLength());continue;}
            }
            boolean ok;io.active=true;try{ok=e.step(monitor);}finally{io.active=false;}
            if(!ok)throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;steps=ticks=chunks=dmaTicks=0;actions=new JsonArray();Helper e=new Helper(currentProgram);io=new Io();io.base=c.get("base").getAsLong();io.clock=c.get("clock_word").getAsLong();
        try{
            byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            e.writeMemory(toAddr(CTRL-32),Arrays.copyOf(sentinel,128));
            for(long[] f:new long[][]{{0,c.get("base_present").getAsBoolean()?io.base:0},{8,c.getAsJsonArray("flags").get(0).getAsLong()},{12,c.getAsJsonArray("flags").get(1).getAsLong()},
                {16,c.get("controller_mode").getAsLong()},{20,c.get("count").getAsLong()},{32,dmaPointer(0)},{36,dmaPointer(1)}})put(e,CTRL+f[0],4,f[1]);
            byte[] ctx=mem(e,CTRL,64),buffer=Arrays.copyOf(sentinel,544);for(int i=0;i<512;i++)buffer[i]=(byte)(i*3+1);e.writeMemory(toAddr(BUFFER-32),Arrays.copyOf(sentinel,32));e.writeMemory(toAddr(BUFFER),buffer);
            e.writeMemory(toAddr(FRAME),Arrays.copyOf(sentinel,76));for(int i=0;i<11;i++)put(e,FRAME+i*4,4,c.getAsJsonArray("frame").get(i).getAsLong());byte[] frame=mem(e,FRAME,76);
            for(long[] f:new long[][]{{0,0x11111111L},{4,0x22222222L},{8,0x33333333L},{12,0x44444444L},{16,0x55555555L},{24,0},{32,c.get("control").getAsLong()},{36,0},{52,0x101},{84,c.get("fifo").getAsLong()}}){io.regs.put(f[0],f[1]);put(e,io.base+f[0],4,f[1]);}
            put(e,CLOCK,4,io.clock);put(e,SHADOW,4,0xa5a5a5a5L);e.filter(io);
            put(e,0x80d81f28L,4,0x80c3e518L);put(e,0x80d81d6cL,1,0);
            if(nativePlatform()){
                for(var item:c.getAsJsonObject("board_initial").entrySet()){long address=Long.parseLong(item.getKey()),value=item.getValue().getAsLong();io.boardRegs.put(address,value);put(e,address,4,value);}
            }
            if(nativeDma()){
                e.writeMemory(toAddr(BOUNCE),Arrays.copyOf(sentinel,544));e.writeMemory(toAddr(TABLE-32),Arrays.copyOf(sentinel,176));e.writeMemory(toAddr(TABLE),new byte[112]);
                if(fullPlatform())e.writeMemory(toAddr(dmaPointer(1)-32),Arrays.copyOf(sentinel,200));
                for(int i=0;i<2;i++){long pointer=dmaPointer(i);byte[] b=HexFormat.of().parseHex(c.get(i==0?"dma_tx_hex":"dma_rx_hex").getAsString());if(b.length!=(fullPlatform()?68:80))throw new IllegalStateException("Connected DMA context size");if(!fullPlatform())e.writeMemory(toAddr(pointer-32),Arrays.copyOf(sentinel,144));e.writeMemory(toAddr(pointer),b);}
                JsonObject p=c.getAsJsonObject("dma_tx");io.dmaBase=p.get("base").getAsLong();
                for(long[] f:new long[][]{{4,p.get("irq_a").getAsLong()},{8,0x100},{12,p.get("irq_b").getAsLong()},{16,0x200},{20,0},{24,0},{36,p.get("enabled").getAsLong()}})io.dmaRegs.put(f[0],f[1]);
                for(int ch=0;ch<7;ch++)for(long[] f:new long[][]{{0x100,0x12340001},{0x104,0xffff},{0x108,0x11111111},{0x10c,0x22222222},{0x110,0x33333333},{0x114,0x44444444}})io.dmaRegs.put(ch*32+f[0],f[1]);
                for(var item:io.dmaRegs.entrySet())put(e,io.dmaBase+item.getKey(),4,item.getValue());
                if(!fullPlatform()){
                    entry(e,a("dma_init"),DMA0);if(stopped!=null||r(e,0)!=0)throw new IllegalStateException("TX DMA initialization failed");
                    entry(e,a("dma_init"),DMA1);if(stopped!=null||r(e,0)!=0)throw new IllegalStateException("RX DMA initialization failed");
                }
            }
            String mode=c.get("mode").getAsString();long controller=c.get("context_present").getAsBoolean()?CTRL:0,timeout=c.get("timeout").getAsLong(),data=BUFFER+c.get("alignment").getAsLong();
            byte[] descriptor=null;
            if(fullPlatform()){
                e.writeMemory(toAddr(CTRL),new byte[64]);put(e,CTRL+16,4,c.get("controller_mode").getAsLong());ctx=mem(e,CTRL,64);
                descriptor=new byte[184];currentProgram.getMemory().getBytes(toAddr(0x80c3e518L),descriptor);e.writeMemory(toAddr(0x81306000L),descriptor);put(e,0x8130600cL,4,c.get("bus_word").getAsLong());if(nativePage())put(e,0x81306096L,1,c.get("plane").getAsBoolean()?1:0);descriptor=mem(e,0x81306000L,184);e.writeMemory(toAddr(0x813060b8L),Arrays.copyOf(sentinel,32));put(e,0x80d81f28L,4,0x81306000L);
                boolean deferred=c.get("defer_reinit").getAsBoolean();put(e,0x80d81d6cL,1,deferred?1:0);
                if(!deferred){entry(e,a("platform_init"),0x81306000L);if(stopped!=null||r(e,0)!=0)throw new IllegalStateException("Actual NAND platform initialization failed");}
                mode=mode.substring("platform_".length());
            }
            byte[] bbt=null;
            if(nativePage()){
                bbt=HexFormat.of().parseHex(c.get("bbt_hex").getAsString());if(bbt.length!=164)throw new IllegalStateException("Read BBT backing");e.writeMemory(toAddr(0x80df42ccL-32),Arrays.copyOf(sentinel,228));e.writeMemory(toAddr(0x80df42ccL),bbt);
                if(!c.get("chip").getAsBoolean())put(e,0x80d81f28L,4,0);
                if(nativeProgram()){put(e,0x80d81b2cL,1,c.get("guard").getAsBoolean()?1:0);put(e,0x80d81f20L,4,512);}
                if(nativeMaintenance()){
                    put(e,0x80d81f1cL,4,8);
                    if(mode.equals("erase"))entry(e,a(mode),c.get("block").getAsLong(),c.get("blocking").getAsBoolean()?1:0);
                    else if(mode.equals("copy_page"))entry(e,a(mode),c.get("page").getAsLong(),c.get("dest").getAsLong());
                    else if(mode.equals("copy_oob"))entry(e,a(mode),c.get("page").getAsLong(),c.get("dest").getAsLong(),data,c.get("count").getAsLong());
                    else throw new IllegalArgumentException("Maintenance root");
                }else entry(e,a(mode),c.get("buffer").getAsBoolean()?data:0,c.get("page").getAsLong(),c.get("column").getAsLong(),c.get("count").getAsLong(),c.get("blocking").getAsBoolean()?1:0);
            }
            else if(fullPlatform()&&mode.equals("init")){}
            else if(mode.equals("pinmux")||mode.equals("pin_function"))entry(e,a(mode),c.get("pin_p0").getAsLong(),c.get("pin_p1").getAsLong(),c.get("pin_value").getAsLong());
            else if(mode.equals("clock"))entry(e,a(mode),c.get("clock_select").getAsLong());
            else if(mode.equals("init"))entry(e,a(mode),controller);
            else if(mode.equals("pack"))entry(e,a(mode),FRAME);
            else if(mode.equals("rx_count")||mode.equals("tx_count"))entry(e,a(mode),io.base);
            else if(mode.equals("complete")||mode.equals("wait_receive")||mode.equals("wait_transmit"))entry(e,a(mode),controller,timeout);
            else if(mode.equals("feature_read"))entry(e,a(mode),c.get("feature_register").getAsLong(),data);
            else if(mode.equals("feature_write"))entry(e,a(mode),c.get("feature_register").getAsLong(),c.get("feature_value").getAsLong());
            else if(mode.equals("cache_read")||mode.equals("cache_write"))entry(e,a(mode),c.get("address").getAsLong(),data,c.get("count").getAsLong(),0);
            else if(nativeDma()&&(mode.equals("cache_read_bounce")||mode.equals("cache_write_bounce")))entry(e,a(mode),c.get("address").getAsLong(),data,c.get("count").getAsLong(),0);
            else if(mode.equals("write_enable"))entry(e,a(mode));
            else{
                if(mode.startsWith("command"))entry(e,a("command"),controller,c.get("frame_present").getAsBoolean()?FRAME:0,timeout);
                if(!mode.equals("command")&&(!mode.startsWith("command")||r(e,0)==0))entry(e,a(mode.replace("command_","")),controller,data,timeout);
            }
            byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{CTRL-32,nativeDma()?BOUNCE+512:CTRL+64,BUFFER-32,BUFFER+512})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("HAL guard changed");
            byte[] endCtx=mem(e,CTRL,64);System.arraycopy(ctx,20,endCtx,20,4);if(fullPlatform())for(int at:new int[]{0,8,12,32,36})System.arraycopy(ctx,at,endCtx,at,4);if(!Arrays.equals(ctx,endCtx)||!Arrays.equals(frame,mem(e,FRAME,76)))throw new IllegalStateException("HAL input changed");
            JsonObject row=new JsonObject();row.add("returned",stopped==null&&!mode.equals("pinmux")&&!mode.equals("pin_function")?new JsonPrimitive(r(e,0)):JsonNull.INSTANCE);row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);row.addProperty("context_hex",HexFormat.of().formatHex(mem(e,CTRL,64)));row.addProperty("buffer_sha256",hash(mem(e,BUFFER,512)));row.addProperty("tx_hex",HexFormat.of().formatHex(io.tx.toByteArray()));row.addProperty("rx_bytes",io.rx);
            JsonObject mmio=new JsonObject();for(var item:io.regs.entrySet())mmio.addProperty(Long.toString(item.getKey()),item.getValue());row.add("mmio",mmio);row.addProperty("clock_word",io.clock);row.addProperty("clock_shadow",word(e,SHADOW));
            if(nativeDma()){
                JsonArray contexts=new JsonArray();for(int i=0;i<2;i++){
                    long pointer=dmaPointer(i);int length=fullPlatform()?68:80;byte[] b=mem(e,pointer,length),original=HexFormat.of().parseHex(c.get(i==0?"dma_tx_hex":"dma_rx_hex").getAsString());contexts.add(HexFormat.of().formatHex(b));
                    System.arraycopy(original,60,b,60,8);if(fullPlatform()){System.arraycopy(original,0,b,0,40);System.arraycopy(original,44,b,44,4);}
                    if(!Arrays.equals(original,b)||!fullPlatform()&&(!Arrays.equals(guard,mem(e,pointer-32,32))||!Arrays.equals(guard,mem(e,pointer+80,32))))throw new IllegalStateException("Connected DMA context/guard changed");
                }row.add("dma_contexts_hex",contexts);JsonArray registry=new JsonArray();for(int i=0;i<28;i++)registry.add(word(e,TABLE+i*4));row.add("dma_registry",registry);
                JsonObject regs=new JsonObject();for(var item:io.dmaRegs.entrySet())regs.addProperty(Long.toString(item.getKey()),item.getValue());row.add("dma_mmio",regs);row.addProperty("bounce_sha256",hash(mem(e,BOUNCE,512)));
                for(long at:new long[]{TABLE-32,TABLE+112})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Connected DMA registry guard");
                if(fullPlatform())for(long at:new long[]{dmaPointer(1)-32,dmaPointer(0)+68})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Adjacent original DMA guard");
            }
            if(nativePage()){
                if(!Arrays.equals(bbt,mem(e,0x80df42ccL,164))||!Arrays.equals(guard,mem(e,0x80df42ccL-32,32))||!Arrays.equals(guard,mem(e,0x80df42ccL+164,32)))throw new IllegalStateException("Read BBT input/guard changed");
                row.addProperty("feature_reads",io.featureReads);
            }
            if(nativePlatform()){JsonObject regs=new JsonObject();for(var item:io.boardRegs.entrySet())regs.addProperty(Long.toString(item.getKey()),item.getValue());row.add("board_mmio",regs);}
            if(fullPlatform()){
                if(!Arrays.equals(descriptor,mem(e,0x81306000L,184))||!Arrays.equals(guard,mem(e,0x813060b8L,32)))throw new IllegalStateException("Platform descriptor changed");
                row.addProperty("reinit_flag",mem(e,0x80d81d6cL,1)[0]&255);
            }
            JsonObject observed=new JsonObject();observed.add("actions",actions);JsonArray rows=new JsonArray();rows.add(row);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/qspi-hal-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized QSPI HAL code");}
        for(JsonElement item:cfg.getAsJsonArray("native_dma_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized connected DMA code");}
        for(JsonElement item:cfg.getAsJsonArray("platform_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized NAND platform code/data");}
        for(JsonElement item:cfg.getAsJsonArray("page_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized connected NAND read code/data");}
        for(JsonElement item:cfg.getAsJsonArray("program_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized NAND program code");}
        for(JsonElement item:cfg.getAsJsonArray("maintenance_guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized NAND maintenance code");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Vector bound");executionBound=input.has("bound_per_case")?input.get("bound_per_case").getAsInt():100000;if(executionBound<1||executionBound>1500000)throw new IllegalArgumentException("Execution bound");JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",executionBound);report.add("cases",rows);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("QSPI_HAL_VALIDATION cases="+rows.size());
    }
}
