// Original main DMA backend joined to QSPI wrappers and NAND bounce packets.
//@category SpellboundOS
import ghidra.program.model.address.AddressSpace;
import com.google.gson.*;
import java.util.*;

public class ValidateMainQspiDma extends ValidateMainQspiBus {
 private static final String DMA_CONFIG="{\"init\":1881800760,\"setup_irq\":1881801152,\"cancel\":1881801316,\"setup\":1881801376,\"remaining\":1881801528,\"wait\":1881801560,\"tick\":2161398884,\"prepare\":1881800352,\"finish\":1881800452,\"callback_a\":1879052288,\"callback_b\":1879056384,\"ranges\":[[1881800760,388],[1881801152,162],[1881801316,58],[1881801376,150],[1881801528,28],[1881801560,194]],\"guards\":[{\"address\":1881800760,\"size\":388,\"sha256\":\"62cbd9af6fae44f8b5742c2e6ea363fcd109e8054bfaeb3302e5a74947069ec2\"},{\"address\":1881801152,\"size\":162,\"sha256\":\"b3a179a5e9265500297bb1071f1190bcca1c98817aa3117a9a7340adc7834efe\"},{\"address\":1881801316,\"size\":58,\"sha256\":\"af24620efafac4d7870df9f3dddfaa2b04da08fd8e6e9d739ee052663ba6018a\"},{\"address\":1881801376,\"size\":150,\"sha256\":\"cfce33a095142823ac3765bd40f6c73a758432dc84030c34d4063fd78dd1a5ef\"},{\"address\":1881801528,\"size\":28,\"sha256\":\"f4108ec707a7124c2625c29db37bf0da941d15205408364520929a78018b8be2\"},{\"address\":1881801560,\"size\":194,\"sha256\":\"9985aae8a70d67cb9b9810ca3d6be4381d12c09cb2b8dd4b85454cd4a0551c0c\"}]}";
 private static final long TABLE=0x80c11738L,DMA_BASE=0x93080000L;
 private JsonObject dma;private boolean receive;private int dmaTicks;
 private class DmaIo extends Io {
  TreeMap<Long,Long> dmaRegs=new TreeMap<>();Map<String,Integer> dmaIndices=new HashMap<>();
  @Override protected void processRead(AddressSpace space,long address,int size,byte[] data){
   if(active&&space.getName().equals("ram")&&address>=DMA_BASE&&address<DMA_BASE+0x200){
    long at=address-DMA_BASE;if(size!=4||!dmaRegs.containsKey(at))throw new IllegalStateException("Connected main DMA read");long value=dmaRegs.get(at);
    if(at==20||at==24){String key=at==20?"status_a":"status_b";JsonArray values=c.getAsJsonObject(receive?"dma_rx":"dma_tx").getAsJsonArray(key);int i=dmaIndices.getOrDefault(key,0);dmaIndices.put(key,i+1);value=values.get(Math.min(i,values.size()-1)).getAsLong();dmaRegs.put(at,value);}
    actions.add("dma_r:"+at+":"+value);for(int i=0;i<4;i++)data[i]=(byte)(value>>>(8*i));return;
   }super.processRead(space,address,size,data);
  }
  @Override protected void processWrite(AddressSpace space,long address,int size,byte[] data){
   if(active&&space.getName().equals("ram")&&address>=DMA_BASE&&address<DMA_BASE+0x200){
    long at=address-DMA_BASE;if(size!=4||!dmaRegs.containsKey(at))throw new IllegalStateException("Connected main DMA write");long value=0;for(int i=0;i<4;i++)value|=(data[i]&255L)<<(8*i);dmaRegs.put(at,value);actions.add("dma_w:"+at+":"+value);return;
   }super.processWrite(space,address,size,data);
  }
 }
 @Override protected Io createIo(){return new DmaIo();}
 @Override protected void configure()throws Exception {
  super.configure();dma=JsonParser.parseString(DMA_CONFIG).getAsJsonObject();
  for(JsonElement item:dma.getAsJsonArray("ranges")){long p=item.getAsJsonArray().get(0).getAsLong();if(p==dma.get("init").getAsLong()||p==dma.get("setup").getAsLong()||p==dma.get("wait").getAsLong())cfg.getAsJsonArray("ranges").add(item.deepCopy());}
  for(JsonElement item:dma.getAsJsonArray("guards"))cfg.getAsJsonArray("guards").add(item.deepCopy());
 }
 @Override protected void setupExtra(Helper e){
  super.setupExtra(e);dmaTicks=0;receive=false;byte[] guard=new byte[204];Arrays.fill(guard,(byte)0xa5);e.writeMemory(toAddr(TABLE-32),guard);e.writeMemory(toAddr(TABLE),new byte[140]);
  for(int i=0;i<2;i++){long p=i==0?DMA0:DMA1;byte[] b=HexFormat.of().parseHex(c.get(i==0?"dma_tx_hex":"dma_rx_hex").getAsString());if(b.length!=80)throw new IllegalStateException("Main DMA descriptor size");e.writeMemory(toAddr(p-32),Arrays.copyOf(guard,144));e.writeMemory(toAddr(p),b);}
  DmaIo d=(DmaIo)io;for(long[] f:new long[][]{{4,32},{8,0x100},{12,0},{16,0x200},{20,0},{24,0},{36,0}})d.dmaRegs.put(f[0],f[1]);
  for(int ch=0;ch<7;ch++)for(long[] f:new long[][]{{0x100,0x12340001},{0x104,0xffff},{0x108,0x11111111},{0x10c,0x22222222},{0x110,0x33333333},{0x114,0x44444444}})d.dmaRegs.put(ch*32+f[0],f[1]);
  for(var item:d.dmaRegs.entrySet())put(e,DMA_BASE+item.getKey(),4,item.getValue());
 }
 @Override protected boolean dispatchExtra(Helper e,String mode)throws Exception {
  entry(e,dma.get("init").getAsLong(),DMA0);if(r(e,0)!=0)throw new IllegalStateException("TX init failed");entry(e,dma.get("init").getAsLong(),DMA1);if(r(e,0)!=0)throw new IllegalStateException("RX init failed");
  return mode.equals("bus")?super.dispatchExtra(e,mode):false;
 }
 @Override protected boolean service(Helper e,long pc)throws Exception {
  if(pc==dma.get("setup").getAsLong()||pc==dma.get("wait").getAsLong()){
   long p=r(e,0);if(p!=DMA0&&p!=DMA1)throw new IllegalStateException("Main DMA binding");receive=p==DMA1;return false;
  }
  if(pc==dma.get("tick").getAsLong()){
   JsonArray values=c.getAsJsonObject(receive?"dma_rx":"dma_tx").getAsJsonArray("ticks");long value=values.get(Math.min(dmaTicks++,values.size()-1)).getAsLong();actions.add("dma_tick:"+Long.toUnsignedString(value));e.writeRegister("a0",value&0xffffffffL);e.writeRegister("a1",value>>>32);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));return true;
  }
  if(pc==dma.get("prepare").getAsLong()||pc==dma.get("finish").getAsLong()){
   long p=r(e,0);int n=(int)r(e,1);if(n<0||n>64||p!=0&&p!=io.base+0x100&&!pointer(p,n))throw new IllegalStateException("Main DMA cache arguments");actions.add((pc==dma.get("prepare").getAsLong()?"dma_cache_prepare:":"dma_cache_finish:")+p+":"+n);ret(e,0);return true;
  }return super.service(e,pc);
 }
 @Override protected void snapshotExtra(Helper e,JsonObject row)throws Exception {
  super.snapshotExtra(e,row);JsonArray contexts=new JsonArray(),registry=new JsonArray();byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);
  for(int i=0;i<2;i++){long p=i==0?DMA0:DMA1;byte[] b=mem(e,p,80),original=HexFormat.of().parseHex(c.get(i==0?"dma_tx_hex":"dma_rx_hex").getAsString());contexts.add(HexFormat.of().formatHex(b));System.arraycopy(original,60,b,60,8);if(!Arrays.equals(original,b)||!Arrays.equals(guard,mem(e,p-32,32))||!Arrays.equals(guard,mem(e,p+80,32)))throw new IllegalStateException("Main DMA descriptor/input guards");}
  for(int i=0;i<35;i++)registry.add(word(e,TABLE+i*4));for(long p:new long[]{TABLE-32,TABLE+140})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Main DMA registry guards");
  JsonObject regs=new JsonObject();for(var item:((DmaIo)io).dmaRegs.entrySet())regs.addProperty(Long.toString(item.getKey()),item.getValue());row.add("dma_contexts_hex",contexts);row.add("dma_registry",registry);row.add("dma_mmio",regs);
 }
}
