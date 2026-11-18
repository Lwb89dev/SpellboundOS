// Actual main NAND platform, original adjacent DMA records and reinitialization.
//@category SpellboundOS
import ghidra.program.model.address.AddressSpace;
import com.google.gson.*;
import java.util.*;

public class ValidateMainNandPlatform extends ValidateMainQspiDma {
 private static final long TX=0x80c10df4L,RX=0x80c10db0L,DESC=0x81307000L,REINIT=0x80c10e38L,DISABLED=0x80c10e39L,TABLE=0x80c11738L,BOUNCE=0x80d93960L,PACKET=0x81306000L;
 private byte[] descriptor,packet;
 private class PlatformIo extends DmaIo {
  TreeMap<Long,Long> board=new TreeMap<>();
  @Override protected void processRead(AddressSpace space,long p,int n,byte[] data){
   if(active&&space.getName().equals("ram")&&board.containsKey(p)){if(n!=4)throw new IllegalStateException("Main board read width");long v=board.get(p);actions.add("board_r:"+p+":"+v);for(int i=0;i<4;i++)data[i]=(byte)(v>>>(i*8));return;}super.processRead(space,p,n,data);
  }
  @Override protected void processWrite(AddressSpace space,long p,int n,byte[] data){
   if(active&&space.getName().equals("ram")&&board.containsKey(p)){if(n!=4)throw new IllegalStateException("Main board write width");long v=0;for(int i=0;i<4;i++)v|=(data[i]&255L)<<(i*8);board.put(p,v);actions.add("board_w:"+p+":"+v);return;}super.processWrite(space,p,n,data);
  }
 }
 @Override protected Io createIo(){return new PlatformIo();}
 @Override protected long dmaPointer(int i){return i==0?TX:RX;}
 @Override protected void setupDmaFixtures(Helper e){
  byte[] guard=new byte[204];Arrays.fill(guard,(byte)0xa5);e.writeMemory(toAddr(RX-32),guard);
  byte[] records=new byte[136];Arrays.fill(records,(byte)c.get("initial_dma_byte").getAsInt());e.writeMemory(toAddr(RX),records);
  for(long p:new long[]{REINIT,DISABLED,REINIT+2,REINIT+3})put(e,p,1,0);
 }
 @Override protected void setupExtra(Helper e){
  super.setupExtra(e);e.writeMemory(toAddr(CTRL),new byte[64]);put(e,CTRL+16,4,c.get("controller_mode").getAsLong());
  put(e,REINIT,1,c.get("defer_reinit").getAsBoolean()?1:0);put(e,DISABLED,1,c.get("platform_disabled").getAsBoolean()?1:0);
  byte[] guard=new byte[248];Arrays.fill(guard,(byte)0xa5);e.writeMemory(toAddr(DESC-32),guard);byte[] b=new byte[184];try{currentProgram.getMemory().getBytes(toAddr(0x70a3204cL),b);}catch(Exception ex){throw new IllegalStateException(ex);}e.writeMemory(toAddr(DESC),b);put(e,DESC+12,4,c.get("bus_word").getAsLong());descriptor=mem(e,DESC,184);put(e,0x70f8e6f8L,4,DESC);packet=mem(e,PACKET,32);
  PlatformIo p=(PlatformIo)io;for(int i=0;i<2;i++){long at=i==0?0x9a000004L:0x9a00000cL,value=c.getAsJsonArray("board_initial").get(i).getAsLong();p.board.put(at,value);put(e,at,4,value);}
 }
 @Override protected boolean dispatchExtra(Helper e,String mode)throws Exception {
  if(!mode.equals("platform"))throw new IllegalStateException("Main platform entry");String op=c.get("platform_operation").getAsString();
  if(op.equals("init")||!c.get("defer_reinit").getAsBoolean()||c.get("initialize_before_defer").getAsBoolean()){entry(e,0x70296ab0L,DESC);if(r(e,0)!=0)throw new IllegalStateException("Platform init failed");}
  if(op.equals("transfer"))entry(e,0x70296c24L,DESC,PACKET);else if(!op.equals("init"))throw new IllegalStateException("Platform operation");return true;
 }
 @Override protected boolean service(Helper e,long pc)throws Exception {
  if(pc==0x80d43a24L||pc==0x80d342f8L){boolean mux=pc==0x80d43a24L;if(r(e,0)!=0||r(e,1)!=127||r(e,2)!=(mux?63:1))throw new IllegalStateException("Platform pin arguments");long status=c.get("pin_status").getAsLong();actions.add((mux?"platform_pinmux:":"platform_gpio:")+status);ret(e,status);return true;}
  var ins=getInstructionAt(toAddr(pc));if(ins!=null&&ins.getMnemonicString().startsWith("fence")){actions.add("fence");e.writeRegister(e.getPCRegister(),pc+ins.getLength());return true;}
  return super.service(e,pc);
 }
 @Override protected void snapshotExtra(Helper e,JsonObject row)throws Exception {
  byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long p:new long[]{RX-32,REINIT+4,TABLE-32,TABLE+140,DESC-32,DESC+184,BOUNCE-32,BOUNCE+512,PACKET-32,PACKET+32})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Main platform guard");
  if(!Arrays.equals(descriptor,mem(e,DESC,184))||!Arrays.equals(packet,mem(e,PACKET,32))||word(e,0x70f8e6f8L)!=DESC||mem(e,REINIT+2,1)[0]!=0||mem(e,REINIT+3,1)[0]!=0)throw new IllegalStateException("Main platform immutable fixture changed");
  JsonArray contexts=new JsonArray(),registry=new JsonArray();for(int i=0;i<2;i++){long p=dmaPointer(i);byte[] b=mem(e,p,68);contexts.add(HexFormat.of().formatHex(b));for(int at:new int[]{40,41,42,43,48,49,50,51,52,53,54,55,56,57,58,59})if((b[at]&255)!=c.get("initial_dma_byte").getAsInt())throw new IllegalStateException("Untouched main DMA field changed");}
  for(int i=0;i<35;i++)registry.add(word(e,TABLE+i*4));JsonObject regs=new JsonObject(),board=new JsonObject();for(var item:((DmaIo)io).dmaRegs.entrySet())regs.addProperty(Long.toString(item.getKey()),item.getValue());for(var item:((PlatformIo)io).board.entrySet())board.addProperty(Long.toString(item.getKey()),item.getValue());
  row.add("dma_contexts_hex",contexts);row.add("dma_registry",registry);row.add("dma_mmio",regs);row.add("board_mmio",board);row.addProperty("bounce_sha256",hash(mem(e,BOUNCE,512)));row.addProperty("reinit_flag",mem(e,REINIT,1)[0]&255);row.addProperty("disabled_flag",mem(e,DISABLED,1)[0]&255);
 }
}
