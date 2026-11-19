// Original cache CSR loops and RTOS critical/trace code; authored state/readbacks.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
public class ValidateMainCacheControl extends GhidraScript {
 private static final String CONFIG="{\"all\":1881800308,\"prepare\":1881800352,\"finish\":1881800452,\"invalidate\":1881800552,\"save\":2161342958,\"restore\":2161343002,\"context\":2161381776,\"enter\":2161352802,\"exit\":2161352878,\"trace\":2161325856,\"ranges\":[[1881800308,44],[1881800352,100],[1881800452,100],[1881800552,100],[2161342958,44],[2161343002,24],[2161381776,10],[2161352802,76],[2161352878,76],[2161325856,26]],\"guards\":[{\"address\":1881800308,\"size\":44,\"sha256\":\"9cb803aef5ce0be509a12eb65dc10d5915b0c451949c8b08ba8da37a8420deed\"},{\"address\":1881800352,\"size\":100,\"sha256\":\"e64c0074c738be7fb278fa37bd95334e8c5a2b3b8c2f8228ce4666357e6c1f7a\"},{\"address\":1881800452,\"size\":100,\"sha256\":\"bcc87b688c79b8076dcc56b180cbd48a4d729ccd1a8b78078ba87b9efcff9d65\"},{\"address\":1881800552,\"size\":100,\"sha256\":\"9b9cfdfda4beb4b2f7cc1855e7166485ac5f919f5176a32be6484e48353b602a\"},{\"address\":2161342958,\"size\":44,\"sha256\":\"df22cb4dab0659357c56844cf70ac9a46d293f1d6a550c5a94017dc5957e5155\"},{\"address\":2161343002,\"size\":24,\"sha256\":\"571b37c235757ad804ddb9009ff95f462674435f1ab7907cbae4d928e4cdeee2\"},{\"address\":2161381776,\"size\":10,\"sha256\":\"ec75315854db7952cbf4a34374939753a3623932d35b142858e774f7c0560724\"},{\"address\":2161352802,\"size\":76,\"sha256\":\"bf1fa0a021f0ccbf98564e67217ef8a5a77ab295fcceb7becf900fcfc28b4386\"},{\"address\":2161352878,\"size\":76,\"sha256\":\"1b2e411079a457949a60c7993eef11c2b2c9a639d4419326e91a2d3182a4b422\"},{\"address\":2161325856,\"size\":26,\"sha256\":\"d87a995a512a6699646eee8fb6e6fec3cb4394d069397b455021757be9de7063\"}]}";
 private static final long END=0x70000000L,SCHED=0x80c07e5cL,CURRENT=0x80c07fa8L,CONTEXT=0x80c121a4L,TRACE_ENABLED=0x80c44244L,TRACE_TABLE=0x80dff708L,THREAD=0x81348000L,COOKIE=0x81349000L;
 private JsonObject cfg,c,stopped;private JsonArray actions;private int steps,commands,readbacks,fences;private Io io;
 private class Helper extends EmulatorHelper {private Emulator core;Helper(Program p){super(p);}@Override protected Emulator newEmulator(){core=super.newEmulator();return core;}void filter(MemoryAccessFilter f){core.addMemoryAccessFilter(f);}}
 private class Io extends MemoryAccessFilter {
  boolean active;TreeMap<Long,Long> csrs=new TreeMap<>();
  private long value(byte[] b){long v=0;for(int i=0;i<b.length;i++)v|=(b[i]&255L)<<(8*i);return v;}
  private boolean watched(long p){return p==SCHED||p==CURRENT||p==CONTEXT||p==TRACE_ENABLED||p==THREAD+80;}
  @Override protected void processRead(AddressSpace space,long offset,int size,byte[] data){if(!active)return;long v;
   if(space.getName().equals("csreg")){long reg=offset/4;if(size!=4||offset%4!=0||!csrs.containsKey(reg))throw new IllegalStateException("Unexpected cache CSR read");if(reg==0x7cb){JsonArray values=c.getAsJsonArray("readbacks");csrs.put(reg,values.get(Math.min(readbacks++,values.size()-1)).getAsLong());}v=csrs.get(reg);actions.add("csr_r:"+reg+":"+v);for(int i=0;i<4;i++)data[i]=(byte)(v>>>(8*i));}
   else if(space.getName().equals("ram")&&watched(offset)){if(size!=(offset==TRACE_ENABLED?1:4))throw new IllegalStateException("Critical read width");actions.add("ram_r:"+offset+":"+size+":"+value(data));}
  }
  @Override protected void processWrite(AddressSpace space,long offset,int size,byte[] data){if(!active)return;long v=value(data);
   if(space.getName().equals("csreg")){long reg=offset/4;if(size!=4||offset%4!=0||!csrs.containsKey(reg)||reg==0x7ca)throw new IllegalStateException("Unexpected cache CSR write");csrs.put(reg,v);actions.add("csr_w:"+reg+":"+v);if(reg==0x7cc)commands++;}
   else if(space.getName().equals("ram")&&(watched(offset)||offset>=TRACE_TABLE&&offset<TRACE_TABLE+48)){if(size!=4||offset!=THREAD+80&&offset!=TRACE_TABLE+24&&offset!=TRACE_TABLE+28&&offset!=TRACE_TABLE+36)throw new IllegalStateException("Unexpected critical/trace store");actions.add("ram_w:"+offset+":"+size+":"+v);}
  }
 }
 private long r(Helper e,int n){return e.readRegister("a"+n).longValue()&0xffffffffL;}
 private byte[] mem(Helper e,long p,int n){return e.readMemory(toAddr(p),n);}
 private long word(Helper e,long p){byte[] b=mem(e,p,4);long v=0;for(int i=0;i<4;i++)v|=(b[i]&255L)<<(8*i);return v;}
 private void put(Helper e,long p,int n,long v){e.writeMemoryValue(toAddr(p),n,v);}
 private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 private void abi(Helper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Cache stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Cache saved register mismatch");}
 private boolean command(Instruction instruction){for(var p:instruction.getPcode()){var out=p.getOutput();if(out!=null&&out.getAddress().getAddressSpace().getName().equals("csreg")&&out.getOffset()==0x7cc*4)return true;}return false;}
 private void entry(Helper e,long start,long... args)throws Exception {
  e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);
  while(e.getExecutionAddress().getOffset()!=END){long pc=e.getExecutionAddress().getOffset();if(++steps>5000)throw new IllegalStateException("Cache instruction bound");boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long at=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=at&&pc<at+n){allowed=true;break;}}if(!allowed)throw new IllegalStateException("Cache escaped at "+Long.toHexString(pc));var instruction=getInstructionAt(toAddr(pc));if(instruction==null)throw new IllegalStateException("Missing cache instruction");
   if(command(instruction)&&commands>=c.get("command_limit").getAsInt()){stopped=new JsonObject();stopped.addProperty("kind","command_bound");stopped.addProperty("limit",c.get("command_limit").getAsInt());return;}
   if(pc==cfg.get("trace").getAsLong()){if(r(e,0)!=6&&r(e,0)!=7&&r(e,0)!=9)throw new IllegalStateException("Trace index bound");actions.add("trace:"+r(e,0)+":"+r(e,1));}
   if(instruction.getMnemonicString().equals("fence")){if(pc!=0x7029fee0L&&pc!=0x7029ff44L&&pc!=0x7029ffa8L||instruction.getLength()!=4)throw new IllegalStateException("Unreviewed cache fence");fences++;actions.add("fence");e.writeRegister(e.getPCRegister(),pc+4);continue;}
   boolean ok;io.active=true;try{ok=e.step(monitor);}finally{io.active=false;}if(!ok)throw new IllegalStateException(e.getLastError());
  }abi(e);
 }
 private JsonObject execute(JsonObject input)throws Exception {
  c=input;steps=commands=readbacks=fences=0;actions=new JsonArray();stopped=null;Helper e=new Helper(currentProgram);io=new Io();
  try{
   byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
   for(long[] span:new long[][]{{SCHED,4},{CURRENT,4},{CONTEXT,4},{TRACE_ENABLED,1},{TRACE_TABLE,48},{THREAD,128},{COOKIE,4}})e.writeMemory(toAddr(span[0]-16),Arrays.copyOf(sentinel,(int)span[1]+32));
   put(e,SCHED,4,c.get("scheduler").getAsLong());put(e,CURRENT,4,THREAD);put(e,CONTEXT,4,c.get("context").getAsLong());put(e,TRACE_ENABLED,1,c.get("trace_enabled").getAsLong());put(e,THREAD+80,4,c.get("depth").getAsLong());byte[] initialThread=mem(e,THREAD,128),payload=new byte[512];for(int i=0;i<512;i++)payload[i]=(byte)(i*13+7);e.writeMemory(toAddr(0x1000),payload);
   String[] names={"mstatus","control","initial_address","initial_command"};long[] regs={0x300,0x7ca,0x7cb,0x7cc};var space=currentProgram.getAddressFactory().getAddressSpace("csreg");for(int i=0;i<4;i++){long v=c.get(names[i]).getAsLong();io.csrs.put(regs[i],v);e.writeMemoryValue(space.getAddress(regs[i]*4),4,v);}e.filter(io);
   JsonArray rows=new JsonArray();for(JsonElement item:c.getAsJsonArray("operations")){JsonObject op=item.getAsJsonObject();String kind=op.get("kind").getAsString();long start=op.get("start").getAsLong(),size=op.get("size").getAsLong();actions.add("op:"+kind+":"+start+":"+size);long at=cfg.get(kind).getAsLong();if(kind.equals("save"))entry(e,at,COOKIE);else if(kind.equals("restore"))entry(e,at,c.get("restore_arg").getAsLong());else if(kind.equals("all")||kind.equals("enter")||kind.equals("exit"))entry(e,at);else entry(e,at,start,size);
    JsonObject row=new JsonObject();boolean cache=kind.equals("all")||kind.equals("prepare")||kind.equals("finish")||kind.equals("invalidate");row.add("returned",stopped!=null||!cache?JsonNull.INSTANCE:new JsonPrimitive(r(e,0)));row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);JsonObject csr=new JsonObject();for(var value:io.csrs.entrySet())csr.addProperty(Long.toString(value.getKey()),value.getValue());row.add("csrs",csr);row.addProperty("depth",word(e,THREAD+80));JsonArray table=new JsonArray();for(int i=0;i<12;i++)table.add(word(e,TRACE_TABLE+i*4));row.add("trace_table",table);row.addProperty("saved_word",word(e,COOKIE));row.addProperty("commands",commands);row.addProperty("readbacks",readbacks);row.addProperty("fences",fences);rows.add(row);if(stopped!=null)break;
   }
   for(long[] span:new long[][]{{SCHED,4},{CURRENT,4},{CONTEXT,4},{TRACE_ENABLED,1},{TRACE_TABLE,48},{THREAD,128},{COOKIE,4}})for(long p:new long[]{span[0]-16,span[0]+span[1]})if(!Arrays.equals(Arrays.copyOf(sentinel,16),mem(e,p,16)))throw new IllegalStateException("Critical backing guard");byte[] thread=mem(e,THREAD,128);System.arraycopy(initialThread,80,thread,80,4);if(!Arrays.equals(initialThread,thread)||!Arrays.equals(payload,mem(e,0x1000,512)))throw new IllegalStateException("Critical/thread/payload fixture changed");if(word(e,SCHED)!=c.get("scheduler").getAsLong()||word(e,CURRENT)!=THREAD||word(e,CONTEXT)!=c.get("context").getAsLong()||(mem(e,TRACE_ENABLED,1)[0]&255)!=c.get("trace_enabled").getAsInt())throw new IllegalStateException("Critical input changed");
   JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/main-cache-control-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
  }finally{e.dispose();}
 }
 public void run()throws Exception {
  if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized cache/critical code");}
  JsonObject vectors=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(vectors.get("schema").getAsInt()!=1||vectors.get("bound_per_case").getAsInt()!=5000||vectors.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Cache vector bound");JsonArray cases=new JsonArray();for(JsonElement item:vectors.getAsJsonArray("cases"))cases.add(execute(item.getAsJsonObject()));JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",cases.size());report.addProperty("bound_per_case",5000);report.add("cases",cases);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("MAIN_CACHE_CONTROL_VALIDATION cases="+cases.size());
 }
}
