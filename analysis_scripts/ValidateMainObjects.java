// Original main-image object lifecycle over authored objects and services.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateMainObjects extends GhidraScript {
 private static final String CONFIG="{\"open\":1882297456,\"close\":1882297568,\"write\":1882297698,\"ioctl\":1882297824,\"active\":1882297956,\"logger\":1881880738,\"diagnostic\":1882296748,\"assertion\":2161337594,\"nand_open\":1882018948,\"nand_close\":1882018882,\"nand_ioctl\":1882018502,\"lower\":1882020902,\"ranges\":[[1882297456,112],[1882297568,130],[1882297698,126],[1882297824,132],[1882297956,14]],\"nand_ranges\":[[1882297456,112],[1882297568,130],[1882297698,126],[1882297824,132],[1882297956,14],[1882018948,66],[1882018882,66],[1882018502,240]],\"guards\":[{\"address\":1882297456,\"size\":112,\"sha256\":\"8778ed8e76af1ae25da412c835754677d176adde30ca65b9349e40a40d917ef5\"},{\"address\":1882297568,\"size\":130,\"sha256\":\"c33c78f7632341dc68d803b7d4f721e390803057a67c573dfed1ca6b6e85fe13\"},{\"address\":1882297698,\"size\":126,\"sha256\":\"b37b3ad667f08d03047c8d56bae6d8175cb1daeafc485c7afcccbae094c8f05b\"},{\"address\":1882297824,\"size\":132,\"sha256\":\"3a477c21c637acb2647e097f3e325ef1f78797b55d51511b5446c4fd22208473\"},{\"address\":1882297956,\"size\":14,\"sha256\":\"26f3a0a33bc2d94c89cde600dcf729200ec8ed69363f294f40e088c61e25bd25\"},{\"address\":1882018948,\"size\":66,\"sha256\":\"425b4ea3dc6c32cd4ec564182b0f1f733db2b8a9519c7f58bcd514ce52b8f150\"},{\"address\":1882018882,\"size\":66,\"sha256\":\"14cd540d3a7936848270819479cc5e2bf849b7142b47233bcf1b459a486e19c6\"},{\"address\":1882018502,\"size\":240,\"sha256\":\"d75b7f8b96d0a12d3c9c5c987d42b53384c612be524ff395cdd8a8770c03c5bc\"},{\"address\":1889812956,\"size\":13,\"sha256\":\"0e5355f57e562d5433d6b8c4c219b43ce31443f8fa5452bc70be5d05a3da6100\"},{\"address\":1889812924,\"size\":14,\"sha256\":\"a819f8d8e82dfce47e02ee79cd1b67c8f4c073d6df33057be580ecc9446c8cd4\"},{\"address\":1889812892,\"size\":14,\"sha256\":\"fcc6f7eb0be17bd5832b01da79078fad8b90a9679ccade6fe96a7ca00ec870d8\"},{\"address\":1889812860,\"size\":15,\"sha256\":\"f5c56972b854dbab45964fff39dc9286a0cd0ef234a7f7eca8f283c3bd2e0d14\"},{\"address\":1889733516,\"size\":14,\"sha256\":\"8779b049270a988f250e27305953d18974ff6ef0913eb3b07b33adbfdebd7d66\"},{\"address\":1889733548,\"size\":15,\"sha256\":\"4e9854870516a747999fd9279163568bf647705b678597876920dccf5101f6ed\"},{\"address\":1889733652,\"size\":16,\"sha256\":\"d9d5d18c3f258009a1af0e018bd94f036e78a26bdf56a8a550c8c16ebcc236c1\"},{\"address\":1895179456,\"size\":28,\"sha256\":\"69b3a7308f0cfa50ba6f6ea643b5b36048e236b7fdf10aa759f5fa3ad86294ab\"},{\"address\":1895332556,\"size\":4,\"sha256\":\"b81ee1d564e1873d93ba60a05f575cf4dfc1f717df15c8593acfbc37f84a7327\"},{\"address\":1895179484,\"size\":28,\"sha256\":\"5442836baf05dbf17dff02ffe9a110ae91833113409aabea51d5bb61092a93ed\"}],\"nand_data_guards\":[{\"address\":1895179456,\"size\":28,\"sha256\":\"69b3a7308f0cfa50ba6f6ea643b5b36048e236b7fdf10aa759f5fa3ad86294ab\"},{\"address\":1895332556,\"size\":4,\"sha256\":\"b81ee1d564e1873d93ba60a05f575cf4dfc1f717df15c8593acfbc37f84a7327\"},{\"address\":1895179484,\"size\":28,\"sha256\":\"5442836baf05dbf17dff02ffe9a110ae91833113409aabea51d5bb61092a93ed\"}],\"logs\":{\"1889812628\":\"unopened_close\",\"1889812768\":\"unopened_write\",\"1889812812\":\"unopened_ioctl\",\"1889733480\":\"geometry_null\"}}";
 private static final long END=0x70000000L,OBJECT=0x81327000L,TABLE=0x81328000L,DATA=0x81329000L,OUTPUT=0x8132a000L,CB=0x70001000L;
 private JsonObject cfg,c,op,stopped;private JsonArray actions;private String scope;private int steps,lowerCalls,lowerPhase;
 private long a(String k){return cfg.get(k).getAsLong();}
 private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
 private void put(EmulatorHelper e,long p,int n,long v){e.writeMemoryValue(toAddr(p),n,v);}
 private byte[] mem(EmulatorHelper e,long p,int n){return e.readMemory(toAddr(p),n);}
 private long word(EmulatorHelper e,long p){byte[] b=mem(e,p,4);long v=0;for(int i=0;i<4;i++)v|=(b[i]&255L)<<(8*i);return v;}
 private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
 private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
 private void entry(EmulatorHelper e,long start,long... args)throws Exception {
  e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
  while((pc=e.getExecutionAddress().getOffset())!=END){
   if(++steps>10000)throw new IllegalStateException("Execution bound");
   for(String k:new String[]{"open","close","write","ioctl","active"})if(pc==a(k))actions.add("native:"+k);
   for(String k:new String[]{"open","close","ioctl"})if(pc==a("nand_"+k))actions.add("nand:"+k+(k.equals("ioctl")?":"+r(e,1):""));
   if(pc>=CB&&pc<CB+16&&(pc-CB)%4==0){
    int index=(int)((pc-CB)/4);String kind=new String[]{"open","close","write","ioctl"}[index];long status=c.getAsJsonObject("status").get(kind).getAsLong();if(r(e,0)!=OBJECT||!scope.equals("callbacks"))throw new IllegalStateException("Callback object/scope");
    if(kind.equals("open")){if(r(e,1)!=op.get("flags").getAsLong())throw new IllegalStateException("Open flags");actions.add("callback:open:"+r(e,1)+":"+status);}
    else if(kind.equals("close"))actions.add("callback:close:"+status);
    else if(kind.equals("write")){if(r(e,1)!=op.get("offset").getAsLong()||r(e,2)!=DATA||r(e,3)!=op.get("size").getAsLong())throw new IllegalStateException("Write forwarding");actions.add("callback:write:"+r(e,1)+":"+r(e,3)+":"+status);}
    else{if(r(e,1)!=op.get("command").getAsLong()||r(e,2)!=0x11223344L||r(e,3)!=0x55667788L||r(e,4)!=(op.get("output").getAsBoolean()?OUTPUT:0))throw new IllegalStateException("Ioctl forwarding");actions.add("callback:ioctl:"+r(e,1)+":"+(r(e,4)!=0?1:0)+":"+status);if(r(e,4)!=0&&c.get("callback_output").getAsBoolean())put(e,OUTPUT,4,r(e,1));}
    ret(e,status);continue;
   }
   if(pc==a("lower")){
    if(!scope.equals("nand")||r(e,1)<0x81000000L||r(e,1)+4>0x81001000L)throw new IllegalStateException("Lower query backing");int phase=++lowerPhase;long q=r(e,0);if(phase>4||q!=new int[]{13,2,1,14}[phase-1])throw new IllegalStateException("Lower query order");lowerCalls++;
    long status=phase==c.get("lower_fail_at").getAsInt()?c.get("lower_status").getAsLong():0,value=c.getAsJsonArray("geometry").get(phase-1).getAsLong();actions.add("lower:"+q+":"+status+":"+value);if(status==0)put(e,r(e,1),q==14?1:4,value);ret(e,status);continue;
   }
   if(pc==a("logger")){String tag=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3))).getAsString();actions.add("log:"+tag);ret(e,0);continue;}
   if(pc==a("diagnostic")){actions.add("diagnostic:"+op.get("op").getAsString());ret(e,0);continue;}
   if(pc==a("assertion")){stopped=new JsonObject();stopped.addProperty("kind","assertion");stopped.addProperty("owner",r(e,1));stopped.addProperty("line",r(e,2));return;}
   boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray(scope.equals("nand")?"nand_ranges":"ranges")){long p=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=p&&pc<p+n){allowed=true;break;}}
   if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
  }abi(e);
 }
 private JsonObject execute(JsonObject input)throws Exception {
  c=input;steps=lowerCalls=0;actions=new JsonArray();stopped=null;EmulatorHelper e=new EmulatorHelper(currentProgram);
  try{
   byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
   for(long[] span:new long[][]{{OBJECT,60},{TABLE,28},{DATA,64},{OUTPUT,32}})e.writeMemory(toAddr(span[0]-32),Arrays.copyOf(sentinel,(int)span[1]+64));
   byte[] obj=Arrays.copyOf(sentinel,60),name="dev_nand".getBytes(java.nio.charset.StandardCharsets.US_ASCII);Arrays.fill(obj,0,32,(byte)0);System.arraycopy(name,0,obj,0,name.length);e.writeMemory(toAddr(OBJECT),obj);put(e,OBJECT+36,1,23);put(e,OBJECT+40,4,scope.equals("nand")?0x70f624c0L:c.get("table").getAsBoolean()?TABLE:0);put(e,OBJECT+48,4,c.get("count").getAsLong());put(e,OBJECT+52,4,0);put(e,OBJECT+56,4,0x81330000L);
   e.writeMemory(toAddr(TABLE),new byte[28]);for(int i=0;i<4;i++){String key=new String[]{"open","close","write","ioctl"}[i];put(e,TABLE+(i==3?24:i*4),4,c.getAsJsonObject("callbacks").get(key).getAsBoolean()?CB+i*4:0);}byte[] table=mem(e,TABLE,28),data=new byte[64];for(int i=0;i<64;i++)data[i]=(byte)(i*3+1);e.writeMemory(toAddr(DATA),data);
   JsonArray rows=new JsonArray();for(JsonElement item:c.getAsJsonArray("operations")){op=item.getAsJsonObject();lowerPhase=0;String kind=op.get("op").getAsString();long pointer=op.get("object").getAsBoolean()?OBJECT:0;
    if(kind.equals("open"))entry(e,a(kind),pointer,op.get("flags").getAsLong());else if(kind.equals("write"))entry(e,a(kind),pointer,op.get("offset").getAsLong(),op.get("data").getAsBoolean()?DATA:0,op.get("size").getAsLong());else if(kind.equals("ioctl"))entry(e,a(kind),pointer,op.get("command").getAsLong(),0x11223344L,0x55667788L,op.get("output").getAsBoolean()?OUTPUT:0);else entry(e,a(kind),pointer);
    JsonObject row=new JsonObject();row.add("returned",stopped==null?new JsonPrimitive(r(e,0)):JsonNull.INSTANCE);row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);row.addProperty("object_hex",HexFormat.of().formatHex(mem(e,OBJECT,60)));row.addProperty("output_hex",HexFormat.of().formatHex(mem(e,OUTPUT,32)));row.addProperty("data_sha256",hash(mem(e,DATA,64)));row.addProperty("lower_calls",lowerCalls);rows.add(row);if(stopped!=null)break;
   }
   byte[] guard=Arrays.copyOf(sentinel,32);for(long[] span:new long[][]{{OBJECT,60},{TABLE,28},{DATA,64},{OUTPUT,32}})for(long p:new long[]{span[0]-32,span[0]+span[1]})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Object lifecycle guard");
   if(!Arrays.equals(table,mem(e,TABLE,28))||!Arrays.equals(data,mem(e,DATA,64)))throw new IllegalStateException("Immutable fixture changed");
   for(JsonElement item:cfg.getAsJsonArray("nand_data_guards")){JsonObject g=item.getAsJsonObject();if(!hash(mem(e,g.get("address").getAsLong(),g.get("size").getAsInt())).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Original NAND data changed");}
   JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/main-object-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
   JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
  }finally{e.dispose();}
 }
 public void run()throws Exception {
  if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(String key:new String[]{"guards","nand_data_guards"})for(JsonElement item:cfg.getAsJsonArray(key)){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized main object code/data");}
  JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();scope=input.get("scope").getAsString();if(input.get("schema").getAsInt()!=1||input.get("bound_per_case").getAsInt()!=10000||!Set.of("callbacks","nand").contains(scope)||input.getAsJsonArray("cases").size()>64)throw new IllegalStateException("Vector scope/bound");JsonArray cases=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))cases.add(execute(item.getAsJsonObject()));
  JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",cases.size());report.addProperty("bound_per_case",10000);report.add("cases",cases);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("MAIN_OBJECT_VALIDATION scope="+scope+" cases="+cases.size());
 }
}
