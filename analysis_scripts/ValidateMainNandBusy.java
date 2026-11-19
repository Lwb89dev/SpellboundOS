// Full original busy loops; stream every busy-window trace event into counted SHA-256.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;
public class ValidateMainNandBusy extends ValidateMainNandBbtRepair {
 private boolean active,target;private String kind;private int ordinal,limit,polls;private long returnPc,out,eventCount;private JsonArray outer;private MessageDigest digest;
 private Map<String,Integer> ordinals;
 @Override protected int executionBound(){return 4000000;}
 @Override protected int fifoReadBound(){return 8192;}
 @Override protected void setupProbe(EmulatorHelper e){super.setupProbe(e);if(!c.get("native_main_busy").getAsBoolean())throw new IllegalStateException("Complete busy scope");active=target=false;ordinals=new HashMap<>();outer=null;digest=null;eventCount=0;}
 private void flush(){for(JsonElement item:actions){if(!item.isJsonPrimitive()||!item.getAsJsonPrimitive().isString())throw new IllegalStateException("Busy trace type");String value=item.getAsString();if(value.indexOf('\n')>=0)throw new IllegalStateException("Busy trace newline");digest.update(value.getBytes(StandardCharsets.UTF_8));digest.update((byte)10);eventCount++;}actions=new JsonArray();}
 @Override protected long fifoResponse(int opcode,int reg,int n,int at){if(active&&target&&opcode==15&&reg==192){long ignored=super.fifoResponse(opcode,reg,n,at);int ready=c.get("busy_ready_at").getAsInt();return ready!=0&&polls>=ready?c.get("busy_final_status").getAsLong():1;}return super.fifoResponse(opcode,reg,n,at);}
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {
  if(active&&pc==returnPc){flush();int status=mem(e,out,1)[0]&255;long returned=r(e,0);String hash=HexFormat.of().formatHex(digest.digest());actions=outer;actions.add("busy_window:"+kind+":"+ordinal+":"+limit+":"+polls+":"+status+":"+returned+":"+eventCount+":"+hash);if(target)println("MAIN_BUSY_WINDOW "+c.get("name").getAsString()+" polls="+polls+" out="+status+" events="+eventCount+" sha256="+hash);active=target=false;}
  if(pc==0x702d6470L){if(active)throw new IllegalStateException("Nested busy window");long ra=e.readRegister("ra").longValue()&0xffffffffL;
   kind=ra>=0x702d6524L&&ra<0x702d67c0L?"uid":ra>=0x702d6bbeL&&ra<0x702d6d2cL?"read":ra>=0x702d730cL&&ra<0x702d7414L?"erase":ra>=0x702d6d2cL&&ra<0x702d6ea0L?"program":null;
   if(kind==null||r(e,0)!=(kind.equals("erase")?20:10)||r(e,1)<0x81000000L||r(e,1)>=0x81001000L)throw new IllegalStateException("Busy caller/arguments");
   ordinal=ordinals.getOrDefault(kind,0)+1;ordinals.put(kind,ordinal);limit=kind.equals("erase")?4000:2000;polls=0;returnPc=ra;out=r(e,1);eventCount=0;digest=MessageDigest.getInstance("SHA-256");outer=actions;actions=new JsonArray();active=true;target=kind.equals(c.get("busy_stage").getAsString())&&ordinal==c.get("busy_call").getAsInt();if(target)println("MAIN_BUSY_START "+c.get("name").getAsString()+" limit="+limit);
  }
  if(active&&pc==0x702d5daaL){flush();polls++;if(polls>limit)throw new IllegalStateException("Busy poll bound");}
  if(active&&pc==0x702b38a2L&&r(e,3)==0x70a31160L){actions.add("log:busy_timeout");ret(e,0);return true;}
  return super.probeService(e,pc);
 }
 @Override protected void validateExtra(EmulatorHelper e)throws Exception {if(active||actions!=outer)throw new IllegalStateException("Unfinished busy trace");super.validateExtra(e);}
}
