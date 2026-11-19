// Actual main remappers over recovered BBT state, after probe/root publication.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.util.*;
public class ValidateMainNandBbtMapping extends ValidateMainNandBbt {
 private static final String MAP_CONFIG="{\"ranges\":[[1882020402,64],[1882020466,96]],\"guards\":[{\"address\":1882020402,\"size\":64,\"sha256\":\"3a02448fa8ad97fcaf8151bf1bd0c80a6c146db7be58c4f09e4cb76a647be6fd\"},{\"address\":1882020466,\"size\":96,\"sha256\":\"f322fc271bb3dba55d896a70e23396f461077c6c10bce42ecf03fbf5aeb1e6c9\"}]}";
 private static final long OUT=0x8132f000L;
 @Override protected void configure()throws Exception {super.configure();JsonObject cfgMap=JsonParser.parseString(MAP_CONFIG).getAsJsonObject();for(JsonElement item:cfgMap.getAsJsonArray("ranges"))cfg.getAsJsonArray("main_probe_ranges").add(item.deepCopy());for(JsonElement item:cfgMap.getAsJsonArray("guards"))cfg.getAsJsonArray("main_probe_guards").add(item.deepCopy());}
 @Override protected void setupProbe(EmulatorHelper e){super.setupProbe(e);if(!c.get("native_main_bbt_mapping").getAsBoolean())throw new IllegalStateException("Main BBT remapping scope");byte[] b=new byte[68];Arrays.fill(b,(byte)0xa5);e.writeMemory(toAddr(OUT-32),b);}
 @Override protected boolean additionalOperation(EmulatorHelper e,String kind)throws Exception {if(!kind.equals("map_block")&&!kind.equals("map_page"))return super.additionalOperation(e,kind);if(!op.get("output").getAsBoolean())throw new IllegalStateException("Main mapping backing");entry(e,kind.equals("map_block")?0x702d5a32L:0x702d5a72L,op.get("offset").getAsLong(),OUT);return true;}
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {if(pc==0x702d5a32L||pc==0x702d5a72L)actions.add((pc==0x702d5a32L?"main_remap_block:":"main_remap_page:")+r(e,0));return super.probeService(e,pc);}
 @Override protected void probeSnapshot(EmulatorHelper e,JsonObject row){super.probeSnapshot(e,row);row.addProperty("map_output",word(e,OUT));}
 @Override protected void validateExtra(EmulatorHelper e)throws Exception {super.validateExtra(e);byte[] guard=new byte[32];Arrays.fill(guard,(byte)0xa5);for(long p:new long[]{OUT-32,OUT+4})if(!Arrays.equals(guard,mem(e,p,32)))throw new IllegalStateException("Main mapping output guard");}
}
