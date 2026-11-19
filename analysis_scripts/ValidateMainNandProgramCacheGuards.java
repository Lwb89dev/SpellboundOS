// Actual original signed cache guards at the selected NAND DMA service boundary.
//@category SpellboundOS
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
public class ValidateMainNandProgramCacheGuards extends ValidateMainNandProgram {
 private static final String CACHE_GUARD_CONFIG="{\"ranges\":[[1881800352,100],[1881800452,100]],\"guards\":[{\"address\":1881800352,\"size\":100,\"sha256\":\"e64c0074c738be7fb278fa37bd95334e8c5a2b3b8c2f8228ce4666357e6c1f7a\"},{\"address\":1881800452,\"size\":100,\"sha256\":\"bcc87b688c79b8076dcc56b180cbd48a4d729ccd1a8b78078ba87b9efcff9d65\"}]}";
 @Override protected void configure()throws Exception {super.configure();JsonObject a=JsonParser.parseString(CACHE_GUARD_CONFIG).getAsJsonObject();for(JsonElement item:a.getAsJsonArray("ranges"))cfg.getAsJsonArray("main_probe_ranges").add(item.deepCopy());for(JsonElement item:a.getAsJsonArray("guards"))cfg.getAsJsonArray("main_probe_guards").add(item.deepCopy());}
 @Override protected void setupProbe(EmulatorHelper e){super.setupProbe(e);if(!c.get("native_main_cache_guards").getAsBoolean())throw new IllegalStateException("Actual cache guard scope");}
 @Override protected boolean probeService(EmulatorHelper e,long pc)throws Exception {if(pc==0x7029fea0L||pc==0x7029ff04L){long p=r(e,0),n=r(e,1);if(n>64||p!=0&&p!=0x80d93960L&&p!=0x93240100L)throw new IllegalStateException("Original NAND cache guard arguments");actions.add((pc==0x7029fea0L?"dma_cache_prepare:":"dma_cache_finish:")+p+":"+n);return false;}return super.probeService(e,pc);}
}
