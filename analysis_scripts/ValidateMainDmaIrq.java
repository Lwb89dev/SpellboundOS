// Ordinary-call main IRQ dispatch and optional actual signed cache guards.
//@category SpellboundOS
import com.google.gson.*;
public class ValidateMainDmaIrq extends ValidateMainDmaBackend {
 private static final String IRQ_CONFIG="{\"irq\":1881801756,\"ranges\":[[1881801756,250],[1881800352,100],[1881800452,100]],\"guards\":[{\"address\":1881801756,\"size\":250,\"sha256\":\"54a80406ae0a6e904abbf7fb6acdd47fa3e058433318651df85cc14892f952f8\"},{\"address\":1881800352,\"size\":100,\"sha256\":\"e64c0074c738be7fb278fa37bd95334e8c5a2b3b8c2f8228ce4666357e6c1f7a\"},{\"address\":1881800452,\"size\":100,\"sha256\":\"bcc87b688c79b8076dcc56b180cbd48a4d729ccd1a8b78078ba87b9efcff9d65\"}]}";
 @Override protected int bank(long base){int value=super.bank(base);return value<0?28:value;}
 @Override protected boolean supplyCacheServices(JsonObject input){return !input.get("native_cache_guards").getAsBoolean();}
 @Override protected String configuration(){JsonObject cfg=JsonParser.parseString(super.configuration()).getAsJsonObject(),extra=JsonParser.parseString(IRQ_CONFIG).getAsJsonObject();cfg.add("irq",extra.get("irq"));for(String key:new String[]{"ranges","guards"})for(JsonElement item:extra.getAsJsonArray(key))cfg.getAsJsonArray(key).add(item.deepCopy());return cfg.toString();}
}
