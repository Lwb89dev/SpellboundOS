// Actual retry/UID, command builders and busy loop over a supplied bus service.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateNandIdentity extends GhidraScript {
    private static final String CONFIG="{\"compat\":2160237900,\"set_level\":2160237972,\"retry\":2160238190,\"check\":2160238428,\"uid\":2160231458,\"get\":2160229608,\"set\":2160229704,\"load\":2160229902,\"cache\":2160230000,\"reset_enable\":2160231002,\"reset\":2160231096,\"busy\":2160231278,\"wait\":2160132848,\"delay_thunk\":2160072778,\"delay\":2160140628,\"transfer\":2160133872,\"compare\":2160256488,\"zero\":2160254996,\"format\":2160255464,\"logger\":2160184698,\"assertion\":2160157974,\"ioctl\":2160235246,\"copy\":2160254520,\"ranges\":[[2160237900,72],[2160237972,218],[2160238190,238],[2160238428,234],[2160231458,656],[2160229608,96],[2160229704,104],[2160229902,98],[2160230000,102],[2160231002,94],[2160231096,94],[2160231278,180],[2160132848,20],[2160072778,4],[2160235246,394]],\"logs\":{\"2160322684\":\"feature_error\",\"2160322716\":\"level_mismatch\",\"2160322752\":\"retry_valid\",\"2160322780\":\"restore_failed\",\"2160322816\":\"retry_invalid\",\"2160322840\":\"level_register\",\"2160322860\":\"check_level\",\"2160322900\":\"check_failed\",\"2160318128\":\"uid_feature_error\",\"2160318168\":\"uid_error\",\"2160318180\":\"uid_ok\",\"2160318116\":\"busy_timeout\",\"2160318088\":\"busy_feature_error\",\"2160319240\":\"ioctl_error\"},\"guards\":[{\"address\":2160237900,\"size\":72,\"sha256\":\"04093b1b9d368004296b8da508d08bfe9242d1c2ced22bac32bc0e67db03569f\"},{\"address\":2160237972,\"size\":218,\"sha256\":\"41fb19b785d644fcec82cd273d1e76ec51fbeff374c8e826aef5c5a6f43c7be7\"},{\"address\":2160238190,\"size\":238,\"sha256\":\"c97829ee76b97c4ee9c40c2c017a018183b2f6a0ce506bcb64ecf195c313aa22\"},{\"address\":2160238428,\"size\":234,\"sha256\":\"bb717b8e710397e05e10d809559f612365d053f7b043dcf64d538bec73d12d80\"},{\"address\":2160231458,\"size\":656,\"sha256\":\"dcc7ef5a870427061ec6b74e32a8d3cf89b5126f796f44d42fa75a282f09395b\"},{\"address\":2160229608,\"size\":96,\"sha256\":\"2fec1eff293a04a76ac7b393c32edfa35c907acfceb78ad3b8d200a5100c1afe\"},{\"address\":2160229704,\"size\":104,\"sha256\":\"db25a8f625930987d4de9167e93c764a9d7bc8d50be4fdd13f84f3e61fda4274\"},{\"address\":2160229902,\"size\":98,\"sha256\":\"46e9abe616332fcdbfc12b6d60f23bd021543b3762f7234b90a30984ebbc9c1d\"},{\"address\":2160230000,\"size\":102,\"sha256\":\"083d5c97de97dfdffc36089019e1f5f6851ff794d94c547ff6abcd4ff9d20345\"},{\"address\":2160231002,\"size\":94,\"sha256\":\"35294017e76703e315f97a3ba06fe6720fb971ac232c7e22db0ad32d7802a2e0\"},{\"address\":2160231096,\"size\":94,\"sha256\":\"f3c33e88c08da69a41ca885c76e9399c08550d6912e5111eab7d29211cc3f63f\"},{\"address\":2160231278,\"size\":180,\"sha256\":\"c23248ed66048f16a449b0a16bac624f9da5bb43ac00fa3fca9d97e72d519836\"},{\"address\":2160132848,\"size\":20,\"sha256\":\"088330a65e8b216c30d4a672c74d98806b12f38cc51620ec322280add4cc5ecd\"},{\"address\":2160072778,\"size\":4,\"sha256\":\"47e47d166a72630fbde2886201a0384899a89ace1574465a679cebdb1bbde755\"},{\"address\":2160235246,\"size\":394,\"sha256\":\"b6e52b407b668858305eb17bad9d83913f542daafec867d12a6cc69b56202fbe\"},{\"address\":2161646336,\"size\":4,\"sha256\":\"4b0501c77bf148c63c954e4aa8941e14678947a7ee018c32fb6b33ac2774e53a\"},{\"address\":2161641896,\"size\":16,\"sha256\":\"81772459228c4e018935677595f2f511a59d157684239146e872f0ce18584de7\"},{\"address\":2160322660,\"size\":21,\"sha256\":\"f55921541d9d75ec32d328252b52fad9e190f4974c4892b73666d1643d90bcc2\"},{\"address\":2160319740,\"size\":21,\"sha256\":\"1f8757b02b10d10816a8e7ea35eee4f92dfd3cb2c55ded01d7477df666682aa8\"},{\"address\":2160319000,\"size\":5,\"sha256\":\"6591ccd67a1fb2749ff086c1db91e89e58b2c8763c03d7807cab6dd7d98d0f61\"},{\"address\":2160321816,\"size\":184,\"sha256\":\"8ff794d0bd1806c93cf2eeab8b03a7b72b951b3021ec67311396a0bd295c39ee\"},{\"address\":2160319952,\"size\":21,\"sha256\":\"43cc1d97557129c6d760f769b3ccad9da1a9eaf3bdd9242e30b48bf90db6e549\"},{\"address\":2161646628,\"size\":2,\"sha256\":\"8f12374e3ec82be9f0c94f9640c6dbf8b9417452d8225cf0b551b4ac65ef1f9c\"},{\"address\":2160320160,\"size\":184,\"sha256\":\"7175b7e125deb627582a1beee00cd1bcc4168e590971c49cd22ab9a4fe208d93\"},{\"address\":2160319764,\"size\":21,\"sha256\":\"bc3c39d04fd0edf0b11fddf3a9ccce5df94a81c7bcf3037310705f963fed7060\"},{\"address\":2161646532,\"size\":2,\"sha256\":\"8f12374e3ec82be9f0c94f9640c6dbf8b9417452d8225cf0b551b4ac65ef1f9c\"},{\"address\":2160321632,\"size\":184,\"sha256\":\"8dd50ee3bb75385762aa6890f8b9a04f52a6d54108559db974f3337351b1f15f\"},{\"address\":2160319932,\"size\":17,\"sha256\":\"52c465c69fd75d1cacb6ca689c72406c0292a319fbe76d4c2b6c4f6d1d7ba2aa\"},{\"address\":2161646620,\"size\":2,\"sha256\":\"8f12374e3ec82be9f0c94f9640c6dbf8b9417452d8225cf0b551b4ac65ef1f9c\"},{\"address\":2160319976,\"size\":184,\"sha256\":\"193b85a675d2b4c0b76cbc9beb2e056de4c6f3baeaa3c26dec242d6d4b2b7e3a\"},{\"address\":2161646520,\"size\":2,\"sha256\":\"8f12374e3ec82be9f0c94f9640c6dbf8b9417452d8225cf0b551b4ac65ef1f9c\"},{\"address\":2160321448,\"size\":184,\"sha256\":\"68946a6d5a5bee0b008272b662d12e3e1f192b78fe447fdacef00191c8ba740a\"},{\"address\":2160319912,\"size\":19,\"sha256\":\"dd54442d6189ece1edd60252752270af2379a91509f74b8593211be1d8fb5ced\"},{\"address\":2161646608,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160321264,\"size\":184,\"sha256\":\"f59a823e03510ca26c047fb238360371aa48c79d8bca71bcaefc95d91c426ee1\"},{\"address\":2160319892,\"size\":19,\"sha256\":\"550d15f9deb428e8318183394549c840c0f319a854d9238272643046f3ba77dd\"},{\"address\":2161646596,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160321080,\"size\":184,\"sha256\":\"75adff4405bb06df5d88fc8b3af00bcc29c7835b7226bf39cf6a89ea379f9650\"},{\"address\":2160319872,\"size\":19,\"sha256\":\"aa52cca6e68e617ab515fcd9d1069650849f8aa497c6781127a772c57ce97699\"},{\"address\":2161646584,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160320896,\"size\":184,\"sha256\":\"a3cc301704a8f284867767c9c2df18153ae3f0c13d4dd1af8713b0030787eb0d\"},{\"address\":2160319852,\"size\":19,\"sha256\":\"cef720be6165e8c83c0a35c58ac5faeacb7c53bbc628bb80647535c73d90558f\"},{\"address\":2161646572,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160320528,\"size\":184,\"sha256\":\"cb5291eae91d18b933717c3c2addb946e1294c67e7f42bd3ea2c7e58f3038619\"},{\"address\":2160319812,\"size\":22,\"sha256\":\"cc89a2646035c0ed731774d6cd9661da51950f7bc8dc18e0467441ba937e0c01\"},{\"address\":2161646552,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160320344,\"size\":184,\"sha256\":\"8492de115fd544467b2edae9a1802a9b9613b31b521e57c3037b6e7ba0a65a7e\"},{\"address\":2160319788,\"size\":22,\"sha256\":\"efeecff390409dcd019b3326174315cc4c7f5b8ff691aa42d03ccc9960f564d1\"},{\"address\":2161646540,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"},{\"address\":2160320712,\"size\":184,\"sha256\":\"4daf962fb2a03da7544821b50f47bd0668b18df8a443f6d26075fba491199af3\"},{\"address\":2160319836,\"size\":16,\"sha256\":\"ce9eb084f90be450f161000b78ad949da5640c268c2a0221883a66fcb9e0a432\"},{\"address\":2161646564,\"size\":2,\"sha256\":\"5ebc514a714b7e738505fabf839804b26e95d56d0ca54cf6b29052ebd8b9fe37\"}]}";
    private static final long END=0x70000000L,CHIP=0x81302000L,NAME=0x81303000L,SEQ=0x81304000L,UID=0x80df4370L,OUT=0x81305000L;
    private JsonObject cfg,c,desc,stopped;private JsonArray actions;private int steps,gets,sets,loads,caches,transfers,e0Reads,c0Reads;
    private int[] registers;
    private long a(String k){return cfg.get(k).getAsLong();}
    private long r(EmulatorHelper e,int i){return e.readRegister("a"+i).longValue()&0xffffffffL;}
    private void put(EmulatorHelper e,long at,int n,long v){e.writeMemoryValue(toAddr(at),n,v);}
    private byte[] mem(EmulatorHelper e,long at,int n){return n==0?new byte[0]:e.readMemory(toAddr(at),n);}
    private long val(EmulatorHelper e,long at,int n){byte[] b=mem(e,at,n);long v=0;for(int i=0;i<n;i++)v|=(b[i]&255L)<<(8*i);return v;}
    private String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void ret(EmulatorHelper e,long v){e.writeRegister("a0",v&0xffffffffL);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
    private boolean stack(long p,int n){return n>=0&&p>=0x81000000L&&p+n<=0x81001000L;}
    private boolean error(String key,int index){for(JsonElement item:c.getAsJsonArray(key))if(item.getAsInt()==index)return true;return false;}
    private String string(EmulatorHelper e,long p){StringBuilder s=new StringBuilder();for(int i=0;i<80;i++){int v=mem(e,p+i,1)[0]&255;if(v==0)return s.toString();s.append((char)v);}throw new IllegalStateException("String bound");}
    private void abi(EmulatorHelper e){if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack mismatch");for(int i=0;i<12;i++)if(e.readRegister("s"+i).longValue()!=0x45670000L+i)throw new IllegalStateException("Saved register mismatch");}
    private void entry(EmulatorHelper e,long start,long... args)throws Exception {
        stopped=null;e.writeRegister("ra",END);for(int i=0;i<args.length;i++)e.writeRegister("a"+i,args[i]);e.writeRegister(e.getPCRegister(),start);long pc;
        while((pc=e.getExecutionAddress().getOffset())!=END){
            if(++steps>500000)throw new IllegalStateException("Execution bound");
            if(pc==a("get")&&error("get_errors",++gets)){actions.add("inject_get:"+r(e,0)+":-9");ret(e,-9);continue;}
            if(pc==a("set")&&error("set_errors",++sets)){actions.add("inject_set:"+r(e,0)+":"+(r(e,1)&255)+":-9");ret(e,-9);continue;}
            if(pc==a("load")&&++loads==c.get("load_error_at").getAsInt()){actions.add("inject_load:"+r(e,0)+":-9");ret(e,-9);continue;}
            if(pc==a("cache")&&++caches==c.get("cache_error_at").getAsInt()){actions.add("inject_cache:"+r(e,0)+":"+r(e,2)+":-9");ret(e,-9);continue;}
            if(pc==a("transfer")){
                long p=r(e,1);if(r(e,0)!=CHIP||!stack(p,32))throw new IllegalStateException("Bus packet pointer");
                int op=(int)val(e,p+8,4),address=(int)val(e,p+16,4),n=(int)val(e,p+24,4),write=(int)val(e,p,1),ab=(int)val(e,p+12,1),dl=(int)val(e,p+28,1),dummy=(int)val(e,p+1,1);
                long data=val(e,p+20,4);if(n<0||n>128||n>0&&!(stack(data,n)||data==UID&&n<=128))throw new IllegalStateException("Bus payload bound");
                if(write!=0&&write!=1||val(e,p+2,1)!=1||val(e,p+4,1)!=1||dl!=1)throw new IllegalStateException("Bus packet fields");
                int expectedAb=op==15||op==31?1:op==19?3:op==3?2:0;
                if(ab!=expectedAb||dummy!=(op==3?1:0)||n!=(op==15||op==31?1:op==3?32:0))throw new IllegalStateException("Bus packet shape");
                if(!(op==15||op==31||op==19||op==3||op==102||op==153))throw new IllegalStateException("Unexpected opcode");
                byte[] payload=write!=0?mem(e,data,n):new byte[0];int status=++transfers==c.get("bus_error_at").getAsInt()?-9:0;
                actions.add("packet:"+op+":"+Integer.toUnsignedString(address)+":"+n+":"+write+":"+ab+":"+dl+":"+dummy+":"+hash(payload)+":"+status);
                if(status==0){
                    if(op==15){
                        if(address<0||address>255)throw new IllegalStateException("Feature register bound");int value;
                        if(address==224){JsonArray values=c.getAsJsonArray("e0_reads");value=e0Reads<values.size()?values.get(e0Reads).getAsInt():registers[224];e0Reads++;}
                        else if(address==192){JsonArray values=c.getAsJsonArray("statuses");value=values.get(Math.min(c0Reads++,values.size()-1)).getAsInt();}
                        else value=registers[address]^(c.get("uid_mismatch").getAsBoolean()?1:0);
                        put(e,data,1,value);actions.add("get:"+address+":"+value);
                    }else if(op==31){
                        if(address<0||address>255)throw new IllegalStateException("Feature register bound");int value=payload[0]&255;actions.add("set:"+address+":"+value);
                        if(address!=224||c.get("apply_writes").getAsBoolean())registers[address]=value;
                    }else if(op==3){
                        if(data!=UID||address!=(caches-1)*32)throw new IllegalStateException("UID cache column");
                        byte[] b=new byte[32];for(int i=0;i<16;i++){b[i]=(byte)(i*7+(caches-1)*13+1);b[i+16]=(byte)~b[i];}
                        if(caches-1!=c.get("first_good").getAsInt())b[31]^=1;e.writeMemory(toAddr(UID),b);
                    }
                }ret(e,status);continue;
            }
            if(pc==a("compare")){
                if(r(e,2)!=20)throw new IllegalStateException("Compatibility compare length");
                byte[] left=mem(e,r(e,0),20),right=mem(e,r(e,1),20);int result=0;
                for(int i=0;i<20;i++){int x=left[i]&255,y=right[i]&255;if(x!=y){result=x-y;break;}if(x==0)break;}
                ret(e,result);continue;
            }
            if(pc==a("delay")){long n=r(e,0);if(n!=5&&n!=1000&&n!=5000)throw new IllegalStateException("Delay argument");actions.add("delay:"+n);ret(e,0);continue;}
            if(pc==a("zero")){
                long out=r(e,0);int n=(int)r(e,2);if(r(e,1)!=0||!(stack(out,n)&&n<=252||out==UID&&n<=128&&n>=0))throw new IllegalStateException("UID zero bound");
                if(n>0)e.writeMemory(toAddr(out),new byte[n]);ret(e,out);continue;
            }
            if(pc==a("format")){
                int value=(int)r(e,3),n=(int)r(e,1);if(value<0||value>255||r(e,2)!=0x80c3da18L||n<3||n>256||!stack(r(e,0),3))throw new IllegalStateException("UID format arguments");
                byte[] b=String.format(java.util.Locale.ROOT,"%02X",value).getBytes(java.nio.charset.StandardCharsets.US_ASCII);e.writeMemory(toAddr(r(e,0)),Arrays.copyOf(b,3));actions.add("format:"+value);ret(e,2);continue;
            }
            if(pc==a("copy")){
                int n=(int)r(e,2);if(r(e,0)!=OUT+1||r(e,1)!=UID||n<0||n>128||n!=val(e,0x80d81f24L,1))throw new IllegalStateException("UID export copy arguments");
                if(n>0)e.writeMemory(toAddr(OUT+1),mem(e,UID,n));actions.add("copy_uid:"+n);ret(e,OUT+1);continue;
            }
            if(pc==a("logger")){
                JsonElement tag=cfg.getAsJsonObject("logs").get(Long.toString(r(e,3)));if(tag==null)throw new IllegalStateException("Unknown identity log "+Long.toHexString(r(e,3)));
                String name=tag.getAsString(),event="log:"+name;
                if(name.equals("uid_error")||name.equals("uid_feature_error"))event+=":"+(int)r(e,5);
                if(name.equals("uid_ok"))event+=":"+r(e,5)+":"+string(e,r(e,6));actions.add(event);ret(e,0);continue;
            }
            if(pc==a("assertion")){stopped=new JsonObject();stopped.addProperty("kind","assertion");stopped.addProperty("owner",r(e,1));stopped.addProperty("line",r(e,2));return;}
            boolean allowed=false;for(JsonElement span:cfg.getAsJsonArray("ranges")){long first=span.getAsJsonArray().get(0).getAsLong(),n=span.getAsJsonArray().get(1).getAsLong();if(pc>=first&&pc<first+n){allowed=true;break;}}
            if(!allowed)throw new IllegalStateException(c.get("name")+" escaped at "+Long.toHexString(pc));
            if(!e.step(monitor))throw new IllegalStateException(c.get("name")+" "+e.getLastError());
        }abi(e);
    }
    private JsonObject execute(JsonObject input)throws Exception {
        c=input;desc=c.getAsJsonObject("descriptor");steps=gets=sets=loads=caches=transfers=e0Reads=c0Reads=0;actions=new JsonArray();registers=new int[256];registers[224]=c.get("e0").getAsInt();EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            byte[] sentinel=new byte[4096];Arrays.fill(sentinel,(byte)0xa5);e.writeMemory(toAddr(0x81000000L),sentinel);e.writeRegister("sp",0x81001000L);for(int i=0;i<12;i++)e.writeRegister("s"+i,0x45670000L+i);
            byte[] chip=new byte[184];currentProgram.getMemory().getBytes(toAddr(desc.get("address").getAsLong()),chip);e.writeMemory(toAddr(CHIP),chip);e.writeMemory(toAddr(CHIP+184),Arrays.copyOf(sentinel,32));
            byte[] name=Arrays.copyOf(sentinel,112);Arrays.fill(name,0,80,(byte)0);byte[] text=desc.get("name").getAsString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);if(text.length>63)throw new IllegalStateException("Name bound");System.arraycopy(text,0,name,0,text.length);e.writeMemory(toAddr(NAME),name);put(e,CHIP+0x38,4,NAME);
            byte[] sequence=Arrays.copyOf(sentinel,48);Arrays.fill(sequence,0,16,(byte)0);JsonArray pairs=desc.getAsJsonArray("sequence");if(pairs.size()>8)throw new IllegalStateException("Sequence bound");for(int i=0;i<pairs.size();i++){sequence[i*2]=(byte)pairs.get(i).getAsJsonArray().get(0).getAsInt();sequence[i*2+1]=(byte)pairs.get(i).getAsJsonArray().get(1).getAsInt();}e.writeMemory(toAddr(SEQ),sequence);put(e,CHIP+0xa8,4,SEQ);put(e,CHIP+0xac,1,pairs.size());
            for(Object[] f:new Object[][]{{0xa6,"uid_flag",1},{0xad,"uid_mode",1},{0xae,"uid_copies",1},{0xb0,"uid_page",4},{0xb4,"uid_size",4}})put(e,CHIP+(int)f[0],(int)f[2],desc.get((String)f[1]).getAsLong());chip=mem(e,CHIP,184);
            e.writeMemory(toAddr(UID-32),Arrays.copyOf(sentinel,192));e.writeMemory(toAddr(OUT-32),Arrays.copyOf(sentinel,193));put(e,0x80d81f24L,1,c.get("initial_uid_length").getAsInt());put(e,0x80d81f28L,4,c.get("present").getAsBoolean()?CHIP:0);
            String mode=c.get("mode").getAsString();if(mode.equals("set_level"))entry(e,a(mode),c.get("level").getAsLong());else if(mode.equals("retry"))entry(e,a(mode),c.get("page").getAsLong());else entry(e,a(mode.equals("uid_export")?"uid":mode));
            JsonObject row=new JsonObject();row.add("returned",stopped!=null||mode.startsWith("uid")?JsonNull.INSTANCE:new JsonPrimitive(r(e,0)));row.add("stopped",stopped==null?JsonNull.INSTANCE:stopped);row.addProperty("uid_length",val(e,0x80d81f24L,1));row.addProperty("uid_sha256",hash(mem(e,UID,128)));row.addProperty("e0",registers[224]);
            JsonArray rows=new JsonArray();rows.add(row);
            if(mode.equals("uid_export")&&stopped==null){
                entry(e,a("ioctl"),24,OUT,1);if(stopped!=null)throw new IllegalStateException("Unexpected UID ioctl assertion");
                if(!row.get("uid_sha256").getAsString().equals(hash(mem(e,UID,128)))||row.get("uid_length").getAsInt()!=val(e,0x80d81f24L,1))throw new IllegalStateException("UID export changed source");
                JsonObject exported=row.deepCopy();exported.addProperty("returned",r(e,0));exported.addProperty("export_sha256",hash(mem(e,OUT,129)));rows.add(exported);
            }
            byte[] guard=Arrays.copyOf(sentinel,32);for(long at:new long[]{UID-32,UID+128,CHIP+184,OUT-32,OUT+129})if(!Arrays.equals(guard,mem(e,at,32)))throw new IllegalStateException("Identity guard changed");
            if(!Arrays.equals(chip,mem(e,CHIP,184))||!Arrays.equals(name,mem(e,NAME,112))||!Arrays.equals(sequence,mem(e,SEQ,48)))throw new IllegalStateException("Identity input changed");
            JsonObject observed=new JsonObject();observed.add("actions",actions);observed.add("rows",rows);
            if(!observed.equals(c.getAsJsonObject("expected"))){Files.writeString(Path.of("firmware/nand-identity-mismatch.json"),observed.toString());throw new IllegalStateException("Mismatch "+c.get("name"));}
            JsonObject result=new JsonObject();result.addProperty("name",c.get("name").getAsString());result.addProperty("steps",steps);result.add("observed",observed);return result;
        }finally{e.dispose();}
    }
    public void run()throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("vectors report");cfg=JsonParser.parseString(CONFIG).getAsJsonObject();for(JsonElement item:cfg.getAsJsonArray("guards")){JsonObject g=item.getAsJsonObject();byte[] b=new byte[g.get("size").getAsInt()];currentProgram.getMemory().getBytes(toAddr(g.get("address").getAsLong()),b);if(!hash(b).equals(g.get("sha256").getAsString()))throw new IllegalStateException("Unrecognized identity code/data");}
        JsonObject input=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonObject();if(input.get("schema").getAsInt()!=1||input.getAsJsonArray("cases").size()>128)throw new IllegalArgumentException("Vector bound");JsonArray rows=new JsonArray();for(JsonElement item:input.getAsJsonArray("cases"))rows.add(execute(item.getAsJsonObject()));
        JsonObject report=new JsonObject();report.addProperty("hardware_execution",false);report.addProperty("case_count",rows.size());report.addProperty("bound_per_case",500000);report.add("cases",rows);Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report)+"\n");println("NAND_IDENTITY_VALIDATION cases="+rows.size());
    }
}
