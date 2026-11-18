// Connected scan and bad-marker boundaries; metadata only, no image writes.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEftlScan extends GhidraScript {
    public void run()throws Exception {
        for(Object[] g:new Object[][]{
            {0x80c01d8aL,352,"627b6414298e79230eb17db6291f05d99573c740082fe86d720f61b914e1b2f4"},
            {0x80c028d8L,52,"2583a6339dc10773ed6f5076237664bbc303f8d32d0d82fd72def3528a11e668"},
            {0x80c29042L,228,"56791bfcb504fdad3d220adc92ef84ffda9b02188631837aa64bb86b1e280c4f"}}){
            byte[] b=new byte[(int)g[1]];currentProgram.getMemory().getBytes(toAddr((long)g[0]),b);
            if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals(g[2]))throw new IllegalStateException("Unrecognized scan body");
        }
        for(long at:new long[]{0x80c01d8aL,0x80c028d8L,0x80c29042L}){
            var address=toAddr(at);disassemble(address);var f=getFunctionAt(address);if(f==null)f=createFunction(address,"candidate_"+Long.toHexString(at));if(f==null)throw new IllegalStateException("Cannot seed scan boundary "+Long.toHexString(at));
            f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,new ParameterImpl("arg0",UnsignedIntegerDataType.dataType,currentProgram),new ParameterImpl("arg1",UnsignedIntegerDataType.dataType,currentProgram));
            println("SCAN_BODY "+Long.toHexString(at)+" "+f.getBody());
        }
    }
}
