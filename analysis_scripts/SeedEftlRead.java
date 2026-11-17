// Pin EFTL translation/page adapter boundaries and reviewed tail calls.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedEftlRead extends GhidraScript {
    public void run()throws Exception {
        byte[] b=new byte[0xfe];currentProgram.getMemory().getBytes(toAddr(0x80c0219aL),b);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)).equals("3298dbbdd33a76b06d90a940376431281bf0fefe6149262226156ff6f90d16dc"))throw new IllegalStateException("Unrecognized EFTL read");
        for(long[] row:new long[][]{{0x80c29532L,5},{0x80c28a98L,5},{0x80c0278aL,5},{0x80c0219aL,4},{0x80c23252L,3}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed EFTL boundary");f.setNoReturn(false);f.setInline(false);
            f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());f.setReturnType(UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        for(long caller:new long[]{0x80c0278aL,0x80c23252L}){
            var instructions=currentProgram.getListing().getInstructions(getFunctionAt(toAddr(caller)).getBody(),true);
            while(instructions.hasNext()){
                var i=instructions.next();if(i.getFlowType().isJump())for(var target:i.getFlows())
                    if(target.getOffset()==0x80c0219aL||target.getOffset()==0x80c28a98L||target.getOffset()==0x80c29532L)i.setFlowOverride(FlowOverride.CALL_RETURN);
            }
        }
        println("EFTL_READ_METADATA applied");
    }
}
