// Static storage exports: establish registry and board-registration boundaries.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.HexFormat;

public class SeedStorageMap extends GhidraScript {
    public void run() throws Exception {
        byte[] bytes=new byte[0x112];currentProgram.getMemory().getBytes(toAddr(0x80c24106L),bytes);
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals("d9c7b34b5876e890c8782fee90061673f367e054e5c7c2eeff8e286ff5ce3d98"))throw new IllegalStateException("Unrecognized storage registry code");
        // Create the registration callee before its caller, so it is not folded
        // into a spurious large caller body by the initial disassembly.
        for(long[] row:new long[][]{{0x80c1cff2L,3},{0x80c01098L,0},{0x80c23bd0L,2},
            {0x80c23ceeL,1},{0x80c24106L,1},{0x80c24140L,2},{0x80c24340L,2},
            {0x80c231b2L,0},{0x80c231d6L,0},{0x80c229ecL,0}}){
            var at=toAddr(row[0]);disassemble(at);var f=getFunctionAt(at);if(f==null)f=createFunction(at,"candidate_"+Long.toHexString(row[0]));
            if(f==null)throw new IllegalStateException("Cannot seed storage boundary");
            f.setNoReturn(false);f.setInline(false);f.setCallingConvention(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName());
            f.setReturnType(row[0]==0x80c01098L||row[0]==0x80c231d6L?VoidDataType.dataType:UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);
            Parameter[] p=new Parameter[(int)row[1]];for(int i=0;i<p.length;i++)p[i]=new ParameterImpl("arg"+i,UnsignedIntegerDataType.dataType,currentProgram);
            f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,p);
        }
        var instructions=currentProgram.getListing().getInstructions(getFunctionAt(toAddr(0x80c01098L)).getBody(),true);
        while(instructions.hasNext()){
            var instruction=instructions.next();
            if(instruction.getFlowType().isJump())for(var target:instruction.getFlows())
                if(target.getOffset()==0x80c1cff2L)instruction.setFlowOverride(FlowOverride.CALL_RETURN);
        }
        println("STORAGE_MAP_METADATA applied");
    }
}
