// Inspect inferred function metadata and call-flow overrides without changing it.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
public class InspectFlow extends GhidraScript {
 public void run() throws Exception {
  for(String value:getScriptArgs()) {
   var f=getFunctionAt(toAddr(Long.decode(value)));
   if(f==null){println("No function at "+value);continue;}
   println(f.getEntryPoint()+" noReturn="+f.hasNoReturn()+" signature="+f.getSignature());
   var instructions=currentProgram.getListing().getInstructions(f.getBody(),true);
   while(instructions.hasNext()){
    var i=instructions.next();
    if(i.getFlowOverride()!=FlowOverride.NONE)println("OVERRIDE "+i.getAddress()+" "+i.getFlowOverride()+" "+i);
   }
  }
 }
}
