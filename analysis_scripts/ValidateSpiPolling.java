// Execute actual optical register wrappers -> bus/CS adapters -> polling HAL.
// SPI status/data, scaled timestamps and mutex/diagnostic outcomes are synthetic.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ValidateSpiPolling extends GhidraScript {
    private static final long D=0x81002000L,B=0x81003000L,S=0x81004000L,C=0x81005000L,
        O=0x81006000L,P=0x81007000L,OUT=0x81009000L,END=0x70000000L,BASE=0x90004000L;
    private class Helper extends EmulatorHelper {
        private Emulator core;
        Helper(Program p){super(p);}
        @Override protected Emulator newEmulator(){core=super.newEmulator();return core;}
        void filter(MemoryAccessFilter f){core.addMemoryAccessFilter(f);}
    }
    private class Io extends MemoryAccessFilter {
        int status,rxIndex;byte[] rx;
        final List<Integer> tx=new ArrayList<>();
        final List<String> events=new ArrayList<>();
        @Override protected void processRead(AddressSpace space,long offset,int size,byte[] data){
            if(!space.getName().equals("ram"))return;
            long value;
            if(offset==BASE+0xc)value=status;
            else if(offset==BASE+0x18){
                if(rxIndex>=rx.length)throw new IllegalStateException("Unexpected SPI receive read");
                value=rx[rxIndex++]&255;
            }else return;
            if(size!=4)throw new IllegalStateException("Unexpected SPI read width");
            for(int i=0;i<4;++i)data[i]=(byte)(value>>>(8*i));
        }
        @Override protected void processWrite(AddressSpace space,long offset,int size,byte[] data){
            if(!space.getName().equals("ram"))return;
            if(offset==BASE+0x18){
                if(size!=4 || data[1]!=0 || data[2]!=0 || data[3]!=0)throw new IllegalStateException("Unexpected SPI transmit word");
                tx.add(data[0]&255);
            }else if(offset==0x91003010L || offset==0x91003014L){
                if(size!=4 || data[0]!=0 || data[1]!=2 || data[2]!=0 || data[3]!=0)
                    throw new IllegalStateException("Unexpected chip-select store");
                events.add(offset==0x91003014L?"select":"deselect");
            }
        }
    }
    private void put(Helper e,long address,long value){e.writeMemoryValue(toAddr(address),4,value);}
    private void guard(long address,int size,String expected)throws Exception{
        byte[] bytes=new byte[size];currentProgram.getMemory().getBytes(toAddr(address),bytes);
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if(!hash.equals(expected))throw new IllegalStateException("Unrecognized SPI path at "+Long.toHexString(address));
    }
    private long reg(Helper e,int index){return e.readRegister("a"+index).longValue()&0xffffffffL;}
    private List<Integer> bytes(int...values){List<Integer> list=new ArrayList<>();for(int v:values)list.add(v);return list;}
    private String jsonStrings(List<String> values){return values.stream().map(s->"\""+s+"\"").toList().toString();}
    private String caseOf(String name,boolean read,boolean ops,boolean dma,int status,long[] clocks,
                          byte[] responses,List<Integer> expectedTx,int expectedRx,int expectedResult,int expectedOut,boolean zero)throws Exception{
        Helper e=new Helper(currentProgram);Io io=new Io();io.status=status;io.rx=responses;
        int clockIndex=0,steps=0;
        try{
            e.writeMemory(toAddr(D),new byte[0x80]);e.writeMemory(toAddr(B),new byte[0x80]);
            e.writeMemory(toAddr(S),new byte[0x40]);e.writeMemory(toAddr(O),new byte[0x40]);
            e.writeMemory(toAddr(P),new byte[0x40]);e.writeMemory(toAddr(BASE),new byte[0x20]);
            put(e,D,B);put(e,D+4,S);put(e,D+8,C);put(e,D+0x14,dma?1:0);
            put(e,B,0x2468);put(e,B+0x24,ops?O:0);put(e,B+0x28,P);
            put(e,S+4,0x80f7b404L);put(e,S+8,0x80f7b3e8L);
            put(e,C,0x91003000L);put(e,C+4,0x200);put(e,P+8,BASE);
            put(e,O+8,0x80f7b3d0L);put(e,O+0x10,0x80f7b3a0L);
            put(e,0x80f1709cL,D);e.writeMemoryValue(toAddr(OUT),1,0xa5);
            e.writeRegister("sp",0x81001000L);e.writeRegister("ra",END);
            for(int i=0;i<12;++i)e.writeRegister("s"+i,0x32100000L+i);
            if(zero){
                e.writeRegister("a0",P+8);e.writeRegister("a1",OUT);e.writeRegister("a2",OUT);
                e.writeRegister("a3",0);e.writeRegister("a4",0);
            }else{
                e.writeRegister("a0",0xff);e.writeRegister("a1",read?OUT:0xab);
            }
            e.filter(io);e.writeRegister(e.getPCRegister(),zero?0x80f7ed84L:(read?0x80f7304cL:0x80f73152L));
            while(e.getExecutionAddress().getOffset()!=END){
                if(++steps>10000)throw new IllegalStateException(name+" execution bound");
                long pc=e.getExecutionAddress().getOffset();
                if(pc==0x80f7b594L){
                    if(clockIndex>=clocks.length)throw new IllegalStateException(name+" unexpected clock read");
                    long value=clocks[clockIndex++];
                    e.writeRegister("a0",value&0xffffffffL);e.writeRegister("a1",value>>>32);
                    e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
                }
                if(pc==0x80f802deL || pc==0x80f80382L || pc==0x80f86d34L){
                    if(pc!=0x80f86d34L){
                        if(reg(e,0)!=0x2468)throw new IllegalStateException("Wrong mutex handle");
                        if(pc==0x80f802deL && reg(e,1)!=0xffffffffL)throw new IllegalStateException("Wrong mutex wait");
                        io.events.add(pc==0x80f802deL?"mutex_take":"mutex_release");
                    }
                    e.writeRegister("a0",0);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
                }
                boolean allowed=(pc>=0x80f7304cL && pc<0x80f7308cL)||(pc>=0x80f73152L && pc<0x80f7317cL)
                    ||(pc>=0x80f8965cL && pc<0x80f899aaL)||(pc>=0x80f7b3a0L && pc<0x80f7b420L)
                    ||(pc>=0x80f7bdbcL && pc<0x80f7bdcaL)||(pc>=0x80f7ed84L && pc<0x80f7ef84L);
                if(!allowed)throw new IllegalStateException(name+" escaped at "+Long.toHexString(pc));
                if(!e.step(monitor))throw new IllegalStateException(e.getLastError());
            }
            int result=(int)reg(e,0),out=e.readMemory(toAddr(OUT),1)[0]&255;
            List<String> expectedEvents=!ops || dma || zero?List.of():List.of("mutex_take","select","deselect","mutex_release");
            if(result!=expectedResult || out!=expectedOut || !io.tx.equals(expectedTx) || io.rxIndex!=expectedRx
                || clockIndex!=clocks.length || !io.events.equals(expectedEvents))
                throw new IllegalStateException(name+" result="+result+" output="+out+" TX="+io.tx+" RX="+io.rxIndex+" clocks="+clockIndex+" events="+io.events);
            if(e.readRegister("sp").longValue()!=0x81001000L)throw new IllegalStateException("Stack restoration");
            for(int i=0;i<12;++i)if(e.readRegister("s"+i).longValue()!=0x32100000L+i)throw new IllegalStateException("Callee-saved register changed");
            return String.format("{\"name\":\"%s\",\"result\":%d,\"output_byte\":%d,\"tx_bytes\":%s,\"rx_reads\":%d,\"clock_reads\":%d,\"steps\":%d,\"events\":%s}",name,result,out,io.tx,io.rxIndex,clockIndex,steps,jsonStrings(io.events));
        }finally{e.dispose();}
    }
    public void run()throws Exception{
        if(getScriptArgs().length!=1)throw new IllegalArgumentException("report-path");
        guard(0x80f8965cL,0x34e,"0c9fe44af7d6dbc29c0363ae54729d568f5e950bbaa3be40f93cc58545c6a91e");
        guard(0x80f7b3a0L,0x80,"ef6ccf0de52467167ad57336c48a39035a7fc2291b8f402805036b54d0a25ff8");
        guard(0x80f7bdbcL,0xe,"0c779278011a9524660c57136188feacc70bffd6f804bf047d7604bf686a5944");
        guard(0x80f7ed84L,0x200,"6ca39c83319e930d68cc9a754780e037dda86a9b2fa998b95f96f0095a185bda");
        guard(0x80f7304cL,0x40,"a52b14bb5c8cfcd61552322a186b65f96f7d1ee5ccffb686c9c616365295b432");
        guard(0x80f73152L,0x2a,"f416a1469fd4f805fde426e34688721360d18d4909d639e52c96b6986ff4b4ac");
        List<String> cases=new ArrayList<>();byte[] rx={0x11,0x22,0x46};
        cases.add(caseOf("register_read",true,true,false,0x12,new long[]{0,0,0,0},rx,bytes(255,128,0),3,0,0x46,false));
        cases.add(caseOf("read_at_limit",true,true,false,0x12,new long[]{0,1000,1000,1000},rx,bytes(255,128,0),3,0,0x46,false));
        cases.add(caseOf("read_timeout_after_final_byte",true,true,false,0x12,new long[]{0,0,0,1001},rx,bytes(255,128,0),3,-14,0xa5,false));
        cases.add(caseOf("read_timeout_after_first_byte",true,true,false,0x12,new long[]{0,1001},rx,bytes(255),1,-14,0xa5,false));
        cases.add(caseOf("read_busy_timeout",true,true,false,4,new long[]{0,1001},rx,bytes(),0,-14,0xa5,false));
        cases.add(caseOf("read_tx_only_timeout",true,true,false,2,new long[]{0,0,0,1001},rx,bytes(255,128,0),0,-14,0xa5,false));
        cases.add(caseOf("read_rx_only_timeout",true,true,false,0x10,new long[]{0,0,0,1001},rx,bytes(),3,-14,0xa5,false));
        cases.add(caseOf("read_unsigned_clock_wrap",true,true,false,0x12,new long[]{-2,-1,0,1},rx,bytes(255,128,0),3,0,0x46,false));
        cases.add(caseOf("read_missing_operations",true,false,false,0x12,new long[]{},rx,bytes(),0,0,0,false));
        cases.add(caseOf("read_dma_unavailable",true,true,true,0x12,new long[]{},rx,bytes(),0,0,0,false));
        cases.add(caseOf("register_write",false,true,false,2,new long[]{0,0,0,0},rx,bytes(255,0,171),0,0,0xa5,false));
        cases.add(caseOf("write_timeout_after_final_byte",false,true,false,2,new long[]{0,0,0,1001},rx,bytes(255,0,171),0,-14,0xa5,false));
        cases.add(caseOf("zero_length_hal",true,true,false,0x12,new long[]{0},rx,bytes(),0,0,0xa5,true));
        Files.writeString(Path.of(getScriptArgs()[0]),"{\n\"case_count\":"+cases.size()+",\n\"hardware_execution\":false,\n\"synthetic_inputs\":[\"SPI status/data\",\"scaled timestamps\",\"mutex outcomes\"],\n\"cases\":[\n"+String.join(",\n",cases)+"\n]}\n");
        println("SPI_POLLING_VALIDATION integrated cases="+cases.size());
    }
}
