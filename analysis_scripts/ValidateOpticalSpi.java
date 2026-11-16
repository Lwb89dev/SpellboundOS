// Execute only adapter metadata/argument forwarding/error conversion on host.
// Stops around HAL calls; never emulates physical SPI completion.
//@category SpellboundOS
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ValidateOpticalSpi extends GhidraScript {
    private void stepTo(EmulatorHelper emu,long entry,long stop,long low,long high) throws Exception {
        emu.writeRegister(emu.getPCRegister(),entry);
        int count=0;
        while (emu.getExecutionAddress().getOffset()!=stop) {
            long pc=emu.getExecutionAddress().getOffset();
            if (pc<low || pc>=high || ++count>64) throw new IllegalStateException("Escaped adapter bounds");
            if (!emu.step(monitor)) throw new IllegalStateException(emu.getLastError());
        }
    }
    private long read(EmulatorHelper emu,long address,int size) {
        byte[] bytes=emu.readMemory(toAddr(address),size); long value=0;
        for (int i=0;i<size;++i) value|=(bytes[i]&255L)<<(8*i);
        return value;
    }
    public void run() throws Exception {
        if (getScriptArgs().length!=1) throw new IllegalArgumentException("report-path");
        byte[] bytes=new byte[0x7c]; currentProgram.getMemory().getBytes(toAddr(0x80f7b36cL),bytes);
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals("772b23d26a0d2030241441e0c319cfc08d48d0901eeddfa7af751760edaf151d"))
            throw new IllegalStateException("Unrecognized SPI adapters");
        int configs=0,transfers=0;
        long context=0x81002000L,config=0x81003000L,sink=0x70000000L;
        for (long flags:new long[]{0,1,2,3,4,5,6,7,0x801,0x803,0xffffffffL}) {
            EmulatorHelper emu=new EmulatorHelper(currentProgram);
            try {
                emu.writeRegister("sp",0x81001000L); emu.writeRegister("ra",sink);
                emu.writeRegister("a0",context); emu.writeRegister("a1",config);
                emu.writeMemoryValue(toAddr(config),4,8000000);
                emu.writeMemoryValue(toAddr(config+4),4,flags);
                stepTo(emu,0x80f7b36cL,0x80f7b390L,0x80f7b36cL,0x80f7b390L);
                if (read(emu,context+12,4)!=8000000 || read(emu,context+16,1)!=((flags&6)==0?0:3)
                    || read(emu,context+20,4)!=8 || emu.readRegister("a0").longValue()!=context+8)
                    throw new IllegalStateException("Adapter configuration differs");
                ++configs;
            } finally { emu.dispose(); }
        }
        for (long[] wrapper:new long[][]{{0x80f7b3a0L,0x80f7ed84L,0x80f7b3acL,5},
                {0x80f7b3b8L,0x80f7eeccL,0x80f7b3c4L,4},{0x80f7b3d0L,0x80f7ee38L,0x80f7b3dcL,4}}) {
            for (long result:new long[]{0,1,3,0xffffffffL}) {
                EmulatorHelper emu=new EmulatorHelper(currentProgram);
                try {
                    emu.writeRegister("sp",0x81001000L); emu.writeRegister("ra",sink);
                    emu.writeRegister("a0",context);
                    for (int i=1;i<wrapper[3];++i) emu.writeRegister("a"+i,0x12340000L+i);
                    stepTo(emu,wrapper[0],wrapper[1],wrapper[0],wrapper[2]);
                    if (emu.readRegister("a0").longValue()!=context+8) throw new IllegalStateException("Context offset differs");
                    for (int i=1;i<wrapper[3];++i)
                        if (emu.readRegister("a"+i).longValue()!=0x12340000L+i) throw new IllegalStateException("Dropped SPI argument");
                    emu.writeRegister("a0",result); // supplied HAL return; no bus execution
                    stepTo(emu,wrapper[2],sink,wrapper[2],wrapper[2]+12);
                    if (emu.readRegister("a0").longValue()!=(result==0?0:2) || emu.readRegister("sp").longValue()!=0x81001000L)
                        throw new IllegalStateException("Adapter return/stack contract differs");
                    ++transfers;
                } finally { emu.dispose(); }
            }
        }
        Files.writeString(Path.of(getScriptArgs()[0]),String.format("{\n  \"adapter_config_cases\":%d,\n  \"forwarding_return_cases\":%d,\n  \"hardware_execution\":false,\n  \"hal_execution\":false\n}\n",configs,transfers));
        println("OPTICAL_SPI_VALIDATION configs="+configs+" forwarding="+transfers);
    }
}
