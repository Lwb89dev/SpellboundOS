#!/usr/bin/env python3
"""Original NAND bus initialization and grouped/table-driven pin controls."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import qspi_dma as integrated
    from . import qspi_hal as qspi
else:
    import qspi_dma as integrated
    import qspi_hal as qspi

ROOT=Path(__file__).resolve().parents[1]
PIN_FACTS=ROOT/'analysis/nand-pins.json'
DMA_ORIGINAL=(0x80de64a0,0x80de645c)
PLATFORM_RANGES=((0x80c10580,0x16e),(0x80c13408,0x286),(0x80df8e94,0xa4),(0x80df8d94,0x90))
RANGES=integrated.RANGES+PLATFORM_RANGES
TARGETS=tuple(a for a,n in RANGES)
EXTRA_CONFIG=dict(platform_init=0x80c10580,pinmux=0x80c13408,pin_function=0x80df8e94)


def pin_facts(memory):
    data=memory.read(0x80d81c30,23*8)
    zero=next(r for r in memory.regions if r['kind']=='zero' and r['destination']<=DMA_ORIGINAL[1] and DMA_ORIGINAL[0]+68<=r['destination']+r['size'])
    return dict(boot_sha256=qspi.BOOT_HASH,table_address=0x80d81c30,sha256=qspi.digest(data),hardware_execution=False,
        dma_startup_zero_region=zero,dma_startup_table_address=0x80c00284,
        records=[dict(index=i,register=0x91000000+offset,shift=shift) for i,(offset,shift) in enumerate(struct.iter_unpack('<II',data))])


def board_initial():
    addresses=[0x9a000004,0x9a00000c,0x910000b4,0x910000b8,0x910000bc]+list(range(0x910001ac,0x910001c4,4))
    return {str(a):(0xa5a55a5a^(i*0x10101))&0xffffffff for i,a in enumerate(addresses)}


class Pins:
    def __init__(self,actions,c):self.actions=actions;self.regs={int(k):v for k,v in c['board_initial'].items()}
    def read(self,at):
        value=self.regs[at];self.actions.append(f'board_r:{at}:{value}');return value
    def write(self,at,value):
        value&=0xffffffff;self.regs[at]=value;self.actions.append(f'board_w:{at}:{value}')
    def field(self,at,shift,value,mask):self.write(at,(self.read(at)&~(mask<<shift))|(value<<shift))
    def pinmux(self,p0,p1,value):
        value&=63
        for bits,mask,at,shift in ((p0,1,0x910001ac,0),(p0,2,0x910001ac,8),(p0,0x3c,0x910001ac,16),
            (p0,0x40,0x910001b4,0),(p0,0x80,0x910001b4,8),(p0,0xf00,0x910001b4,16),
            (p1,1,0x910001b0,0),(p1,2,0x910001b0,8),(p1,4,0x910001b0,24),(p1,0x7f8,0x910001b0,16),
            (p0,0x1000,0x910001b8,0),(p0,0x2000,0x910001b8,8),(p0,0x4000,0x910001b8,16),(p0,0x8000,0x910001b8,24),
            (p1,0x1000,0x910001bc,0),(p1,0x2000,0x910001bc,8),(p1,0x4000,0x910001bc,16),(p1,0x8000,0x910001bc,24)):
            if bits&mask:self.field(at,shift,value,63)
        if p0&0xffff0000:self.field(0x910001c0,0,value,63);self.field(0x910001c0,8,value,63)
        if p1&0xffff0000:self.field(0x910001c0,16,value,63);self.field(0x910001c0,24,value,63)
    def function(self,p0,p1,value):
        if (p0|p1)&0xfffff000:return
        records=json.loads(PIN_FACTS.read_bytes())['records']
        for i,row in enumerate(records):
            if ((p0>>i) if i<12 else (p1>>(i-12)))&1:self.field(row['register'],row['shift'],value,15)


def qspi_row(model,result):
    return dict(returned=result,stopped=model.stopped,context_hex=model.context.hex(),buffer_sha256=qspi.digest(model.buffer),
        tx_hex=model.tx.hex(),rx_bytes=model.rx,mmio={str(k):v for k,v in sorted(model.regs.items())},
        clock_word=model.clock,clock_shadow=model.shadow)


class PlatformModel(integrated.Model):
    def __init__(self,c):
        runtime=c|dict(mode=c['mode'].removeprefix('platform_'))
        super().__init__(runtime);self.context=bytearray(64);struct.pack_into('<I',self.context,16,c['controller_mode'])
        self.pins=Pins(self.actions,c)
        for i,backend in enumerate(self.backends):backend.contexts[0]=bytearray.fromhex(c['dma_tx_hex' if i==0 else 'dma_rx_hex'])
    def initialize(self):
        c=self.c;selector=2 if c['bus_word']<100 else 1;old=self.clock
        self.actions.append('clock_read:'+str(old));self.shadow=(old&0xffff0fff)|((selector&15)<<12)
        if selector!=((old>>12)&15):self.clock=self.shadow;self.actions.append('clock_write:'+str(self.clock))
        struct.pack_into('<I',self.context,0,0x93240000);struct.pack_into('<II',self.context,8,0,0)
        self.pins.write(0x9a00000c,self.pins.read(0x9a00000c)&~0x200)
        self.pins.write(0x9a00000c,self.pins.read(0x9a00000c)|0x200)
        self.pins.pinmux(0,127,63);self.pins.function(0,127,1);self.actions.append('fence')
        self.pins.write(0x9a000004,self.pins.read(0x9a000004)|0x200);self.init();self.actions.append('fence')
        self.pins.write(0x9a000004,self.pins.read(0x9a000004)|8)
        for i,backend in enumerate(self.backends):
            profile=backend.c;words=[profile[k] for k in ('request','direction','source_increment','dest_increment','source_width','dest_width','burst','priority','base','channel')]
            struct.pack_into('<10I',backend.contexts[0],0,*words);backend.init();self.drain()
            struct.pack_into('<I',self.context,32+i*4,DMA_ORIGINAL[i]);backend.put(44,qspi.CTRL)
    def run(self):
        self.initialize()
        result=self.snapshot(0) if self.c['mode']=='init' else self.transfer()
        result['rows'][0]['board_mmio']={str(k):v for k,v in sorted(self.pins.regs.items())}
        result['rows'][0]['reinit_flag']=0
        return result


def contract(c):
    if c['full_platform']:
        if c['mode'] not in ('platform_init','platform_cache_read_bounce','platform_cache_write_bounce'):raise ValueError('bounded platform entry')
        if not 0<=c['count']<=64 or c['alignment'] or c['mode']!='platform_init' and c['count']<=31:raise ValueError('bounded platform payload')
        return PlatformModel(c).run()
    if any(not 0<=c[k]<=0xffffffff for k in ('pin_p0','pin_p1','pin_value')):raise ValueError('bounded pin fields')
    model=qspi.Model(c);pins=Pins(model.actions,c)
    if c['mode']=='pinmux':pins.pinmux(c['pin_p0'],c['pin_p1'],c['pin_value'])
    elif c['mode']=='pin_function':pins.function(c['pin_p0'],c['pin_p1'],c['pin_value'])
    else:raise ValueError('pin entry')
    row=qspi_row(model,None);row['board_mmio']={str(k):v for k,v in sorted(pins.regs.items())}
    return dict(actions=model.actions,rows=[row])


def native_vectors():
    cases=[];base=integrated.native_vectors()['cases'][0]
    def add(name,mode='pin_function',**changes):
        full=mode.startswith('platform_')
        c=base|dict(name=name,mode=mode,native_platform=True,full_platform=full,native_dma=full,
            board_initial=board_initial(),pin_p0=0,pin_p1=0,pin_value=1,bus_word=104,initial_dma_byte=0,defer_reinit=False)|changes
        if full:
            c['frame']=[0 if 'read' in mode else 2,0,0x6b if 'read' in mode else 0x32,1,1,c['address'],1,2,3,c['count'],8 if 'read' in mode else 0]
            for i,label in enumerate(('tx','rx')):
                c['dma_'+label]=c['dma_'+label]|dict(descriptor_address=DMA_ORIGINAL[i])
                c['dma_'+label+'_hex']=(bytes([c['initial_dma_byte']])*68).hex()
        c['expected']=contract(c);cases.append(c)
    for i in range(12):add('function_p0_'+str(i),pin_p0=1<<i)
    for i in range(11):add('function_p1_'+str(i),pin_p1=1<<i)
    add('function_combined',pin_p0=0xfff,pin_p1=0x7ff)
    add('function_p1_bit11',pin_p1=0x800);add('function_rejects_p0_high',pin_p0=0x1000,pin_p1=1)
    add('function_rejects_p1_high',pin_p1=0x1000,pin_p0=1)
    add('function_zero_mode',pin_p1=1,pin_value=0);add('function_mode_spill',pin_p1=1,pin_value=31)
    for p0,p1,label in ((1,0,'p0_first'),(2,0,'p0_second'),(0x3c,0,'p0_group'),(0xfc0,0,'p0_upper'),
        (0,0x7ff,'p1_group'),(0xf000,0,'p0_high'),(0,0xf000,'p1_high'),(0x10000,0,'p0_pair'),(0,0x10000,'p1_pair'),(0xffffffff,0xffffffff,'all')):
        add('pinmux_'+label,'pinmux',pin_p0=p0,pin_p1=p1,pin_value=0xffffffff)
    add('platform_original_clock','platform_init',count=0)
    add('platform_low_clock_word','platform_init',count=0,bus_word=83)
    add('platform_boundary_99','platform_init',count=0,bus_word=99)
    add('platform_boundary_100','platform_init',count=0,bus_word=100)
    add('platform_preserves_other_fields','platform_init',count=0,initial_dma_byte=165,controller_mode=1)
    add('platform_read_bounce','platform_cache_read_bounce',count=64)
    add('platform_write_bounce','platform_cache_write_bounce',count=64)
    add('platform_reinit_read_bounce','platform_cache_read_bounce',count=64,defer_reinit=True,bus_word=83)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(PIN_FACTS.read_bytes())!=pin_facts(memory):raise ValueError('pin records differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,pin_inventory_sha256=qspi.digest(PIN_FACTS.read_bytes()),
        vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual grouped/table-driven pin controls and NAND bus initialization connect actual clock/QSPI/DMA init and selected private-buffer transfers.',
            'MMIO, reset clearing, timestamps, ROM version and cache/copy bodies are authored; fences are recorded single-thread markers.',
            'Original adjacent DMA contexts use 68-byte backing for observed fields; this is not a complete object-allocation claim.',
            'Physical pin/package mapping, electrical operation, DMA movement/coherency, persistence/restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('pins-output','vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not a.archive:p.error('need archive')
        with zipfile.ZipFile(a.archive) as z:
            if a.pins_output:a.pins_output.write_text(json.dumps(pin_facts(qspi.image_memory(z)),indent=2,sort_keys=True)+'\n');return
            if not all((a.decompiled,a.vectors,a.validation)):p.error('need decompiled/vectors/validation')
            result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND platform: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
