#!/usr/bin/env python3
"""QSPI HAL command/FIFO/DMA policy over authored MMIO and timer services."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH,digest,image_memory
else:
    from recovery_validator import BOOT_HASH,digest,image_memory

CTRL=0x80dfb880
BUFFER=0x81301000
DMA=(0x81304000,0x81305000)
MASK=0xffffffff
CONFIG=dict(init=0x80df9220,command=0x80df928c,receive=0x80df93c4,receive_dma=0x80df94bc,
    transmit=0x80df951c,transmit_dma=0x80df960c,pack=0x80df8f38,complete=0x80df9000,
    wait_receive=0x80df9098,wait_transmit=0x80df9138,tx_count=0x80df91d8,rx_count=0x80df91fc,
    clock=0x80df9f80,tick=0x80c12218,frequency=0x80c1222c,dma_setup=0x80c12628,dma_wait=0x80c126e0,
    bus=0x80c106f0,feature_read=0x80c27ce8,feature_write=0x80c27d48,cache_read=0x80c27e70,
    cache_write=0x80c2806c,write_enable=0x80c27db0,version=0x80c12298,
    logger=0x80c1cd7a,diagnostic=0x80c10304,assertion=0x80c16516)
RANGES=((0x80df9220,0x6c),(0x80df928c,0xcc),(0x80df93c4,0xf8),(0x80df94bc,0x60),
    (0x80df951c,0xf0),(0x80df960c,0x58),(0x80df8f38,0x64),(0x80df9000,0x98),
    (0x80df9098,0xa0),(0x80df9138,0xa0),(0x80df91d8,0x24),(0x80df91fc,0x24),(0x80df9f80,0x34),
    (0x80c106f0,0x376),(0x80c27ce8,0x60),(0x80c27d48,0x68),(0x80c27e70,0x66),
    (0x80c2806c,0x64),(0x80c27db0,0x5e))
TARGETS=tuple(a for a,n in RANGES)


def context(c):
    data=bytearray(b'\xa5'*64)
    for at,value in ((0,c['base'] if c['base_present'] else 0),(8,c['flags'][0]),(12,c['flags'][1]),
                     (16,c['controller_mode']),(20,c['count']),(32,DMA[0]),(36,DMA[1])):struct.pack_into('<I',data,at,value)
    return data
def pack(frame):
    if frame[3]==1:
        if frame[6]==1:return {1:0,2:0x20,3:0x40}.get(frame[8],0)
        return {2:0x60,3:0x80}.get(frame[6],0)
    return {2:0xa0,3:0xc0}.get(frame[3],0)


class Model:
    def __init__(self,c):
        self.c=c;self.actions=[];self.regs={0:0x11111111,4:0x22222222,8:0x33333333,12:0x44444444,
            16:0x55555555,24:0,32:c['control'],36:0,52:0x101,84:c['fifo']}
        self.indices={};self.context=context(c);self.buffer=bytearray((i*3+1)&255 for i in range(512));self.tx=bytearray();self.rx=0
        self.clock=c['clock_word'];self.shadow=0xa5a5a5a5;self.reset=False;self.ticks=0;self.stopped=None
    def count(self):return struct.unpack_from('<I',self.context,20)[0]
    def set_count(self,n):struct.pack_into('<I',self.context,20,n&MASK)
    def next(self,key):
        i=self.indices.get(key,0);self.indices[key]=i+1;values=self.c[key];return values[min(i,len(values)-1)]
    def read(self,offset,size=4):
        if offset==0x100:
            value=int.from_bytes(bytes((0x5a+(self.rx+i)*7)&255 for i in range(size)),'little');self.rx+=size
        elif offset==0x10 and self.reset:
            value=self.next('reset_reads');self.regs[offset]=value
            if not value&0x100:self.reset=False
        elif offset==0x18:value=self.next('ready');self.regs[offset]=value
        elif offset==0x24:value=self.next('done');self.regs[offset]=value
        else:value=self.regs[offset]
        self.actions.append(f'r:{offset}:{size}:{value}');return value
    def write(self,offset,value,size=4):
        value&=(1<<(size*8))-1;self.actions.append(f'w:{offset}:{size}:{value}')
        if offset==0x100:self.tx+=value.to_bytes(size,'little')
        else:
            self.regs[offset]=0 if offset==0x24 and value==1 else value
            if offset==0x10 and value&0x100:self.reset=True
    def tick(self):
        values=self.c['ticks'];v=values[min(self.ticks,len(values)-1)];self.ticks+=1;self.actions.append('tick:'+str(v));return v
    def wait(self,offset,mask):
        start=self.tick();frequency=self.c['frequency'];self.actions.append('frequency:'+str(frequency));limit=((frequency//1000)*self.c['timeout'])&MASK
        for _ in range(32):
            if self.read(offset)&mask:
                if offset==0x24:self.write(offset,1)
                return 0
            elapsed=(self.tick()-start)&0xffffffffffffffff
            if elapsed>>32 or (elapsed&MASK)>limit:break
        else:raise ValueError('fixture timer does not expire')
        if self.read(offset)&mask:
            if offset==0x24:self.write(offset,1)
            return 0
        return 3
    def fifo_count(self,receive):
        raw=self.read(0x54);control=self.read(0x20)
        shift=((control>>12) if receive else (control>>8))&3
        units=((raw>>8) if receive else raw)&255
        return ((units*4)>>((3-shift)&31))&MASK
    def init(self):
        self.write(0x10,0x100)
        for _ in range(8):
            if not self.read(0x10)&0x100:break
        else:raise ValueError('fixture reset does not complete')
        if self.c['controller_mode']!=1:self.write(0x10,(self.read(0x10)&0xffffffec)|self.c['flags'][0]|self.c['flags'][1])
        self.write(0x34,self.read(0x34)|0x300);self.write(0x20,0x3300);return 0
    def command(self):
        c=self.c;f=c['frame']
        if not c['context_present'] or not c['frame_present'] or not c['base_present']:return 1
        address=(f[4]<<24)|(f[10]<<16)|f[7];direction=f[0]
        if direction==7:address|=0x10000000;direction=f[2]<<16
        op=(f[2]<<24)|direction|pack(f)
        if c['base']==0x93240000:op|=1
        for at,v in ((0,f[5]),(4,address),(8,f[9]),(12,op)):self.write(at,v)
        self.set_count(f[9]);return self.wait(0x24,1) if not f[9] else 0
    def data(self,receive,dma):
        c=self.c
        if dma:
            if not receive:self.write(0x20,self.read(0x20)|1)
            n=self.count();payload=b'' if receive else self.buffer[c['alignment']:c['alignment']+n]
            self.actions.append(f'dma_setup:{"receive" if receive else "transmit"}:{n}:{self.regs[32]}:{c["dma_setup_status"]}:{digest(payload)}')
            if receive and not c['dma_setup_status'] and c['dma_copy']:
                self.buffer[c['alignment']:c['alignment']+n]=bytes((0x5a+i*7)&255 for i in range(n))
            if receive:self.write(0x20,self.read(0x20)|1)
            self.actions.append(f'dma_wait:{c["timeout"]}:{self.regs[32]}:{c["dma_wait_status"]}')
            self.write(0x20,self.read(0x20)&~1)
            return c['dma_wait_status']&MASK if c['dma_wait_status'] else self.wait(0x24,1)
        offset=c['alignment'];chunks=0
        while self.count():
            if chunks>=128:raise ValueError('fixture FIFO does not advance')
            if c['stop_chunks'] and chunks==c['stop_chunks']:
                self.actions.append('stop_no_progress:'+str(chunks));self.stopped=dict(kind='bounded_prefix',chunks=chunks);return None
            chunks+=1
            if self.wait(0x18,2 if receive else 1):return 3
            remaining=self.count();n=self.fifo_count(receive)
            if n<=remaining:n=self.fifo_count(receive);self.set_count(remaining-n)
            else:n=remaining;self.set_count(0)
            sizes=[4]*(n//4)+[1]*(n%4) if c['alignment']==0 else [1]*n
            for size in sizes:
                if receive:self.buffer[offset:offset+size]=self.read(0x100,size).to_bytes(size,'little')
                else:
                    source=bytes([c['feature_value']]) if c['mode']=='feature_write' else self.buffer
                    self.write(0x100,int.from_bytes(source[offset:offset+size],'little'),size)
                offset+=size
        return self.wait(0x24,1)
    def run(self):
        c=self.c;mode=c['mode']
        if mode=='pack':result=pack(c['frame'])
        elif mode=='clock':
            old=self.clock;self.actions.append('clock_read:'+str(old))
            self.shadow=((old&0xffff0fff)|((c['clock_select']&15)<<12)) if c['clock_select']!=((old>>12)&15) else old
            if c['clock_select']!=((old>>12)&15):self.clock=self.shadow;self.actions.append('clock_write:'+str(self.clock))
            result=0
        elif mode=='init':result=self.init()
        elif mode in ('tx_count','rx_count'):result=self.fifo_count(mode=='rx_count')
        elif mode in ('complete','wait_receive','wait_transmit'):result=self.wait(0x24 if mode=='complete' else 0x18,1 if mode!='wait_receive' else 2)
        elif mode in ('feature_read','feature_write','cache_read','cache_write','write_enable'):
            self.actions.append('version:2');result=self.command()
            stage='command'
            if not result and c['frame'][9]:
                receive=mode in ('feature_read','cache_read');stage='receive_poll' if receive else 'transmit_poll'
                result=self.data(receive,False)
            if result:
                self.actions.extend(('log:'+stage+'_error','diagnostic'))
                self.stopped=dict(kind='assertion',owner=0x80c37b7c,line={'command':0x11f,'receive_poll':0x12a,'transmit_poll':0x132}[stage]);result=None
        else:
            result=self.command() if mode.startswith('command') else 0
            if mode!='command' and not result:
                label=mode.removeprefix('command_');result=self.data(label.startswith('receive'),label.endswith('dma'))
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=self.stopped,context_hex=self.context.hex(),
            buffer_sha256=digest(self.buffer),tx_hex=self.tx.hex(),rx_bytes=self.rx,mmio={str(k):v for k,v in sorted(self.regs.items())},
            clock_word=self.clock,clock_shadow=self.shadow)])


def contract(c):
    if not 0<=c['count']<=64 or c['alignment'] not in (0,1) or len(c['frame'])!=11:raise ValueError('bounded HAL payload')
    if not 0<=c['frame'][9]<=64 or any(not 0<=v<=MASK for v in c['frame']):raise ValueError('bounded HAL frame')
    if not all(c[key] for key in ('ready','done','reset_reads','ticks')) or any(not 0<=x<=0xffffffffffffffff for x in c['ticks']):raise ValueError('bounded HAL inputs')
    return Model(c).run()


def native_vectors():
    cases=[]
    def add(name,mode='command',frame_changes=None,**changes):
        c=dict(name=name,mode=mode,base=0x93240000,context_present=True,base_present=True,frame_present=True,
            count=9,alignment=0,control=0x3300,fifo=0x101,flags=[0,0],controller_mode=0,reset_reads=[0x100,0],
            ready=[3],done=[1],ticks=[0],frequency=1000,timeout=1000,dma_setup_status=0,dma_wait_status=0,dma_copy=True,
            clock_word=0xa5a5b5a5,clock_select=1,stop_chunks=0,feature_register=0xb0,feature_value=0xa5,address=0x1234)|changes
        c['frame']=[2 if 'transmit' in mode else 0,0,0x6b,1,1,0x1234,1,2,3,c['count'],8]
        for at,value in (frame_changes or {}).items():c['frame'][int(at)]=value
        if mode in ('feature_read','feature_write'):
            c['frame']=[0 if mode=='feature_read' else 2,0,0xf if mode=='feature_read' else 0x1f,1,1,c['feature_register'],1,1,1,1,0]
        elif mode in ('cache_read','cache_write'):
            c['frame']=[0 if mode=='cache_read' else 2,0,3 if mode=='cache_read' else 0x32,1,1,c['address'],1,2,1 if mode=='cache_read' else 3,c['count'],8 if mode=='cache_read' else 0]
        elif mode=='write_enable':c['frame']=[2,0,6,1,1,0,1,0,1,0,0]
        c['expected']=contract(c);cases.append(c)
    add('init_reset_then_ready','init');add('init_mode_one','init',controller_mode=1)
    add('init_preserves_other_control_bits','init',flags=[1,2],reset_reads=[0x144,0x44])
    for value in (1,2,11,17):add('clock_'+str(value),'clock',clock_select=value)
    for a,d,l in ((1,1,1),(1,1,2),(1,1,3),(1,2,1),(1,3,1),(2,1,1),(3,1,1),(0,1,1),(1,0,1),(1,1,4)):
        add(f'pack_{a}_{d}_{l}','pack',frame_changes={3:a,6:d,8:l})
    for receive in (False,True):
        for shift in range(4):add(('rx' if receive else 'tx')+'_count_'+str(shift),'rx_count' if receive else 'tx_count',control=shift<<(12 if receive else 8),fifo=0x0305)
    add('command_read');add('command_write',frame_changes={0:2});add('command_mode_seven',frame_changes={0:7})
    add('command_other_base',base=0x93200000);add('command_no_context',context_present=False)
    add('command_no_frame',frame_present=False);add('command_no_base',base_present=False)
    add('command_empty_ready',count=0);add('command_empty_timeout',count=0,done=[0],ticks=[0,1001])
    for mode in ('receive','transmit','receive_dma','transmit_dma'):
        add(mode+'_ready',mode);add('command_'+mode,'command_'+mode)
        add(mode+'_empty',mode,count=0)
    for mode in ('receive','transmit'):
        for n in (1,3,4,5,8):add(mode+'_count_'+str(n),mode,count=n)
        add(mode+'_unaligned',mode,alignment=1,count=9)
        add(mode+'_data_timeout',mode,ready=[0],ticks=[0,1001])
        add(mode+'_completion_timeout',mode,count=1,done=[0],ticks=[0,0,1001])
        add(mode+'_zero_fifo_prefix',mode,fifo=0,stop_chunks=4)
    for mode in ('receive_dma','transmit_dma'):
        add(mode+'_wait_error',mode,dma_wait_status=-9,control=0x3301)
        add(mode+'_setup_error_ignored',mode,dma_setup_status=-9)
        add(mode+'_completion_timeout',mode,done=[0],ticks=[0,1001])
    add('complete_ready','complete');add('complete_timeout','complete',done=[0],ticks=[0,1001])
    add('complete_ready_on_recheck','complete',done=[0,1],ticks=[0,1001])
    add('complete_exact_deadline','complete',done=[0,1],ticks=[0,1000])
    add('complete_low_word_wrap','complete',ticks=[0xfffffffe,0x100000001],done=[0,1],timeout=3)
    add('complete_full_counter_wrap','complete',ticks=[0xfffffffffffffffe,1],done=[0,1],timeout=3)
    add('complete_high_word_elapsed','complete',ticks=[0,0x100000000],done=[0])
    add('complete_sub_khz_frequency','complete',frequency=999,ticks=[0,1],done=[0])
    add('complete_limit_multiply_wrap','complete',frequency=4000000000,timeout=2000,ticks=[0,3705032705],done=[0])
    add('wait_receive_ready_recheck','wait_receive',ready=[0,2],ticks=[0,1001])
    add('wait_transmit_ready_recheck','wait_transmit',ready=[0,1],ticks=[0,1001])
    add('nand_feature_read','feature_read',count=1)
    add('nand_feature_write','feature_write',count=1)
    add('nand_cache_read','cache_read');add('nand_cache_write','cache_write')
    add('nand_feature_read_timeout','feature_read',count=1,done=[0],ticks=[0,0,1001])
    add('nand_feature_write_timeout','feature_write',count=1,done=[0],ticks=[0,0,1001])
    add('nand_write_enable_timeout','write_enable',count=0,done=[0],ticks=[0,1001])
    for mode in ('receive','transmit'):
        add(mode+'_zero_fifo_advancing_prefix',mode,fifo=0,stop_chunks=4,ticks=[0,1001,2002,3003])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual QSPI HAL init/command/FIFO/DMA wrappers, packing/status/count helpers and clock selection execute over authored MMIO and 64-bit timer inputs; selected NAND builders connect through the actual bus wrapper.',
            'Reset self-clear, status/ready values, FIFO data, completion W1C and DMA setup/wait/copy behavior are supplied; no controller or DMA hardware is accessed.',
            'Zero-FIFO cases stop at a bounded no-progress prefix; NAND errors stop before assertion bodies. Neither claims normal return ABI. The connected bus uses a supplied ROM-version result and authored initialized context.',
            'Actual DMA setup/wait internals, electrical bus operation, frequency calibration, coherency, physical persistence and device boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect QSPI HAL: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
