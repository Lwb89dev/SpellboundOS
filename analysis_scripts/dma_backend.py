#!/usr/bin/env python3
"""DMA initialization/setup/wait/cancel/IRQ policy over authored MMIO services."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH,digest,image_memory
else:
    from recovery_validator import BOOT_HASH,digest,image_memory

D=0x81300000
SOURCE=0x81301000
DEST=0x81302000
OUTPUT=0x81303000
TABLE=0x80de65ec
BANKS={0x92000000:0,0x93000000:7,0x93040000:14,0x93080000:21}
CONFIG=dict(init=0x80c123ac,setup_irq=0x80c12548,cancel=0x80c125ec,setup=0x80c12628,
    remaining=0x80c126c0,wait=0x80c126e0,irq=0x80c1279c,tick=0x80c121e4,
    prepare=0x80c122f4,finish=0x80c12350,fatal=0x80c1b5c0,callback_a=0x70001000,callback_b=0x70002000)
RANGES=((0x80c123ac,0x198),(0x80c12548,0xa2),(0x80c125ec,0x3a),(0x80c12628,0x96),
    (0x80c126c0,0x1c),(0x80c126e0,0xba),(0x80c1279c,0x112))
TARGETS=tuple(a for a,n in RANGES)


def context(c,channel):
    data=bytearray(b'\xa5'*80)
    fields=(c['request'],c['direction'],c['source_increment'],c['dest_increment'],c['source_width'],
        c['dest_width'],c['burst'],c['priority'],c['base'],channel,c['linked'])
    struct.pack_into('<11I',data,0,*fields)
    for at,v in ((48,CONFIG['callback_a'] if c['callback_a'] else 0),(52,(CONFIG['callback_b']|1) if c['callback_b'] else 0),
                 (60,c['tracked_address']),(64,c['tracked_size'])):struct.pack_into('<I',data,at,v)
    return data


class Model:
    def __init__(self,c):
        self.c=c;self.actions=[];self.stopped=None;self.output=0xa5a5a5a5;self.ticks=0;self.indices={}
        self.address=c.get('descriptor_address',D)
        self.slots=c['slots'];self.contexts=[context(c,ch) for ch in self.slots];self.registry=[0]*28
        self.regs={4:c['irq_a'],8:0x100,12:c['irq_b'],16:0x200,20:0,24:0,36:c['enabled']}
        for ch in range(7):
            for at,v in ((0x100,0x12340001),(0x104,0xffff),(0x108,0x11111111),(0x10c,0x22222222),(0x110,0x33333333),(0x114,0x44444444)):
                self.regs[ch*32+at]=v
        if c['registered'] and c['base'] in BANKS:
            for i,ch in enumerate(self.slots):
                if ch<7:self.registry[BANKS[c['base']]+ch]=self.address+i*256
    def word(self,at,i=0):return struct.unpack_from('<I',self.contexts[i],at)[0]
    def put(self,at,value,i=0):struct.pack_into('<I',self.contexts[i],at,value&0xffffffff)
    def read(self,at):
        if at in (20,24):
            key='status_a' if at==20 else 'status_b';i=self.indices.get(key,0);self.indices[key]=i+1
            values=self.c[key];value=values[min(i,len(values)-1)];self.regs[at]=value
        else:value=self.regs[at]
        self.actions.append(f'r:{at}:{value}');return value
    def write(self,at,value):
        value&=0xffffffff;self.regs[at]=value;self.actions.append(f'w:{at}:{value}')
    def cache(self,finish=False,address=None,n=None,i=0):
        if address is None:address=self.word(60,i);n=self.word(64,i)
        self.actions.append(f'cache_{"finish" if finish else "prepare"}:{address}:{n}')
    def fatal(self):
        self.stopped=dict(kind='fatal_boundary',line=0x2a);return None
    def init(self):
        c=self.c;ch=c['channel'];base=c['base']
        if ch>6 or base==0x92000000 and ch>3:return 1
        if not self.read(36)&1:self.write(36,1)
        old=self.read(8);self.put(60,0);self.put(64,0);self.write(8,old|(1<<ch))
        self.write(16,self.read(16)|(1<<ch))
        ctl=((c['source_width']&7)<<11)|((c['dest_width']&7)<<8)|((c['burst']&7)<<16)|((c['priority']&3)<<22)
        ctl|=((c['source_increment']&3)<<5)|((c['dest_increment']&3)<<3)
        config=7
        if c['direction']:
            ctl|=0x80
            if c['direction']==2:config|=(c['request']&15)<<9
            elif c['direction']==1:config|=(c['request']&15)<<3
        config|=(int(c['dest_increment']==2)<<13)|(int(c['source_increment']==2)<<7)
        for at,v in ((0x100,ctl),(0x104,config),(0x110,0)):self.write(ch*32+at,v)
        if base not in BANKS:return self.fatal()
        self.registry[BANKS[base]+ch]=self.address;return 0
    def setup(self,irq=False,source=SOURCE,dest=DEST,size=None):
        c=self.c;mode=c['direction'];n=c['size'] if size is None else size
        if mode in (0,1):self.put(60,dest);self.put(64,n)
        if mode in (0,2):self.cache(address=source,n=n)
        if mode in (0,1):self.cache(address=dest,n=n)
        if mode==2:self.put(60,0);self.put(64,0)
        ch=c['channel']
        for at,value in ((0x108,source),(0x10c,dest),(0x114,n>>(c['source_width']&31))):self.write(ch*32+at,value)
        if irq:
            self.write(ch*32+0x104,self.read(ch*32+0x104)&~1)
            self.write(ch*32+0x104,self.read(ch*32+0x104)&~2)
        self.write(ch*32+0x100,self.read(ch*32+0x100)|1);return 0
    def cancel(self):
        self.cache(True);self.put(60,0);self.put(64,0);at=self.c['channel']*32+0x100
        self.write(at,self.read(at)|0x8000);self.write(at,self.read(at)&~1);return 0
    def tick(self):
        values=self.c['ticks'];v=values[min(self.ticks,len(values)-1)];self.ticks+=1;self.actions.append('tick:'+str(v));return v
    def wait(self):
        c=self.c;mask=1<<c['channel'];start=self.tick();primary=False;status=0
        for _ in range(32):
            first=self.read(20);second=self.read(24)
            if first&mask:primary=True;break
            if second&mask:break
            delta=(self.tick()-start)&0xffffffffffffffff
            if delta>>32 or (delta&0xffffffff)>c['timeout']:
                first=self.read(20);second=self.read(24)
                if first&mask:primary=True;break
                status=0 if second&mask else 3;break
        else:raise ValueError('fixture DMA clock does not expire')
        if primary:self.cache(True);self.put(60,0);self.put(64,0)
        self.write(8,self.read(8)|mask);self.write(16,self.read(16)|mask)
        at=c['channel']*32+0x100;self.write(at,self.read(at)&~1)
        return 0 if primary else status
    def irq(self):
        c=self.c;a=self.read(4);b=self.read(12)
        if c['base'] not in BANKS:return self.fatal()
        self.write(8,a);self.write(16,b)
        for ch in range(7):
            if not (a|b)&(1<<ch):continue
            pointer=self.registry[BANKS[c['base']]+ch]
            if not pointer:raise ValueError('IRQ requires populated active channel')
            i=(pointer-self.address)//256;at=ch*32+0x100
            if a&(1<<ch):
                if not self.word(40,i):self.write(at,self.read(at)&~1)
                self.cache(True,i=i);self.put(60,0,i);self.put(64,0,i)
                if c['callback_a']:self.actions.append(f'callback_a:{ch}:0:0')
            if b&(1<<ch):
                self.write(at,self.read(at)&~1)
                if c['callback_b']:self.actions.append(f'callback_b:{ch}:{self.word(60,i)}:{self.word(64,i)}')
        return None
    def run(self):
        c=self.c;mode=c['mode'];result=0
        if mode.startswith('init'):
            result=self.init()
            if not result and mode!='init':result=self.setup(mode=='init_setup_irq')
            if not result and mode=='init_setup_wait':result=self.wait()
            elif not result and mode=='init_setup_irq':result=self.irq()
        elif mode in ('setup','setup_irq'):result=self.setup(mode=='setup_irq')
        elif mode=='cancel':result=self.cancel()
        elif mode=='wait':result=self.wait()
        elif mode=='irq':result=self.irq()
        elif mode=='remaining':
            if not c['context_present'] or not c['output_present']:result=1
            else:self.output=self.read(c['channel']*32+0x114)
        else:raise ValueError('DMA mode')
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=self.stopped,output=self.output,
            contexts_hex=[v.hex() for v in self.contexts],registry=self.registry,mmio={str(k):v for k,v in sorted(self.regs.items())})])


def contract(c):
    if not 0<=c['size']<=64 or not 0<=c['channel']<=7 or len(c['slots'])>2:raise ValueError('bounded DMA fixture')
    if not c['ticks'] or not c['status_a'] or not c['status_b']:raise ValueError('DMA input sequence')
    if c['mode']!='init' and c['channel']>6:raise ValueError('active channel bound')
    return Model(c).run()


def native_vectors():
    cases=[]
    def add(name,mode='init',**changes):
        c=dict(name=name,mode=mode,base=0x93080000,channel=5,request=12,direction=2,source_increment=0,dest_increment=2,
            source_width=0,dest_width=0,burst=6,priority=1,linked=0,tracked_address=DEST,tracked_size=13,
            size=13,enabled=0,registered=not mode.startswith('init'),slots=None,context_present=True,output_present=True,
            callback_a=True,callback_b=True,irq_a=None,irq_b=0,status_a=None,status_b=[0],ticks=[0],timeout=1000)|changes
        if c['slots'] is None:c['slots']=[c['channel']]
        if c['irq_a'] is None:c['irq_a']=1<<c['channel']
        if c['status_a'] is None:c['status_a']=[1<<c['channel']]
        c['context_hex']=[context(c,ch).hex() for ch in c['slots']]
        c['expected']=contract(c);cases.append(c)
    for base in BANKS:
        add('init_base_'+format(base,'x'),base=base,channel=3 if base==0x92000000 else 6)
    add('init_nand_tx');add('init_nand_rx',channel=6,direction=1,source_increment=2,dest_increment=0)
    add('init_invalid_channel',channel=7);add('init_restricted_channel',base=0x92000000,channel=4)
    add('init_unknown_base',base=0x93100000);add('init_already_enabled',enabled=0x101)
    add('init_memory_mode',direction=0,source_increment=1,dest_increment=1)
    add('init_other_direction',direction=3);add('init_field_masks',request=31,source_increment=7,dest_increment=6,source_width=15,dest_width=14,burst=15,priority=7)
    for direction in range(4):
        add('setup_direction_'+str(direction),'setup',direction=direction)
        add('setup_irq_direction_'+str(direction),'setup_irq',direction=direction)
    for width in (0,1,2,3,32):add('setup_width_'+str(width),'setup',direction=1,source_width=width)
    add('setup_zero_size','setup',direction=1,size=0)
    add('remaining_count','remaining');add('remaining_null_context','remaining',context_present=False)
    add('remaining_null_output','remaining',output_present=False)
    add('cancel_tracking','cancel');add('cancel_empty_tracking','cancel',tracked_address=0,tracked_size=0)
    add('wait_primary','wait');add('wait_alternate','wait',status_a=[0],status_b=[32])
    add('wait_both','wait',status_b=[32]);add('wait_timeout','wait',status_a=[0],ticks=[0,1001])
    add('wait_primary_on_recheck','wait',status_a=[0,32],ticks=[0,1001])
    add('wait_alternate_on_recheck','wait',status_a=[0],status_b=[0,32],ticks=[0,1001])
    add('wait_exact_limit','wait',status_a=[0,32],ticks=[0,1000])
    add('wait_low_wrap','wait',status_a=[0,32],ticks=[0xfffffffe,0x100000001],timeout=3)
    add('wait_full_wrap','wait',status_a=[0,32],ticks=[0xfffffffffffffffe,1],timeout=3)
    add('wait_high_elapsed','wait',status_a=[0],ticks=[0,0x100000000])
    add('wait_unrelated_bits','wait',status_a=[1],status_b=[2],ticks=[0,1001])
    for base in BANKS:add('irq_base_'+format(base,'x'),'irq',base=base,channel=3 if base==0x92000000 else 6)
    add('irq_primary','irq');add('irq_linked_primary','irq',linked=1)
    add('irq_alternate','irq',irq_a=0,irq_b=32);add('irq_both','irq',irq_b=32)
    add('irq_no_callbacks','irq',callback_a=False,callback_b=False)
    add('irq_no_pending','irq',irq_a=0,irq_b=0,registered=False)
    add('irq_high_bit_only','irq',irq_a=128,registered=False)
    add('irq_two_channels','irq',channel=0,slots=[0,2],irq_a=5,irq_b=4)
    add('irq_unknown_base','irq',base=0x93100000)
    add('connected_init_setup_wait_tx','init_setup_wait')
    add('connected_init_setup_wait_rx','init_setup_wait',direction=1,channel=6,source_increment=2,dest_increment=0)
    add('connected_init_setup_wait_timeout','init_setup_wait',direction=1,status_a=[0],ticks=[0,1001])
    add('connected_init_setup_irq','init_setup_irq',direction=1)
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
            'Actual DMA initializer, setup variants, cancel, remaining-count query, wait and IRQ handler execute with authored MMIO/status/timestamps and descriptor registry.',
            'Cache-maintenance and callback bodies are supplied. No physical DMA movement, IRQ delivery or cache coherency is established.',
            'Status A/B names identify tested software branches, not independently verified hardware error/completion semantics.',
            'Fatal cases stop before the fatal body and claim no return ABI; IRQ cases claim normal stack/saved registers but no return-value semantics.',
            'QSPI-to-DMA integration, board wiring/timing, persistence and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect DMA backend: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
