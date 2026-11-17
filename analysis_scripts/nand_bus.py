#!/usr/bin/env python3
"""NAND QSPI platform, command packets and busy polling with supplied HAL.

MMIO is emulator backing only. ROM strings, HAL results, DMA/pin services and
response bytes are authored; no physical controller or clock is accessed.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH,digest,image_memory
else:
    from recovery_validator import BOOT_HASH,digest,image_memory

ROOT=Path(__file__).resolve().parents[1]
CHIPS=ROOT/'analysis/nand-chips.json'
CTRL=0x80dfb880
BOUNCE=0x80dfb8c0
DMA=(0x80de64a0,0x80de645c)
CONFIG=dict(init=0x80c10580,transfer=0x80c106f0,version=0x80c12298,wait=0x80c102f0,deinit=0x80c102e0,
    read_feature=0x80c27ce8,write_feature=0x80c27d48,write_enable=0x80c27db0,
    read_to_cache=0x80c27e0e,cache_read_x1=0x80c27e70,cache_read_x4=0x80c27ed6,
    cache_read_bounce=0x80c27f3e,program_execute=0x80c27fa8,
    cache_write_x4=0x80c2806c,cache_write_bounce=0x80c280d0,erase=0x80c28136,
    busy=0x80c2836e,erase_busy=0x80c286b2,
    clock_select=0x80df9f80,pinmux=0x80c13408,gpio=0x80df8e94,controller_init=0x80df9220,dma_init=0x80c123ac,
    command=0x80df928c,receive_poll=0x80df93c4,receive_bounce=0x80df94bc,
    transmit_poll=0x80df951c,transmit_bounce=0x80df960c,
    copy=0x80c2de38,strcmp=0x80c2e3d8,delay_us=0x80c12154,sleep=0x80c16884,
    diagnostic=0x80c10304,logger=0x80c1cd7a,assertion=0x80c16516)
RANGES=((0x80c10580,0x16e),(0x80c106f0,0x376),(0x80c12298,0x4e),(0x80c102f0,0x14),(0x80c102e0,4),
    (0x80c27ce8,0x60),(0x80c27d48,0x68),(0x80c27db0,0x5e),(0x80c27e0e,0x62),
    (0x80c27e70,0x66),(0x80c27ed6,0x68),(0x80c27f3e,0x6a),(0x80c27fa8,0x62),
    (0x80c2806c,0x64),(0x80c280d0,0x66),(0x80c28136,0x68),(0x80c2836e,0xb4),(0x80c286b2,0x98))
TARGETS=tuple(CONFIG[k] for k in ('init','transfer','version','wait','deinit','read_feature','write_feature','write_enable',
    'read_to_cache','cache_read_x1','cache_read_x4','cache_read_bounce','program_execute','cache_write_x4','cache_write_bounce','erase','busy','erase_busy'))
LOGS={0x80c37a64:'command_error',0x80c37a88:'receive_bounce_error',0x80c37acc:'transmit_bounce_error',
      0x80c37b14:'receive_poll_error',0x80c37b54:'transmit_poll_error',0x80c3d6a4:'busy_timeout'}


class Stop(Exception):
    def __init__(self,owner,line):self.info=dict(kind='assertion',owner=owner,line=line)


class Model:
    def __init__(self,c):
        self.c=c;self.actions=[];self.buffer=bytearray((i*3+1)&255 for i in range(512));self.bounce=bytearray(b'\xa5'*512)
        self.controller=bytearray(b'\xa5'*64);self.dma=[bytearray(b'\xa5'*48) for _ in range(2)]
        self.mmio=list(c['mmio']);self.reinit=int(c['reinit']);self.reads=0
    def init(self):
        c=self.c;self.actions.extend((f'clock_select:{2 if c["bus_word"]<100 else 1}','pinmux:0:127:63','gpio:0:127:1','fence'))
        self.mmio[1]|=0x200;self.mmio[0]|=0x200
        for at,v in ((0,0x93240000),(8,0),(12,0)):struct.pack_into('<I',self.controller,at,v)
        self.actions.append('controller_init:'+str(c['init_status']));self.actions.append('fence');self.mmio[0]|=8
        rows=((12,2,0,2,0,0,6,1,0x93080000,5),(12,1,2,0,0,0,6,1,0x93080000,6))
        for i,words in enumerate(rows):
            struct.pack_into('<10I',self.dma[i],0,*words)
            self.actions.append(f'dma_init:{i}:{digest(self.dma[i][:44])}:{c["init_status"]}')
            struct.pack_into('<I',self.dma[i],44,CTRL);struct.pack_into('<I',self.controller,32+i*4,DMA[i])
        return 0
    def version(self):
        self.actions.append('version_query');return {'v1.1.03':1,'v1.1.16':2}.get(self.c['rom_version'],0)
    def fail(self,stage,bounce):
        c=self.c;self.actions.append('log:'+stage+'_error');self.actions.append('diagnostic')
        owner=0x80c37b98 if bounce else 0x80c37b7c
        line={'command':0x162 if bounce else 0x11f,'receive_bounce':0x16f,'receive_poll':0x12a,'transmit_bounce':0x17b,'transmit_poll':0x132}[stage]
        raise Stop(owner,line)
    def transfer(self,p,local=None,temporary=False):
        c=self.c
        if self.reinit:self.reinit=0;self.init()
        version=self.version();bounce=not p['force'] and p['size']>31 and version>1;write=bool(p['write'])
        data=local if local is not None else self.buffer
        if bounce and write and p['size']:
            self.actions.append(f'copy_to_bounce:{p["size"]}');self.bounce[:p['size']]=data[:p['size']]
        frame=[2 if write else 0,0,p['opcode'],1,p['command_lines'],p['address'],1,p['address_bytes'],p['data_lines'],p['size'],8 if p['dummy'] else 0]
        self.actions.append('command:'+':'.join(map(str,frame))+':'+str(c['command_status']))
        if c['command_status']:self.fail('command',bounce)
        response=None
        if p['size']:
            label=('transmit_' if write else 'receive_')+('bounce' if bounce else 'poll');target=self.bounce if bounce else data
            if write:
                self.actions.append(f'{label}:{p["size"]}:{digest(target[:p["size"]])}:{c["write_status"]}')
                if c['write_status']:self.fail(label,bounce)
            else:
                self.actions.append(f'{label}:{p["size"]}:{c["read_status"]}');self.reads+=1
                if c['read_status']:self.fail(label,bounce)
                response=c['responses'][min(self.reads-1,len(c['responses'])-1)]
                n=min(p['size'],c['copy_limit']);target[:n]=bytes((response+i*7)&255 for i in range(n))
                if bounce:
                    self.actions.append(f'copy_from_bounce:{p["size"]}');data[:p['size']]=self.bounce[:p['size']]
        return 0,response
    def packet(self,mode):
        c=self.c;p=dict(write=c['write_byte'],dummy=c['dummy_byte'],force=c['force_block'],opcode=c['opcode'],
            command_lines=c['command_lines'],address=c['address'],address_bytes=c['address_bytes'],data_lines=c['data_lines'],size=c['size'])
        specs={'read_feature':(0,0,1,0x0f,1,1,1),'write_feature':(1,0,1,0x1f,1,1,1),
            'write_enable':(1,0,1,6,0,1,0),'read_to_cache':(1,0,1,0x13,3,1,0),'program_execute':(1,0,1,0x10,3,1,0),
            'erase':(1,0,1,0xd8,3,1,0),'cache_read_x1':(0,1,1,3,2,1,c['size']),
            'cache_read_x4':(0,1,1,0x6b,2,3,c['size']),'cache_read_bounce':(0,1,0,0x6b,2,3,c['size']),
            'cache_write_x4':(1,0,1,0x32,2,3,c['size']),'cache_write_bounce':(1,0,0,0x32,2,3,c['size'])}
        if mode in specs:
            w,d,f,op,ab,dl,n=specs[mode];p.update(write=w,dummy=d,force=f,opcode=op,address_bytes=ab,data_lines=dl,size=n,command_lines=1)
            p['address']=c['feature_register'] if mode.endswith('feature') else (0 if mode=='write_enable' else c['address'])
            if mode=='erase':p['address']=(c['address']*64)&0xffffffff
        return p
    def run(self):
        c=self.c;stopped=None;result=0
        try:
            mode=c['mode']
            if mode=='init':result=self.init()
            elif mode=='version':result=self.version()
            elif mode=='wait':self.actions.append('wait_us:'+str(c['wait_value']))
            elif mode=='deinit':pass
            elif mode in ('busy','erase_busy'):
                self.buffer[0]=255;temp=bytearray(1);count=0
                while True:
                    count+=1
                    self.actions.append('wait_us:5' if mode=='busy' else 'sleep_tick:1')
                    p=self.packet('read_feature');p['address']=0xc0
                    _,response=self.transfer(p,temp,True)
                    limit=((c['timeout']*1000)&0xffffffff)//5 if mode=='busy' else c['timeout']
                    if count>=limit:self.actions.append('log:busy_timeout');break
                    if temp[0]&1==0:self.buffer[0]=temp[0];break
            else:
                local=bytearray((c['feature_value']&255,)) if mode=='write_feature' else None
                result,_=self.transfer(self.packet(mode),local)
        except Stop as stop:result=None;stopped=stop.info
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=stopped,reinit=self.reinit,mmio=self.mmio,
            buffer_sha256=digest(self.buffer),bounce_sha256=digest(self.bounce),controller_hex=self.controller.hex(),
            dma_sha256=[digest(b) for b in self.dma])])


def contract(c):
    if not 0<=c['size']<=512 or not c['responses'] or any(not 0<=b<=255 for b in c['responses']):raise ValueError('bounded bus payload')
    if not 0<=c['timeout']<=4 or len(c['rom_version'])>24:raise ValueError('bounded version/timeout')
    return Model(c).run()


def native_vectors():
    cases=[]
    def add(name,mode='transfer',**changes):
        c=dict(name=name,mode=mode,bus_word=104,rom_version='v1.1.16',write_byte=0,dummy_byte=1,force_block=1,
            opcode=3,command_lines=1,address=0x1234,address_bytes=2,data_lines=1,size=64,reinit=False,
            mmio=[0x01000001,0x20000001],init_status=0,command_status=0,read_status=0,write_status=0,
            responses=[0x5a],copy_limit=512,feature_register=0xb0,feature_value=0xa5,timeout=1,wait_value=5)|changes
        c['expected']=contract(c);cases.append(c)
    add('init_high_word','init');add('init_low_word','init',bus_word=83);add('init_boundary_99','init',bus_word=99)
    add('init_boundary_100','init',bus_word=100);add('init_callback_status_ignored','init',init_status=-9)
    for ver in ('v1.1.03','v1.1.16','v9.9.99','unknown'):add('version_'+ver.replace('.','_'),'version',rom_version=ver)
    add('poll_read');add('poll_write',write_byte=1);add('bounce_read',force_block=0);add('bounce_write',force_block=0,write_byte=1)
    add('bounce_threshold_31',force_block=0,size=31);add('bounce_threshold_32',force_block=0,size=32)
    add('old_rom_uses_poll',force_block=0,rom_version='v1.1.03');add('unknown_rom_uses_poll',force_block=0,rom_version='unknown')
    add('raw_boolean_fields',write_byte=128,dummy_byte=255);add('transfer_reinitializes',reinit=True)
    add('zero_length_command',size=0);add('poll_command_error',command_status=-9);add('poll_read_error',read_status=-9)
    add('poll_write_error',write_byte=1,write_status=-9);add('bounce_command_error',force_block=0,command_status=-9)
    add('bounce_read_error',force_block=0,read_status=-9);add('bounce_write_error',force_block=0,write_byte=1,write_status=-9)
    add('positive_command_error',command_status=1);add('partial_supplied_read',copy_limit=3)
    for mode in ('read_feature','write_feature','write_enable','read_to_cache','program_execute','erase','cache_read_x1','cache_read_x4','cache_read_bounce','cache_write_x4','cache_write_bounce'):add(mode,mode)
    add('write_feature_truncates','write_feature',feature_value=0x1a5)
    add('command_builder_hal_error','read_feature',command_status=-9)
    add('busy_ready','busy',responses=[0x10]);add('busy_second_read','busy',responses=[1,0])
    add('busy_zero_timeout','busy',responses=[0],timeout=0)
    add('busy_timeout','busy',responses=[1]);add('busy_ready_at_deadline','busy',responses=[1]*199+[0])
    add('erase_busy_first_deadline','erase_busy',responses=[0],timeout=1)
    add('erase_busy_second_ready','erase_busy',responses=[1,0],timeout=3)
    add('erase_busy_second_deadline','erase_busy',responses=[1,0],timeout=2)
    add('wait_passthrough','wait');add('deinit_noop','deinit')
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=200000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    for chip in json.loads(CHIPS.read_bytes())['chips']:
        for offset,opcode in ((0x7a,0xf),(0x7b,0x1f),(0x7c,6),(0x7e,0x13),(0x7f,0x10),(0x80,3),(0x82,0x6b),(0x83,0x32),(0x84,0xd8)):
            if memory.read(chip['address']+offset,1)[0]!=opcode:raise ValueError('original command opcode')
    return dict(boot_sha256=BOOT_HASH,chip_inventory_sha256=digest(CHIPS.read_bytes()),vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual QSPI bus initialization/packet conversion, selected NAND builders, ROM-version policy and busy loops execute over emulator-only MMIO and supplied HAL/DMA/pin services.',
            'Fences are recorded as single-thread ordering markers. No physical MMIO, electrical timing, controller transfer, DMA completion or scheduler behavior is validated.',
            'ROM identity strings, response bytes and status faults are authored; assertion cases stop before the assertion body and claim no return ABI.',
            'Lower RAM HAL/ROM routines, bus/ECC timing, physical NAND behavior, UID/BBT, SFTL, persistence and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND bus: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
