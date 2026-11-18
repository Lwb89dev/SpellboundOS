#!/usr/bin/env python3
"""Original main NAND bus/platform and feature packets over supplied HAL services."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_bus as boot
    from . import main_nand_probe as probe
else:
    import nand_bus as boot
    import main_nand_probe as probe

base=probe.base
CTRL=0x80d94a60
BOUNCE=0x80d93960
DMA=(0x80c10df4,0x80c10db0)
REINIT=0x80c10e38
DISABLED=0x80c10e39
CONFIG=dict(init=0x70296ab0,transfer=0x70296c24,read_feature=0x702d5daa,write_feature=0x702d5e0e,
    version=0x80d4556c,clock_select=0x80d3580c,pinmux=0x80d43a24,gpio=0x80d342f8,
    controller_init=0x80d34ac4,dma_init=0x702a0038,command=0x80d34b30,
    receive_poll=0x80d34c68,receive_bounce=0x80d34d60,transmit_poll=0x80d34dc0,transmit_bounce=0x80d34eb0,
    copy=0x70947b0c,diagnostic=0x70296834,logger=0x702b38a2,assertion=0x80d364fa)
RANGES=((CONFIG['init'],370),(CONFIG['transfer'],938),(CONFIG['read_feature'],100),(CONFIG['write_feature'],108))
DATA_RANGES=((probe.BUS,20),(probe.facts()['chips'][0]['address'],184))
LOGS={0x70a1bb74:'command_error',0x70a1bb98:'receive_bounce_error',0x70a1bbdc:'transmit_bounce_error',
    0x70a1bc24:'receive_poll_error',0x70a1bc64:'transmit_poll_error'}
BOUND=10000
DEFAULT=dict(mode='transfer',bus_word=104,rom_revision=2,disabled=False,write_byte=0,dummy_byte=1,force_block=1,
    opcode=3,command_lines=1,address=0x1234,address_bytes=2,data_lines=1,size=64,reinit=False,
    mmio=[0x01000001,0x20000001],init_status=0,command_status=0,read_status=0,write_status=0,
    responses=[0x5a],copy_limit=512,feature_register=0xb0,feature_value=0xa5)


class Model(boot.Model):
    """Shared packet conversion policy; main addresses, flags and assertions differ."""
    def init(self):
        c=self.c;self.actions.extend((f'clock_select:{2 if c["bus_word"]<100 else 1}','pinmux:0:127:63','gpio:0:127:1','fence'))
        self.mmio[1]|=0x200;self.mmio[0]|=0x200
        for at,v in ((0,0x93240000),(8,0),(12,0)):struct.pack_into('<I',self.controller,at,v)
        self.actions.append('controller_init:'+str(c['init_status']));self.actions.append('fence');self.mmio[0]|=8
        for i,words in enumerate(((12,2,0,2,0,0,6,1,0x93080000,5),(12,1,2,0,0,0,6,1,0x93080000,6))):
            struct.pack_into('<10I',self.dma[i],0,*words)
            self.actions.append(f'dma_init:{i}:{base.digest(self.dma[i][:44])}:{c["init_status"]}')
            struct.pack_into('<I',self.dma[i],44,CTRL);struct.pack_into('<I',self.controller,32+i*4,DMA[i])
        return 0
    def version(self):self.actions.append('version_query');return self.c['rom_revision']
    def fail(self,stage,bounce):
        self.actions.extend(('log:'+stage+'_error','diagnostic'))
        line={'command':361 if bounce else 294,'receive_bounce':374,'receive_poll':305,'transmit_bounce':386,'transmit_poll':313}[stage]
        raise boot.Stop(0x70a1bca8 if bounce else 0x70a1bc8c,line)
    def transfer(self,p,local=None,temporary=False):
        if self.c['disabled']:return -1,None
        return super().transfer(p,local,temporary)
    def run(self):
        c=self.c;stopped=None
        try:
            if c['mode']=='init':result=self.init()
            else:
                local=bytearray((c['feature_value']&255,)) if c['mode']=='write_feature' else None
                result,_=self.transfer(self.packet(c['mode']),local)
                if result and c['mode']!='transfer':raise boot.Stop(0x70a31114 if c['mode']=='write_feature' else 0x70a3112c,74 if c['mode']=='write_feature' else 55)
        except boot.Stop as stop:result=None;stopped=stop.info
        return dict(actions=self.actions,rows=[dict(returned=None if result is None else result&0xffffffff,stopped=stopped,
            reinit=self.reinit,disabled=int(c['disabled']),mmio=self.mmio,buffer_sha256=base.digest(self.buffer),
            bounce_sha256=base.digest(self.bounce),controller_hex=self.controller.hex(),dma_sha256=[base.digest(b) for b in self.dma])])


def contract(c):
    if c['mode'] not in ('init','transfer','read_feature','write_feature'):raise ValueError('main bus entry')
    if not 0<=c['size']<=512 or not c['responses'] or len(c['responses'])>8 or any(not 0<=b<=255 for b in c['responses']):raise ValueError('bounded payload')
    if not 0<=c['rom_revision']<=0xffffffff or not 0<=c['bus_word']<=0xffffffff:raise ValueError('main bus words')
    if any(not 0<=c[k]<=255 for k in ('write_byte','dummy_byte','force_block','command_lines','address_bytes','data_lines','feature_register')):raise ValueError('packet bytes')
    if any(not 0<=c[k]<=0xffffffff for k in ('address','opcode','feature_value')) or not 0<=c['copy_limit']<=512:raise ValueError('packet words')
    if len(c['mmio'])!=2 or any(not 0<=v<=0xffffffff for v in c['mmio']):raise ValueError('MMIO backing')
    if any(not -100<=c[k]<=100 for k in ('init_status','command_status','read_status','write_status')):raise ValueError('HAL statuses')
    return Model(c).run()


def native_vectors():
    cases=[]
    def add(name,mode='transfer',**changes):
        c=DEFAULT|dict(name='main_bus_'+name,mode=mode)|changes
        c['expected']=contract(c);cases.append(c)
    add('init_high','init');add('init_low','init',bus_word=83);add('init_99','init',bus_word=99);add('init_100','init',bus_word=100)
    add('init_status_ignored','init',init_status=-9);add('init_keeps_flags','init',reinit=True,disabled=True)
    add('poll_read');add('poll_write',write_byte=1);add('bounce_read',force_block=0);add('bounce_write',force_block=0,write_byte=1)
    add('threshold_31',force_block=0,size=31);add('threshold_32',force_block=0,size=32)
    add('revision_1_poll',force_block=0,rom_revision=1);add('revision_0_poll',force_block=0,rom_revision=0)
    add('revision_unsigned_bounce',force_block=0,rom_revision=0xffffffff)
    add('boolean_bytes',write_byte=128,dummy_byte=255);add('reinitialize',reinit=True)
    add('disabled',disabled=True);add('disabled_keeps_reinit',disabled=True,reinit=True)
    add('zero_length',size=0);add('command_error',command_status=-9);add('read_error',read_status=-9)
    add('write_error',write_byte=1,write_status=-9);add('bounce_command_error',force_block=0,command_status=-9)
    add('bounce_read_error',force_block=0,read_status=-9);add('bounce_write_error',force_block=0,write_byte=1,write_status=-9)
    add('positive_command_error',command_status=1);add('partial_read',copy_limit=3)
    add('feature_read','read_feature');add('feature_write','write_feature');add('feature_truncates','write_feature',feature_value=0x1a5)
    add('feature_read_bus_error','read_feature',command_status=-9);add('feature_write_bus_error','write_feature',write_status=-9)
    add('feature_read_disabled','read_feature',disabled=True);add('feature_write_disabled','write_feature',disabled=True)
    return dict(schema=1,bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if probe.inventory(mem)!=probe.facts():raise ValueError('original main inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    for chip in probe.facts()['chips']:
        if mem.read(chip['address']+0x7a,2)!=b'\x0f\x1f':raise ValueError('original feature opcodes')
    return dict(main_sha256=base.MAIN_HASH,inventory_sha256=base.digest(probe.FACTS.read_bytes()),vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in DATA_RANGES},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in RANGES},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main bus init/transfer and feature packet builders execute over authored MMIO, revision return, HAL/DMA/pin/copy services and response/status inputs.',
            'The direct fixture clones the first original descriptor only to vary its bus word; original bus binding and source descriptor are hash guarded. This does not identify physical geometry.',
            'Fences are recorded as single-thread ordering markers. Actual HAL/FIFO/DMA, electrical timing, physical power/UID/BBT, concurrency, persistence and standalone boot remain unverified.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main NAND bus: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
