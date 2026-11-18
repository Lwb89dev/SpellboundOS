#!/usr/bin/env python3
"""Original main QSPI HAL/FIFO/DMA wrappers and revision policy over authored I/O."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import qspi_hal as boot
    from .main_nand_bus import base,CTRL
else:
    import qspi_hal as boot
    from main_nand_bus import base,CTRL

CONFIG=dict(pack=0x80d34800,complete=0x80d348c8,wait_receive=0x80d34954,wait_transmit=0x80d349e8,
    tx_count=0x80d34a7c,rx_count=0x80d34aa0,init=0x80d34ac4,command=0x80d34b30,
    receive=0x80d34c68,receive_dma=0x80d34d60,transmit=0x80d34dc0,transmit_dma=0x80d34eb0,
    clock=0x80d3580c,version=0x80d4556c,tick=0x80d4549c,frequency=0x80d454b0,
    dma_setup=0x702a02a0,dma_wait=0x702a0358,strcmp=0x70949820)
RANGES=tuple((CONFIG[key],size) for key,size in (('pack',100),('complete',140),('wait_receive',148),('wait_transmit',148),
    ('tx_count',36),('rx_count',36),('init',108),('command',204),('receive',248),('receive_dma',96),
    ('transmit',240),('transmit_dma',88),('clock',52),('version',86)))
DATA_RANGES=((0x709a84d4,8),(0x709a84dc,8))
SHADOW=0x80c11c4c
BOUND=10000


class Model(boot.Model):
    def version(self):
        text=self.c['rom_version'];result=0
        if text.startswith('v'):
            self.actions.append('compare:v1.1.03:'+text)
            if text=='v1.1.03':result=1
            else:
                self.actions.append('compare:v1.1.16:'+text);result=2 if text=='v1.1.16' else 0
        return result
    def run(self):
        if self.c['mode']!='version':return super().run()
        result=self.version()
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=None,context_hex=self.context.hex(),
            buffer_sha256=base.digest(self.buffer),tx_hex='',rx_bytes=0,mmio={str(k):v for k,v in sorted(self.regs.items())},
            clock_word=self.clock,clock_shadow=self.shadow)])


def contract(c):
    mode=c['mode'];data_modes=('receive','transmit','receive_dma','transmit_dma')
    entries=set(CONFIG)-{'tick','frequency','dma_setup','dma_wait','strcmp'}
    if mode not in entries|{'command_'+key for key in data_modes}:raise ValueError('main HAL entry')
    if not 0<=c['count']<=64 or c['alignment'] not in (0,1) or len(c['frame'])!=11:raise ValueError('bounded HAL payload')
    if not 0<=c['frame'][9]<=64 or any(not 0<=v<=boot.MASK for v in c['frame']):raise ValueError('bounded HAL frame')
    for key in ('ready','done','reset_reads','ticks'):
        if not c[key] or len(c[key])>32 or any(not 0<=x<=(0xffffffffffffffff if key=='ticks' else boot.MASK) for x in c[key]):raise ValueError('bounded I/O')
    if c['base'] not in (0x93240000,0x93200000) or not 0<=c['timeout']<=0xffffffff or not 0<=c['frequency']<=0xffffffff:raise ValueError('controller/time words')
    if not 0<=c['stop_chunks']<=8 or any(not -100<=c[k]<=100 for k in ('dma_setup_status','dma_wait_status')):raise ValueError('DMA/prefix bounds')
    if len(c['rom_version'])>24 or '\x00' in c['rom_version'] or not c['rom_version'].isascii():raise ValueError('ROM fixture string')
    return Model(c).run()


def native_vectors():
    cases=[]
    for original in boot.native_vectors()['cases']:
        if original['mode'] in ('feature_read','feature_write','cache_read','cache_write','write_enable'):continue
        c=original|dict(name='main_hal_'+original['name'],rom_version='v1.1.16');c.pop('expected');c['expected']=contract(c);cases.append(c)
    for name,text in (('version_old','v1.1.03'),('version_new','v1.1.16'),('version_other','v9.9.99'),('version_no_prefix','unknown'),('version_empty',''),('version_suffix','v1.1.16-extra')):
        c=cases[0]|dict(name='main_hal_'+name,mode='version',rom_version=text);c['expected']=contract(c);cases.append(c)
    return dict(schema=1,bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in DATA_RANGES},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in RANGES},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main QSPI init/command/FIFO/status/count/clock/revision and DMA wrappers execute over authored MMIO, 64-bit ticks/frequency, ROM string and DMA setup/wait/copy services.',
            'Reset self-clear, ready/completion/FIFO data and W1C behavior are authored. Zero-FIFO cases stop at a bounded non-progress prefix; no normal-return ABI is claimed for stopped cases.',
            'The standalone context and DMA pointers are fixtures. Actual DMA backend/cache coherency, peripheral timing, UID/BBT/media, persistence, restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main QSPI HAL: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
