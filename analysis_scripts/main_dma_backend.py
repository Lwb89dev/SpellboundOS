#!/usr/bin/env python3
"""Original main DMA init/setup/cancel/count/wait over authored MMIO/cache services."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import dma_backend as boot
    from .main_nand_bus import base
else:
    import dma_backend as boot
    from main_nand_bus import base

TABLE=0x80c11738
CONFIG=dict(init=0x702a0038,setup_irq=0x702a01c0,cancel=0x702a0264,setup=0x702a02a0,
    remaining=0x702a0338,wait=0x702a0358,tick=0x80d45464,prepare=0x7029fea0,finish=0x7029ff04,
    callback_a=boot.CONFIG['callback_a'],callback_b=boot.CONFIG['callback_b'])
RANGES=((CONFIG['init'],388),(CONFIG['setup_irq'],162),(CONFIG['cancel'],58),(CONFIG['setup'],150),(CONFIG['remaining'],28),(CONFIG['wait'],194))
BOUND=10000


class Model(boot.Model):
    def __init__(self,c):super().__init__(c);self.registry.extend([0]*7)
    def fatal(self):
        # Main init falls through to bank index 28 for unrecognized bases.
        self.registry[28+self.c['channel']]=self.address;return 0


def contract(c):
    if c['mode'] not in ('init','setup','setup_irq','cancel','remaining','wait','init_setup_wait'):raise ValueError('main DMA entry')
    if c['slots']!=[c['channel']] or not 0<=c['channel']<=7 or c['channel']==7 and c['mode']!='init':raise ValueError('main DMA descriptor backing')
    if not 0<=c['size']<=64 or c['base'] not in (*boot.BANKS,0x93100000):raise ValueError('main DMA range')
    if c['base']==0x93100000 and c['mode']!='init':raise ValueError('unknown base scope')
    if not 0<=c['timeout']<=0xffffffff or not 0<=c['tracked_size']<=64:raise ValueError('main DMA words')
    for key in ('status_a','status_b','ticks'):
        if not c[key] or len(c[key])>32 or any(not 0<=v<=(0xffffffffffffffff if key=='ticks' else 0xffffffff) for v in c[key]):raise ValueError('main DMA I/O bounds')
    return Model(c).run()


def native_vectors():
    cases=[]
    for original in boot.native_vectors()['cases']:
        if original['mode'] in ('irq','init_setup_irq'):continue
        c=original|dict(name='main_dma_'+original['name']);c.pop('expected');c['expected']=contract(c);cases.append(c)
    return dict(schema=1,bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in RANGES},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main DMA init/setup variants/cancel/count/wait execute over authored descriptors, MMIO/status/ticks and supplied cache services. Main IRQ dispatch is outside this scope.',
            'An unrecognized-base init writes fallback slot 28+channel in explicitly authored 35-slot backing; this does not establish a valid fifth hardware bank or the production allocation boundary.',
            'Status A/B identify software branches, not verified hardware meanings. No physical data movement, IRQ delivery, cache coherency, persistence, restoration or standalone boot is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main DMA: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
