#!/usr/bin/env python3
"""Original main DMA IRQ dispatch and actual high-half cache-range guards."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_dma_backend as dma
else:
    import main_dma_backend as dma

base=dma.base
IRQ=0x702a041c
EXTRA=((IRQ,250),(dma.CONFIG['prepare'],100),(dma.CONFIG['finish'],100))
RANGES=dma.RANGES+EXTRA
BOUND=dma.BOUND


class Model(dma.Model):
    def __init__(self,c):
        super().__init__(c)
        if c['base'] not in dma.boot.BANKS and c['registered']:
            for i,ch in enumerate(self.slots):self.registry[28+ch]=self.address+i*256
    def irq(self):
        c=self.c;a=self.read(4);b=self.read(12);bank=dma.boot.BANKS.get(c['base'],28)
        self.write(8,a);self.write(16,b)
        for ch in range(7):
            if not (a|b)&(1<<ch):continue
            pointer=self.registry[bank+ch]
            if not pointer:raise ValueError('active IRQ slot needs a supplied descriptor')
            i=(pointer-self.address)//256;at=self.word(36,i)*32+0x100
            if a&(1<<ch):
                if not self.word(40,i):self.write(at,self.read(at)&~1)
                self.cache(True,i=i);self.put(60,0,i);self.put(64,0,i)
                if c['callback_a']:self.actions.append(f'callback_a:{self.word(36,i)}:0:0')
            if b&(1<<ch):
                self.write(at,self.read(at)&~1)
                if c['callback_b']:self.actions.append(f'callback_b:{self.word(36,i)}:{self.word(60,i)}:{self.word(64,i)}')
        return None


def contract(c,scope='irq'):
    if scope not in ('irq','cache-guards') or c['native_cache_guards']!=(scope=='cache-guards'):raise ValueError('main DMA IRQ/cache scope')
    modes=('irq','init_setup_irq') if scope=='irq' else ('irq','init_setup_irq','init','setup','setup_irq','cancel','remaining','wait','init_setup_wait')
    if c['mode'] not in modes or c['base'] not in (*dma.boot.BANKS,0x93100000):raise ValueError('main DMA entry/base')
    if not c['slots'] or len(c['slots'])>2 or len(set(c['slots']))!=len(c['slots']) or any(not 0<=ch<=7 for ch in c['slots']):raise ValueError('descriptor slots')
    if c['mode'] not in ('irq','init_setup_irq'):
        dma.contract(c)
    else:
        if not 0<=c['channel']<=6 or any(ch>6 for ch in c['slots']):raise ValueError('active channel bound')
        if c['mode']=='init_setup_irq' and c['slots']!=[c['channel']]:raise ValueError('one initialized IRQ descriptor')
        if c['mode']=='init_setup_irq' and c['base']==0x92000000 and c['channel']>3:raise ValueError('restricted init channel')
        active=(c['irq_a']|c['irq_b'])&127
        if active&~sum(1<<ch for ch in c['slots']) or active and not (c['registered'] or c['mode']=='init_setup_irq'):raise ValueError('unpopulated active IRQ slot')
    if not 0<=c['size']<=64 or not 0<=c['tracked_size']<=64 or c['tracked_address'] not in (0,dma.boot.SOURCE,dma.boot.DEST):raise ValueError('cache backing bounds')
    if any(not 0<=c[k]<=0xffffffff for k in ('irq_a','irq_b','linked','timeout')):raise ValueError('DMA input words')
    for key in ('status_a','status_b','ticks'):
        if not c[key] or len(c[key])>32 or any(not 0<=v<=(0xffffffffffffffff if key=='ticks' else 0xffffffff) for v in c[key]):raise ValueError('DMA I/O bounds')
    if c['context_hex']!=[dma.boot.context(c,ch).hex() for ch in c['slots']]:raise ValueError('descriptor bytes differ from contract')
    return Model(c).run()


def native_vectors(scope='irq'):
    cases=[]
    def add(c,name=None,**changes):
        c=c|changes|dict(name='main_irq_'+(name or c['name']),native_cache_guards=scope=='cache-guards')
        c['context_hex']=[dma.boot.context(c,ch).hex() for ch in c['slots']];c.pop('expected',None);c['expected']=contract(c,scope);cases.append(c)
    originals=dma.boot.native_vectors()['cases'];irqs={c['name']:c for c in originals if c['mode'] in ('irq','init_setup_irq')}
    for c in irqs.values():add(c)
    initial=irqs['irq_primary']
    add(initial,'linked_both',linked=1,irq_b=32);add(initial,'linked_alternate',linked=1,irq_a=0,irq_b=32)
    add(initial,'no_primary_callback',callback_a=False,irq_b=32);add(initial,'no_alternate_callback',callback_b=False,irq_b=32)
    add(initial,'fallback_both',base=0x93100000,irq_b=32)
    add(initial,'fallback_two',base=0x93100000,channel=0,slots=[0,6],irq_a=65,irq_b=64)
    add(irqs['connected_init_setup_irq'],'fallback_init_setup_irq',base=0x93100000)
    add(initial,'restricted_bank_channel_six',base=0x92000000,channel=6,slots=[6],irq_a=64)
    add(initial,'unwalked_high_bits',irq_a=0x80000080,irq_b=0x40000000,registered=False)
    add(initial,'reverse_descriptor_order',channel=6,slots=[6,0],irq_a=65,irq_b=1)
    add(initial,'zero_tracking',tracked_address=0,tracked_size=0)
    add(initial,'linked_nonboolean',linked=0x80000000)
    if scope=='cache-guards':
        for c in dma.native_vectors()['cases']:add(c,'guard_'+c['name'].removeprefix('main_dma_'))
    elif scope!='irq':raise ValueError('DMA scope')
    return dict(schema=1,bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in RANGES},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main IRQ handler executes by ordinary harness call over authored pending/MMIO/descriptor/registry state. Unknown bases use slots 28..34 over explicit guarded backing, without proving a fifth hardware bank or production allocation extent.',
            'Callbacks are supplied. IRQ scope supplies cache services; cache-guards scope executes actual prepare/finish bodies only for signed-nonpositive high-half or zero addresses. Positive-address CSR loops, IRQ entry/delivery/scheduling/nesting and real coherency remain open.',
            'IRQ return values are unspecified; normal stack/saved-register preservation is checked. No physical DMA payload movement, peripheral completion semantics, persistence, restoration or standalone boot is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('irq','cache-guards'),default='irq')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main DMA IRQ/cache guards: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
