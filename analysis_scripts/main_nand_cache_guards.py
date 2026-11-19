#!/usr/bin/env python3
"""Actual original high-half cache guards inside full main NAND RX/TX DMA paths."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_dma_irq as irq
    from . import main_nand_async as read
    from . import main_nand_program as program
else:
    import main_dma_irq as irq
    import main_nand_async as read
    import main_nand_program as program

base=read.base
BOUND=read.BOUND
EXTRA=irq.EXTRA[1:]


def module(scope):
    if scope=='read':return read
    if scope=='program':return program
    raise ValueError('NAND cache guard scope')
def ranges(scope):return module(scope).ranges()+EXTRA
def data_ranges(scope):return module(scope).data_ranges()


def contract(c,scope):
    if not c['native_main_cache_guards']:raise ValueError('actual cache guard entry')
    selected=module(scope)
    return selected.contract(c,'read') if scope=='read' else selected.contract(c)


def native_vectors(scope='read'):
    original=read.native_vectors('read') if scope=='read' else module(scope).native_vectors();cases=[]
    for c in original['cases']:
        c=c|dict(name='main_cache_'+scope+'_'+c['name'],native_main_cache_guards=True)
        c['expected']=contract(c,scope);cases.append(c)
    return original|dict(cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if read.repair.read.aux.inventory(mem)!=json.loads(read.repair.read.aux.FACTS.read_bytes()) or mem.read(read.GUARD,1)!=b'\1':raise ValueError('original main facts differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges(scope)},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges(scope)},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges(scope)},native_validation=report,
        native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main NAND mode-zero read/program, full BBT/root, initialized original DMA records/setup/wait now execute original cache prepare/finish signed guards for actual selected high-half private-buffer or zero arguments.',
            'Those selected cache calls return zero before IRQ-state services, cache CSRs or fences. This is software guard behavior, not proof of physical cacheability, maintenance or coherency. Positive-address CSR loops remain outside this scope.',
            'MMIO/status/ticks/source/FIFO/bounce inputs are authored. Copy/pin/power/RTOS/BSP/heap/PM remain supplied. No DMA data movement, live IRQ/scheduling, physical persistence, safe restoration or standalone boot is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('read','program'),default='read')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect original main NAND cache guards: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
