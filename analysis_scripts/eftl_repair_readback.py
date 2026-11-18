#!/usr/bin/env python3
"""Combined original EFTL prefix repair and enabled write readback through QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import eftl_prefix_stack as prefix
else:
    import eftl_prefix_stack as prefix

RANGES=prefix.RANGES
TARGETS=prefix.TARGETS


def metadata(variant='valid'):
    b=bytearray(b'\xff'*64);logical=7 if variant=='wrong_logical' else 0
    tag=68 if variant=='bad_tag' else 69
    b[20:24]=struct.pack('<H',logical)+bytes([tag,(logical+tag)&255])
    if variant=='bad_crc':b[23]^=1
    return bytes(b)


def contract(c):
    if not c['write_readback'] or c['repair_entry']:raise ValueError('combined upper write entry')
    if not 1<=len(c['cache_payloads'])<=8 or any(len(bytes.fromhex(v)) not in (64,2112) for v in c['cache_payloads']):raise ValueError('mixed page/OOB backing')
    if not c['responses'] or len(c['responses'])>24 or any(v not in (0,8,32) for v in c['responses']):raise ValueError('bounded combined statuses')
    prefix.contract(c|dict(write_readback=False,responses=[8,0],prefix_fail_alloc_at=0,
        cache_payloads=[prefix.page_bytes(i).hex() for i in range(c['repair_prefix'])]))
    return prefix.Model(c).run()


def native_vectors():
    base=prefix.native_vectors()['cases'][0];cases=[]
    two=[1,1,1,0,1,254,254,1]
    def add(name,variant='valid',pages=1,payloads=None,**changes):
        c=base|dict(name=name,write_readback=True,repair_prefix=pages,storage_offset=pages*2048)|changes
        c['cache_payloads']=[v.hex() for v in (payloads or [*[prefix.page_bytes(i) for i in range(pages)],metadata(variant)])]
        c['expected']=contract(c);cases.append(c)
    add('combined_program_repair')
    add('combined_bad_tag',variant='bad_tag');add('combined_bad_crc',variant='bad_crc')
    add('combined_wrong_logical',variant='wrong_logical')
    add('combined_two_pages',pages=2)
    add('combined_generic',fast=False);add('combined_irq',fast=False,irq_context=1)
    add('combined_rewrite',mutation_operation='rewrite')
    for variant in ('valid','wrong_logical','bad_tag'):
        add('combined_initial_io_'+variant,responses=[0,32,0],payloads=[metadata(variant),prefix.page_bytes(0),metadata()])
    again=[8,0,0,0,0,0,0,0,32,0]
    add('combined_retry_io_no_free',responses=again)
    add('combined_retry_io_relocate',responses=again,write_flags=two,
        payloads=[prefix.page_bytes(0),metadata('wrong_logical'),prefix.page_bytes(1),metadata('wrong_logical')])
    add('combined_retry_program_no_free',responses=[8,0,0,0,0,0,0,8,0])
    add('combined_retry_program_relocate',responses=[8,0,0,0,0,0,0,8,0],write_flags=two,
        payloads=[prefix.page_bytes(0),prefix.page_bytes(1),metadata()])
    add('combined_recursive_prefix',responses=[8,0,0,8,0],write_flags=two,
        payloads=[prefix.page_bytes(0),prefix.page_bytes(1),metadata()])
    add('combined_alloc_failure',prefix_fail_alloc_at=1)
    add('combined_prefix_wrong_logical',payloads=[prefix.page_bytes(0,'wrong_logical'),metadata()])
    add('combined_second_prefix_wrong_logical',pages=2,
        payloads=[prefix.page_bytes(0),prefix.page_bytes(1,'wrong_logical'),metadata()])
    actions=cases[0]['expected']['actions'];last=max(i for i,a in enumerate(actions) if a.startswith('w:12:4:') and int(a.split(':')[-1])>>24==0x6b)
    before=actions[:last];ready=sum(a.startswith('r:24:4:') for a in before);ticks=sum(a.startswith('tick:') for a in before)
    add('combined_final_readback_assertion',ready=[3]*ready+[0],ticks=[0]*(ticks+1)+[1001])
    return dict(schema=1,bound_per_case=prefix.read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=prefix.qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=prefix.read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=prefix.read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=prefix.qspi.BOOT_HASH,vectors_sha256=prefix.qspi.digest(vectors.read_bytes()),validation_sha256=prefix.qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':prefix.qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':prefix.qspi.digest(memory.read(a,n)) for a,n in prefix.mutation.storage.DATA_RANGES},
        export_sha256={f'{a:08x}.c':prefix.qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original combined upper program/rewrite, prefix repair, enabled readback and selected repeated/recursive relocation execute through NAND/QSPI.',
            'FIFO page/OOB bytes, statuses, ready mappings/flags, guarded heap/copy/free and peripheral/RTOS leaf services are authored; DMA movement is not simulated.',
            'RAM publication and scratch reuse do not establish physical media contents, persistent atomicity, full concurrency/recovery or standalone boot.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect combined EFTL repair/readback: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
