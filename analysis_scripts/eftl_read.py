#!/usr/bin/env python3
"""Logical EFTL translation and page-read dispatch over supplied mappings/data."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH, digest, image_memory
else:
    from recovery_validator import BOOT_HASH, digest, image_memory

CONFIG = dict(map_read=0x80c0219a, wrapper=0x80c23252, page=0x80c0278a,
              generic=0x80c29532, fast=0x80c28a98, memset=0x80c2e014, logger=0x80c1cd7a)
RANGES = ((0x80c0219a,0xfe), (0x80c23252,0x4e), (0x80c0278a,0x26))
TARGETS = (0x80c0219a, 0x80c23252, 0x80c0278a)
LOGS = {0x80c34244:'unmapped_block', 0x80c3425c:'page_read_error'}


def contract(c):
    if not 0 <= c['size'] <= 512 or not 0 <= c['offset'] <= 0xffffffff or not 1 <= c['repeat'] <= 2: raise ValueError('bounded read probe')
    if not c['page_size'] or not c['pages_per_block'] or len(c['mapping']) != 8: raise ValueError('geometry/map fixture')
    output = bytearray(b'\xa5'*1024); actions=[]; rows=[]; calls=0
    def physical(ppn, column, count, out):
        nonlocal calls
        if c['fast']: ppn=(ppn+c['base_page'])&0xffffffff
        calls+=1; status=c['driver_error'] if calls==c['fail_at'] else c['driver_status']
        wrote=min(count,c['copy_limit']) if status>=0 else 0
        actions.append(f'physical:{"fast" if c["fast"] else "generic"}:{ppn}:{column}:{count}:{status}:{wrote}')
        output[out:out+wrote]=bytes((ppn*19+(column+i)*3)&255 for i in range(wrote))
        return status
    for _ in range(c['repeat']):
        if c['mode']=='page': returned=physical(c['page'], c['column'], c['size'],0)&0xffffffff
        else:
            todo=c['size']; address=c['offset']; returned=c['size']
            while todo:
                logical_page=address//c['page_size']; column=address%c['page_size']
                count=min(todo,c['page_size']-column); block=(logical_page//c['pages_per_block'])&0xffff
                if block>=8: raise ValueError('translation fixture backing bound')
                mapped=c['mapping'][block]; done=c['size']-todo
                if mapped==0xffff:
                    actions.append('log:unmapped_block'); output[done:done+todo]=b'\xff'*todo;returned=done;break
                ppn=(mapped*c['pages_per_block']+((logical_page%c['pages_per_block'])&0xffff))&0xffffffff
                if physical(ppn,column&0xffff,count&0xffff,done)<0:
                    actions.append('log:page_read_error');returned=0xffffffff;break
                todo-=count; address=(address+count)&0xffffffff
        rows.append(dict(returned=returned,buffer_sha256=digest(output)))
    return dict(actions=actions,rows=rows)


def native_vectors():
    cases=[]
    def add(name,mode='map_read',**changes):
        c=dict(name=name,mode=mode,repeat=1,mapping=[3,1,4,0xffff,2,0,5,6],pages_per_block=4,page_size=32,
               offset=4,size=16,fast=False,base_page=8,page=12,column=4,fail_at=0,driver_error=-9,
               driver_status=0,copy_limit=512)|changes
        c['expected']=contract(c);cases.append(c)
    add('map_single');add('map_unaligned',offset=29,size=8);add('map_multiblock',offset=120,size=48)
    add('map_three_pages',offset=17,size=96);add('map_zero',size=0)
    add('map_first_unmapped',mapping=[0xffff,1,4,0xffff,2,0,5,6])
    add('map_gap_after_prefix',mapping=[3,0xffff,4,0xffff,2,0,5,6],offset=120,size=48)
    add('map_all_unmapped',mapping=[0xffff]*8,offset=29,size=96)
    add('map_first_error',fail_at=1);add('map_second_error',offset=29,size=8,fail_at=2)
    add('map_positive_status',driver_status=7);add('map_short_supplied_data',copy_limit=3)
    add('map_fast',fast=True);add('map_fast_multiblock',fast=True,offset=120,size=48)
    add('map_fast_error',fast=True,fail_at=1);add('map_repeat',repeat=2)
    add('wrapper_read','wrapper',offset=120,size=48)
    add('wrapper_gap','wrapper',offset=380,size=16)
    add('page_generic','page');add('page_fast','page',fast=True)
    add('page_fast_base_wrap','page',fast=True,base_page=0xffffffff)
    add('page_backend_error','page',fail_at=1)
    add('map_logical_block_alias',offset=65536*4*32)
    add('map_column_u16',page_size=131072,offset=65536,size=16)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors(); execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Actual EFTL translation loop, ready read wrapper and page-dispatch adapter execute over authored geometry and eight u16 mapping slots.',
            'The two physical-page services supply status and procedural bytes; no NAND geometry, ECC, bus, DMA, physical data or persistence is established.',
            'The wrapper fixtures start EFTL ready; geometry discovery, mapping reconstruction, writes and full boot are outside this pass.',
            'Logical-index alias, column truncation and base wrapping use selected synthetic inputs; real geometry/caller constraints remain unknown.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect EFTL read: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
