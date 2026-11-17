#!/usr/bin/env python3
"""Actual NAND page policy and busy loops connected to actual BBT remapping."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_bbt as bbt
    from . import nand_page as page
else:
    import nand_bbt as bbt
    import nand_page as page

RANGES=page.RANGES+((0x80c279d8,64),(0x80c27a18,96))
TARGETS=tuple(a for a,n in RANGES)


class Model(page.Model):
    def map(self,value,block=False):
        self.actions.append(('native_remap_block:' if block else 'native_remap_page:')+str(value))
        state=bytes.fromhex(self.c['bbt_hex']);magic,count=struct.unpack_from('<II',state)
        ppb=struct.unpack_from('<I',state,148)[0];limit=struct.unpack_from('<I',state,160)[0]
        if magic!=bbt.MAGIC:return 0,value
        logical=value if block else value//ppb
        if not block:self.actions.append('native_remap_block:'+str(logical))
        mapped=logical
        for bad in struct.unpack_from('<'+'H'*count,state,12):
            if bad>mapped:break
            mapped=(mapped+1)&0xffffffff
        if mapped>=limit:return -1,value
        return 0,mapped if block else (value%ppb+ppb*mapped)&0xffffffff


def contract(c):
    state=bytes.fromhex(c['bbt_hex'])
    if len(state)!=164 or struct.unpack_from('<I',state,4)[0]>64 or struct.unpack_from('<I',state,148)[0]!=64:raise ValueError('bounded BBT mapping fixture')
    if not 0<=c['size']<=512 or not c['responses'] or not c['feature_status']:raise ValueError('bounded page fixture')
    return Model(c).run()


def native_vectors():
    cases=[];base=page.native_vectors()['cases'][0]
    def add(name,mode='read',bad=None,active=True,**changes):
        state=bbt.initial(dict(active=active,bad=[1,3,7] if bad is None else bad,blocks=1024,page_size=2048,ppb=64,reserve=16,primary=1023,backup=1022))
        c=base|dict(name=name,mode=mode,native_bbt=True,bbt_hex=state.hex())|changes
        c['expected']=contract(c);cases.append(c)
    for mode in ('read','write','copy_page','copy_oob','erase'):
        add(mode+'_mapped',mode);add(mode+'_inactive',mode,active=False)
    add('read_last_usable','read',page=65215);add('read_reserved_limit','read',page=65216)
    add('write_below_mapped_guard','write',page=319);add('write_at_mapped_guard','write',page=320)
    add('copy_dest_reserved_limit','copy_page',dest=65216)
    add('erase_below_mapped_guard','erase',block=4);add('erase_at_mapped_guard','erase',block=5)
    add('erase_reserved_limit','erase',block=1019)
    add('read_unsorted_table','read',bad=[7,1],page=64)
    add('read_duplicate_table','read',bad=[1,1],page=64)
    add('read_mapped_busy_timeout','read',responses=[1])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=300000:raise ValueError('native mismatch/bound')
    memory=bbt.image_memory(archive)
    return dict(boot_sha256=bbt.BOOT_HASH,vectors_sha256=bbt.digest(vectors.read_bytes()),validation_sha256=bbt.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':bbt.digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':bbt.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual page read/write/copy/copy-OOB/erase, both busy loops and BBT page/block remappers execute together over an authored immutable BBT.',
            'Command builders, feature/cache data, retry workaround and delays are supplied; actual QSPI/HAL and physical NAND effects remain unvalidated.',
            'Guard outcomes refer to mapped physical-address arithmetic within the fixture, not proof of physical write protection or a fitted-device partition map.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND page mapping: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
