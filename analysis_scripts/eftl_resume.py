#!/usr/bin/env python3
"""EFTL mapping reconstruction over authored bad-block/OOB services."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH, digest, image_memory
else:
    from recovery_validator import BOOT_HASH, digest, image_memory

CONTEXT=0x81300000
FLAGS=0x81301000
MAP=0x81302000
CONFIG=dict(resume=0x80c01d8a, checksum=0x80c01a0a, bad=0x80c028d8,
            erase=0x80c0282a, oob=0x80c027b0, logger=0x80c1cd7a)
RANGES=((0x80c01d8a,0x160),(0x80c01a0a,0x50))
TARGETS=(0x80c01d8a,0x80c01a0a)
LOGS={0x80c340b0:'bad_block',0x80c340d0:'oob_read_error',0x80c33f68:'checksum_error'}


def record(block):
    data=bytearray(struct.pack('<H',block['logical'])+bytes((block['tag'],0)))
    data[3]=(sum(data[:3])+int(block['corrupt']))&255
    return bytes(data)


def contract(c):
    if not 0<=c['block_count']<=8 or len(c['blocks'])!=8 or len(c['mapping'])!=8 or len(c['flags'])!=8 or not 1<=c['repeat']<=2:raise ValueError('bounded resume fixture')
    flags=bytearray(c['flags']);mapping=list(c['mapping']);free,used,reserved=c['counters'];marker=c['marker'];actions=[];rows=[]
    def checksum(data):
        good=data[3]==sum(data[:3])&255
        if not good:actions.append('log:checksum_error')
        return good
    for _ in range(c['repeat']):
        if c['mode']=='checksum':returned=int(checksum(record(c['blocks'][0])))
        else:
            returned=None
            for i,block in enumerate(c['blocks'][:c['block_count']]):
                flags[i]|=0xfe;result=block['bad'];actions.append(f'bad:{i}:{result}')
                if result:
                    actions.append('log:bad_block')
                    if result<1 or c['repair']:
                        result=block['erase'];actions.append(f'erase:{i}:{result}')
                if result:
                    flags[i]|=1;reserved=(reserved+1)&0xffff;continue
                data=record(block);status=block['read'];actions.append(f'oob:{(i*c["pages_per_block"])&0xffffffff}:{status}:{data.hex()}')
                if status:
                    actions.append('log:oob_read_error');returned=0xffffffff;break
                if data[2]==0x45 and checksum(data):
                    logical=struct.unpack_from('<H',data)[0]
                    if logical>=len(mapping):raise ValueError('logical mapping backing bound')
                    if mapping[logical]==0xffff:
                        mapping[logical]=i;used=(used+1)&0xffff;flags[i]=(flags[i]&1)|((c['pages_per_block']<<1)&255)
                else:free=(free+1)&0xffff
            if returned is None:
                returned=0 if c['repair'] or free or not reserved else 1
                if returned==0:marker=0xa5
        context=bytearray(64);context[4]=marker
        for offset,value in ((8,c['pages_per_block']),(16,c['block_count']),(44,FLAGS),(48,MAP)):
            struct.pack_into('<I',context,offset,value)
        struct.pack_into('<HHH',context,56,free,used,reserved)
        rows.append(dict(returned=returned,marker=marker,free=free,used=used,reserved=reserved,
            flags=flags.hex(),mapping=list(mapping),context_sha256=digest(context)))
    return dict(actions=actions,rows=rows)


def native_vectors():
    cases=[]
    def block(logical=0,tag=0x45,**changes):return dict(logical=logical,tag=tag,corrupt=False,bad=0,erase=0,read=0)|changes
    def add(name,mode='resume',**changes):
        c=dict(name=name,mode=mode,repeat=1,block_count=4,pages_per_block=4,repair=0,marker=0,
            flags=[0]*8,mapping=[0xffff]*8,counters=[0,0,0],
            blocks=[block(2),block(0xffff,tag=255),block(0),block(1,bad=1)]+[block(0xffff,tag=255) for _ in range(4)])|changes
        c['expected']=contract(c);cases.append(c)
    def only(b):return [b]+[block(0xffff,tag=255) for _ in range(7)]
    add('resume_mixed');add('resume_repeat',repeat=2)
    add('resume_empty_count',block_count=0)
    add('resume_all_unmapped',blocks=[block(0xffff,tag=255) for _ in range(8)])
    add('resume_all_reserved_retry',blocks=[block(i,bad=1) for i in range(8)])
    add('resume_all_reserved_repair',repair=1,blocks=[block(i,bad=1,erase=-9) for i in range(8)])
    add('resume_repair_positive_bad',repair=1,block_count=1,blocks=only(block(1,bad=1)))
    add('resume_negative_bad_erased',block_count=1,blocks=only(block(1,bad=-9)))
    add('resume_negative_bad_erase_error',block_count=1,blocks=only(block(1,bad=-9,erase=-1)))
    add('resume_negative_bad_positive_erase',block_count=1,blocks=only(block(1,bad=-9,erase=1)))
    add('resume_first_oob_error',block_count=1,blocks=only(block(1,read=-9)))
    add('resume_positive_oob_error',block_count=1,blocks=only(block(1,read=1)))
    add('resume_later_oob_error',blocks=[block(2),block(1,read=-1)]+[block(0xffff,tag=255) for _ in range(6)])
    add('resume_bad_checksum',block_count=1,blocks=only(block(1,corrupt=True)))
    add('resume_wrong_tag',block_count=1,blocks=only(block(1,tag=0x44)))
    add('resume_wrong_tag_bad_checksum',block_count=1,blocks=only(block(1,tag=0x44,corrupt=True)))
    add('resume_duplicate_mapping',block_count=2,blocks=[block(2),block(2)]+[block(0xffff,tag=255) for _ in range(6)])
    add('resume_existing_mapping',block_count=1,mapping=[0xffff,7]+[0xffff]*6,blocks=only(block(1)))
    add('resume_logical_beyond_count',block_count=1,blocks=only(block(7)))
    add('resume_preserve_low_flag',block_count=1,flags=[1]+[0]*7,blocks=only(block(1)))
    add('resume_used_counter_wrap',block_count=1,counters=[0,65535,0],blocks=only(block(1)))
    add('resume_free_counter_wrap',block_count=1,counters=[65535,0,1],blocks=only(block(0xffff,tag=255)))
    add('resume_reserved_counter_wrap',block_count=1,counters=[0,0,65535],blocks=only(block(1,bad=1)))
    add('resume_page_count_flag_wrap',block_count=1,pages_per_block=128,blocks=only(block(1)))
    add('checksum_valid','checksum',blocks=only(block(0x80ff)))
    add('checksum_invalid','checksum',blocks=only(block(0x80ff,corrupt=True)))
    add('checksum_other_tag','checksum',blocks=only(block(3,tag=0x44)))
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
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Actual EFTL resume/checksum code executes over authored bad-block, erase and first-page OOB services.',
            'Geometry, translation/flag backing, OOB records and counters are synthetic; no physical NAND, ECC, bus or erase is accessed.',
            'Direct repeat/malformed logical-index/counter-wrap fixtures do not establish caller invariants or observed hardware failures.',
            'Full initializer allocation/retry, actual geometry discovery, NAND/OOB transport, other mapping repair/write paths and boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect EFTL resume: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
