#!/usr/bin/env python3
"""Successful bounded EFTL prefix copying and recursive relocation through QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import eftl_repair_stack as repair
else:
    import eftl_repair_stack as repair

qspi=repair.qspi
read=repair.read
mutation=repair.mutation
RANGES=repair.RANGES
TARGETS=repair.TARGETS
HEAP=0x81310000


class Model(repair.Model):
    def __init__(self,c):super().__init__(c);self.heap={};self.live=set();self.frees=0;self.depth=0
    def allocate(self):
        self.allocations+=1
        if self.allocations==self.c['prefix_fail_alloc_at']:
            self.actions.append('repair_alloc:2112:0');self.stopped=dict(kind='assertion',owner=0x80c3436c,line=0xa3);return 0
        at=HEAP+(self.allocations-1)*4096;self.heap[at]=bytearray(b'\xa5'*2112);self.live.add(at)
        self.actions.append('repair_alloc:2112:'+str(at));return at
    def save(self,at):
        self.heap[at][:]=self.scratch;self.actions.append(f'repair_save:{at}:'+qspi.digest(self.scratch))
    def restore_free(self,at):
        self.scratch[:]=self.heap[at];self.actions.append(f'repair_restore:{at}:'+qspi.digest(self.scratch))
        self.live.remove(at);self.frees+=1;self.actions.append('repair_free:'+str(at))
    def prefix_read(self,ppn):
        saved=self.buffer;self.buffer=self.scratch
        value=self.adapter(ppn,0,2112);self.scratch[:]=self.buffer[:2112];self.buffer=saved
        return value
    def repair(self,logical,old,prefix):
        self.depth+=1
        if self.depth>3:raise ValueError('bounded repair recursion')
        self.flags[old]|=1;new=self.find_block(65535)
        if self.stopped:return None
        result=-1 if new==65535 else new;at=0
        if new!=65535 and prefix:
            at=self.allocate()
            if self.stopped:return None
            self.save(at)
            for i in range(prefix):
                value=self.prefix_read(old*64+i)
                if self.stopped:return None
                if value<0:
                    result=-2;self.actions.append('log:repair_read_failed');break
                got=struct.unpack_from('<H',self.scratch,2068)[0]
                if got!=logical:
                    result=-3;self.actions.append('log:repair_logical_mismatch');break
                value=self.program_page(new*64+i)
                if self.stopped:return None
                if value<0:
                    self.restore_free(at);self.actions.append('log:repair_copy_write_failed');self.mark(new)
                    if self.stopped:return None
                    self.flags[new]=1;result=self.repair(logical,old,prefix);self.depth-=1;return result
            else:
                self.flags[new]=(self.flags[new]&1)|((prefix<<1)&255);self.mapping[logical]=new
        self.actions.append('log:eftl_retire_old');self.mark(old)
        if self.stopped:return None
        self.flags[old]=1
        if at:self.restore_free(at)
        self.depth-=1;return result
    def run(self):
        result=super().run();row=result['rows'][0]
        row.update(prefix_live_heap=sorted(self.live),prefix_frees=self.frees,
            prefix_heap_sha256={str(k):qspi.digest(v) for k,v in sorted(self.heap.items())})
        return result


def page_bytes(index,variant='valid'):
    data=bytearray((0x31+index*17+i*5)&255 for i in range(2048))+bytearray(b'\xff'*64)
    logical=7 if variant=='wrong_logical' else 0;tag=68 if variant=='bad_tag_crc' else 69
    data[2068:2072]=struct.pack('<H',logical)+bytes([tag,(logical+tag)&255])
    if variant=='bad_tag_crc':data[2071]^=1
    return bytes(data)


def contract(c):
    if not c['native_prefix'] or c['repair_prefix'] not in (1,2) or c['storage_offset'] not in (2048,4096):raise ValueError('prefix backing')
    if c['write_readback'] or c['mutation_operation'] not in ('program','rewrite'):raise ValueError('selected prefix entry')
    if not 0<=c['prefix_fail_alloc_at']<=3 or sum(v==254 for v in c['write_flags'])>2:raise ValueError('bounded prefix allocation')
    if not 1<=len(c['cache_payloads'])<=6 or any(len(bytes.fromhex(v))!=2112 for v in c['cache_payloads']):raise ValueError('full-page FIFO backing')
    if len(c['responses'])>8 or any(v not in (0,8,32) for v in c['responses']):raise ValueError('prefix statuses')
    safe=bytearray(b'\xff'*64);safe[20:24]=bytes([0,0,69,69])
    repair.contract(c|dict(native_prefix=False,repair_prefix=1,storage_offset=2048,repair_alloc_fail=True,
        responses=[0],write_readback=False,cache_payloads=[safe.hex()]))
    return Model(c).run()


def native_vectors():
    base=repair.native_vectors()['cases'][0];cases=[]
    def add(name,prefix=1,variants=None,**changes):
        flags=[1]*8;flags[3]=0;flags[5]=254
        c=base|dict(name=name,native_prefix=True,repair_prefix=prefix,repair_entry=False,repair_alloc_fail=False,
            prefix_fail_alloc_at=0,storage_offset=prefix*2048,write_flags=flags,responses=[8,0],write_readback=False)|changes
        c['cache_payloads']=[page_bytes(i,variant).hex() for i,variant in enumerate(variants or ['valid']*prefix)]
        c['expected']=contract(c);cases.append(c)
    add('prefix_one');add('prefix_two',prefix=2)
    add('prefix_generic',fast=False);add('prefix_irq',fast=False,irq_context=1)
    add('prefix_direct',repair_entry=True,responses=[0]);add('prefix_direct_two',prefix=2,repair_entry=True,responses=[0])
    add('prefix_bad_tag_crc_accepted',variants=['bad_tag_crc'])
    add('prefix_wrong_logical',variants=['wrong_logical'])
    add('prefix_direct_wrong_logical',repair_entry=True,responses=[0],variants=['wrong_logical'])
    add('prefix_read_error',responses=[8,0,32,0])
    add('prefix_second_read_error',prefix=2,responses=[8,0,0,0,32,0])
    add('prefix_recursive',responses=[8,0,0,8,0],write_flags=[1,1,1,0,1,254,254,1])
    add('prefix_recursive_no_free',responses=[8,0,0,8,0])
    add('prefix_direct_recursive',repair_entry=True,responses=[0,0,8,0],write_flags=[1,1,1,0,1,254,254,1])
    add('prefix_alloc_failure',prefix_fail_alloc_at=1)
    add('prefix_recursive_alloc_failure',prefix_fail_alloc_at=2,responses=[8,0,0,8,0],write_flags=[1,1,1,0,1,254,254,1])
    actions=cases[0]['expected']['actions'];cache=next(i for i,a in enumerate(actions) if a.startswith('w:12:4:') and int(a.split(':')[-1])>>24==0x6b)
    before=actions[:cache];ready=sum(a.startswith('r:24:4:') for a in before);ticks=sum(a.startswith('tick:') for a in before)
    add('prefix_cache_assertion',ready=[3]*ready+[0],ticks=[0]*(ticks+1)+[1001])
    add('prefix_rewrite',mutation_operation='rewrite')
    add('prefix_second_logical_mismatch',prefix=2,variants=['valid','wrong_logical'])
    add('prefix_two_generic',prefix=2,fast=False)
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in mutation.storage.DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original one/two-page prefix migration, heap save/restore/free, publication and selected recursive relocation execute through full NAND/QSPI and DMA control.',
            'Heap backing/lifetimes at supplied allocator/copy/free boundaries, ready map/flags, cache FIFO pages, RTOS/peripheral effects and other leaf services are authored.',
            'DMA movement is not simulated; generic RX can copy stale TX data. Physical source-page integrity, persistent atomicity, larger migrations/concurrency/recovery/boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect EFTL prefix copying: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
