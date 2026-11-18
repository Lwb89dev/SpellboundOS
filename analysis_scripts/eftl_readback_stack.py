#!/usr/bin/env python3
"""Original EFTL write readback and checksum through the full NAND/QSPI stack."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import eftl_mutation_stack as mutation
else:
    import eftl_mutation_stack as mutation

qspi=mutation.qspi
read=mutation.read
EXTRA_RANGES=((0x80c01a0a,80),)
RANGES=mutation.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)


def context(c):
    data=mutation.context(c);data[5]=int(c['write_readback']);return data


class Model(mutation.Model):
    def __init__(self,c):super().__init__(c);self.readback_index=-1;self.readback_at=0
    def write(self,offset,value,size=4):
        if offset==12 and value>>24==0x6b:
            self.readback_index+=1;self.readback_at=0
        return super().write(offset,value,size)
    def read(self,offset,size=4):
        if offset!=256 or self.regs[12]>>24!=0x6b:return super().read(offset,size)
        values=self.c['cache_payloads'];data=bytes.fromhex(values[min(self.readback_index,len(values)-1)])
        at=self.readback_at;self.readback_at+=size
        value=int.from_bytes(data[at:at+size],'little');self.rx+=size;self.actions.append(f'r:{offset}:{size}:{value}');return value
    def readback(self,ppn):
        saved=self.buffer;old_page=self.c['page'];self.buffer=bytearray(512);self.c['page']=ppn
        value=mutation.eftl.Model.oob(self);metadata=bytes(self.buffer[:4]);self.buffer=saved;self.c['page']=old_page
        return value,metadata
    def check_metadata(self,metadata):
        if metadata[2]!=69:return False
        self.actions.append('readback_checksum:'+metadata.hex())
        if sum(metadata[:3])&255!=metadata[3]:self.actions.append('log:checksum_error');return False
        return True
    def map_write(self,address,payload):
        if address%2048:self.actions.append('log:eftl_write_alignment');return -1
        if not payload:return 0
        logical_page=address//2048;logical,within=divmod(logical_page,64);pbn=self.mapping[logical]
        n=len(payload);self.actions.append('write_input:'+str(n)+':'+qspi.digest(payload));self.scratch[:n]=payload
        self.actions.append(f'write_fill:{n}:{2048-n}');self.scratch[n:2048]=b'\xff'*(2048-n)
        if within==0:
            pbn=self.find_block(pbn)
            if self.stopped:return None
        if pbn==65535:self.actions.append('log:eftl_write_failed');return -2
        metadata=struct.pack('<H',logical)+bytes([69,(logical%256+logical//256+69)&255])
        self.actions.append('write_fill:2048:64');self.scratch[2048:]=b'\xff'*64;self.scratch[2068:2072]=metadata
        if within<self.flags[pbn]>>1:self.actions.extend(('log:eftl_sequence_error','log:eftl_write_failed'));return -2
        self.flags[pbn]=(self.flags[pbn]&1)|(((within+1)*2)&255)
        value=self.program_page(pbn*64+within)
        if self.stopped:return None
        if value:raise ValueError('deferred returned program failure')
        if self.c['write_readback']:
            value,metadata=self.readback(pbn*64+within)
            if self.stopped:return None
            if value:raise ValueError('deferred readback I/O repair')
            if not self.check_metadata(metadata):
                self.actions.extend(('log:eftl_readback_check_failed','log:eftl_write_failed'));return -2
        if within==0:self.mapping[logical]=pbn
        return n
    def run(self):
        result=super().run();result['rows'][0]['eftl_context_hex']=context(self.c).hex();return result


def contract(c):
    if not c['native_readback'] or len(c['cache_payloads'])!=1 or len(bytes.fromhex(c['cache_payloads'][0]))!=64:raise ValueError('readback backing')
    mutation.contract(c|dict(native_readback=False))
    return Model(c).run()


def native_vectors():
    base=mutation.native_vectors()['cases'][0];cases=[]
    def add(name,variant='valid',**changes):
        c=base|dict(name=name,native_readback=True,write_readback=True,fast=True)|changes
        logical=(mutation.storage.selected(c)[1]['offset']+c['storage_offset'])//131072
        value=7 if variant=='wrong_logical' else logical
        tag=68 if variant=='bad_tag' else 69
        payload=bytearray(b'\xff'*64);payload[20:24]=struct.pack('<H',value)+bytes([tag,(value%256+value//256+tag)&255])
        if variant=='bad_crc':payload[23]^=1
        c['cache_payloads']=[payload.hex()];c['expected']=contract(c);cases.append(c)
    add('readback_fast');add('readback_irq',fast=False,irq_context=1)
    add('readback_private_stale',fast=False)
    add('readback_bad_tag',variant='bad_tag');add('readback_bad_crc',variant='bad_crc')
    add('readback_wrong_logical',variant='wrong_logical')
    add('readback_disabled',write_readback=False,fast=False)
    add('readback_allocate',storage_offset=0,mapping=[65535]*8,write_flags=[1,1,1,1,1,254,1,1])
    add('readback_allocate_bad_crc',variant='bad_crc',storage_offset=0,mapping=[65535]*8,write_flags=[1,1,1,1,1,254,1,1])
    add('readback_first_page',storage_offset=0)
    add('readback_rewrite',mutation_operation='rewrite')
    add('readback_erase',mutation_operation='erase',storage_offset=0)
    add('readback_erase_bad_crc',variant='bad_crc',mutation_operation='erase',storage_offset=0)
    add('readback_page_two',storage_offset=4096)
    add('readback_envbak',storage_name='envbak',mapping=[65535,65535,3,4,65535,65535,65535,65535])
    actions=cases[0]['expected']['actions'];cache=next(i for i,a in enumerate(actions) if a.startswith('w:12:4:') and int(a.split(':')[-1])>>24==0x6b)
    prefix=actions[:cache];ready=sum(a.startswith('r:24:4:') for a in prefix);ticks=sum(a.startswith('tick:') for a in prefix)
    add('readback_cache_assertion',ready=[3]*ready+[0],ticks=[0]*(ticks+1)+[1001])
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
            'Actual enabled write readback, page/OOB adapter/extraction and checksum connect original program/read/NAND/QSPI and selected bidirectional DMA.',
            'Cache FIFO bytes, ready state, mapping and peripheral/leaf services are authored; private RX does not simulate DMA movement and can copy stale TX data.',
            'Readback I/O-status repair, prefix relocation, physical correction/data/persistence, recovery and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect EFTL readback: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
