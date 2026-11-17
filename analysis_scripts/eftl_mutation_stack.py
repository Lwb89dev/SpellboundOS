#!/usr/bin/env python3
"""Bounded original EFTL page program/logical erase/rewrite through NAND/QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import storage_eftl_stack as storage
else:
    import storage_eftl_stack as storage

eftl=storage.eftl
read=storage.read
qspi=storage.qspi
FLAGS=0x8130c000
EXTRA_RANGES=((0x80c01eea,688),(0x80c01a5a,276),(0x80c026a6,228),(0x80c02806,36),
    (0x80c0282a,48),(0x80c29576,68),(0x80c275ee,32),(0x80c27c20,80),
    (0x80c232a0,150),(0x80c23336,78),(0x80c23384,4),(0x80c24502,188),
    (0x80c245be,148),(0x80c24652,204))
RANGES=storage.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)


def context(c):
    data=eftl.context(c);struct.pack_into('<II',data,16,8,0);struct.pack_into('<I',data,44,FLAGS)
    flags=c['write_flags'];free=sum(v==254 for v in flags);reserved=sum(v&1 for v in flags)
    struct.pack_into('<3H',data,56,free,8-free-reserved,reserved);return data
def backend_bytes(c):
    data=bytearray(storage.backend_bytes(c))
    if c['rewrite_missing']:struct.pack_into('<I',data,56,0)
    return data


class Model(storage.Model):
    def __init__(self,c):
        super().__init__(c);self.flags=bytearray(c['write_flags']);self.mapping=list(c['mapping']);self.bounce=bytearray(b'\xa5'*2112)
    def erase_block(self,pbn):
        c=self.c
        if not c['fast']:return self.partition_ioctl(12,bytearray(struct.pack('<I',pbn)))
        block=self.map(pbn+c['fast_base']//64,True)
        value=-151 if block is None else (-1 if block>=1024 else 0)
        if not value and c['guard'] and block<8:self.actions.append('log:block_guard');value=-250
        if not value:
            if self.bus(6)[0] or self.bus(0xd8,block*64,3)[0]:return None
            status=self.poll(4000)
            if status is None:return None
            value=-104 if status&4 else 0
        if value:self.actions.append('log:erase_result')
        return value
    def find_block(self,pbn):
        if pbn!=65535 and self.flags[pbn]&1:self.actions.append('log:eftl_block_bad')
        if pbn==65535 or self.flags[pbn]&1:
            pbn=next((i for i,v in enumerate(self.flags) if v==254),65535)
        if pbn==65535:self.actions.append('log:eftl_map_full');return 65535
        status=self.erase_block(pbn)
        if self.stopped:return None
        if status:raise ValueError('erase failure enters deferred bad-mark/reallocation path')
        self.flags[pbn]&=1;return pbn
    def nand_program(self,page,blocking):
        c=self.c;page=self.map(page)
        if page is None:self.actions.append('log:page_result');return -150
        if c['guard'] and page<512:self.actions.extend(('log:page_guard','log:page_result'));return -250
        if self.bus(6)[0]:return None
        column=4096 if c['plane'] and page&64 else 0
        original=self.buffer;self.buffer=self.scratch
        status,_=self.bus(0x32,column,2,2112,0,3,True,not blocking)
        self.buffer=original
        if status:return None
        if self.bus(0x10,page,3)[0]:return None
        status=self.poll(2000)
        if status is None:return None
        if status&8:raise ValueError('program failure enters deferred relocation path')
        return 0
    def program_page(self,ppn):
        c=self.c
        if c['fast']:return self.nand_program((ppn+c['fast_base'])&0xffffffff,True)
        absolute=(ppn+c['partition_base']//2048)&0xffffffff
        self.actions.append(f'driver_program:{absolute}:0:2112');self.dispatches+=1
        direct=self.execution_context()
        if not direct and not self.mutex():return None
        value=self.nand_program(absolute,direct)
        if not self.stopped and not direct:self.mutex(True)
        return value
    def map_write(self,address,payload):
        if address%2048:self.actions.append('log:eftl_write_alignment');return -1
        if not payload:return 0
        logical_page=address//2048;logical,within=divmod(logical_page,64);pbn=self.mapping[logical]
        self.actions.append('write_input:'+str(len(payload))+':'+qspi.digest(payload));self.scratch[:len(payload)]=payload
        n=len(payload);self.actions.append(f'write_fill:{n}:{2048-n}');self.scratch[n:2048]=b'\xff'*(2048-n)
        if within==0:
            pbn=self.find_block(pbn)
            if self.stopped:return None
        if pbn==65535:
            self.actions.append('log:eftl_write_failed');return -2
        metadata=struct.pack('<H',logical)+bytes([69,(logical%256+logical//256+69)&255])
        self.actions.append('write_fill:2048:64');self.scratch[2048:]=b'\xff'*64;self.scratch[2068:2072]=metadata
        if within<self.flags[pbn]>>1:
            self.actions.extend(('log:eftl_sequence_error','log:eftl_write_failed'));return -2
        self.flags[pbn]=(self.flags[pbn]&1)|(((within+1)*2)&255)
        value=self.program_page(pbn*64+within)
        if self.stopped:return None
        if value:raise ValueError('lower program failure enters deferred relocation path')
        if within==0:self.mapping[logical]=pbn
        return len(payload)
    def storage_mutation(self):
        c=self.c;operation=c['mutation_operation'];handle=c['storage_handle']
        if handle!='normal' or operation!='erase' and c['storage_null_output']:
            if handle in ('below','above'):line=125 if handle=='below' else 126;owner=0x80c3c340
            else:
                line={'program':245,'erase':281,'rewrite':317}[operation]+int(handle!='null');owner={'program':0x80c3c318,'erase':0x80c3c2f0,'rewrite':0x80c3c2c0}[operation]
            self.actions.append('storage_diagnostic:'+str(line));self.stopped=dict(kind='assertion',owner=owner,line=line);return None
        _,p=storage.selected(c)
        if c['storage_owner_missing']:self.actions.append('log:storage_no_owner');return -1
        span=c['storage_span'] if c['storage_span']>=0 else p['declared_span'];span=span or c['storage_capacity']-p['offset']
        if c['storage_offset']>=span:self.actions.append('log:storage_bounds');return -1
        n=min(c['storage_size'],span-c['storage_offset']);address=p['offset']+c['storage_offset']
        if operation=='rewrite' and c['rewrite_missing']:self.actions.append('log:storage_rewrite_missing');return -1
        kind='erase' if operation=='erase' else 'program';self.actions.append(f'storage_backend_{kind}:{address}:{n}');self.storage_calls+=1
        if operation=='erase':
            remainder=address%131072;self.actions.append(f'erase_remainder:{address}:{remainder}')
            value=-1 if remainder else n
            if not remainder:
                for offset in range(0,n,131072):
                    status=self.map_write(address+offset,b'\xff')
                    if self.stopped:return None
                    if status<0:value=-14;break
        else:value=self.map_write(address,bytes(self.buffer[:n]))
        if not self.stopped and value<0:self.actions.append('log:storage_'+operation+'_error')
        return value
    def run(self):
        c=self.c
        if not c['defer_reinit']:self.initialize();self.initialized=True
        value=self.storage_mutation();result=self.snapshot(None if self.stopped else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=int(c['defer_reinit'] and not self.initialized),feature_reads=self.feature_reads,
            argument_hex=self.argument.hex(),driver_calls=self.dispatches,scratch_sha256=qspi.digest(self.scratch),
            eftl_context_hex=context(c).hex(),mapping_hex=struct.pack('<8H',*self.mapping).hex(),write_flags_hex=self.flags.hex(),
            storage_backend_calls=self.storage_calls,storage_table_sha256=qspi.digest(storage.table_bytes(c)),
            storage_backend_sha256=qspi.digest(backend_bytes(c)),storage_owners_sha256=qspi.digest(storage.owners_bytes(c)))
        return result


def contract(c):
    if c['mode']!='platform_mutation' or not c['native_mutation'] or not c['native_storage'] or c['mutation_operation'] not in ('program','erase','rewrite'):raise ValueError('mutation entry')
    if c['storage_name'] not in ('nvms','envbak','recovery') or c['storage_handle'] not in ('normal','null','below','above'):raise ValueError('storage backing')
    if not 0<=c['storage_offset']<=1048576 or not 0<=c['storage_size']<=0xffffffff or not -1<=c['storage_span']<=1048576:raise ValueError('bounded caller')
    _,p=storage.selected(c);span=c['storage_span'] if c['storage_span']>=0 else p['declared_span'];span=span or c['storage_capacity']-p['offset']
    if not 0<=c['storage_capacity']<=1048576 or span<0:raise ValueError('runtime capacity')
    n=min(c['storage_size'],max(0,span-c['storage_offset']))
    if c['mutation_operation']=='erase':
        if n>262144:raise ValueError('two logical erase blocks')
    elif n>64:raise ValueError('partial-page caller backing')
    if p['offset']+c['storage_offset']+min(n,262144)>1048576:raise ValueError('logical map backing')
    if len(c['write_flags'])!=8 or any(not 0<=v<=255 for v in c['write_flags']):raise ValueError('flag backing')
    if any(v!=65535 and v>=8 for v in c['mapping']):raise ValueError('physical map backing')
    if c['responses']!=[0] or c['driver_state']!='ok' or not c['chip'] or c['ecc_total']!=16 or c['ecc_unit']!=4 or c['positions']!=[4,20,36,52]:raise ValueError('deferred repair/geometry path')
    if c['partition_base']!=1048576 or c['fast_base']!=512 or c['null_handle'] or c['null_output']:raise ValueError('selected lower binding')
    if c['fifo_iteration_bound']!=1024:raise ValueError('FIFO bound')
    if c['storage_offset']%2048==0 and n:
        first=(p['offset']+c['storage_offset'])//131072
        if (p['offset']+c['storage_offset'])%131072 and c['mapping'][first]==65535:raise ValueError('midblock unmapped flags')
    eftl.contract(c|dict(mode='platform_eftl',dispatch_operation='eftl_map',offset=0,count=0))
    return Model(c).run()


def native_vectors():
    base=storage.native_vectors()['cases'][0];cases=[]
    def add(name,operation='program',**changes):
        flags=[1]*8;flags[3]=flags[4]=0
        c=base|dict(name=name,mode='platform_mutation',native_mutation=True,dispatch_operation='storage_mutation',
            mutation_operation=operation,storage_offset=2048,storage_size=32,rewrite_missing=False,
            write_flags=flags,mapping=[3,4,65535,65535,65535,65535,65535,65535],fifo_iteration_bound=1024)|changes
        if c['storage_name']!='nvms':
            index=storage.selected(c)[1]['offset']//131072;c['mapping']=[65535]*8;c['mapping'][index:index+2]=[3,4]
        c['expected']=contract(c);cases.append(c)
    add('program_existing');add('program_fast',fast=True);add('program_irq',irq_context=1)
    add('program_envbak',storage_name='envbak');add('program_recovery',storage_name='recovery')
    add('program_64',storage_size=64);add('program_zero',storage_size=0)
    add('program_zero_unaligned',storage_offset=16,storage_size=0);add('program_unaligned',storage_offset=16)
    add('program_sequence_error',write_flags=[1,1,1,6,0,1,1,1])
    add('program_first_page',storage_offset=0)
    add('program_allocate_free',storage_offset=0,mapping=[65535]*8,write_flags=[1,1,1,1,1,254,1,1])
    add('program_no_free',storage_offset=0,mapping=[65535]*8,write_flags=[1]*8)
    add('erase_block','erase',storage_offset=0);add('erase_fast','erase',storage_offset=0,fast=True)
    add('erase_two_blocks','erase',storage_offset=0,storage_size=131104)
    add('erase_zero','erase',storage_offset=0,storage_size=0)
    add('erase_zero_unaligned','erase',storage_offset=16,storage_size=0);add('erase_unaligned','erase',storage_offset=16)
    add('erase_no_free','erase',storage_offset=0,mapping=[65535]*8,write_flags=[1]*8)
    add('rewrite_existing','rewrite');add('rewrite_fast','rewrite',fast=True);add('rewrite_missing','rewrite',rewrite_missing=True)
    add('rewrite_sequence_error','rewrite',write_flags=[1,1,1,6,0,1,1,1])
    for operation in ('program','erase','rewrite'):add(operation+'_null',operation,storage_handle='null')
    add('program_null_input',storage_null_output=True);add('rewrite_null_input','rewrite',storage_null_output=True)
    add('program_owner_missing',storage_owner_missing=True);add('program_at_end',storage_offset=262144)
    add('program_end_clamp_unaligned',storage_offset=262136)
    add('program_acquire_assertion',acquire_status=-1);add('program_release_assertion',release_status=-1)
    add('program_fifo_assertion',fast=True,ready=[0],ticks=[0,0,1001])
    add('program_dma_assertion',dma_tx=base['dma_tx']|dict(status_a=[0],status_b=[0],ticks=[0,1001]))
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in storage.DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual upper storage program/erase/rewrite, original EFTL callbacks/page writer/free-block selection/OOB packing and selected NAND erase/program connect original bus/QSPI/DMA.',
            'Ready map/flags/counters/registry, full 2112-byte scratch/private-buffer backing, RTOS/peripherals and leaf copy/fill/signed-remainder services are authored.',
            'Readback is disabled; program/erase status errors entering bad-mark/relocation, complete repair/atomicity and physical payload/persistence are not validated.',
            'Original rewrite aliases program; callback name alone does not prove physical rewrite, erase or atomic replacement. Backup/restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect EFTL mutation stack: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
