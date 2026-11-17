#!/usr/bin/env python3
"""Ready EFTL mapped/page/OOB reads through original NAND dispatch and QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_dispatch_stack as dispatch
else:
    import nand_dispatch_stack as dispatch

read=dispatch.read
qspi=dispatch.qspi
EXTRA_RANGES=((0x80c0219a,254),(0x80c23252,78),(0x80c0278a,38),(0x80c027b0,86),(0x80c025d4,210))
RANGES=dispatch.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
CONTEXT=0x80de5fb8
MAP=0x81309100
SCRATCH=0x8130a000


def context(c):
    data=bytearray(64);struct.pack_into('<I',data,0,0 if c['null_handle'] else dispatch.PART);data[6]=int(c['fast'])
    for at,value in ((8,64),(12,2048),(24,c['fast_base']),(48,MAP),(52,SCRATCH)):struct.pack_into('<I',data,at,value)
    for at,value in ((28,64),(30,c['ecc_total']),(32,c['ecc_unit']),*zip((34,36,38,40),c['positions'])):struct.pack_into('<H',data,at,value)
    return data


class Model(dispatch.Model):
    def __init__(self,c):super().__init__(c);self.scratch=bytearray((i*5+7)&255 for i in range(2112))
    def adapter(self,page,column,count,out=0):
        if self.c['fast']:return self.page_read((page+self.c['fast_base'])&0xffffffff,column,count,True,out)
        return self.partition_read(page,column,count,out)
    def mapped(self):
        c=self.c;remaining=c['count'];address=c['offset']
        while remaining:
            page,column=divmod(address,2048);count=min(remaining,2048-column);block=(page//64)&0xffff
            physical=c['mapping'][block];done=c['count']-remaining
            if physical==65535:
                self.actions.append('log:unmapped_block');self.buffer[done:done+remaining]=b'\xff'*remaining;return done
            status=self.adapter(physical*64+(page%64),column,count,done)
            if self.stopped:return None
            if status<0:self.actions.append('log:page_read_error');return -1
            address=(address+count)&0xffffffff;remaining-=count
        return c['count']
    def oob(self):
        c=self.c;saved=self.buffer;self.buffer=self.scratch[2048:]+bytearray(448)
        value=self.adapter(c['page'],2048,64)
        self.scratch[2048:]=self.buffer[:64];self.buffer=saved
        if self.stopped or value:return value
        if c['ecc_total']<4:
            self.stopped=dict(kind='assertion',owner=0x80c3446c,line=0x48);return None
        if c['ecc_unit']>=4:
            pos=c['positions'][1];self.buffer[:4]=self.scratch[2048+pos:2052+pos];return 0
        done=0
        for i,pos in enumerate(c['positions']):
            n=c['ecc_unit']
            if i==0 and pos==0:n=(n-2)&65535;pos=2
            n=min(4-done,n);self.actions.append(f'oob_copy:{done}:{pos}:{n}')
            self.buffer[done:done+n]=self.scratch[2048+pos:2048+pos+n];done+=n
            if done>=4:break
        return 0
    def run(self):
        c=self.c
        if not c['defer_reinit']:self.initialize();self.initialized=True
        op=c['dispatch_operation']
        if op=='eftl_page':value=self.adapter(c['page'],c['column'],c['count'])
        elif op=='eftl_oob':value=self.oob()
        else:value=self.mapped()
        result=self.snapshot(None if self.stopped else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=int(c['defer_reinit'] and not self.initialized),feature_reads=self.feature_reads,
            argument_hex=self.argument.hex(),driver_calls=self.dispatches,scratch_sha256=qspi.digest(self.scratch),
            eftl_context_hex=context(c).hex(),mapping_hex=struct.pack('<8H',*c['mapping']).hex())
        return result


def contract(c):
    if c['mode']!='platform_eftl' or c['dispatch_operation'] not in ('eftl_page','eftl_map','eftl_wrapper','eftl_oob'):raise ValueError('EFTL entry')
    if not all(c[k] for k in ('native_eftl','native_dispatch','native_page','native_platform','native_dma','full_platform')):raise ValueError('connected EFTL')
    if not 0<=c['count']<=64 or c['alignment'] or len(c['mapping'])!=8 or any(not 0<=v<=65535 for v in c['mapping']):raise ValueError('bounded mapping')
    if not 0<=c['offset']<=0xffffffff or (c['offset']+max(c['count']-1,0))//131072>=8:raise ValueError('logical map backing')
    if not 0<=c['fast_base']<=0xffffffff or not 0<=c['page']<=0xffffffff or not 0<=c['column']<=0xffffffff:raise ValueError('unsigned EFTL fields')
    if c['ecc_unit'] not in (0,2,4) or not 0<=c['ecc_total']<=16 or len(c['positions'])!=4 or any(not 0<=p<=60 for p in c['positions']):raise ValueError('OOB backing')
    if not c['responses'] or len(c['responses'])>2000 or any(not 0<=v<=255 for v in c['responses']):raise ValueError('status backing')
    return Model(c).run()


def native_vectors():
    base=dispatch.native_vectors()['cases'][0];cases=[]
    def add(name,operation='eftl_map',**changes):
        c=base|dict(name=name,mode='platform_eftl',native_eftl=True,dispatch_operation=operation,fast=False,
            fast_base=512,mapping=[3,1,4,65535,2,0,5,6],offset=16,count=32,
            ecc_total=16,ecc_unit=4,positions=[4,20,36,52])|changes
        c['expected']=contract(c);cases.append(c)
    add('eftl_map_normal');add('eftl_map_fast',fast=True);add('eftl_map_irq',irq_context=1)
    add('eftl_two_pages',offset=2040,count=32);add('eftl_two_pages_fast',offset=2040,count=32,fast=True)
    add('eftl_two_dma_pages',offset=2016,count=64);add('eftl_two_dma_pages_fast',offset=2016,count=64,fast=True)
    add('eftl_cross_block',offset=131064,count=32)
    add('eftl_first_gap',mapping=[65535]*8);add('eftl_gap_after_prefix',offset=131064,count=32,mapping=[3,65535,4,65535,2,0,5,6])
    add('eftl_zero',count=0);add('eftl_wrapper','eftl_wrapper',offset=2040,count=32)
    add('eftl_wrapper_gap','eftl_wrapper',mapping=[65535]*8)
    add('eftl_lower_missing_driver',driver_state='root_missing');add('eftl_fast_bypasses_missing_driver',fast=True,driver_state='root_missing')
    add('eftl_lower_mapping_rejected',mapping=[65534,1,4,65535,2,0,5,6])
    add('eftl_second_ecc_error',offset=2040,count=32,responses=[0,32])
    add('eftl_page_generic','eftl_page',count=64);add('eftl_page_fast','eftl_page',count=64,fast=True)
    add('eftl_fast_base_wrap','eftl_page',fast=True,fast_base=0xffffffff)
    add('eftl_page_zero','eftl_page',count=0);add('eftl_page_ecc','eftl_page',responses=[32],fast=True)
    add('eftl_oob_generic','eftl_oob');add('eftl_oob_fast','eftl_oob',fast=True)
    add('eftl_oob_irq','eftl_oob',irq_context=1)
    add('eftl_oob_segmented','eftl_oob',fast=True,ecc_unit=2)
    add('eftl_oob_skip_marker','eftl_oob',fast=True,ecc_unit=2,positions=[0,20,36,52])
    add('eftl_oob_zero_unit','eftl_oob',fast=True,ecc_unit=0)
    add('eftl_oob_ecc_error','eftl_oob',fast=True,responses=[32])
    add('eftl_oob_ecc_metadata_assertion','eftl_oob',fast=True,ecc_total=2)
    add('eftl_oob_missing_driver','eftl_oob',driver_state='callback_missing')
    add('eftl_page_deferred','eftl_page',defer_reinit=True,count=64)
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in dispatch.DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Ready EFTL map/read wrapper/page/OOB adapters execute through actual original partition/driver/context/BBT/page/bus/QSPI and selected DMA.',
            'Mapping, context, ready state, RTOS results and peripheral data are authored; real selected geometry is used with identified OOB metadata variants.',
            'No map reconstruction/provenance, physical NAND payload/ECC/OOB/persistence, concurrency/coherency, restoration or standalone boot is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect EFTL/QSPI stack: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
