#!/usr/bin/env python3
"""Actual NAND program policy through original BBT, bus, FIFO and DMA."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_read_stack as read
    from . import qspi_hal as qspi
else:
    import nand_read_stack as read
    import qspi_hal as qspi

EXTRA_RANGES=((0x80c28c06,372),(0x80c27fa8,98))
RANGES=read.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)


class Model(read.Model):
    def bus(self,opcode,address=0,address_bytes=0,count=0,dummy=0,lines=1,write=True,private=False,status=False):
        if not write or not count:return super().bus(opcode,address,address_bytes,count,dummy,lines,write,private,status)
        c=self.c
        if not self.initialized:self.initialize();self.initialized=True
        self.actions.append('version:2')
        if private:self.actions.append('copy_to_bounce:'+str(count));self.bounce[:count]=self.buffer[:count]
        c['frame']=[2,0,opcode,1,1,address,1,address_bytes,lines,count,dummy]
        result=self.command();stage='command'
        if not result:
            stage='transmit_bounce' if private else 'transmit_poll'
            if private:
                c['mode']='cache_write_bounce';result=read.platform.integrated.Model.data(self,False,True);c['mode']='page_write'
            else:result=qspi.Model.data(self,False,False)
        if result:
            self.actions.extend(('log:'+stage+'_error','diagnostic'))
            self.stopped=dict(kind='assertion',owner=0x80c37b98 if private else 0x80c37b7c,
                line={'command':0x162 if private else 0x11f,'transmit_poll':0x132,'transmit_bounce':0x17b}[stage])
        return result,None
    def run(self):
        c=self.c
        if not c['defer_reinit']:self.initialize();self.initialized=True
        value=0
        if not c['chip']:value=-2
        else:
            self.actions.append('native_remap_page:'+str(c['page']))
            state=bytes.fromhex(c['bbt_hex']);magic,count=struct.unpack_from('<II',state);page=c['page']
            if magic==read.bbt.MAGIC:
                block=page//64;self.actions.append('native_remap_block:'+str(block))
                for bad in struct.unpack_from('<'+'H'*count,state,12):
                    if bad>block:break
                    block=(block+1)&0xffffffff
                if block>=struct.unpack_from('<I',state,160)[0]:value=-150
                else:page=(page%64+64*block)&0xffffffff
            if not value and (not c['buffer'] or not c['count'] or page>=65536 or ((c['column']+c['count'])&0xffffffff)>2112):value=-1
            if not value and c['guard'] and page<512:self.actions.append('log:page_guard');value=-250
            if not value:
                result,_=self.bus(0x06)
                if not result:
                    address=c['column']|(0x1000 if c['plane'] and page&64 else 0)
                    result,_=self.bus(0x32,address,2,c['count'],0,3,True,not c['blocking'] and c['count']>31)
                    if not result:
                        result,_=self.bus(0x10,page,3)
                        if not result:
                            status=255
                            for i in range(2000):
                                self.actions.append('delay:5');result,response=self.bus(0x0f,192,1,1,write=False,status=True)
                                if result:break
                                if i==1999:self.actions.append('log:busy_timeout');break
                                if not response&1:status=response;break
                            if not result and status&8:value=-102
        if value and self.stopped is None:self.actions.append('log:page_result')
        result=self.snapshot(None if self.stopped else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=int(c['defer_reinit'] and not self.initialized),feature_reads=self.feature_reads)
        return result


def contract(c):
    state=bytes.fromhex(c['bbt_hex'])
    if c['mode']!='platform_page_write' or not c['native_page'] or not c['native_program'] or not c['full_platform'] or not c['native_dma']:raise ValueError('connected program entry')
    if len(state)!=164 or struct.unpack_from('<I',state,4)[0]>64 or struct.unpack_from('<I',state,148)[0]!=64:raise ValueError('bounded BBT')
    if not 0<=c['count']<=64 or c['alignment'] or not 0<=c['page']<=0xffffffff or not 0<=c['column']<=0xffffffff:raise ValueError('bounded program')
    if not c['responses'] or len(c['responses'])>2000 or any(not 0<=v<=255 for v in c['responses']):raise ValueError('bounded status input')
    return Model(c).run()


def native_vectors():
    cases=[];read_cases=read.native_vectors()['cases'];base=next(c for c in read_cases if c['name']=='read_direct')
    tx=next(c for c in read.platform.native_vectors()['cases'] if c['name']=='platform_write_bounce')['dma_tx']
    def add(name,**changes):
        c=base|dict(name=name,mode='platform_page_write',native_program=True,guard=True,dma_tx=tx)|changes
        c['expected']=contract(c);cases.append(c)
    add('program_direct');add('program_private_dma',blocking=False)
    add('program_deferred_platform',blocking=False,defer_reinit=True)
    add('program_word_tail',count=13);add('program_private_threshold_31',blocking=False,count=31)
    add('program_private_threshold_32',blocking=False,count=32)
    add('program_busy_then_ready',responses=[1,1,0]);add('program_failed_status',responses=[8])
    add('program_busy_timeout',responses=[1]);add('program_failure_at_timeout',responses=[1]*1999+[8])
    add('program_ready_at_timeout',responses=[1]*1999+[0])
    add('program_ecc_bits_ignored',responses=[0x20]);add('program_plane',plane=True,page=536)
    add('program_below_mapped_guard',page=319);add('program_mapped_guard_boundary',page=320)
    add('program_guard_disabled',page=0,guard=False)
    add('program_no_chip',chip=False);add('program_null_buffer',buffer=False);add('program_zero_length',count=0)
    add('program_column_boundary',column=2049);add('program_column_wrap',column=0xfffffff0)
    add('program_reserved_limit',page=65216)
    add('program_enable_assertion',done=[0],ticks=[0,1001])
    add('program_fifo_assertion',ready=[0],ticks=[0,0,1001])
    add('program_dma_assertion',blocking=False,dma_tx=tx|dict(status_a=[0],status_b=[0],ticks=[0,1001]))
    add('program_dma_alternate_status',blocking=False,dma_tx=tx|dict(status_a=[0],status_b=[32]))
    add('program_execute_assertion',blocking=False,done=[1,1,0],ticks=[0,0,0,1001])
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(read.platform.PIN_FACTS.read_bytes())!=read.platform.pin_facts(memory):raise ValueError('pin records differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['bound_per_case']!=read.BOUND or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in read.DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual page program and BBT mapping execute through enable/cache/program/status builders, platform, bus, QSPI/FIFO and DMA.',
            'BBT/plane/guard variants, peripheral/status/timer inputs and leaf delay/cache/copy services are authored; no device was accessed.',
            'Direct FIFO writes capture caller bytes; DMA movement and physical programming/persistence are not simulated or established.',
            'Physical guards, chip geometry, ECC, coherency, restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect connected NAND program: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
