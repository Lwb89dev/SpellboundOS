#!/usr/bin/env python3
"""Actual NAND page read through remapping, status FIFO, platform and DMA."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_platform as platform
    from . import nand_bbt as bbt
    from . import qspi_hal as qspi
else:
    import nand_platform as platform
    import nand_bbt as bbt
    import qspi_hal as qspi

PAGE_RANGES=((0x80c28a98,366),(0x80c279d8,64),(0x80c27a18,96),(0x80c27e0e,98),
    (0x80c2836e,180),(0x80c102f0,20),(0x80c27ed6,104),(0x80c29e6e,238),(0x80c29d4c,72))
RANGES=platform.RANGES+PAGE_RANGES
TARGETS=tuple(a for a,n in RANGES)
EXTRA_CONFIG=dict(page_read=0x80c28a98,page_delay=0x80c12154,page_compare=0x80c2e5e8)
BOUND=1500000


EXTRA_RANGES=((0x80c28a98,366),(0x80c279d8,64),(0x80c27a18,96),(0x80c27e0e,98),(0x80c2836e,180),
    (0x80c102f0,20),(0x80c27ed6,104),(0x80c29e6e,238),(0x80c29d4c,72))
RANGES=platform.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
BOUND=1500000
DATA_RANGES=((0x80d81b00,4),(0x80d809a8,16),(0x80c3e518,184),(0x80d81c30,184),
    (0x80c00284,8),(0x80c3ddd0,20),(0x80c3e864,20),(0x80c3dcfc,20))

class Model(platform.PlatformModel):
    def __init__(self,c):
        super().__init__(c);self.feature_reads=0;self.payload_rx=0;self.initialized=False
    def read(self,offset,size=4):
        if offset!=0x100:return super().read(offset,size)
        if self.regs[12]>>24==0x0f:
            if size!=1:raise ValueError('status FIFO width')
            values=self.c['responses'];value=values[min(self.feature_reads,len(values)-1)];self.feature_reads+=1
        else:
            value=int.from_bytes(bytes((0x5a+(self.payload_rx+i)*7)&255 for i in range(size)),'little');self.payload_rx+=size
        self.rx+=size;self.actions.append(f'r:{offset}:{size}:{value}');return value
    def bus(self,opcode,address=0,address_bytes=0,count=0,dummy=0,lines=1,write=True,private=False,status=False):
        c=self.c
        if not self.initialized:self.initialize();self.initialized=True
        self.actions.append('version:2')
        c['frame']=[2 if write else 0,0,opcode,1,1,address,1,address_bytes,lines,count,dummy]
        result=self.command();stage='command'
        if not result and count:
            stage='receive_bounce' if private else 'receive_poll'
            if status:
                saved=self.buffer;self.buffer=bytearray(512)
                result=qspi.Model.data(self,True,False);value=self.buffer[0];self.buffer=saved
            elif private:
                c['mode']='cache_read_bounce';result=super().data(True,True);c['mode']='page_read'
                if not result:self.actions.append('copy_from_bounce:'+str(count));self.buffer[:count]=self.bounce[:count]
            else:result=qspi.Model.data(self,True,False)
        if result:
            self.actions.extend(('log:'+stage+'_error','diagnostic'))
            self.stopped=dict(kind='assertion',owner=0x80c37b98 if private else 0x80c37b7c,
                line={'command':0x11f,'receive_poll':0x12a,'receive_bounce':0x16f}[stage])
        return (result,value if status and not result else None)
    def run(self):
        c=self.c
        if not c['defer_reinit']:self.initialize();self.initialized=True
        value=0
        if not c['chip']:value=-2
        else:
            self.actions.append('native_remap_page:'+str(c['page']))
            state=bytes.fromhex(c['bbt_hex']);magic,count=struct.unpack_from('<II',state);page=c['page']
            if magic==bbt.MAGIC:
                block=page//64;self.actions.append('native_remap_block:'+str(block))
                for bad in struct.unpack_from('<'+'H'*count,state,12):
                    if bad>block:break
                    block=(block+1)&0xffffffff
                if block>=struct.unpack_from('<I',state,160)[0]:value=-150
                else:page=(page%64+64*block)&0xffffffff
            if not value and (not c['buffer'] or not c['count'] or page>=65536 or ((c['column']+c['count'])&0xffffffff)>2112):value=-1
            if not value:
                result,_=self.bus(0x13,page,3)
                if not result:
                    status=255
                    for i in range(2000):
                        self.actions.append('delay:5');result,response=self.bus(0x0f,192,1,1,write=False,status=True)
                        if result:break
                        if i==1999:self.actions.append('log:busy_timeout');break
                        if not response&1:status=response;break
                    if not result:
                        ecc=(status&0x30)==0x20
                        if ecc:
                            # Actual retry returns early for the original first descriptor.
                            self.actions.extend(('compare20:-1','compare20:-1'))
                        address=c['column']|(0x1000 if c['plane'] and page&64 else 0)
                        self.bus(0x6b,address,2,c['count'],8,3,False,not c['blocking'] and c['count']>31)
                        if ecc:value=-101
        if value and value!=-150 and self.stopped is None:self.actions.append('log:page_result')
        result=self.snapshot(None if self.stopped else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=int(c['defer_reinit'] and not self.initialized),feature_reads=self.feature_reads)
        return result


def contract(c):
    state=bytes.fromhex(c['bbt_hex'])
    if c['mode']!='platform_page_read' or not c['native_page'] or not c['full_platform'] or not c['native_dma']:raise ValueError('connected read entry')
    if len(state)!=164 or struct.unpack_from('<I',state,4)[0]>64 or struct.unpack_from('<I',state,148)[0]!=64:raise ValueError('bounded BBT')
    if not 0<=c['count']<=64 or c['alignment'] or not 0<=c['page']<=0xffffffff or not 0<=c['column']<=0xffffffff:raise ValueError('bounded read')
    if not c['responses'] or len(c['responses'])>2000 or any(not 0<=v<=255 for v in c['responses']):raise ValueError('bounded status input')
    return Model(c).run()


def native_vectors():
    base=next(c for c in platform.native_vectors()['cases'] if c['name']=='platform_read_bounce');cases=[]
    def add(name,active=True,bad=None,**changes):
        state=bbt.initial(dict(active=active,bad=[1,3,7] if bad is None else bad,blocks=1024,page_size=2048,ppb=64,reserve=16,primary=1023,backup=1022))
        c=base|dict(name=name,mode='platform_page_read',native_page=True,bbt_hex=state.hex(),page=600,column=16,
            blocking=True,chip=True,buffer=True,plane=False,responses=[0])|changes
        # Each fixture owns the dictionaries changed during command composition.
        c['expected']=contract(c);cases.append(c)
    add('read_direct');add('read_private_dma',blocking=False);add('read_inactive_bbt',active=False)
    add('read_deferred_platform',defer_reinit=True,blocking=False,bus_word=83)
    add('read_one_byte',count=1);add('read_direct_word_tail',count=13)
    add('read_private_threshold_31',blocking=False,count=31);add('read_private_threshold_32',blocking=False,count=32)
    add('read_busy_then_ready',responses=[1,1,0]);add('read_corrected_ecc',responses=[0x10])
    add('read_uncorrectable_direct',responses=[0x20]);add('read_uncorrectable_private',responses=[0x20],blocking=False)
    add('read_plane',plane=True,page=536);add('read_plane_cleared_by_mapping',plane=True)
    add('read_exact_end',column=2048)
    add('read_no_chip',chip=False);add('read_null_buffer',buffer=False);add('read_zero_length',count=0)
    add('read_page_boundary',page=65536,active=False);add('read_column_boundary',column=2049)
    add('read_reserved_limit',page=65216);add('read_last_usable',page=65215)
    add('read_unsorted_bbt',bad=[7,1],page=64);add('read_duplicate_bbt',bad=[1,1],page=64)
    add('read_busy_timeout',responses=[1]);add('read_ecc_at_timeout',responses=[1]*1999+[0x20])
    add('read_load_assertion',done=[0],ticks=[0,1001])
    add('read_feature_assertion',ready=[0],ticks=[0,0,1001])
    profile=base['dma_rx']|dict(status_a=[0],status_b=[0],ticks=[0,1001])
    add('read_dma_assertion',blocking=False,dma_rx=profile)
    add('read_dma_alternate_status',blocking=False,dma_rx=base['dma_rx']|dict(status_a=[0],status_b=[64]))
    add('read_cache_completion_assertion',blocking=False,done=[1,1,0],ticks=[0,0,0,0,1001])
    return dict(schema=1,bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(platform.PIN_FACTS.read_bytes())!=platform.pin_facts(memory):raise ValueError('pin records differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['bound_per_case']!=BOUND or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual page read, BBT remapping, page-load/status/cache builders, busy loop and bus/QSPI/platform/DMA execute together.',
            'BBT/plane variants, status FIFO, peripherals, timers, delay/cache/copy/strncmp services and descriptor backing are authored.',
            'Retry executes only its original first-chip unsupported-family branch; supported-family levels were covered separately over a supplied bus.',
            'Direct FIFO payload is authored; DMA moves no physical data and sentinel copies do not establish delivered NAND payload.',
            'Physical ECC, board timing/pins/IRQ/coherency, BBT provenance, persistence, restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect connected NAND read: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
