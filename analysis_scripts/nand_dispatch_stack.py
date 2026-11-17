#!/usr/bin/env python3
"""Original NAND partition dispatch, RTOS-context wrappers and lower QSPI stack."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_maintenance_stack as lower
else:
    import nand_maintenance_stack as lower

read=lower.read
qspi=lower.qspi
EXTRA_RANGES=((0x80c29532,68),(0x80c275ce,32),(0x80c2964c,270),(0x80c27646,28),
    (0x80c27c70,80),(0x80c27b64,64),(0x80c27a90,28),(0x80c27af2,58),(0x80c27b2c,56),(0x80c292ee,394))
RANGES=lower.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
PART=0x81308000
ARG=0x81308300
DATA_RANGES=read.DATA_RANGES+((0x80d81b28,4),(0x80d811f4,28))


class Model(lower.Model):
    def __init__(self,c):
        super().__init__(c);self.argument=bytearray(struct.pack('<4I',*c['arguments'])+b'\xa5'*16)
        self.dispatches=0
    def execution_context(self):
        c=self.c;self.actions.append('irq_context:'+str(c['irq_context']))
        if c['irq_context']:return True
        self.actions.append('scheduler_context:'+str(c['scheduler_context']));return bool(c['scheduler_context'])
    def mutex(self,release=False):
        if not self.c['mutex_present']:return True
        status=self.c['release_status' if release else 'acquire_status'];self.actions.append(('mutex_release:' if release else 'mutex_acquire:')+str(status))
        if status:self.stopped=dict(kind='assertion',owner=0x80c3d44c if release else 0x80c3d464,line=0x2a if release else 0x24)
        return not status
    def page_read(self,page,column,count,blocking,out=0):
        c=self.c
        if not c['chip']:self.actions.append('log:page_result');return -2
        page=self.map(page)
        if page is None:return -150
        if not count or page>=65536 or ((column+count)&0xffffffff)>2112:self.actions.append('log:page_result');return -1
        if self.bus(19,page,3)[0]:return None
        status=self.poll(2000)
        if status is None:return None
        ecc=(status&0x30)==0x20
        if ecc:self.actions.extend(('compare20:-1','compare20:-1'))
        column|=4096 if c['plane'] and page&64 else 0
        original=self.buffer;self.buffer=bytearray(original[out:])+bytearray(out)
        failed,_=self.bus(0x6b,column,2,count,8,3,False,not blocking and count>31)
        original[out:out+count]=self.buffer[:count];self.buffer=original
        if failed:return None
        if ecc:self.actions.append('log:page_result');return -101
        return 0
    def driver_read(self,page,column,count,out=0):
        self.actions.append(f'driver_read:{page}:{column}:{count}');self.dispatches+=1
        direct=self.execution_context()
        if not direct and not self.mutex():return None
        value=self.page_read(page,column,count,direct,out)
        if not self.stopped and not direct:self.mutex(True)
        return value
    def extent(self):
        c=self.c;base=c['partition_base'];span=c['partition_span'] or ((2048*65536-base)&0xffffffff)
        return None if (base|span)&2047 else span
    def partition_read(self,page,column,count,out=0):
        c=self.c
        if c['null_handle'] or c['null_output'] or self.extent() is None:return -10
        if c['driver_state']!='ok':return -6
        return self.driver_read((page+c['partition_base']//2048)&0xffffffff,column,count,out)
    def chip_query(self,query,arg):
        self.actions.append('chip_ioctl:'+str(query));c=self.c
        if not c['chip']:self.actions.append('log:chip_error');return -2
        values={1:65536,2:2048,3:64,18:64,19:16,20:4}
        if query in values:arg[:4]=struct.pack('<I',values[query]);return 0
        if query==21:arg[:16]=struct.pack('<4I',4,20,36,52);return 0
        if query==12:
            block=self.map(struct.unpack_from('<I',arg)[0],True)
            value=-151 if block is None else (-1 if block>=1024 else 0)
            if not value and c['guard'] and block<8:self.actions.append('log:block_guard');value=-250
            if not value:
                if self.bus(6)[0] or self.bus(0xd8,block*64,3)[0]:return None
                status=self.poll(4000 if self.current_direct else 20,not self.current_direct)
                if status is None:return None
                value=-104 if status&4 else 0
            if value:self.actions.append('log:erase_result')
            return value
        if query==15:
            old={k:c[k] for k in ('operation','page','dest','count')};source,dest,pointer,count=struct.unpack_from('<4I',arg)
            if pointer!=qspi.BUFFER:raise ValueError('copy caller backing')
            c.update(operation='copy_oob',page=source,dest=dest,count=count);value=super().policy();c.update(old)
            if value and not self.stopped:self.actions.extend(('log:copy_result','log:chip_error'))
            return value
        self.actions.append('log:chip_error');return -9
    def driver_ioctl(self,query,arg):
        if self.c['driver_state']!='ok':return -6
        self.actions.append('driver_ioctl:'+str(query));self.dispatches+=1
        direct=self.execution_context();self.current_direct=direct
        if not direct and not self.mutex():return None
        value=self.chip_query(query,arg)
        if not self.stopped and not direct:self.mutex(True)
        return value
    def partition_ioctl(self,query,arg):
        c=self.c
        if c['null_handle'] or self.extent() is None:return -10
        base=c['partition_base'];span=self.extent()
        if query==1:
            if c['null_argument']:return -10
            arg[:4]=struct.pack('<I',span//2048);return 0
        if query==8:
            if (base|span)&(131072-1):return -10
            for block in range(base//131072,(base+span)//131072):
                self.driver_ioctl(12,bytearray(struct.pack('<I',block)))
                if self.stopped:return None
            return 0
        if query in (10,11,12):
            if base&(131072-1):return -10
            block=(base//131072+struct.unpack_from('<I',arg)[0])&0xffffffff
            return self.driver_ioctl(query,bytearray(struct.pack('<I',block)))
        if query==15:
            a,b=struct.unpack_from('<II',arg);struct.pack_into('<II',arg,0,(a+base//2048)&0xffffffff,(b+base//2048)&0xffffffff)
        return self.driver_ioctl(query,arg)
    def run(self):
        c=self.c
        if not c['defer_reinit']:self.initialize();self.initialized=True
        operation=c['dispatch_operation']
        if operation=='partition_read':value=self.partition_read(c['page'],c['column'],c['count'])
        elif operation=='driver_read':value=-6 if c['driver_state']!='ok' else self.driver_read(c['page'],c['column'],c['count'])
        elif operation=='partition_ioctl':value=self.partition_ioctl(c['query'],self.argument)
        else:value=self.driver_ioctl(c['query'],self.argument)
        result=self.snapshot(None if self.stopped else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=int(c['defer_reinit'] and not self.initialized),feature_reads=self.feature_reads,
            argument_hex=self.argument.hex(),driver_calls=self.dispatches)
        return result


def contract(c):
    if c['dispatch_operation'] not in ('partition_read','driver_read','partition_ioctl','driver_ioctl') or c['mode']!='platform_dispatch':raise ValueError('dispatch entry')
    if not all(c[k] for k in ('native_dispatch','native_page','native_platform','full_platform','native_dma')):raise ValueError('connected dispatch')
    if not 0<=c['count']<=64 or c['alignment'] or c['driver_state'] not in ('ok','root_missing','ops_missing','callback_missing'):raise ValueError('bounded dispatch')
    if any(not 0<=c[k]<=0xffffffff for k in ('partition_base','partition_span','page','column')):raise ValueError('unsigned dispatch fields')
    state=bytes.fromhex(c['bbt_hex'])
    if len(state)!=164 or struct.unpack_from('<I',state,4)[0]>64 or struct.unpack_from('<I',state,148)[0]!=64:raise ValueError('bounded BBT')
    if not c['responses'] or len(c['responses'])>4000 or any(not 0<=v<=255 for v in c['responses']):raise ValueError('bounded statuses')
    span=c['partition_span'] or ((2048*65536-c['partition_base'])&0xffffffff)
    if span//131072>2 and c['query']==8:raise ValueError('bounded format')
    if c['query'] not in (1,2,3,8,12,15,18,19,20,21,99) or len(c['arguments'])!=4:raise ValueError('bounded ioctl')
    if any(not 0<=v<=0xffffffff for v in c['arguments']):raise ValueError('unsigned ioctl fields')
    if c['query']==15 and (c['arguments'][2]!=qspi.BUFFER or c['arguments'][3]>64):raise ValueError('copy backing')
    return Model(c).run()


def native_vectors():
    base=lower.native_vectors()['cases'][0];cases=[]
    def add(name,operation='partition_read',**changes):
        c=base|dict(name=name,mode='platform_dispatch',native_dispatch=True,dispatch_operation=operation,
            partition_base=0x100000,partition_span=0xb00000,null_handle=False,null_output=False,null_argument=False,
            driver_state='ok',irq_context=0,scheduler_context=0,mutex_present=True,acquire_status=0,release_status=0,
            query=2,arguments=[5,9,qspi.BUFFER,64],page=7,column=16,count=64)|changes
        c['expected']=contract(c);cases.append(c)
    add('partition_read_normal');add('partition_read_irq',irq_context=1);add('partition_read_scheduler',scheduler_context=1)
    add('partition_read_no_mutex',mutex_present=False);add('partition_read_tail',count=13)
    add('partition_read_derived_extent',partition_span=0);add('partition_read_beyond_extent',partition_span=2048,page=9999)
    add('partition_read_wrapping_page',page=0xffffffff);add('partition_read_zero',count=0)
    add('partition_read_bad_base',partition_base=0x100001);add('partition_read_bad_span',partition_span=2049)
    add('partition_read_null_handle',null_handle=True);add('partition_read_null_output',null_output=True)
    for state in ('root_missing','ops_missing','callback_missing'):add('partition_read_'+state,driver_state=state)
    add('partition_read_lock_assertion',acquire_status=-1);add('partition_read_unlock_assertion',release_status=-1)
    add('partition_read_ecc',responses=[0x20]);add('partition_read_irq_ecc',irq_context=1,responses=[0x20])
    add('driver_read_normal','driver_read',page=600);add('driver_read_irq','driver_read',page=600,irq_context=1)
    add('driver_read_missing_chip','driver_read',chip=False);add('partition_read_deferred',defer_reinit=True)
    for query in (1,2,3,18,19,20,21,99):add('partition_query_'+str(query),'partition_ioctl',query=query)
    add('partition_erase','partition_ioctl',query=12);add('partition_erase_irq','partition_ioctl',query=12,irq_context=1)
    add('partition_erase_sleep_timeout','partition_ioctl',query=12,responses=[1])
    add('partition_format_ignores_guard_errors','partition_ioctl',query=8,partition_base=0,partition_span=0x40000)
    add('partition_copy_oob','partition_ioctl',query=15);add('partition_copy_oob_missing_driver','partition_ioctl',query=15,driver_state='root_missing')
    add('driver_erase','driver_ioctl',query=12,arguments=[12,0,qspi.BUFFER,64])
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original partition read/ioctl, original operation-table callbacks, RTOS-context/mutex wrappers and selected chip queries/read/erase/OOB copy connect actual lower BBT/platform/bus/QSPI/DMA.',
            'Driver root binding, partition/geometry/BBT backing, RTOS context/mutex results, peripherals and leaf services are authored.',
            'No concurrent execution, physical mutex guarantees, NAND payload/persistence, restoration or standalone boot is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND dispatch stack: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
