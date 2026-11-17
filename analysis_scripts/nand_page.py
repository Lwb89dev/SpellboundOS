#!/usr/bin/env python3
"""Bounded NAND page policy and actual busy loops with supplied command services."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH,digest,image_memory
else:
    from recovery_validator import BOOT_HASH,digest,image_memory

CONFIG=dict(read=0x80c28a98,write=0x80c28c06,copy_page=0x80c28d7a,copy_oob=0x80c28ec4,erase=0x80c291e6,
    busy=0x80c2836e,erase_busy=0x80c286b2,wait=0x80c102f0,
    remap_page=0x80c27a18,remap_block=0x80c279d8,load=0x80c27e0e,enable=0x80c27db0,
    program=0x80c27fa8,erase_command=0x80c28136,cache_read_bounce=0x80c27f3e,cache_read_direct=0x80c27ed6,
    cache_write_bounce=0x80c280d0,cache_write_direct=0x80c2806c,cache_write_oob=0x80c2800a,
    workaround=0x80c29e6e,feature=0x80c27ce8,delay=0x80c12154,sleep=0x80c16884,logger=0x80c1cd7a)
RANGES=((0x80c28a98,366),(0x80c28c06,372),(0x80c28d7a,330),(0x80c28ec4,382),(0x80c291e6,264),
    (0x80c2836e,180),(0x80c286b2,152),(0x80c102f0,20))
TARGETS=tuple(a for a,n in RANGES)
LOGS={0x80c3d8a8:'page_result',0x80c3d8f8:'page_guard',0x80c3d878:'workaround_ok',
    0x80c3d93c:'copy_result',0x80c3da4c:'block_guard',0x80c3da90:'erase_result',
    0x80c3d6a4:'busy_timeout',0x80c3d688:'feature_error'}


class Model:
    def __init__(self,c):
        self.c=c;self.actions=[];self.buffer=bytearray((i*3+1)&255 for i in range(512));self.reads=0;self.maps=0
    def log(self,tag):self.actions.append('log:'+tag)
    def map(self,value,block=False):
        c=self.c;i=self.maps;self.maps+=1
        status=c['map_status'][min(i,len(c['map_status'])-1)];mapped=(value+c['map_delta'])&0xffffffff
        self.actions.append(f'remap_{"block" if block else "page"}:{value}:{mapped}:{status}')
        return status,mapped
    def call(self,name,*args):
        status=self.c['faults'].get(name,0);self.actions.append(':'.join(map(str,(name,*args,status))));return status
    def busy(self,erase=False):
        c=self.c;limit=(20 if erase else 10)*200 if c['blocking'] or not erase else 20
        status=0;out=255
        for i in range(limit):
            self.actions.append('delay:5' if c['blocking'] or not erase else 'sleep:1')
            j=self.reads;self.reads+=1;v=c['responses'][min(j,len(c['responses'])-1)]
            status=c['feature_status'][min(j,len(c['feature_status'])-1)]
            self.actions.append(f'feature:192:{v}:{status}')
            if status:self.log('feature_error');return status,out
            if i+1==limit:self.log('busy_timeout');return 0,out
            if not v&1:return 0,v
        raise AssertionError('unreachable busy')
    def cache(self,write=False,oob=False,address=None):
        c=self.c;name='cache_write_oob' if oob else ('cache_write_' if write else 'cache_read_')+('direct' if c['blocking'] else 'bounce')
        address=c['column'] if address is None else address
        status=self.c['faults'].get(name,0)
        payload=digest(self.buffer[:c['size']]) if write else None
        args=(address,c['size'],payload) if write else (address,c['size'])
        self.actions.append(':'.join(map(str,(name,*args,status))))
        if not write and not status:self.buffer[:c['size']]=bytes((0x5a+i*7)&255 for i in range(c['size']))
        return status
    def run(self):
        c=self.c;mode=c['mode'];tail='copy_result' if mode.startswith('copy') else ('erase_result' if mode=='erase' else 'page_result')
        def finish(value,log=True):
            if log:self.log(tail)
            return dict(actions=self.actions,rows=[dict(returned=value&0xffffffff,buffer_sha256=digest(self.buffer),feature_reads=self.reads)])
        if not c['chip']:return finish(-2)
        block=mode=='erase';status,page=self.map(c['block'] if block else c['page'],block)
        if status:return finish(-151 if block else -150,mode!='read')
        dest=None
        if mode.startswith('copy'):
            status,dest=self.map(c['dest'])
            if status:return finish(-150)
        if block:
            if page>=1024:return finish(-1)
        elif mode.startswith('copy'):
            if page>=65536 or dest>=65536 or (mode=='copy_oob' and c['size']>64):return finish(-1)
        elif not c['buffer'] or not c['size'] or page>=65536 or ((c['column']+c['size'])&0xffffffff)>2112:return finish(-1)
        if mode!='read' and c['guard'] and (page<(8 if block else 512) or dest is not None and dest<512):
            self.log('block_guard' if block else 'page_guard');return finish(-250)
        if block:
            if self.call('enable'):return finish(-55)
            if self.call('erase_command',page):return finish(-60)
            status,busy=self.busy(True)
            return finish(-100 if status else (-104 if busy&4 else 0),bool(status or busy&4))
        if mode=='write':
            if self.call('enable'):return finish(-55)
            address=c['column']|(0x1000 if c['plane'] and page&64 else 0)
            if self.cache(True,address=address):return finish(-56 if c['blocking'] else -57)
            if self.call('program',page):return finish(-58)
            status,busy=self.busy()
            return finish(-100 if status else (-102 if busy&8 else 0),bool(status or busy&8))
        if self.call('load',page):return finish(-52)
        status,busy=self.busy()
        if status:return finish(-100)
        ecc=(busy&0x30)==0x20
        if mode=='read':
            if ecc and not self.call('workaround',page):ecc=False;self.log('workaround_ok')
            address=c['column']|(0x1000 if c['plane'] and page&64 else 0)
            error=-53 if c['blocking'] else -54
            if not self.cache(address=address):error=0
            if ecc:error=-101
            return finish(error,bool(error))
        if ecc:return finish(-101)
        if self.call('enable'):return finish(-55)
        if mode=='copy_oob':
            address=2048|(0x1000 if c['plane'] and page&64 else 0)
            if self.cache(True,True,address):return finish(-56)
        if self.call('program',dest):return finish(-58)
        status,busy=self.busy()
        return finish(-100 if status else (-102 if busy&8 else 0),bool(status or busy&8))


def contract(c):
    if not 0<=c['size']<=512 or not c['responses'] or not c['feature_status'] or not c['map_status']:raise ValueError('bounded page fixture')
    return Model(c).run()


def native_vectors():
    cases=[]
    def add(name,mode='read',**changes):
        c=dict(name=name,mode=mode,chip=True,buffer=True,page=600,dest=700,block=12,column=16,size=64,
            blocking=True,guard=True,plane=False,map_delta=0,map_status=[0],faults={},responses=[0],feature_status=[0])|changes
        c['expected']=contract(c);cases.append(c)
    add('read_direct');add('read_bounce',blocking=False)
    add('read_missing_chip',chip=False);add('read_null_buffer',buffer=False);add('read_zero_length',size=0)
    add('read_page_boundary',page=65536);add('read_column_boundary',column=2049);add('read_exact_end',column=2048)
    add('read_remapped',map_delta=64);add('read_remap_error',map_status=[-1])
    add('read_ecc_recovered',responses=[0x20]);add('read_ecc_unrecovered',responses=[0x20],faults=dict(workaround=-1))
    add('read_ecc_overrides_cache_error',responses=[0x20],faults=dict(workaround=-1,cache_read_direct=-9))
    add('read_load_fault',faults=dict(load=-9));add('read_cache_fault',faults=dict(cache_read_direct=-9))
    add('read_bounce_cache_fault',blocking=False,faults=dict(cache_read_bounce=-9))
    add('read_feature_fault',feature_status=[-9]);add('read_busy_timeout',responses=[1]);add('read_plane',plane=True,page=600|64)
    for mode in ('write','copy_page','copy_oob','erase'):
        add(mode+'_ready',mode);add(mode+'_missing_chip',mode,chip=False)
        add(mode+'_remap_error',mode,map_status=[-1]);add(mode+'_out_of_range',mode,page=65536,block=1024)
        add(mode+'_guarded',mode,page=0,block=0);add(mode+'_guard_boundary',mode,page=512,block=8)
        add(mode+'_guard_disabled',mode,page=0,block=0,guard=False)
        add(mode+'_enable_fault',mode,faults=dict(enable=-9))
    add('write_bounce','write',blocking=False);add('write_null_buffer','write',buffer=False)
    add('write_cache_fault','write',faults=dict(cache_write_direct=-9));add('write_bounce_cache_fault','write',blocking=False,faults=dict(cache_write_bounce=-9))
    add('write_program_fault','write',faults=dict(program=-9));add('write_failed_status','write',responses=[8])
    add('write_feature_fault','write',feature_status=[-9]);add('write_busy_timeout','write',responses=[1]);add('write_plane','write',plane=True,page=600|64)
    add('copy_dest_remap_error','copy_page',map_status=[0,-1]);add('copy_dest_guarded','copy_page',dest=0)
    add('copy_dest_range','copy_page',dest=65536);add('copy_ecc_error','copy_page',responses=[0x20])
    add('copy_load_fault','copy_page',faults=dict(load=-9));add('copy_program_fault','copy_page',faults=dict(program=-9))
    add('copy_second_feature_fault','copy_page',feature_status=[0,-9]);add('copy_program_failed','copy_page',responses=[0,8])
    add('copy_oob_excess','copy_oob',size=65);add('copy_oob_cache_fault','copy_oob',faults=dict(cache_write_oob=-9))
    add('copy_oob_plane','copy_oob',plane=True,page=600|64)
    add('erase_tick_ready','erase',blocking=False);add('erase_command_fault','erase',faults=dict(erase_command=-9))
    add('erase_failed_status','erase',responses=[4]);add('erase_feature_fault','erase',feature_status=[-9])
    add('erase_poll_timeout','erase',responses=[1]);add('erase_tick_timeout','erase',blocking=False,responses=[1])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=300000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual page read/write/copy/copy-OOB/erase policy and both busy loops execute; remapping, command builders, feature reads and workaround are supplied.',
            'Original first chip descriptor is used, with a separately identified authored plane-flag variant. Responses and helper faults are fixtures.',
            'Injected command-helper returns exercise outer branches; actual builders normally return zero or assert on HAL faults.',
            'No physical cache, page, ECC correction, BBT map, program/erase, persistence or device boot is validated.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND page policy: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
