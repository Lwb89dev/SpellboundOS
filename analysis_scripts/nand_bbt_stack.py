#!/usr/bin/env python3
"""Original BBT verification/resume/repair and subsequent reads through NAND/QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile
import zlib

if __package__:
    from . import eftl_scan_stack as scan
    from . import nand_bbt as bbt
else:
    import eftl_scan_stack as scan
    import nand_bbt as bbt

qspi=scan.qspi
EXTRA_RANGES=tuple(r for r in bbt.RANGES if r not in scan.RANGES)
RANGES=scan.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
DATA_RANGES=scan.repair.mutation.storage.DATA_RANGES+((0x80c32e8c,1024),(0x80c3d324,4))


class BbtMixin:
    def init_bbt(self):
        self.bbt_state=bytearray.fromhex(self.c['bbt_hex']);self.loaded_page=0;self.cache_at=0
        self.bbt_status_reads=0;self.bbt_resume_result=None;self.bbt_follow_return=None
    def bword(self,at):return struct.unpack_from('<I',self.bbt_state,at)[0]
    def bput(self,at,v):
        struct.pack_into('<I',self.bbt_state,at,v&0xffffffff);self.sync_bbt()
    def sync_bbt(self):self.c['bbt_hex']=self.bbt_state.hex()
    def write(self,offset,value,size=4):
        if offset==12 and value>>24==0x13:self.loaded_page=self.regs[0]
        if offset==12 and value>>24==0x6b:self.cache_at=0
        return super().write(offset,value,size)
    def read(self,offset,size=4):
        if offset!=256:return super().read(offset,size)
        op=self.regs[12]>>24
        if op==0x0f and self.regs[0]==192:
            values=self.c['responses'];value=values[min(self.bbt_status_reads,len(values)-1)]
            self.bbt_status_reads+=1;self.feature_reads+=1
        elif op==0x6b:
            block=self.loaded_page//64;column=self.regs[0]
            if column==2048:data=b'\xff\xff' if block in self.c['bbt_good_blocks'] else b'\0\0'
            elif column==0:data=bytes.fromhex(self.c['bbt_record_hex'].get(str(block),bbt.record(dict(bad=[],magic=0)).hex()))
            elif column==16:data=bytes(range(32))
            else:raise ValueError('bounded BBT cache column')
            if self.cache_at+size>len(data):raise ValueError('BBT FIFO payload bound')
            value=int.from_bytes(data[self.cache_at:self.cache_at+size],'little');self.cache_at+=size
        else:return super().read(offset,size)
        self.rx+=size;self.actions.append(f'r:{offset}:{size}:{value}');return value
    def bbt_read(self,block):
        saved=self.buffer;self.buffer=bytearray(512)
        result=self.page_read(block*64,0,140,True);data=bytes(self.buffer[:140]);self.buffer=saved
        return result,data
    def verify_bbt(self,block):
        result,data=self.bbt_read(block)
        if self.stopped or result:return 0
        self.actions.append('log:bbt_record');magic,count,checksum=struct.unpack_from('<3I',data)
        if magic!=bbt.MAGIC:self.actions.append('log:bbt_magic_error');return 0
        if count>self.bword(152)-2:self.actions.append('log:bbt_count_error');return 0
        entries=data[12:12+count*2];self.actions.append(f'bbt_crc:{len(entries)}:'+qspi.digest(entries))
        if zlib.crc32(entries)!=checksum:self.actions.append('log:bbt_crc_error');return 0
        self.bbt_state[:140]=data;self.sync_bbt();self.actions.extend(('bbt_publish:140','log:bbt_loaded'))
        for start in range(0,count,20):
            for i in range(start,min(start+20,count)):self.actions.append('bbt_format:'+str(struct.unpack_from('<H',data,12+i*2)[0]))
            self.actions.append('log:bbt_entries')
        return 1
    def check_bbt_block(self,block):
        self.actions.append('bbt_bad:'+str(block));return self.bad_marker(block,True)
    def erase_bbt(self,block):
        mapped=self.map(block,True)
        if mapped is None:return -151
        if self.bus(6)[0] or self.bus(0xd8,mapped*64,3)[0]:return None
        status=self.poll(4000)
        if self.stopped:return None
        if status&4:self.actions.append('log:erase_result');return -104
        return 0
    def write_bbt(self,block,data):
        page=self.map(block*64)
        if page is None:self.actions.append('log:page_result');return -150
        if self.bus(6)[0]:return None
        saved=self.buffer;self.buffer=bytearray(data)+bytearray(512-len(data))
        failed,_=self.bus(0x32,0,2,140,0,3,True);self.buffer=saved
        if failed or self.bus(0x10,page,3)[0]:return None
        status=self.poll(2000)
        if self.stopped:return None
        if status&8:self.actions.append('log:page_result');return -102
        return 0
    def resume_bbt(self):
        self.actions.append('bbt_resume:1024:2048:64');self.bbt_state[:]=b'\0'*164;self.sync_bbt()
        for at,v in ((140,1024),(144,2048),(148,64),(152,16)):self.bput(at,v)
        scan_index=1024;primary=0
        while True:
            self.bput(156,primary);scan_index-=1;backup=self.bword(160)
            if scan_index<1008:break
            if not self.bword(156):
                result=self.check_bbt_block(scan_index)
                if self.stopped:return None
                if result==0:primary=scan_index;continue
            primary=self.bword(156)
            if self.bword(160):continue
            backup=scan_index;result=self.check_bbt_block(scan_index)
            if self.stopped:return None
            if result:continue
            break
        self.bput(160,backup)
        if not self.bword(156) or not self.bword(160):
            self.actions.append('log:bbt_too_many_bad');self.stopped=dict(kind='assertion',owner=0x80c3d3b0,line=0xac);return None
        if self.verify_bbt(self.bword(156)):self.bbt_resume_result=0;return 0
        if self.stopped:return None
        if not self.verify_bbt(self.bword(160)):
            if self.stopped:return None
            self.actions.append('log:bbt_no_bbt');self.bbt_resume_result=1;return 1
        self.bput(0,0);status,data=self.bbt_read(self.bword(160))
        if self.stopped:return None
        if status==0:
            status=self.erase_bbt(self.bword(156))
            if self.stopped:return None
            if status==0:status=self.write_bbt(self.bword(156),data)
        if self.stopped:return None
        if status:self.actions.append('log:bbt_repair_failed')
        self.bput(0,bbt.MAGIC);self.bbt_resume_result=0;return 0
    def bbt_snapshot(self,row):
        row.update(bbt_state_hex=self.bbt_state.hex(),bbt_status_reads=self.bbt_status_reads,
            bbt_resume_result=self.bbt_resume_result,bbt_follow_return=self.bbt_follow_return)


class Model(BbtMixin,scan.Model):
    def __init__(self,c):super().__init__(dict(c));self.init_bbt()
    def storage_mutation(self):
        value=self.resume_bbt() if self.c['bbt_entry']=='resume' else self.verify_bbt(self.c['bbt_verify_block'])
        if not self.stopped and self.c['bbt_follow_read']:
            self.bbt_follow_return=self.page_read(self.c['bbt_follow_page'],16,32,True)
            if self.stopped:self.bbt_follow_return=None
            elif self.bbt_follow_return is not None:self.bbt_follow_return&=0xffffffff
        return value
    def run(self):
        result=scan.repair.Model.run(self);self.bbt_snapshot(result['rows'][0]);return result


def contract(c):
    if c['mode']!='platform_mutation' or not c['native_bbt_stack'] or c['bbt_entry'] not in ('resume','verify'):raise ValueError('BBT entry')
    state=bytes.fromhex(c['bbt_hex'])
    if len(state)!=164 or struct.unpack_from('<4I',state,140)!=(1024,2048,64,16):raise ValueError('selected BBT geometry')
    if c['bbt_verify_block'] not in (1022,1023) or not 0<=c['bbt_follow_page']<65536:raise ValueError('BBT read bound')
    if len(c['bbt_good_blocks'])>16 or any(not 1008<=v<1024 for v in c['bbt_good_blocks']):raise ValueError('BBT tail backing')
    if not c['responses'] or len(c['responses'])>64 or any(v not in (0,4,8,32) for v in c['responses']):raise ValueError('BBT statuses')
    for key,spec in c['bbt_records'].items():
        if not 1008<=int(key)<1024 or len(spec['bad'])>64 or any(not 0<=v<=65535 for v in spec['bad']):raise ValueError('BBT record backing')
    if c['bbt_record_hex']!={k:bbt.record(v).hex() for k,v in c['bbt_records'].items()}:raise ValueError('BBT encoded records')
    scan.contract(c|dict(native_bbt_stack=False,responses=[0],scan_count=0))
    return Model(c).run()


def native_vectors():
    base=scan.native_vectors()['cases'][0];cases=[]
    def add(name,records=None,**changes):
        seed=dict(active=False,bad=[],blocks=1024,page_size=2048,ppb=64,reserve=16,primary=1023,backup=1022)
        c=base|dict(name=name,native_bbt_stack=True,bbt_entry='resume',bbt_verify_block=1023,
            bbt_follow_read=False,bbt_follow_page=600,bbt_good_blocks=[1023,1022],
            bbt_records={'1023':dict(bad=[1,3,7])} if records is None else records,
            bbt_hex=bbt.initial(seed).hex(),responses=[0],scan_count=8)|changes
        c['bbt_record_hex']={k:bbt.record(v).hex() for k,v in c['bbt_records'].items()}
        c['expected']=contract(c);cases.append(c)
    add('bbt_primary');add('bbt_primary_then_read',bbt_follow_read=True)
    backup={'1022':dict(bad=[1,3,7])}
    add('bbt_backup_repair',records=backup);add('bbt_backup_then_read',records=backup,bbt_follow_read=True)
    add('bbt_backup_reread_error',records=backup,responses=[0]*8+[32,0],bbt_follow_read=True)
    add('bbt_backup_erase_error',records=backup,responses=[0]*9+[4,0],bbt_follow_read=True)
    add('bbt_backup_program_error',records=backup,responses=[0]*10+[8,0],bbt_follow_read=True)
    add('bbt_both_invalid',records={},bbt_follow_read=True)
    add('bbt_primary_crc_bad',records={'1023':dict(bad=[1],bad_crc=True)}|backup)
    add('bbt_primary_ecc_bad',responses=[0]*6+[32,0],records={'1023':dict(bad=[1])}|backup)
    add('bbt_skip_bad_tail',bbt_good_blocks=[1022,1020],records={'1022':dict(bad=[1])})
    add('bbt_no_good_blocks',bbt_good_blocks=[],records={})
    add('bbt_only_one_good',bbt_good_blocks=[1023],records={})
    add('bbt_verify',bbt_entry='verify')
    add('bbt_verify_bad_crc',bbt_entry='verify',records={'1023':dict(bad=[1],bad_crc=True)})
    add('bbt_count_exceeds',bbt_entry='verify',records={'1023':dict(bad=list(range(15)))})
    add('bbt_count_limit',bbt_entry='verify',records={'1023':dict(bad=list(range(14)))})
    add('bbt_unsorted',records={'1023':dict(bad=[7,1])},bbt_follow_read=True,bbt_follow_page=64)
    add('bbt_duplicates',records={'1023':dict(bad=[1,1])},bbt_follow_read=True,bbt_follow_page=64)
    active=dict(active=True,bad=[1,3,7],blocks=1024,page_size=2048,ppb=64,reserve=16,primary=1023,backup=1022)
    add('bbt_verify_active_rejected',bbt_entry='verify',bbt_hex=bbt.initial(active).hex())
    add('bbt_follow_reserved',bbt_follow_read=True,bbt_follow_page=65216)
    return dict(schema=1,bound_per_case=scan.repair.read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=scan.repair.read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=scan.repair.read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual BBT verify/CRC/resume/backup repair and subsequent mapped page reads execute through original bad-marker/page/program/erase/BBT/bus/QSPI code.',
            'Geometry, initial RAM, marker and record FIFO bytes, status scripts and peripheral/RTOS/library leaf effects are authored; physical erase/program/persistence is not modeled.',
            'Restored RAM magic and zero return after repair errors do not prove redundant persistent copies or successful device boot/recovery.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect connected BBT recovery: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
