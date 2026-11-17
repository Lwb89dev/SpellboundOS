#!/usr/bin/env python3
"""NAND BBT verification, resume and remapping with authored storage records."""
import argparse
import json
from pathlib import Path
import struct
import zipfile
import zlib

if __package__:
    from .recovery_validator import BOOT_HASH,digest,image_memory
else:
    from recovery_validator import BOOT_HASH,digest,image_memory

BASE=0x80df42cc
MAGIC=0x746242
MASK=0xffffffff
CONFIG=dict(verify=0x80c27662,resume=0x80c2785a,block=0x80c279d8,page=0x80c27a18,active=0x80c27a78,
    crc=0x80c00b24,bad_check=0x80c29042,read=0x80c28a98,write=0x80c28c06,erase=0x80c291e6,
    zero=0x80c2e014,copy=0x80c2de38,format=0x80c2e1e8,logger=0x80c1cd7a,assertion=0x80c16516)
RANGES=((0x80c27662,504),(0x80c2785a,382),(0x80c279d8,64),(0x80c27a18,96),(0x80c27a78,24),(0x80c00b24,46))
TARGETS=tuple(a for a,n in RANGES)
LOGS={0x80c3d218:'record',0x80c3d26c:'magic_error',0x80c3d29c:'count_error',0x80c3d2c8:'crc_error',
    0x80c3d304:'loaded',0x80c3d328:'entries',0x80c3d340:'too_many_bad',0x80c3d360:'repair_failed',0x80c3d384:'no_bbt'}


def record(spec):
    data=bytearray(b'\xff'*140)
    entries=struct.pack('<'+'H'*len(spec['bad']),*spec['bad'])
    struct.pack_into('<III',data,0,spec.get('magic',MAGIC),len(spec['bad']),zlib.crc32(entries)^int(spec.get('bad_crc',False)))
    data[12:12+len(entries)]=entries
    return bytes(data)


def initial(c):
    data=bytearray(record(dict(bad=c['bad'],magic=MAGIC if c['active'] else 0)))
    return data+struct.pack('<6I',c['blocks'],c['page_size'],c['ppb'],c['reserve'],c['primary'],c['backup'])


class Model:
    def __init__(self,c):
        self.c=c;self.state=initial(c);self.output=0xa5a5a5a5;self.actions=[];self.rows=[];self.reads=0
    def word(self,at):return struct.unpack_from('<I',self.state,at)[0]
    def put(self,at,value):struct.pack_into('<I',self.state,at,value&MASK)
    def log(self,name):self.actions.append('log:'+name)
    def read(self,block):
        c=self.c;spec=c['records'].get(str(block),dict(bad=[],magic=0,read_status=0))
        status=c['reread_status'] if self.reads==2 else spec.get('read_status',0);self.reads+=1
        data=record(spec)
        self.actions.append(f'read:{(block*self.word(148))&MASK}:140:{self.word(0)}:{status}')
        return status,data
    def verify(self,block):
        status,data=self.read(block)
        if status:return 0
        self.log('record');magic,count,checksum=struct.unpack_from('<III',data)
        if magic!=MAGIC:self.log('magic_error');return 0
        if count>((self.word(152)-2)&MASK):self.log('count_error');return 0
        payload=data[12:12+count*2];self.actions.append(f'crc:{len(payload)}:{digest(payload)}')
        if zlib.crc32(payload)!=checksum:self.log('crc_error');return 0
        self.state[:140]=data;self.actions.append('publish:140');self.log('loaded')
        for start in range(0,count,20):
            for i in range(start,min(start+20,count)):self.actions.append('format:'+str(struct.unpack_from('<H',data,12+i*2)[0]))
            self.log('entries')
        return 1
    def map_block(self,value):
        if self.word(0)!=MAGIC:return 0,value
        end=(value+self.word(4))&MASK
        i=0
        while value!=end and struct.unpack_from('<H',self.state,12+2*i)[0]<=value:
            value=(value+1)&MASK;i+=1
        if value>=self.word(160):return MASK,self.output
        return 0,value
    def map(self,page=False):
        c=self.c;value=c['value']
        if page and self.word(0)==MAGIC:
            ppb=self.word(148);status,mapped=self.map_block(value//ppb)
            if status:return MASK
            self.output=(value%ppb+ppb*mapped)&MASK;return 0
        status,mapped=self.map_block(value)
        if not status:self.output=mapped
        return status
    def bad(self,block):
        status=0 if block in self.c['good_blocks'] else 103
        self.actions.append(f'bad_check:{block}:1:{status}');return status
    def resume(self):
        c=self.c;self.state=bytearray(164)
        for at,v in ((140,c['blocks']),(144,c['page_size']),(148,c['ppb']),(152,c['blocks']>>6)):self.put(at,v)
        scan=c['blocks'];primary=0
        while True:
            self.put(156,primary);scan=(scan-1)&MASK;backup=self.word(160)
            if scan<((c['blocks']-self.word(152))&MASK):break
            if self.word(156)==0 and self.bad(scan)==0:primary=scan;continue
            primary=self.word(156)
            if self.word(160)!=0:continue
            backup=scan
            if self.bad(scan)!=0:continue
            break
        self.put(160,backup)
        if not self.word(156) or not self.word(160):
            self.log('too_many_bad');return None,dict(kind='assertion',owner=0x80c3d3b0,line=0xac)
        if self.verify(self.word(156)):return 0,None
        if not self.verify(self.word(160)):self.log('no_bbt');return 1,None
        self.put(0,0);status,data=self.read(self.word(160))
        if not status:
            status=c['erase_status'];self.actions.append(f'erase:{self.word(156)}:1:{self.word(0)}:{status}')
            if not status:
                status=c['write_status'];self.actions.append(f'write:{(self.word(156)*self.word(148))&MASK}:140:{self.word(0)}:{digest(data)}:{status}')
        if status:self.log('repair_failed')
        self.put(0,MAGIC);return 0,None
    def snapshot(self,result,stopped=None):
        self.rows.append(dict(returned=result,stopped=stopped,state_hex=self.state.hex(),output=self.output))
    def run(self):
        c=self.c;mode=c['mode'];stopped=None
        if mode.startswith('resume'):result,stopped=self.resume()
        elif mode.startswith('verify'):result=self.verify(c['verify_block'])
        elif mode=='active':result=int(self.word(0)==MAGIC)
        else:result=self.map(mode=='page')
        self.snapshot(result,stopped)
        if mode.endswith('_map') and stopped is None:
            self.snapshot(self.map(c['map_page']))
        return dict(actions=self.actions,rows=self.rows)


def contract(c):
    if not 64<=c['blocks']<=4096 or not 1<=c['ppb']<=128:raise ValueError('bounded geometry')
    if len(c['bad'])>64 or any(not 0<=v<=65535 for v in c['bad']):raise ValueError('bounded initial BBT')
    for spec in c['records'].values():
        if len(spec['bad'])>64 or any(not 0<=v<=65535 for v in spec['bad']):raise ValueError('bounded BBT record')
    return Model(c).run()


def native_vectors():
    cases=[]
    def add(name,mode='block',**changes):
        c=dict(name=name,mode=mode,active=True,bad=[1,3,7],blocks=1024,page_size=2048,ppb=64,reserve=16,
            primary=1023,backup=1022,value=1,verify_block=1023,map_page=False,good_blocks=[1023,1022],
            records={'1023':dict(bad=[1,3,7])},reread_status=0,erase_status=0,write_status=0)|changes
        c['initial_hex']=initial(c).hex()
        c['record_hex']={block:record(spec).hex() for block,spec in c['records'].items()}
        c['expected']=contract(c);cases.append(c)
    add('inactive_block_passthrough',active=False,value=0xffffffff)
    add('inactive_page_passthrough','page',active=False,value=0xffffffff)
    add('active_true','active');add('active_false','active',active=False)
    for value in (0,1,2,3,4,5,7,8,1018,1019,1021,1022,1023):add('block_'+str(value),value=value)
    add('empty_table',bad=[],value=1021);add('duplicate_entries',bad=[1,1],value=1)
    add('unsorted_entries',bad=[7,1],value=1);add('block_wraps_to_zero',bad=[1],value=0xffffffff)
    for value in (0,63,64,65,127,128,191,511,65215,65216):add('page_'+str(value),'page',value=value)
    add('page_different_ppb','page',ppb=128,value=129)
    add('verify_valid','verify',active=False);add('verify_empty','verify',records={'1023':dict(bad=[])})
    add('verify_bad_magic','verify',records={'1023':dict(bad=[1],magic=0)})
    add('verify_bad_crc','verify',records={'1023':dict(bad=[1],bad_crc=True)})
    add('verify_count_limit','verify',records={'1023':dict(bad=list(range(14)))})
    add('verify_count_exceeds','verify',records={'1023':dict(bad=list(range(15)))})
    add('verify_read_error','verify',records={'1023':dict(bad=[1],read_status=-9)})
    add('verify_two_log_groups','verify',reserve=64,records={'1023':dict(bad=list(range(21)))})
    add('verify_max_reserved_count','verify',blocks=4096,reserve=64,records={'1023':dict(bad=list(range(62)))})
    add('verify_then_map','verify_map',active=False,value=3)
    add('verify_then_page','verify_map',active=False,value=193,map_page=True)
    add('verify_unsorted_then_map','verify_map',active=False,value=1,records={'1023':dict(bad=[7,1])})
    add('verify_duplicate_then_map','verify_map',active=False,value=1,records={'1023':dict(bad=[1,1])})
    add('resume_primary','resume_map',value=3)
    backup={'1022':dict(bad=[1,3,7])}
    add('resume_backup','resume_map',records=backup,value=3)
    add('resume_backup_reread_error','resume_map',records=backup,reread_status=-9,value=3)
    add('resume_backup_erase_error','resume_map',records=backup,erase_status=-9,value=3)
    add('resume_backup_write_error','resume_map',records=backup,write_status=-9,value=3)
    add('resume_both_invalid','resume_map',records={},value=3)
    add('resume_primary_crc_error','resume',records={'1023':dict(bad=[1],bad_crc=True)}|backup)
    add('resume_skips_bad_tail','resume',good_blocks=[1022,1020],records={'1022':dict(bad=[1])})
    add('resume_last_reserved_pair','resume',good_blocks=[1009,1008],records={'1009':dict(bad=[])})
    add('resume_no_good','resume',good_blocks=[],records={})
    add('resume_only_one_good','resume',good_blocks=[1023],records={})
    add('resume_one_reserved_block','resume',blocks=64,good_blocks=[63],records={})
    add('resume_4096_blocks','resume',blocks=4096,page_size=4096,good_blocks=[4095,4094],records={'4095':dict(bad=[1,2])})
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
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual BBT verifier/resume/remappers/active query and CRC execute over authored records and RAM state; page read/write/erase, bad-block checks and formatting are supplied.',
            'Malformed ordering/duplicates and wrapping inputs are bounded counterexamples; no corresponding physical table corruption is observed.',
            'Repair callbacks simulate storage effects only. Assertion cases stop before the assertion body and claim no return ABI.',
            'Physical BBT provenance, initial table creation, repair atomicity, ECC, UID, lower HAL/ROM and standalone device boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND BBT: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
