#!/usr/bin/env python3
"""Actual detailed sector parsing and reservation over synthetic flash bytes.

No detailed-space callback is supplied. Low-level reads/writes are synthetic;
startup, GC relocation/erase and physical persistence remain outside scope.
"""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from .env_scan import Model as ScanModel, CONFIG as SCAN_CONFIG, RANGES as SCAN_RANGES, BASE, sector
    from .env_records import state, word, put
    from .recovery_validator import BOOT_HASH, digest, image_memory, table
else:
    from env_scan import Model as ScanModel, CONFIG as SCAN_CONFIG, RANGES as SCAN_RANGES, BASE, sector
    from env_records import state, word, put
    from recovery_validator import BOOT_HASH, digest, image_memory, table

CONFIG=SCAN_CONFIG|dict(space=0x80c0c818,memset=0x80c2e014,write_service=0x80c24502,warn=0x80c0c220)
RANGES=tuple((a,0x74 if a==0x80c0c2f0 else n) for a,n in SCAN_RANGES)+((0x80c0bfe2,0x8a),(0x80c0c5cc,0x94))
TARGETS=(0x80c0c818,0x80c0c30a,0x80c0c44c,0x80c0c6f8,0x80c0c5cc,
         0x80c0bfe2,0x80c0c9fe,0x80c0ca72,0x80c0c59c)


class Model(ScanModel):
    def __init__(self,c):
        super().__init__(c);self.ends=bytearray(b'\xff'*32);self.write_count=0
        for r in c['records']:
            if r['total_override'] is not None:put(self.flash,r['offset']+12,r['total_override'])
        for patch in c['patches']:
            data=bytes.fromhex(patch['hex']);self.flash[patch['offset']:patch['offset']+len(data)]=data
        for entry in c['warm_cache']:
            put(self.ends,entry['slot']*8,BASE+entry['sector']*4096);put(self.ends,entry['slot']*8+4,entry['cursor'])
    def write_marker(self,at):
        self.write_count+=1;result=-1 if self.c['write_error'] and self.write_count==1 else 1
        self.actions.append(f'write:{at}:1:{result}:{digest(bytes(1))}')
        if result<0:self.actions.append('log:write_error');return
        self.flash[at-BASE]=0
    def decode(self,at):
        total=word(self.flash,at-BASE+12)
        if 28<=total<=512:return super().decode(at)
        if total not in (0,0xffffffff):raise ValueError('bounded invalid length fixture')
        data=self.read(at,28);status=state(data,6);self.desc[0]=status;put(self.desc,8,28)
        if status!=5:
            self.desc[0]=5;self.actions.append('diagnostic:283');self.write_marker(at+4)
        self.desc[1]=0
    def cached_end(self,at):
        for i in range(4):
            if word(self.ends,i*8)==at:return word(self.ends,i*8+4)
        return None
    def update_end(self,at,cursor):
        free_slot=None
        for i in range(4):
            existing=word(self.ends,i*8)
            if at<cursor<at+4096:
                if existing==at:put(self.ends,i*8+4,cursor);return
                if existing==0xffffffff and free_slot is None:free_slot=i
            elif existing==at:put(self.ends,i*8,0xffffffff);return
        if free_slot is not None:
            put(self.ends,free_slot*8,at);put(self.ends,free_slot*8+4,cursor)
    def full_at(self,at,target):
        status=super().header_at(at,target)
        if status:return status
        put(target,16,0);put(target,20,at+20)
        if target[1]==1:put(target,16,4076);return 0
        if target[1]!=2:return 0
        cached=self.cached_end(at)
        if cached is not None:put(target,20,cached);put(target,16,at+4096-cached);return 0
        put(target,16,4076);self.desc=bytearray(56);put(self.desc,48,0xffffffff);result=0
        for _ in range(8):
            address=self.next_record(at);put(self.desc,48,address)
            if address==0xffffffff:break
            self.decode(address)
            if not self.desc[1] and self.desc[0]&0xfb!=1:
                self.actions.append('warn:record_integrity');put(target,16,0);result=2;break
            put(target,20,word(target,20)+word(self.desc,8));put(target,16,word(target,16)-word(self.desc,8))
        else:raise ValueError('bounded record count')
        start=word(target,20);candidate=start;previous=0
        for block in range(start,at+4096,32):
            data=self.read(block,min(32,at+4096-block))
            for i,byte in enumerate(data):
                if previous!=255 and byte==255:candidate=block+i
                previous=byte
        if previous!=255:candidate=at+4096
        if candidate!=start:put(target,20,candidate);put(target,16,at+4096-candidate)
        self.update_end(at,word(target,20));return result
    def details(self,context):self.full_at(word(context,4),context)
    def result(self):
        rows=[]
        for operation in self.c['operations']:
            returned=self.full_at(BASE+self.c['space_sector']*4096,self.header) if operation=='space' else self.reserve()
            rows.append(dict(returned=returned,header_sha256=digest(self.header),free=word(self.header,16),cursor=word(self.header,20),
                sector_cache_sha256=digest(self.ends),maintenance_flag=self.flag,flash_sha256=digest(self.flash)))
        return dict(actions=self.actions,rows=rows)


def contract(c):
    if len(c['sectors'])!=4 or not 0<c['request']<=4076 or not 0<=c['space_sector']<4:raise ValueError('bounded sector fixture')
    if not c['operations'] or any(op not in ('space','reserve') for op in c['operations']):raise ValueError('bounded operations')
    for r in c['records']:
        if not 1<=len(r['key'])<=32 or len(bytes.fromhex(r['payload_hex']))>128:raise ValueError('bounded record fixture')
    for entry in c['warm_cache']:
        at=BASE+entry['sector']*4096
        if not 0<=entry['slot']<4 or not 0<=entry['sector']<4 or not at<=entry['cursor']<=at+4096:raise ValueError('bounded cache fixture')
    return Model(c).result()


def native_vectors():
    cases=[]
    def entry(offset=20,status=2,bad=False,total=None):
        return dict(key='upgrade',offset=offset,state=status,bad_crc=bad,total_override=total,payload_hex=b'payload'.hex())
    def add(name,operations=None,**changes):
        c=dict(name=name,operations=operations or ['space'],key='upgrade',sectors=[sector(primary=2)]+[sector(primary=3) for _ in range(3)],
               records=[entry()],patches=[],warm_cache=[],write_error=False,maintenance_flag=0,request=100,space_sector=0)|changes
        c['expected']=contract(c);cases.append(c)
    add('space_one');add('space_twice',['space','space']);add('space_then_reserve',['space','reserve'])
    add('space_two',records=[entry(),entry(offset=62)])
    add('space_gap',records=[entry(),entry(offset=100)])
    add('space_erased_open',records=[]);add('space_erased_write_error',records=[],write_error=True)
    for value in (0,0xffffffff):add('space_invalid_length_'+str(value),records=[entry(total=value)])
    add('space_bad_header',sectors=[sector(valid=False)]+[sector(primary=3) for _ in range(3)])
    for value in (0,1,3):add('space_primary_'+str(value),sectors=[sector(primary=value)]+[sector(primary=3) for _ in range(3)])
    for value in (1,2,3,4,5):add('space_bad_crc_state_'+str(value),records=[entry(status=value,bad=True)])
    add('space_bad_crc_twice',['space','space'],records=[entry(bad=True)])
    add('space_incomplete',records=[entry(status=1)])
    add('space_deleted',records=[entry(status=4)])
    add('space_tail_noise',patches=[dict(offset=100,hex='00010203')])
    add('space_tail_holes',patches=[dict(offset=100,hex='00ff00ffffff00ff')])
    add('space_tail_last_byte',patches=[dict(offset=4095,hex='00')])
    add('space_tail_chunk_boundary',patches=[dict(offset=93,hex='00')])
    for slot,cursor in ((0,BASE+20),(2,BASE+100),(3,BASE+4096)):
        add('space_warm_slot_'+str(slot),warm_cache=[dict(slot=slot,sector=0,cursor=cursor)])
    add('space_warm_bad_crc',records=[entry(bad=True)],warm_cache=[dict(slot=0,sector=0,cursor=BASE+62)])
    add('reserve_cold',['reserve']);add('reserve_exact',['reserve'],request=4034)
    add('reserve_below',['reserve'],request=4033)
    add('reserve_bad_crc',['reserve'],records=[entry(bad=True)])
    add('space_bad_then_reserve',['space','reserve'],records=[entry(bad=True)])
    add('reserve_tail_full',['reserve'],patches=[dict(offset=4095,hex='00')])
    add('reserve_second_sector',['reserve'],records=[entry(),entry(offset=4096+20)],patches=[dict(offset=4095,hex='00')],
        sectors=[sector(primary=2),sector(primary=2),sector(primary=3),sector(primary=3)])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=300000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    if memory.read(0x80c32e8c,1024)!=table():raise ValueError('CRC table')
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},crc_table_sha256=digest(table()),
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Native detailed EF40 parsing, record CRC/search, tail scan, sector end cache and reservation execute; no detailed-space callback is supplied.',
            'Device reads/writes use synthetic arrays; status programming is modeled as bytewise AND. Complete reads, bounded records and selected invalid lengths only.',
            'No actual startup, GC relocation/erase, physical I/O, power-loss simulation or persistence guarantee.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.vectors,a.validation,a.decompiled)):p.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect environment space: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
