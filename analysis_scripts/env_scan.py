#!/usr/bin/env python3
"""Cold-cache lookup and reservation policy over synthetic sector headers.

Detailed sector free-space decoding and GC relocation are supplied boundaries.
Cache-empty fixtures do not execute startup or establish reboot persistence.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile
import zlib

if __package__:
    from .env_records import record, marker, state, word, put
    from .recovery_validator import BOOT_HASH, digest, image_memory, table
else:
    from env_records import record, marker, state, word, put
    from recovery_validator import BOOT_HASH, digest, image_memory, table

BASE=0x6000
KEY=0x81200000
DESC=0x81210000
OUTPUT=0x81220000
LENGTH=0x81230000
HEADER=0x81240000
CONTEXT=0x81250000
CONFIG=dict(find=0x80c0cdf6,get=0x80c0d344,next=0x80c0c364,header=0x80c0c818,
    reserve=0x80c0ca72,retry=0x80c0cb7a,maintenance=0x80c0cb16,walk=0x80c0cd82,
    strlen=0x80c2e57c,strncmp=0x80c2e5e8,read_service=0x80c24446,
    gc=0x80c0d27e,logger=0x80c1cd7a,diagnostic=0x80c0c120)
RANGES=((0x80c0bf58,0x8a),(0x80c0c0f6,0x22),(0x80c0c2f0,0x1c),
        (0x80c0c364,0x3e),(0x80c0c3a2,0x22a),(0x80c0c6d4,0x24),
        (0x80c0c6f8,0x120),(0x80c0c818,0x3b2),(0x80c0cd82,0x154),
        (0x80c0d344,0x70),(0x80c0d85c,4),(0x80c00b24,0x2e))
TARGETS=(0x80c0c364,0x80c0c818,0x80c0c44c,0x80c0c54c,0x80c0c59c,
         0x80c0c6d4,0x80c0c9fe,0x80c0ca72,0x80c0cb7a,0x80c0cb16,0x80c0c392,0x80c0cd82)


def sector(primary=1,dirty=1,link=0xffffffff,valid=True,free=4076,cursor=0):
    return dict(primary=primary,dirty=dirty,link=link,valid=valid,free=free,cursor=cursor)


class Model:
    def __init__(self,c):
        self.c=c;self.flash=bytearray(b'\xff'*0x4000);self.actions=[];self.flag=c['maintenance_flag']
        self.output=bytearray(b'\xa5'*256);self.length=0xa5a5a5a5;self.desc=bytearray(56)
        self.header=bytearray(24);self.cache=0xffffffff
        for i,s in enumerate(c['sectors']):
            at=i*4096;self.flash[at:at+3]=marker(s['primary'],4);self.flash[at+3:at+6]=marker(s['dirty'],4)
            self.flash[at+8:at+12]=b'EF40' if s['valid'] else b'BAD!';put(self.flash,at+12,s['link'])
        for entry in c['records']:
            data=record(entry['key'],bytes.fromhex(entry['payload_hex']));data[:5]=marker(entry['state'])
            if entry['bad_crc']:data[16]^=1
            self.flash[entry['offset']:entry['offset']+len(data)]=data
    def read(self,at,n):
        if not BASE<=at or at+n>BASE+len(self.flash):raise ValueError('synthetic storage extent')
        self.actions.append(f'read:{at}:{n}');return bytes(self.flash[at-BASE:at-BASE+n])
    def header_at(self,at,destination):
        data=self.read(at,20);put(destination,4,at);put(destination,8,word(data,8))
        if data[8:12]!=b'EF40':destination[0]=0;put(destination,12,0xffffffff);return 7
        destination[0]=1;destination[1]=state(data,4);destination[2]=state(data[3:],4);put(destination,12,word(data,12));return 0
    def next_address(self,context):
        at=word(context,4)
        if at==0xffffffff:return BASE
        link=word(context,12);candidate=at+(4096 if link==0xffffffff else link*4096)
        return candidate if candidate<BASE+0x4000 else 0xffffffff
    def contexts(self):
        context=bytearray(24);put(context,4,0xffffffff)
        for _ in range(4):
            at=self.next_address(context)
            if at==0xffffffff:return
            status=self.header_at(at,context);yield context,status
        if self.next_address(context)!=0xffffffff:raise ValueError('bounded noncyclic sector chain')
    def decode(self,at):
        data=self.read(at,28);total=word(data,12);self.desc[0]=state(data,6);put(self.desc,8,total)
        if not 28<=total<=512:raise ValueError('bounded synthetic record')
        crc=0
        for i in range(20,total,32):crc=zlib.crc32(self.read(at+i,min(32,total-i)),crc)
        if crc==word(data,16):
            self.desc[1]=1;self.desc[2]=data[20];put(self.desc,12,word(data,24))
            name=self.read(at+28,data[20]);self.desc[16:16+len(name)]=name;put(self.desc,52,at+28+data[20])
        else:self.desc[1]=0
    def next_record(self,sector_address):
        previous=word(self.desc,48)
        if previous==0xffffffff:return sector_address+20
        if previous>sector_address+4096:return 0xffffffff
        start=previous+(word(self.desc,8) if self.desc[1] else 1)
        for block in range(start,sector_address+0xfec,28):
            data=self.read(block,32)
            for offset in range(28):
                candidate=block-8+offset
                if candidate==sector_address+0xfe4:break
                if data[offset:offset+4]==b'KV40' and candidate>=start:
                    return candidate if word(self.desc,8)!=0 else 0xffffffff
        return 0xffffffff
    def find(self):
        # All fixtures start with empty key and sector caches.
        for context,status in self.contexts():
            if status or context[1] not in (2,3):continue
            put(self.desc,48,0xffffffff)
            for _ in range(8):
                at=self.next_record(word(context,4));put(self.desc,48,at)
                if at==0xffffffff:break
                self.decode(at);key=self.c['key'].encode()
                if self.desc[2]==len(key) and self.desc[1] and self.desc[0]==2 and self.desc[16:16+len(key)]==key:
                    self.cache=at;return 1
            else:raise ValueError('bounded record count')
        return 0
    def details(self,context):
        at=word(context,4);s=self.c['sectors'][(at-BASE)//4096]
        self.actions.append('details:'+str(at));put(context,16,s['free']);put(context,20,s['cursor'] or at+20)
    def reserve(self):
        empty=opened=0
        for context,_ in self.contexts():
            if context[0]:empty+=context[1]==1;opened+=context[1]==2
        def attempt(primary):
            for context,_ in self.contexts():
                if context[1]!=primary:continue
                self.details(context)
                if context[0] and self.c['request']<word(context,16) and (context[2]==1 or context[2]==2 and not self.flag):return word(context,20)
            return 0xffffffff
        result=attempt(2) if opened else 0xffffffff
        if empty and result==0xffffffff:
            if empty==1 and not self.flag:self.actions.append('diagnostic:506');self.flag=1
            else:result=attempt(1)
        return result
    def maintenance(self):
        count=0
        for context,_ in self.contexts():
            if context[1]==1 and context[0]:count+=1
        self.actions.append('diagnostic:603')
        if count<2:
            for context,_ in self.contexts():self.actions.append('gc_boundary:'+str(word(context,4)))
        self.flag=0
    def result(self):
        c=self.c;op=c['operation'];returned=None
        if op in ('find','get'):
            found=self.find()
            if op=='find':returned=found
            elif found:
                self.length=word(self.desc,12);returned=min(c['capacity'],self.length);data=self.read(word(self.desc,52),returned);self.output[:len(data)]=data
            else:self.length=0;returned=0
        elif op=='next':
            context=bytearray(24);put(context,4,c['current']);put(context,12,c['link']);returned=self.next_address(context)
        elif op=='header':returned=self.header_at(BASE+c['header_sector']*4096,self.header)
        elif op=='reserve':returned=self.reserve()
        elif op=='retry':
            returned=self.reserve()
            if returned==0xffffffff and self.flag:self.actions.append('diagnostic:5b4');self.maintenance();returned=self.reserve()
        elif op=='maintenance':self.maintenance()
        else:raise ValueError('unknown operation')
        return dict(actions=self.actions,returned=returned,descriptor_sha256=digest(self.desc) if op=='find' else None,
            header_sha256=digest(self.header),output_sha256=digest(self.output),length_output=self.length,
            key_cache_record=self.cache,maintenance_flag=self.flag,flash_sha256=digest(self.flash))


def contract(c):
    if len(c['sectors'])!=4 or not 0<=c['capacity']<=256 or not 0<c['request']<=4076:raise ValueError('fixture bounds')
    if c['operation'] in ('reserve','retry','maintenance') and any(not s['valid'] for s in c['sectors']):raise ValueError('policy fixtures require valid headers')
    if not c['key'].isascii() or not 1<=len(c['key'])<=32 or '\0' in c['key']:raise ValueError('bounded key')
    return Model(c).result()


def native_vectors():
    cases=[]
    def add(name,operation,**changes):
        c=dict(name=name,operation=operation,key='upgrade',sectors=[sector() for _ in range(4)],records=[],capacity=64,
               maintenance_flag=0,request=100,current=0xffffffff,link=0xffffffff,header_sector=0)|changes
        c['expected']=contract(c);cases.append(c)
    def entry(key='upgrade',offset=20,status=2,bad_crc=False):
        return dict(key=key,offset=offset,state=status,bad_crc=bad_crc,payload_hex=b'payload'.hex())
    def occupied():return [sector(primary=2),sector(),sector(),sector()]
    add('find_first','find',sectors=occupied(),records=[entry()]);add('get_empty_cache','get',sectors=occupied(),records=[entry()])
    add('get_clip','get',sectors=occupied(),records=[entry()],capacity=3)
    for status in (1,3,4):add('find_state_'+str(status),'find',sectors=occupied(),records=[entry(status=status)])
    add('find_bad_crc','find',sectors=occupied(),records=[entry(bad_crc=True)])
    add('find_wrong_name','find',sectors=occupied(),records=[entry(key='unknown')])
    add('find_wrong_length','find',sectors=occupied(),records=[entry(key='up')])
    add('find_second','find',sectors=occupied(),records=[entry(key='unknown'),entry(offset=62)])
    add('find_gap','find',sectors=occupied(),records=[entry(key='unknown'),entry(offset=100)])
    add('find_deleted_then_live','find',sectors=occupied(),records=[entry(status=4),entry(offset=62)])
    add('find_bad_crc_then_live','find',sectors=occupied(),records=[entry(bad_crc=True),entry(offset=62)])
    add('find_duplicate_first','find',sectors=occupied(),records=[entry(),entry(offset=62)])
    add('find_no_open_sectors','find')
    add('find_full_sector','find',sectors=[sector(primary=3),sector(),sector(),sector()],records=[entry()])
    add('find_skip_bad_header','find',sectors=[sector(valid=False),sector(primary=2),sector(),sector()],records=[entry(offset=4096+20)])
    add('find_link2','find',sectors=[sector(primary=2,link=2),sector(primary=2),sector(primary=2),sector()],records=[entry(key='unknown'),entry(offset=8192+20)])
    for name,current,link in (
        ('first',0xffffffff,0xffffffff),('sequential',BASE,0xffffffff),
        ('last',BASE+3*4096,0xffffffff),('link2',BASE,2)):
        add('next_'+name,'next',current=current,link=link)
    add('header_valid','header');add('header_bad','header',sectors=[sector(valid=False),sector(),sector(),sector()])
    add('header_link','header',sectors=[sector(primary=3,dirty=2,link=2),sector(),sector(),sector()])
    add('reserve_open','reserve',sectors=[sector(primary=2,free=101),sector(primary=3),sector(primary=3),sector(primary=3)])
    add('reserve_equal_rejected','reserve',sectors=[sector(primary=2,free=100),sector(primary=3),sector(primary=3),sector(primary=3)])
    add('reserve_none','reserve',sectors=[sector(primary=3) for _ in range(4)])
    add('reserve_two_empty','reserve')
    one=[sector(),sector(primary=3),sector(primary=3),sector(primary=3)]
    add('reserve_last_empty_guard','reserve',sectors=one)
    add('reserve_last_empty_flagged','reserve',sectors=one,maintenance_flag=1)
    for flag in (0,1):add('reserve_dirty2_flag_'+str(flag),'reserve',maintenance_flag=flag,
                         sectors=[sector(primary=2,dirty=2,free=101),sector(primary=3),sector(primary=3),sector(primary=3)])
    add('reserve_dirty3','reserve',sectors=[sector(primary=2,dirty=3,free=101)]+[sector(primary=3) for _ in range(3)])
    add('reserve_second_candidate','reserve',sectors=[sector(primary=2,free=99),sector(primary=2,free=101),sector(primary=3),sector(primary=3)])
    add('maintenance_enough_empty','maintenance',maintenance_flag=1)
    add('maintenance_few_empty','maintenance',sectors=one,maintenance_flag=1)
    add('retry_last_empty','retry',sectors=one)
    add('retry_none_unflagged','retry',sectors=[sector(primary=3) for _ in range(4)])
    add('retry_flagged_failure','retry',maintenance_flag=1,sectors=[sector(primary=3) for _ in range(4)])
    add('retry_flag_clear_enables_dirty','retry',maintenance_flag=1,
        sectors=[sector(primary=2,dirty=2,free=101),sector(primary=3),sector(primary=3),sector(primary=3)])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=200000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    if memory.read(0x80c32e8c,1024)!=table():raise ValueError('CRC table')
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},crc_table_sha256=digest(table()),
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Synthetic EF40 sector headers and KV40 records; complete reads, empty key/sector caches and bounded noncyclic chains.',
            'Detailed sector parsing at full=1 and GC relocation callbacks are supplied, not executed.',
            'Header/light decoding, traversal, record search, CRC/filtering and reservation/maintenance scheduling execute.',
            'No actual startup, post-reset reconstruction, flash I/O, writes, power-loss recovery or physical persistence is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.vectors,a.validation,a.decompiled)):p.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect environment scan: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
