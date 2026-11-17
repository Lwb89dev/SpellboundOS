#!/usr/bin/env python3
"""Native boot KV records with synthetic NOR-like storage and supplied sector scan.

The model covers a single key/cache slot. It does not establish device flash
semantics, reboot reconstruction, garbage collection or power-loss recovery.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile
import zlib

if __package__:
    from .recovery_validator import BOOT_HASH, digest, image_memory, table
    from .boot_environment import upgrade_record
else:
    from recovery_validator import BOOT_HASH, digest, image_memory, table
    from boot_environment import upgrade_record

BASE=0x4000
EXTENT=0x8000
OLD=0x6014
CURSOR=0x7014
KEY=0x81200000
INPUT=0x81210000
OUTPUT=0x81220000
LENGTH=0x81230000
DESC=0x81240000
CONTEXT=0x81250000
CACHE=0x80de6304
CONFIG=dict(append=0x80c0cbca,decode=0x80c0c6f8,remove=0x80c0ced6,get=0x80c0d344,set=0x80c0d3b4,
    read=0x80c0bf58,write=0x80c0bfe2,status=0x80c0c5cc,strlen=0x80c2e57c,memset=0x80c2e014,
    strncmp=0x80c2e5e8,read_service=0x80c24446,write_service=0x80c24502,
    reserve=0x80c0cb7a,scan=0x80c0cd82,diagnostic=0x80c0c120,warn=0x80c0c220,logger=0x80c1cd7a)
RANGES=((0x80c0bf58,0x114),(0x80c0c0f6,0x22),(0x80c0c2f0,0x74),(0x80c0c3a2,0xaa),
        (0x80c0c5cc,0x108),(0x80c0c6f8,0x120),(0x80c0cbca,0x18c),
        (0x80c0cdf6,0x1b6),(0x80c0d344,0x150),(0x80c0d85c,4),(0x80c00b24,0x2e))
TARGETS=(0x80c0bf58,0x80c0bfe2,0x80c0c2f0,0x80c0c30a,0x80c0c3a2,0x80c0c5cc,
         0x80c0c660,0x80c0c6f8,0x80c0cbca,0x80c0cdf6,0x80c0ced6)


def put(b,at,v):struct.pack_into('<I',b,at,v&0xffffffff)
def word(b,at):return struct.unpack_from('<I',b,at)[0]
def marker(state,n=6):
    b=bytearray(b'\xff'*(n-1))
    if state:b[state-1]=0
    return b
def state(b,n):
    return next((i+1 for i in range(n-2,-1,-1) if b[i]==0),0)
def record(key,payload):
    name=key.encode('ascii');b=bytearray(b'\xff'*28);b[0]=0;b[1]=0
    b[8:12]=b'KV40';put(b,12,28+len(name)+len(payload));b[20]=len(name);put(b,24,len(payload))
    b+=name+payload;put(b,16,zlib.crc32(b[20:]));return b


class Model:
    def __init__(self,c):
        self.c=c;self.flash=bytearray(b'\xff'*EXTENT);self.actions=[];self.writes=0
        self.output=bytearray(b'\xa5'*4096);self.length=0xa5a5a5a5;self.desc=bytearray(56);put(self.desc,48,OLD)
        self.cache=OLD if c['existing'] else 0xffffffff;self.flag=0;self.pending=0;self.sector_end=0xffffffff
        for sector in (OLD&~0xfff,CURSOR&~0xfff):
            self.store(sector,marker(c['context_state'] if sector==(CURSOR&~0xfff) else 2,4))
            self.store(sector+3,marker(c['sector_state'],4))
        if c['existing']:
            data=record(c['key'],bytes.fromhex(c['old_hex']))
            if c['bad_magic']:data[8:12]=b'BAD!'
            if c['bad_crc']:data[16]^=1
            self.store(OLD,data)
    def store(self,at,b):
        i=at-BASE
        if i<0 or i+len(b)>len(self.flash):raise ValueError('synthetic storage bound')
        self.flash[i:i+len(b)]=b
    def bytes(self,at,n):
        if not n:return b''
        i=at-BASE
        if i<0 or i+n>len(self.flash):raise ValueError('synthetic storage bound')
        return bytes(self.flash[i:i+n])
    def route(self,at):
        c=self.c
        if 0x4000<=at<0x5000:
            return (c['special'],at-0x4000) if c['special'] else (c['fallback'],at)
        return c['general'],at
    def read(self,at,n):
        handle,offset=self.route(at)
        if not handle and 0x4000<=at<0x5000:
            self.actions.append('log:read_error');return 2,None
        result=self.c['read_result']
        if result is None:result=n
        self.actions.append(f'read:{handle}:{offset}:{n}:{result}')
        if result<0:self.actions.append('log:read_error');return 2,None
        return 0,self.bytes(at,min(n,result))
    def write(self,at,data):
        handle,offset=self.route(at)
        if not handle and 0x4000<=at<0x5000:self.actions.append('log:write_error');return 3
        self.writes+=1;result=len(data)
        if self.writes==self.c['fault_write']:result=self.c['write_result']
        self.actions.append(f'write:{handle}:{offset}:{len(data)}:{result}:{digest(data)}')
        if result<0:self.actions.append('log:write_error');return 3
        n=min(len(data),result);before=self.bytes(at,n)
        self.store(at,bytes(a&b for a,b in zip(before,data[:n])))
        return 0
    def status(self,at,value):return self.write(at+value-1,b'\0')
    def decode(self,at,descriptor):
        _,data=self.read(at,28)
        if data is None or len(data)!=28:raise ValueError('decode fixtures require complete header reads')
        total=word(data,12);descriptor[0]=state(data,6);put(descriptor,8,total)
        if not 28<=total<=4076:raise ValueError('bounded record decode')
        crc=0
        for i in range(20,total,32):
            _,chunk=self.read(at+i,min(32,total-i))
            if chunk is None or len(chunk)!=min(32,total-i):raise ValueError('decode fixtures require complete body reads')
            crc=zlib.crc32(chunk,crc)
        if crc==word(data,16):
            descriptor[1]=1;_,name=self.read(at+28,data[20]);descriptor[16:16+len(name)]=name
            descriptor[2]=data[20];put(descriptor,12,word(data,24));put(descriptor,52,at+28+data[20])
        else:descriptor[1]=0
    def find(self,descriptor):
        if self.cache!=0xffffffff:
            _,name=self.read(self.cache+28,32)
            if name[:len(self.c['key'])]==self.c['key'].encode():
                put(descriptor,48,self.cache);self.decode(self.cache,descriptor);return True
        self.actions.append('boundary:scan_miss');return False
    def append(self):
        c=self.c;name=c['key'].encode();payload=bytes.fromhex(c['payload_hex']);total=28+len(name)+len(payload)
        if len(name)>32:self.actions.append('warn:key_length');return 4
        if total>4076:self.actions.append('warn:record_length');return 6
        cursor=c['cursor']
        if cursor==0xffffffff:
            self.actions.append('boundary:reserve:'+str(total));cursor=c['reserve_result']
            if cursor==0xffffffff:return 6
        full=False
        if c['context_state']==1:
            result=self.status(CURSOR&~0xfff,2)
            if result:return result
        elif c['context_state']==2 and (c['free']<60 or ((c['free']-total)&0xffffffff)<60):
            result=self.status(CURSOR&~0xfff,3);self.sector_end=0xffffffff;full=True
            if result:return result
        result=self.status(cursor,1)
        if result:return result
        value=record(c['key'],payload);result=self.write(cursor+8,value[8:28])
        if result:return result
        result=self.write(cursor+28,name)
        if not full:self.sector_end=cursor+total
        self.cache=cursor
        if result:return result
        result=self.write(cursor+28+len(name),payload)
        if result:return result
        result=self.status(cursor,2)
        if not result and full:self.actions.append('diagnostic:68c');self.flag=1
        return result
    def remove(self,descriptor=None,final=True):
        if descriptor is None:
            descriptor=bytearray(56)
            if not self.find(descriptor):self.actions.append('diagnostic:526');return 4
        at=word(descriptor,48);result=self.status(at,4 if final else 3)
        if final:
            if not self.pending and not result:self.cache=0xffffffff
            self.pending=0
        else:self.pending=1
        if not result:
            sector=(at&~0xfff)+3;_,data=self.read(sector,3)
            if state(data,4)==1:result=self.status(sector,2)
        return result
    def get(self):
        descriptor=bytearray(56)
        if not self.find(descriptor):self.length=0;return 0
        n=min(self.c['capacity'],word(descriptor,12));self.length=word(descriptor,12)
        if n:
            _,data=self.read(word(descriptor,52),n)
            if data is not None:self.output[:len(data)]=data
        else:
            # The wrapper still requests zero bytes from its descriptor address.
            self.read(word(descriptor,52),0)
        return n
    def set(self):
        name=self.c['key'];payload=bytes.fromhex(self.c['payload_hex'])
        self.actions.append('boundary:reserve:'+str(28+len(name)+len(payload)))
        if self.c['reserve_result']==0xffffffff:return 6
        old=bytearray(56);found=self.find(old);result=self.remove(old,False) if found else 0
        if not result:
            result=self.append()
            if not result and found:result=self.remove(old,True)
        if self.flag:self.actions.append('boundary:maintenance');self.flag=0
        return result
    def result(self):
        rows=[]
        for op in self.c['operations']:
            if op=='append':returned=self.append()
            elif op=='decode':self.decode(OLD,self.desc);returned=None
            elif op=='remove':returned=self.remove(final=self.c['final'])
            elif op=='get':returned=self.get()
            elif op=='set':returned=self.set()
            elif op=='read':
                returned,data=self.read(self.c['address'],self.c['capacity'])
                if data is not None:self.output[:len(data)]=data
            elif op=='write':returned=self.write(self.c['address'],bytes.fromhex(self.c['payload_hex']))
            else:raise ValueError('unknown operation')
            rows.append(dict(returned=returned,flash_sha256=digest(self.flash),output_sha256=digest(self.output),
                descriptor_sha256=digest(self.desc),length_output=self.length,key_cache_record=self.cache,
                sector_cache_end=self.sector_end,maintenance_flag=self.flag,pending_replace=self.pending))
        return dict(actions=self.actions,rows=rows)


def contract(c):
    if not c['key'].isascii() or '\0' in c['key'] or not 1<=len(c['key'])<=33:raise ValueError('bounded ASCII key')
    if len(bytes.fromhex(c['payload_hex']))>4077 or not 0<=c['capacity']<=4096:raise ValueError('fixture size bound')
    if any(op in c['operations'] for op in ('get','decode','set','remove')) and c['read_result'] is not None:raise ValueError('structured cases require complete reads')
    return Model(c).result()


def native_vectors():
    cases=[]
    def add(name,operations,**changes):
        c=dict(name=name,operations=operations,key='upgrade',payload_hex=bytes(range(16)).hex(),old_hex=b'previous'.hex(),
               existing=False,bad_magic=False,bad_crc=False,cursor=CURSOR,reserve_result=CURSOR,
               context_state=2,sector_state=2,free=0x1000,capacity=64,final=True,
               special=17,general=34,fallback=51,read_result=None,fault_write=0,write_result=-1,address=0x5100)|changes
        c['expected']=contract(c);cases.append(c)
    add('append',['append']);add('append_get',['append','get']);add('set_get_new',['set','get'])
    add('set_get_replace',['set','get'],existing=True)
    add('set_upgrade_record',['set','get'],payload_hex=upgrade_record().hex(),capacity=298)
    add('append_empty',['append','get'],payload_hex='')
    add('append_key32',['append','get'],key='x'*32);add('append_key33',['append'],key='x'*33)
    add('append_record_max',['append','get'],payload_hex=(b'x'*4041).hex())
    add('append_record_large',['append'],payload_hex=(b'x'*4042).hex())
    add('append_reserve',['append'],cursor=0xffffffff);add('append_no_space',['append'],cursor=0xffffffff,reserve_result=0xffffffff)
    add('append_sector_open',['append'],context_state=1,sector_state=1)
    add('append_sector_full',['append'],free=100);add('append_free_underflow',['append'],free=64,payload_hex=(b'x'*64).hex())
    add('append_free_below_60',['append'],free=40)
    add('append_free_60',['append'],free=111);add('append_free_59',['append'],free=110)
    for at in range(1,6):add('append_error_'+str(at),['append','get'] if at==5 else ['append'],fault_write=at)
    for at in (2,3,4,5):add('append_short_'+str(at),['append','get'] if at==5 else ['append'],fault_write=at,write_result=0)
    add('replace_final_error',['set','get'],existing=True,fault_write=7)
    add('replace_mark_error',['set','get'],existing=True,fault_write=1)
    add('remove_missing',['remove']);add('remove',['remove','get'],existing=True)
    add('mark_then_get',['remove','get'],existing=True,final=False)
    add('remove_error',['remove','get'],existing=True,fault_write=1)
    add('remove_sector_update',['remove'],existing=True,sector_state=1)
    add('remove_sector_error',['remove'],existing=True,sector_state=1,fault_write=2)
    add('decode',['decode'],existing=True);add('decode_bad_crc',['decode'],existing=True,bad_crc=True)
    add('decode_bad_magic',['decode'],existing=True,bad_magic=True)
    add('get_clip',['get'],existing=True,capacity=3)
    for op in ('read','write'):
        add(op+'_general',[op]);add(op+'_special',[op],address=0x4100)
        add(op+'_special_end',[op],address=0x4fff,capacity=1,payload_hex='00')
        add(op+'_general_boundary',[op],address=0x5000)
        add(op+'_fallback',[op],address=0x4100,special=0)
        add(op+'_missing_special',[op],address=0x4100,special=0,fallback=0)
        add(op+'_zero_general',[op],general=0)
    add('read_error',['read'],read_result=-1);add('read_short',['read'],read_result=3)
    add('write_error',['write'],fault_write=1);add('write_short',['write'],fault_write=1,write_result=3)
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
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Low-level device read/write services use synthetic NOR-like arrays; real flash/device semantics and durability remain unknown.',
            'Reservation, sector-scan miss and maintenance are supplied; sector enumeration/GC/reboot cache reconstruction do not execute.',
            'Native CRC, cached lookup, descriptor parsing, status updates, sector/key cache updates, append/delete and get/set wrappers execute.',
            'One key/cache slot per case; bounded valid record extents, complete structured reads; no physical I/O or power-loss simulation.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.vectors,a.validation,a.decompiled)):p.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect environment records: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
