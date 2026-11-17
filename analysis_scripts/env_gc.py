#!/usr/bin/env python3
"""Native environment relocation/reclamation/default restoration on fake storage.

All erase/program operations affect synthetic arrays only. This does not prove
physical flash behavior, boot initialization or power-loss-safe restoration.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile
import zlib

if __package__:
    from .env_space import Model as SpaceModel, CONFIG as SPACE_CONFIG, RANGES as SPACE_RANGES
    from .env_scan import Model as ScanModel, sector
    from .env_records import record, state, word, put
    from .recovery_validator import BOOT_HASH, digest, image_memory, table
else:
    from env_space import Model as SpaceModel, CONFIG as SPACE_CONFIG, RANGES as SPACE_RANGES
    from env_scan import Model as ScanModel, sector
    from env_records import record, state, word, put
    from recovery_validator import BOOT_HASH, digest, image_memory, table

CONFIG=SPACE_CONFIG|dict(move=0x80c0cfac,format=0x80c0d184,collect=0x80c0d27e,
    defaults=0x80c0d494,erase_service=0x80c245be,strncpy=0x80c2e684)
RANGES=SPACE_RANGES+((0x80c0c172,0xae),(0x80c0c660,0x74),(0x80c0cbca,0x18c),
                   (0x80c0ced6,0x2ae),(0x80c0d184,0x1c0),(0x80c0d494,0xfa))
TARGETS=(0x80c0cfac,0x80c0d184,0x80c0d27e,0x80c0d494,0x80c0c172,0x80c0c660,0x80c0cbca,0x80c0d58e)


class Model(SpaceModel):
    base=0
    def __init__(self,c):
        super().__init__(c);self.index=bytearray(b'\xff'*128);self.pending=c['pending'];self.erases=0;self.programs=0;self.last_context=None
        if c['source_cache']:self.cache_update('upgrade',20)
        self.direct=bytearray(56)
        if c['records']:
            r=c['records'][0];payload=bytes.fromhex(r['payload_hex']);name=r['key'].encode()
            self.direct[:3]=bytes([r['state'],1,len(name)]);put(self.direct,8,28+len(name)+len(payload));put(self.direct,12,len(payload))
            self.direct[16:16+len(name)]=name;put(self.direct,48,r['offset']);put(self.direct,52,r['offset']+28+len(name))
    def program(self,at,data):
        self.programs+=1;result=-1 if self.programs==self.c['fail_write'] else (self.c['short_count'] if self.programs==self.c['short_write'] else len(data))
        self.actions.append(f'write:{at}:{len(data)}:{result}:{digest(data)}')
        if result<0:self.actions.append('log:write_error');return 3
        for i,b in enumerate(data[:min(result,len(data))]):self.flash[at+i]&=b
        return 0
    def write_marker(self,at):return self.program(at,b'\0')
    def status_write(self,at,status):return self.program(at+status-1,b'\0')
    def cache_update(self,key,address):
        tag=zlib.crc32(key.encode())>>16;free=old=None;old_age=0xffff
        for i in range(16):
            p=i*8;h,age=struct.unpack_from('<HH',self.index,p);current=word(self.index,p+4)
            if h==tag:
                put(self.index,p+4,address)
                if address==0xffffffff:struct.pack_into('<H',self.index,p+2,0)
                return
            if address==0xffffffff:continue
            if current==0xffffffff:
                if free is None:free=i
            else:
                if age:age-=1;struct.pack_into('<H',self.index,p+2,age)
                if age<old_age:old=i;old_age=age
        if address!=0xffffffff:
            slot=free if free is not None else old
            if slot is not None:struct.pack_into('<HHI',self.index,slot*8,tag,0,address)
    def details(self,context):
        saved=self.desc;self.full_at(word(context,4),context);self.desc=saved;self.last_context=bytearray(context)
    def remove_record(self,descriptor,final):
        at=word(descriptor,48);result=self.status_write(at,4 if final else 3)
        if final:
            if not self.pending and not result:self.cache_update(bytes(descriptor[16:16+descriptor[2]]).decode(),0xffffffff)
            self.pending=0
        else:self.pending=1
        if not result:
            sector=(at&~0xfff)+3;data=self.read(sector,3)
            if state(data,4)==1:result=self.status_write(sector,2)
        return result
    def prepare(self,context,total):
        at=word(context,4);primary=context[1];full=False;result=0
        if primary==1:result=self.status_write(at,2)
        elif primary==2 and (word(context,16)<60 or (word(context,16)-total)&0xffffffff<60):
            result=self.status_write(at,3);self.update_end(at,at+4096);full=True
        return result,full
    def format_sector(self,at):
        self.erases+=1;result=-1 if self.erases==self.c['fail_erase'] else 0;self.actions.append(f'erase:{at}:4096:{result}')
        if result<0:self.actions.append('log:erase_error');return 1
        self.flash[at:at+4096]=b'\xff'*4096
        header=bytearray(b'\xff'*20);header[0]=0;header[3]=0;header[8:12]=b'EF40'
        result=self.program(at,header);self.update_end(at,at+4096);return result
    def reserve_for(self,size):
        saved=self.c;self.c=self.c|dict(request=size)
        try:return self.reserve()
        finally:self.c=saved
    def move_record(self,descriptor):
        descriptor=bytearray(descriptor);key=bytes(descriptor[16:16+descriptor[2]]).decode();total=word(descriptor,8);source=word(descriptor,48)
        if descriptor[0]==2:self.remove_record(descriptor,False)
        destination=self.reserve_for(total)
        if destination==0xffffffff:return 6
        if self.c['duplicate_guard']:
            saved=self.desc;self.desc=bytearray(56);found=ScanModel.find(self);self.desc=saved
            if found:self.remove_record(descriptor,True);return 0
        self.prepare(self.last_context,total);self.status_write(destination,1);result=0
        for i in range(0,total-8,32):
            data=self.read(source+8+i,min(32,total-8-i));result=self.program(destination+8+i,data)
        self.status_write(destination,2);self.update_end(destination&~0xfff,destination+28+descriptor[2]+word(descriptor,12));self.cache_update(key,destination)
        self.actions.append('diagnostic:5a4');self.remove_record(descriptor,True);return result
    def collect(self,context):
        if not context[0] or context[2] not in (2,3):return 0
        at=word(context,4);self.status_write(at+3,3);self.desc=bytearray(56);put(self.desc,48,0xffffffff)
        for _ in range(8):
            address=self.next_record(at);put(self.desc,48,address)
            if address==0xffffffff:break
            self.decode(address);descriptor=bytearray(self.desc)
            if descriptor[1] and descriptor[0] in (2,3):
                if self.move_record(descriptor):self.actions.append('diagnostic:5e9')
                self.desc=descriptor
        else:raise ValueError('bounded collection records')
        self.format_sector(at);self.actions.append('diagnostic:5f0');return 0
    def maintenance(self):
        count=sum(1 for context,_ in self.contexts() if context[0] and context[1]==1)
        self.actions.append('diagnostic:603')
        if count<2:
            for context,_ in self.contexts():self.collect(context)
        self.flag=0
    def append_default(self,key,payload):
        total=28+len(key)+len(payload);cursor=self.reserve_for(total)
        if cursor==0xffffffff:raise ValueError('defaults fixtures require successful reservation')
        result,full=self.prepare(self.last_context,total)
        if result:return result
        value=record(key,payload);result=self.status_write(cursor,1)
        if result:return result
        result=self.program(cursor+8,value[8:28])
        if result:return result
        result=self.program(cursor+28,key.encode())
        if not full:self.update_end(cursor&~0xfff,cursor+total)
        self.cache_update(key,cursor)
        if result:return result
        result=self.program(cursor+28+len(key),payload)
        if result:return result
        result=self.status_write(cursor,2)
        if not result and full:self.actions.append('diagnostic:68c');self.flag=1
        return result
    def restore_defaults(self):
        for at in range(0,0x4000,4096):
            result=self.format_sector(at)
            if result:return result
        for row in self.c['defaults']:
            payload=row['value'].encode();self.append_default(row['key'],payload[:row['length'] or len(payload)])
        return 0
    def result(self):
        rows=[]
        for operation in self.c['operations']:
            if operation=='format':returned=self.format_sector(self.c['format_sector']*4096)
            elif operation=='move':returned=self.move_record(self.direct)
            elif operation=='collect':returned=self.collect(self.source_context())
            elif operation=='maintenance':self.maintenance();returned=None
            elif operation=='defaults':returned=self.restore_defaults()
            else:raise ValueError('unknown GC operation')
            rows.append(dict(returned=returned,flash_sha256=digest(self.flash),sector_cache_sha256=digest(self.ends),key_cache_sha256=digest(self.index),
                pending_replace=self.pending,maintenance_flag=self.flag))
        return dict(actions=self.actions,rows=rows)
    def source_context(self):
        context=bytearray(24);s=self.c['sectors'][0];context[:3]=bytes([int(self.c['source_valid']),s['primary'],s['dirty']]);put(context,4,0);return context


def contract(c):
    if len(c['sectors'])!=4 or not c['defaults'] or len(c['defaults'])>3:raise ValueError('bounded table/sector fixtures')
    if any(not 1<=len(d['key'])<=31 or not 1<=len(d['value'])<=31 or not 0<=d['length']<=len(d['value']) for d in c['defaults']):raise ValueError('bounded defaults')
    return Model(c).result()


def native_vectors():
    cases=[]
    def entry(offset=20,status=2,bad=False,payload=b'payload'):
        return dict(key='upgrade',offset=offset,state=status,bad_crc=bad,total_override=None,payload_hex=payload.hex())
    def add(name,operations=None,**changes):
        c=dict(name=name,operations=operations or ['move'],key='upgrade',sectors=[sector(primary=3,dirty=2),sector(),sector(),sector(primary=3)],
               records=[entry()],patches=[],warm_cache=[],write_error=False,maintenance_flag=0,request=42,space_sector=0,
               pending=0,source_cache=True,source_valid=True,duplicate_guard=False,fail_write=0,short_write=0,short_count=0,fail_erase=0,format_sector=0,
               defaults=[dict(key='upgrade',value='one',length=0),dict(key='mode',value='two',length=2)])|changes
        c['expected']=contract(c);cases.append(c)
    add('move');add('move_marked',records=[entry(status=3)])
    add('move_no_space',sectors=[sector(primary=3,dirty=2)]+[sector(primary=3) for _ in range(3)])
    for ordinal in range(1,8):add('move_write_error_'+str(ordinal),fail_write=ordinal)
    add('move_short_copy',short_write=4,short_count=3)
    add('move_duplicate_absent',duplicate_guard=True,sectors=[sector(primary=3,dirty=2),sector(),sector(),sector()])
    add('move_duplicate_present',duplicate_guard=True,sectors=[sector(primary=3,dirty=2),sector(primary=2),sector(),sector()],records=[entry(),entry(offset=4116,payload=b'newer')])
    add('format',['format']);add('format_erase_error',['format'],fail_erase=1)
    add('format_header_error',['format'],fail_write=1);add('format_short_header',['format'],short_write=1,short_count=3)
    add('format_warm_cache',['format'],warm_cache=[dict(slot=0,sector=0,cursor=62)])
    add('collect',['collect']);add('collect_invalid',['collect'],source_valid=False)
    add('collect_two',['collect'],records=[entry(),entry(offset=62,payload=b'other')])
    add('collect_marked',['collect'],records=[entry(status=3)])
    add('collect_clean',['collect'],sectors=[sector(primary=3),sector(),sector(primary=3),sector(primary=3)])
    add('collect_deleted',['collect'],records=[entry(status=4)])
    add('collect_bad_crc',['collect'],records=[entry(bad=True)])
    add('collect_no_space',['collect'],sectors=[sector(primary=3,dirty=2)]+[sector(primary=3) for _ in range(3)])
    add('collect_move_error',['collect'],fail_write=6)
    add('collect_erase_error',['collect'],fail_erase=1)
    add('maintenance',['maintenance'],maintenance_flag=1,sectors=[sector(primary=3,dirty=2),sector(),sector(primary=3),sector(primary=3)])
    add('maintenance_enough_empty',['maintenance'],sectors=[sector(primary=3,dirty=2),sector(),sector(),sector()],maintenance_flag=1)
    add('defaults',['defaults']);add('defaults_erase_error',['defaults'],fail_erase=2)
    add('defaults_header_error',['defaults'],fail_write=2)
    add('defaults_prepare_error',['defaults'],fail_write=5,defaults=[dict(key='upgrade',value='one',length=0)])
    add('defaults_append_final_error',['defaults'],fail_write=10,defaults=[dict(key='upgrade',value='one',length=0)])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=1000000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    if memory.read(0x80c32e8c,1024)!=table():raise ValueError('CRC table')
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},crc_table_sha256=digest(table()),
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Native relocation, sector collection/format, detailed reservation and defaults restoration execute on four synthetic sectors at logical base zero.',
            'Low-level read/write/erase, string/memory and logging services are supplied. Erase fills arrays with ff; writes use bytewise AND.',
            'Selected complete reads, finite records, write/erase errors and short writes only; no actual startup, physical I/O, power-loss recovery or durability guarantee.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.vectors,a.validation,a.decompiled)):p.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect environment GC: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
