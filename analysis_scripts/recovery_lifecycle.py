#!/usr/bin/env python3
"""Recovery selection/counters/preparation and stopped handoff on synthetic files.

Availability checks and filesystem/BSP services are supplied. Writes affect only
in-memory fixtures; execution stops at entry or after one encoded startup jump.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH,digest,raw_crc,table,image_memory
else:
    from recovery_validator import BOOT_HASH,digest,raw_crc,table,image_memory

NAMES=('recovery0','recovery1','recovery_ota')
SELECTORS=(0,1,8)
POINTERS=(0x80c36fc0,0x80c36fcc,0x80c36fd8)
RAM=0x80d00000
HEADER=0x81100000
MAPPED=0x81110000
CONFIG=dict(get=0x80c0e438,set=0x80c0e4d0,select=0x80c0e9cc,prepare=0x80c0eaa6,finish=0x80c0ebd4,
            handoff=0x80c0084a,launch=0x80c0098c,validate=0x80c0e9c2,open=0x80c0b7c0,read=0x80c0b82c,
            write=0x80c0b874,close=0x80c0b828,base=0x80c0b8dc,zero=0x80c2e014,strcmp=0x80c2e3d8,
            logger=0x80c1cd7a,printf=0x80c1c776,console_close=0x80c160ac,interrupts=0x80c1634c,teardown=0x80c133c0)
RANGES=((0x80c00b52,0x26),(0x80c0e438,0x140),(0x80c0e9cc,0x2a2),(0x80c0080a,0x22),
        (0x80c0084a,0x2c),(0x80c0098c,0x96),(0x80c16344,8))
TARGETS=(0x80c00b52,0x80c0e438,0x80c0e4d0,0x80c0e9cc,0x80c0eaa6,0x80c0ebd4,
         0x80c0080a,0x80c0084a,0x80c0098c,0x80c16344)
LOGS={0x80c36e2c:'open_error',0x80c36e58:'read_error',0x80c36e84:'write_error',
      0x80c36fe8:'selected',0x80c37014:'counters',0x80c37044:'finish',0x80c32d88:'launch',0x80c32da4:'jump'}
RECOVERY_HASH='2af5c1c1a1283c0b1d558c7f4df3b77abfbd4a429c1141ec67c751adf904f412'


def entry_jump():
    # Independently encode JAL x0,+0x22c; compare its bytes with OTA entry.
    delta=0x22c
    return ((delta>>20&1)<<31)|((delta>>1&1023)<<21)|((delta>>11&1)<<20)|((delta>>12&255)<<12)|0x6f


def u32(data,at):return int.from_bytes(data[at:at+4],'little')
def put(data,at,value):struct.pack_into('<I',data,at,value&0xffffffff)
def signed(value):return (value+0x80000000)%0x100000000-0x80000000


def header(part,size):
    data=bytearray(72);data[:4]=b'RECO'
    for at,key in ((4,'generation'),(8,'bootup'),(12,'complete')):put(data,at,part[key])
    put(data,16,size);data[20:36]=b'2.3.1'.ljust(16,b'\0');put(data,68,raw_crc(data[:68]));return data


def files(c):
    result=[]
    for i,part in enumerate(c['parts']):
        data=header(part,c['size'])+bytes(4096-72)+bytes((j*13+i*17+7)&255 for j in range(c['size']))
        result.append(bytearray(data))
    return result


def source_header(c):
    data=header(dict(generation=99,bootup=10,complete=4),c['size']);put(data,68,0);return data


class Model:
    def __init__(self,c):
        self.c=c;self.files=files(c);self.actions=[];self.handles={};self.next_fd=100;self.calls={};self.buffer=source_header(c)
        self.ram=bytearray(b'\xa5'*4096);put(self.ram,0,c['entry_word']);self.mapped=0xa5a5a5a5;self.console=c['console'];self.mstatus=c['mstatus'];self.jump=None
    def count(self,service,index):
        key=(service,index);self.calls[key]=self.calls.get(key,0)+1;return self.calls[key]
    def fault(self,kind,index,ordinal):return self.c[kind]==[index,ordinal]
    def open(self,index):
        ordinal=self.count('open',index);self.actions.append(f'open:{index}:{ordinal}')
        if self.fault('open_failure',index,ordinal):return None
        fd=self.next_fd;self.next_fd+=1;self.handles[fd]=index;return fd
    def close(self,fd):self.actions.append('close:'+str(self.handles.pop(fd)))
    def read(self,fd,offset,n,dest):
        index=self.handles[fd];ordinal=self.count('read',index);returned=n-int(self.fault('read_short',index,ordinal))
        self.actions.append(f'read:{index}:{offset}:{n}:{returned}');dest[:returned]=self.files[index][offset:offset+returned];return returned
    def write(self,fd,data):
        index=self.handles[fd];ordinal=self.count('write',index);returned=72-int(self.fault('write_short',index,ordinal))
        self.actions.append(f'write:{index}:72:{returned}');self.files[index][:returned]=data[:returned];return returned
    def get(self,index,data):
        fd=self.open(index)
        if fd is None:self.actions.append('log:open_error');return 0
        result=int(self.read(fd,0,72,data)==72)
        if not result:self.actions.append('log:read_error')
        self.close(fd);return result
    def set(self,index,data):
        fd=self.open(index)
        if fd is None:self.actions.append('log:open_error');return
        put(data,68,raw_crc(data[:68]))
        if self.write(fd,data)!=72:self.actions.append('log:write_error')
        self.close(fd)
    def validate(self,index):
        result=int(self.c['available'][index]);self.actions.append(f'validate:{SELECTORS[index]}:{result}');return result
    def choose(self):
        if self.validate(2):return 2
        eligible0=False;difference0=0;first=bytearray(b'\xa5'*72)
        if self.validate(0):
            self.get(0,first);difference0=signed(u32(first,8)-u32(first,12));eligible0=difference0<10
        if self.validate(1):
            second=bytearray(b'\xa5'*72);self.get(1,second);difference1=signed(u32(second,8)-u32(second,12))
            if difference1<10:
                if not eligible0:return 1
                if difference0==0 and difference1==0:return 1 if signed(u32(first,4))<signed(u32(second,4)) else 0
                return 1 if difference1<=difference0 else 0
        if eligible0:return 0
        self.actions.append('log:error:379');return None
    def prepare(self,force_ram=False):
        ram=force_ram or self.c['ram_output'];mapped=False if force_ram else self.c['mapped_output']
        if not ram and not mapped:return 0
        choice=self.choose()
        if choice is None:self.actions.append('log:error:3c5');return 0
        self.actions.append('log:selected');fd=self.open(choice)
        if fd is None:self.actions.append('log:error:3d0');return 0
        data=bytearray(b'\xa5'*72)
        if self.read(fd,0,72,data)!=72:self.actions.append('log:error:3d8');return 0
        self.actions.append('log:counters')
        if ram:
            n=u32(data,16)
            if self.read(fd,4096,n,self.ram)!=n:self.actions.append('log:error:3e3');return 0
        if mapped:
            self.actions.append('base:'+str(choice));self.mapped=(self.c['parts'][choice]['base']+4096)&0xffffffff
        self.close(fd);data=bytearray(72)
        if choice!=2 and self.get(choice,data):put(data,8,u32(data,8)+1)
        self.set(choice,data);return 1
    def finish(self):
        self.actions.append('log:finish');data=bytearray(72);self.set(2,data)
        if self.c['finish_all']:
            for index in (0,1):
                if self.validate(index) and self.get(index,data):put(data,12,u32(data,8));self.set(index,data)
        return 1
    def handoff(self,launch=False):
        if self.console:self.actions.append('boundary:console_close');self.console=0
        self.mstatus&=0xfffffff7;self.actions.extend(['boundary:interrupts','boundary:teardown','print:entry'])
        self.jump=dict(pc=RAM+(0x22c if self.c['trampoline'] else 0),sp=0x81001000-(16 if launch else 0),ra=0x80c009d2 if launch else 0x70000000,first_word=u32(self.ram,0))
        self.actions.append('handoff:stopped')
    def result(self):
        rows=[]
        for op in self.c['operations']:
            returned=None
            if op=='get':returned=self.get(self.c['target'],self.buffer)
            elif op=='set':self.set(self.c['target'],self.buffer)
            elif op=='select':
                choice=self.choose();returned=0 if choice is None else POINTERS[choice]
            elif op=='prepare':returned=self.prepare()
            elif op=='finish':returned=self.finish()
            elif op=='handoff':self.handoff()
            elif op=='launch':
                self.actions.append('log:launch')
                if self.prepare(True):self.actions.append('log:jump');self.handoff(True)
                else:self.actions.extend(['log:launch_error:164','log:launch_error:167']);returned=0
            else:raise ValueError('unknown lifecycle operation')
            rows.append(dict(returned=returned,header_sha256=digest(self.buffer),header_crc_valid=raw_crc(self.buffer[:68])==u32(self.buffer,68),
                ram_sha256=digest(self.ram),mapped=self.mapped,console=self.console,mstatus=self.mstatus,handoff=self.jump,
                partitions=[dict(sha256=digest(data),bootup=u32(data,8),complete=u32(data,12),magic_hex=data[:4].hex(),crc_valid=raw_crc(data[:68])==u32(data,68)) for data in self.files],
                open_handles=[dict(fd=fd,partition=NAMES[index]) for fd,index in sorted(self.handles.items())]))
        return dict(actions=self.actions,rows=rows)


def contract(c):
    if len(c['parts'])!=3 or len(c['available'])!=3 or not 4<=c['size']<=4096 or c['target'] not in (0,1,2):raise ValueError('bounded lifecycle fixture')
    if any(not isinstance(flag,bool) for flag in c['available']) or not 0<=c['console']<=255 or any(not 0<=c[k]<=0xffffffff for k in ('mstatus','entry_word')):raise ValueError('bounded service/state fields')
    if any(op in ('handoff','launch') for op in c['operations'][:-1]):raise ValueError('stopped handoff is terminal')
    if c['trampoline'] and (c['operations']!=['handoff'] or c['entry_word']!=entry_jump()):raise ValueError('only the encoded direct entry jump is modeled')
    for part in c['parts']:
        if any(not 0<=part[k]<=0xffffffff for k in ('generation','bootup','complete','base')):raise ValueError('32-bit header/base fields')
    return Model(c).result()


def native_vectors():
    cases=[]
    defaults=[dict(generation=2,bootup=3,complete=3,base=0x90100000),dict(generation=1,bootup=3,complete=3,base=0x90200000),dict(generation=0,bootup=0,complete=0,base=0x90300000)]
    def add(name,ops,**changes):
        c=dict(name=name,operations=ops,parts=[dict(p) for p in defaults],available=[True,True,False],size=512,target=0,
               ram_output=True,mapped_output=True,finish_all=True,console=1,mstatus=0x1888,entry_word=0x13,trampoline=False,
               open_failure=[],read_short=[],write_short=[])|changes
        c['files_hex']=[bytes(data).hex() for data in files(c)];c['source_header_hex']=source_header(c).hex();c['expected']=contract(c);cases.append(c)
    for index in (0,1,2):add('get_'+str(index),['get'],target=index);add('set_'+str(index),['set'],target=index)
    add('get_open_failure',['get'],open_failure=[0,1]);add('get_short',['get'],read_short=[0,1])
    add('set_open_failure',['set'],open_failure=[0,1]);add('set_short',['set'],write_short=[0,1])
    for flags in ((False,False,False),(True,False,False),(False,True,False),(True,True,False),(True,True,True)):
        add('select_available_'+''.join(str(int(f)) for f in flags),['select'],available=list(flags))
    for first,second in ((0,0),(0,1),(1,0),(1,1),(9,9),(9,10),(10,9),(10,10),(11,0),(0,11),(-1,0),(0,-1),(-1,-1)):
        parts=[dict(p) for p in defaults]
        for p,delta in zip(parts,(first,second)):p['complete']=4;p['bootup']=(4+delta)&0xffffffff
        add(f'select_delta_{first}_{second}',['select'],parts=parts)
    for first,second in ((1,2),(2,1),(2,2),(0xffffffff,0),(0,0x80000000)):
        parts=[dict(p) for p in defaults];parts[0]['generation']=first;parts[1]['generation']=second
        add(f'select_generation_{first}_{second}',['select'],parts=parts)
    add('select_get_open_failure',['select'],open_failure=[0,1]);add('select_get_short',['select'],read_short=[0,1])
    add('prepare_normal',['prepare']);add('prepare_ota',['prepare'],available=[True,True,True])
    add('prepare_no_outputs',['prepare'],ram_output=False,mapped_output=False)
    add('prepare_mapping_only',['prepare'],ram_output=False);add('prepare_ram_only',['prepare'],mapped_output=False)
    add('prepare_none_available',['prepare'],available=[False,False,False])
    for name,key,ordinal in (('open','open_failure',2),('header_short','read_short',2),('image_short','read_short',3),
                             ('counter_open','open_failure',3),('counter_short','read_short',4),('write_open','open_failure',4),('write_short','write_short',1)):
        add('prepare_'+name,['prepare'],**{key:[0,ordinal]})
    parts=[dict(p) for p in defaults];parts[0]['bootup']=0xffffffff;parts[0]['complete']=0xffffffff
    add('prepare_counter_wrap',['prepare'],parts=parts,available=[True,False,False])
    parts=[dict(p) for p in defaults];parts[0]['base']=0xfffff800
    add('prepare_mapping_wrap',['prepare'],parts=parts)
    parts=[dict(p) for p in defaults];parts[0]['bootup']=5;parts[1]['bootup']=7
    add('finish_all',['finish'],parts=parts);add('finish_ota_only',['finish'],finish_all=False)
    add('finish_invalid_normals',['finish'],available=[False,False,False])
    add('finish_ota_open_failure',['finish'],open_failure=[2,1]);add('finish_normal_short',['finish'],read_short=[0,1])
    add('lifecycle_prepare_finish_select',['prepare','select','finish','select'])
    add('handoff_console',['handoff']);add('handoff_console_off',['handoff'],console=0)
    add('handoff_interrupts_already_off',['handoff'],mstatus=0x1880)
    add('handoff_entry_trampoline',['handoff'],entry_word=entry_jump(),trampoline=True)
    add('launch_normal',['launch']);add('launch_ota',['launch'],available=[True,True,True])
    add('launch_none',['launch'],available=[False,False,False]);add('launch_image_short',['launch'],read_short=[0,3])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from reviewed model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    if memory.read(0x80c32e8c,1024)!=table():raise ValueError('unexpected CRC table')
    recovery=archive.read('META/extfw/recovery_sign.bin')
    if digest(recovery)!=RECOVERY_HASH or recovery[:4]!=struct.pack('<I',entry_jump()):raise ValueError('unexpected recovery entry jump')
    return dict(boot_sha256=BOOT_HASH,recovery_sha256=RECOVERY_HASH,entry_jump_sha256=digest(struct.pack('<I',entry_jump())),
        vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Validator availability, partition filesystem/base addresses, string/zero/log services and BSP cleanup are supplied.',
            'All writes mutate only in-memory synthetic partition fixtures; no flash/environment/device access.',
            'Actual selection/counter/header/prepare/finish/launch/handoff control code executes; one encoded entry-jump case stops at startup +22c, others before image instructions.',
            'This does not establish device enforcement, safe physical entry/restoration or a viable independent-code boot path.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect recovery lifecycle: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
