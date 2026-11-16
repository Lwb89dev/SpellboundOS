#!/usr/bin/env python3
"""Host contracts for filtered cache packets, buffer rebasing, flush and opcode 21.

Only synthetic packet fixtures and bounded offline native execution are used.
OS queues/locks, allocation, memory copying, event scheduling and sends are supplied.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensor_packets import TICK,put
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import SENSOR,SENSOR_HASH,uint
else:
    from sensor_packets import TICK,put
    from sensorhub_memory import StartupMemory
    from zrpc_packets import SENSOR,SENSOR_HASH,uint

SOURCE=0x81020000
CLONE=0x81030000
BUFFER=0x81100000
CAPACITY=4000
MAGIC=0xa3b4c5d6
TARGETS=(0x80f65a0e,0x80f65920,0x80f657ee,0x80f6585e,0x80f65884,0x80f658c6,0x80f655d2,
         0x80f63c2e,0x80fa6278,0x80fa61ca,0x80fa60e4,0x80fa6028,0x80fa5d1e,0x80fa5d5e,
         0x80fa5dd2,0x80fa5e6a,0x80fa5eb6,0x80f9b34e,0x80f9b390,0x80f9ba6e,
         0x80f99ce0,0x80f99c26,0x80f9a5e6,0x80fa27e6,0x80fa27ea)
RANGES=((0x80f6453e,0x122),(0x80f655d2,0x30),(0x80f657ee,0x480),(0x80f63c2e,0x86),
        (0x80f85cbe,0x84),(0x80f80aa2,0x44),(0x80fd2c3e,0x1a),(0x80fa5d1e,0x5b2),
        (0x80f9b34e,0xb0),(0x80f9ba6e,0x27c),(0x80f99c26,0xdc),(0x80f9a5e6,0xa20),(0x80fa27e6,8))


def digest(data):return hashlib.sha256(data).hexdigest()
def u32(data,offset):return int.from_bytes(data[offset:offset+4],'little')


def packet(base,types=(0x10,0x8000,0x100000),stride=8):
    uint(base,32);uint(stride,16)
    if not 1<=len(types)<=8 or not 1<=stride<=4000:raise ValueError('synthetic packet bounds')
    for value in types:uint(value,64)
    data=bytearray(24+len(types)*(40+stride));mask=0
    for value in types:mask|=value
    struct.pack_into('<HHHHQII',data,0,len(types),stride,6,0,mask,1,base+24)
    for i,kind in enumerate(types):
        at=24+40*i;payload=24+40*len(types)+stride*i
        struct.pack_into('<QQIHHHH',data,at,kind,TICK+i,0x100+i,stride//4,10,20,0)
        put(data,at+28,4,i+1);put(data,at+32,4,base+payload);put(data,at+36,4,0xcafe0000+i)
        data[payload:payload+stride]=bytes(((i+1)*17+j)&255 for j in range(stride))
    return data


def rebase(data,base):
    data=bytearray(data);count,stride=struct.unpack_from('<HH',data)
    put(data,16,4,1);put(data,20,4,base+24)
    for i in range(count):put(data,24+40*i+32,4,base+24+40*count+stride*i)
    return data


def rebase_blob(blob,used,base):
    data=bytearray(blob);cursor=0
    while cursor!=used:
        if cursor+4>len(data):raise ValueError('host malformed prefix bound')
        size=u32(data,cursor);end=cursor+4+size
        if size==0 or end>used:break
        if end>len(data):raise ValueError('host malformed record bound')
        data[cursor+4:end]=rebase(data[cursor+4:end],base+cursor+4);cursor=end
    return data


def parse_wire(wire):
    """Strict host parser; native pointers remain opaque sender addresses."""
    if not isinstance(wire,bytes) or len(wire)<5 or wire[0]!=21:raise ValueError('opcode 21 header')
    length=u32(wire,1)
    if length!=len(wire)-5:raise ValueError('cache envelope length')
    cursor=5;packets=[]
    while cursor<len(wire):
        if cursor+4>len(wire):raise ValueError('cache record prefix')
        size=u32(wire,cursor);cursor+=4
        if size<24 or cursor+size>len(wire):raise ValueError('cache record size')
        data=wire[cursor:cursor+size];count,stride=struct.unpack_from('<HH',data)
        if not count or not stride or size!=24+count*(40+stride):raise ValueError('native packet shape')
        packets.append(data);cursor+=size
    return packets


def fixture(base,data):return dict(address=base,size=len(data),hex=bytes(data).hex())


def contract(case):
    kind=case['kind'];actions=[];buffers=[];wires=[];events=[];packets={p['address']:bytearray.fromhex(p['hex']) for p in case.get('packets',[])}
    clone=None;cached=case.get('cached',123);motion=7;queue=[];statuses=[];returned=None
    def label(base):
        if base==CLONE:return 'clone'
        if base in packets:return 'p'+str(list(packets).index(base))
        return 'b'+str((base-BUFFER)//0x10000)
    def release(base):
        data=clone if base==CLONE else packets[base];put(data,16,4,(u32(data,16)-1)&0xffffffff)
        if u32(data,16)==0:put(data,20,4,0);actions.append('free:'+label(base))
    def alloc_buffer(capacity,index,success=True):
        base=BUFFER+index*0x10000;actions.append(('alloc:' if success else 'alloc_fail:')+f'b{index}:{capacity+16}')
        if not success:actions.append('log:80fd5134');return None
        data=bytearray(capacity+16);struct.pack_into('<IIII',data,0,1,MAGIC,capacity,base+16)
        buffers.append(data);return data
    def buffer_release(index):
        data=buffers[index]
        if u32(data,8) and u32(data,12) and u32(data,4)==MAGIC:
            put(data,0,4,(u32(data,0)-1)&0xffffffff)
            if u32(data,0)==0:put(data,4,4,0);actions.append(f'free:b{index}')
    if kind=='buffer':
        capacity=case['capacity'];returned=0
        if capacity:
            data=alloc_buffer(capacity,0,case['allocated'])
            if data is not None:
                returned=BUFFER+8;blob=bytes.fromhex(case['blob_hex']);data[16:16+len(blob)]=blob
                put(data,8,4,case['used']);put(data,4,4,MAGIC if case['magic'] else 0)
                if not case['pointer']:put(data,12,4,0)
                valid=bool(case['used'] and case['magic'] and case['pointer']);statuses=[int(valid)]*5
                if valid:
                    data[16:]=rebase_blob(data[16:],case['used'],BUFFER+16);put(data,0,4,2)
                buffer_release(0);buffer_release(0);statuses.append(0)
                if not valid:statuses[-1]=0
    else:
        if kind=='filter':
            source=packets[SOURCE];mask=case['mask'];original=u32(source,8)|(u32(source,12)<<32);selected=mask&original;chosen=None
            if selected==original:
                put(source,16,4,u32(source,16)+1);chosen=SOURCE
            elif selected:
                count=selected.bit_count();stride=int.from_bytes(source[2:4],'little');size=24+count*(40+stride)
                actions.append(('alloc:' if case['clone_allocated'] else 'alloc_fail:')+f'clone:{size}')
                if case['clone_allocated']:
                    clone=bytearray(size);struct.pack_into('<HHHHQII',clone,0,count,stride,6,0,selected,1,CLONE+24)
                    j=0
                    for i in range(int.from_bytes(source[:2],'little')):
                        at=24+40*i;typ=int.from_bytes(source[at:at+8],'little')
                        if typ&selected:
                            clone[24+40*j:24+40*j+32]=source[at:at+32]
                            dest=24+40*count+stride*j;put(clone,24+40*j+32,4,CLONE+dest)
                            src=u32(source,at+32)-SOURCE;clone[dest:dest+stride]=source[src:src+stride];j+=1
                    chosen=CLONE
                else:actions.extend(('log:80fd4b4c','log:80fd5180','log:80fd51a4'))
            if chosen is not None:
                actions.append('alloc_node:0')
                if case['node_allocated']:
                    queue=[(chosen,len(clone if chosen==CLONE else source),0)];cached=queue[0][1]
                else:actions.append('log:80fd51c0');release(chosen);cached=0
            else:cached=0
            release(SOURCE)
        else:queue=[(p['address'],p['size'],i) for i,p in enumerate(case['packets'])]
        index=0
        while queue:
            if index>=case['buffer_limit']:
                alloc_buffer(CAPACITY,index,False);actions.append('log:80fd515c');break
            data=alloc_buffer(CAPACITY,index);cursor=0
            while queue and cursor+4+queue[0][1]<=CAPACITY:
                base,size,node=queue.pop(0);source=clone if base==CLONE else packets[base]
                actions.append(f'free:n{node}');put(data,16+cursor,4,size);data[20+cursor:20+cursor+size]=source
                release(base);cursor+=4+size
            put(data,8,4,cursor)
            if cursor:data[16:]=rebase_blob(data[16:],cursor,BUFFER+index*0x10000+16)
            actions.append(f'dispatch:{index}:{cursor}')
            if case['bridge']:
                actions.extend((f'event:{index}',f'post:{index}'))
                if cursor:put(data,0,4,u32(data,0)+1)
                events.append(index)
            buffer_release(index);index+=1
        if not queue:cached=0;motion=0
        for index in events:
            data=buffers[index];payload=bytes(data[16:16+u32(data,8)]);wire=b'\x15'+struct.pack('<I',len(payload))+payload
            actions.extend((f'wire_alloc:{len(wire)}',f'send:{index}:{len(wire)}'))
            wires.append(dict(header_hex='000102',length=len(wire),sha256=digest(wire),prefix_hex=wire[:21].hex()))
            if case['send_result']:actions.extend(('log:80fe18e0','log:80fe22dc'))
            buffer_release(index)
    snapshots=[]
    for i,data in enumerate(buffers):
        snapshots.append(dict(base=BUFFER+i*0x10000,used=u32(data,8),refs=u32(data,0),magic=u32(data,4),sha256=digest(data)))
    return dict(actions=actions,packets_sha256=[digest(data) for data in packets.values()],clone_sha256=digest(clone) if clone is not None else None,
                buffers=snapshots,wires=wires,queue_count=len(queue),cached=cached,motion=motion,statuses=statuses,returned=returned)


def native_vectors():
    cases=[]
    def flush(name,specs,**changes):
        options=dict(bridge=True,buffer_limit=4,send_result=0,cached=123)|changes
        packets=[fixture(SOURCE+0x2000*i,packet(SOURCE+0x2000*i,types,stride)) for i,(types,stride) in enumerate(specs)]
        c=dict(name=name,kind='flush',packets=packets,**options);c['expected']=contract(c);cases.append(c)
    flush('flush_empty',[]);flush('flush_one',[((0x8000,),4)])
    flush('flush_multi',[((0x10,0x8000,0x100000),8),((1<<32,),12)])
    flush('flush_multiple_buffers',[((0x8000,),1000)]*5)
    flush('flush_exact_fit',[((0x8000,),3932)])
    flush('flush_oversized_no_progress',[((0x8000,),3933)],bridge=False,buffer_limit=2)
    flush('flush_prefix_then_oversized',[((0x8000,),4),((0x8000,),3933)],bridge=False,buffer_limit=2)
    flush('flush_allocation_failure',[((0x8000,),4)],buffer_limit=0)
    flush('flush_synchronous_listener',[((0x8000,),4)],bridge=False)
    flush('flush_send_error',[((0x8000,),4)],send_result=7)
    for index,mask in enumerate((0,0x10,0x8000,0x100000,0x108000,0x108010,0xffffffffffffffff,1<<32,(1<<32)|0x8000)):
        source=packet(SOURCE,(0x10,0x8000,0x100000,1<<32),8)
        c=dict(name=f'filter_{index}',kind='filter',packets=[fixture(SOURCE,source)],mask=mask,
               clone_allocated=True,node_allocated=True,bridge=True,buffer_limit=4,send_result=0,cached=0)
        c['expected']=contract(c);cases.append(c)
    for key in ('clone_allocated','node_allocated'):
        c=dict(name='filter_'+key+'_failure',kind='filter',packets=[fixture(SOURCE,packet(SOURCE))],mask=0x8000,
               clone_allocated=True,node_allocated=True,bridge=True,buffer_limit=4,send_result=0,cached=0);c[key]=False
        c['expected']=contract(c);cases.append(c)
    raw=struct.pack('<I',68)+packet(SOURCE,(0x8000,),4)
    for name,changes in (('valid',{}),('zero_record',dict(prefix=0)),('overrun_record',dict(prefix=80)),
                         ('zero_length',dict(used=0)),('bad_magic',dict(magic=False)),('null_pointer',dict(pointer=False)),
                         ('allocation_failure',dict(allocated=False)),('zero_capacity',dict(capacity=0))):
        options=dict(capacity=128,allocated=True,used=72,magic=True,pointer=True)|{k:v for k,v in changes.items() if k!='prefix'}
        blob=bytearray(raw)
        if 'prefix' in changes:put(blob,0,4,changes['prefix'])
        c=dict(name='buffer_'+name,kind='buffer',blob_hex=blob.hex(),**options);c['expected']=contract(c);cases.append(c)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    data=archive.read(SENSOR)
    if digest(data)!=SENSOR_HASH:raise ValueError('requires reviewed image')
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from reviewed host contracts')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('unexpected native report')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected']:raise ValueError(f'native mismatch {case["name"]}')
        if not 0<row['steps']<=200000:raise ValueError('native bound')
    m=StartupMemory(data)
    return dict(sensor_sha256=SENSOR_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        byte_range_sha256={f'{a:08x}_{n:x}':digest(m.read(a,n)) for a,n in RANGES},native_validation=execution,
        native_steps=sum(row['steps'] for row in execution['cases']),
        limitations=['Packet fixtures, registrations, allocator/free/copy operations, context, locks, event scheduling and send results are supplied.',
            'Flush and event handler execute separately across the supplied event scheduler; transport send stops at the configured operation callback.',
            'Partial filtering uses distinct single-bit stream types with consistent header masks; inconsistent/corrupt descriptor counts are excluded.',
            'Oversized-head tests supply allocation failure after two iterations; no physical incidence or unbounded device hang is established.',
            'Native buffer validity/fixup return does not validate complete record shape; the host wire parser enforces stricter bounds.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive, --vectors, --validation and --decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect cache pipeline: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
