#!/usr/bin/env python3
"""Native sensor reference, listener fanout and cache queue contracts.

Packets, listener registrations, scheduler/context, allocation and OS locks
are synthetic. Free calls are observed without invoking the vendor allocator.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensor_packets import OPTICAL_MASK,TICK,put
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import SENSOR,SENSOR_HASH,uint
else:
    from sensor_packets import OPTICAL_MASK,TICK,put
    from sensorhub_memory import StartupMemory
    from zrpc_packets import SENSOR,SENSOR_HASH,uint

P0=0x81020000
P1=0x81030000
QUEUE=0x81050000
NODE=0x81051000
TARGETS=(0x80f64622,0x80f6462c,0x80f85cbe,0x80f85d14,0x80f80aa2,0x80f80ace,
         0x80f82fb8,0x80f82fe8,0x80fd2c3e,0x80f649be,0x80f635fa,0x80f637dc,
         0x80f63f7a,0x80f63f96,0x80f655f8,0x80f65a0e,0x80fa6028,0x80fa60e4)
RANGES=((0x80f64622,0x3e),(0x80f85cbe,0x2a),(0x80f85d14,0x2e),(0x80f80aa2,0x44),
        (0x80f82fb8,0x6e),(0x80fd2c3e,0x1a),(0x80f649be,0x5a),(0x80f635fa,0x154),
        (0x80f637dc,0xaa),(0x80f63f7a,0x1c),(0x80f63f96,0x20),(0x80f655f8,0xa),
        (0x80f65a0e,0x260),(0x80fa6028,0xbc),(0x80fa60e4,0xe6))


def digest(data):return hashlib.sha256(data).hexdigest()


def packet(base,refs=1,sensor=6,private=0,frames=1):
    for value,bits in ((base,32),(refs,32),(sensor,8),(private,16),(frames,16)):uint(value,bits)
    data=bytearray(68);struct.pack_into('<HHHH',data,0,1,4,sensor,private)
    put(data,8,4,0x8000);put(data,16,4,refs);put(data,20,4,base+24)
    put(data,24,4,0x8000);put(data,32,8,TICK);struct.pack_into('<HHH',data,44,frames,10,20)
    put(data,56,4,base+64);put(data,64,4,0x12345678)
    return data


def summary(data):
    return dict(refs=int.from_bytes(data[16:20],'little'),descriptor=int.from_bytes(data[20:24],'little'),sha256=digest(data))


def change(data,retain,actions,label):
    refs=int.from_bytes(data[16:20],'little');refs=(refs+(1 if retain else -1))&0xffffffff
    put(data,16,4,refs);actions.append(('retain:' if retain else 'release:')+label)
    if not retain and refs==0:put(data,20,4,0);actions.append('free:'+label)


def references_contract(refs,operations,*,context=1,started=True,depth=0,mstatus=0x1888,null=False):
    uint(refs,32);uint(depth,32);uint(mstatus,32)
    if context not in (0,1) or type(started) is not bool or type(null) is not bool:raise ValueError('bad execution context')
    data=packet(P0,refs);actions=[];rows=[]
    if len(operations)>16:raise ValueError('host operation bound')
    for operation in operations:
        if operation not in ('retain','release'):raise ValueError('unknown reference operation')
        if not null:
            if context==0:
                mstatus&=~8
                if started:depth=(depth+1)&0xffffffff
            change(data,operation=='retain',actions,'p0')
            if context==0 and started and depth:
                depth-=1
                if depth==0:mstatus|=8
        rows.append(dict(refs=int.from_bytes(data[16:20],'little'),descriptor=int.from_bytes(data[20:24],'little'),
                         depth=depth,mstatus=mstatus))
    return dict(actions=actions,operations=rows,packet=summary(data),depth=depth,mstatus=mstatus)


def listener_matches(sensor,private,listener):
    uint(sensor,8);uint(private,16);uint(listener,32)
    if private:return 1<=private&255<=5 and listener in (private&255,6)
    if not 1<=sensor<=35:return False
    imu=lambda n:bool(6>>(n&31)&1)
    optical=lambda n:bool(OPTICAL_MASK>>(n&31)&1)
    return listener in (sensor,36) or (imu(listener) and imu(sensor)) or (optical(listener) and optical(sensor))


def fanout_contract(sensor,private,listeners,*,source=True,fusion='none',thread=False):
    if fusion not in ('none','ready','empty') or type(source) is not bool or type(thread) is not bool:
        raise ValueError('bad delivery switches')
    if len(listeners)>12:raise ValueError('host listener bound')
    p0=packet(P0,sensor=sensor,private=private);p1=packet(P1,sensor=sensor,private=private,frames=0 if fusion=='empty' else 1)
    actions=['read'];leases=[]
    if source:
        if 6>>(sensor&31)&1:actions.append('sync')
        actions.append('fusion')
        selected=1 if fusion=='ready' else 0 if fusion=='none' else None
        if selected is not None:
            label='p'+str(selected);data=(p0,p1)[selected];actions.append('cache:'+label)
            valid=1<=private&255<=5 if private else 1<=sensor<=35
            if thread and valid:actions.append('listener_lock')
            for index,(identifier,retain) in enumerate(listeners):
                if type(retain) is not bool:raise ValueError('retain policy must be bool')
                if listener_matches(sensor,private,identifier):
                    actions.append(f'callback:{index}:{label}')
                    if retain:change(data,True,actions,label);leases.append(selected)
            if thread and valid:actions.append('listener_unlock')
        if fusion!='none':change(p1,False,actions,'p1')
        change(p0,False,actions,'p0')
        for selected in leases:change((p0,p1)[selected],False,actions,'p'+str(selected))
    return dict(actions=actions,packets=[summary(p0),summary(p1)])


def cache_contract(*,enabled=True,selected=True,magic=True,allocated=True,drain='take',cached=0,free_memory=200000):
    if any(type(x) is not bool for x in (enabled,selected,magic,allocated)) or drain not in ('none','take','short'):
        raise ValueError('bad cache switches')
    uint(cached,32);uint(free_memory,32)
    data=packet(P0);node=bytearray(b'\xa5'*24);actions=[];queued=False;get_result=None;out=bytes(b'\xa5'*8)
    if enabled and selected:
        change(data,True,actions,'p0')
        if magic:
            actions.append('queue_alloc')
            if allocated:
                queued=True;node=bytearray(struct.pack('<6I',QUEUE,QUEUE,0x80f655f8,8,68,P0))
                actions.extend(('queue_lock','queue_unlock'));cached=(cached+68)&0xffffffff
        if not queued:
            actions.append('cache_failure_log');change(data,False,actions,'p0')
        if cached>0x4fff or free_memory<0x19001:actions.extend(('pressure_log','cache_flush'))
    change(data,False,actions,'p0')
    if queued and drain!='none':
        actions.append('queue_lock');put(node,0,4,NODE);put(node,4,4,NODE)
        if drain=='short':change(data,False,actions,'p0');actions.append('queue_short_log');get_result=1
        else:out=struct.pack('<II',68,P0);get_result=0
        actions.extend(('free:node','queue_unlock'));queued=False
        if drain=='take':change(data,False,actions,'p0')
    return dict(actions=actions,packet=summary(data),cached=cached,get_result=get_result,
                queue=dict(head=NODE if queued else QUEUE,tail=NODE if queued else QUEUE,count=int(queued)),
                node_sha256=digest(node),output_hex=out.hex())


def native_vectors():
    cases=[]
    for refs in (0,1,2,0xffffffff):
        for operations in (['retain'],['release'],['retain','release','release'],['release','release']):
            for context,started,depth,mstatus in ((1,True,0,0x1888),(0,True,0,0x1888),(0,True,0,0x1880),
                                                (0,True,2,0x1880),(0,False,0,0x1888),(0,True,0xffffffff,0x1888)):
                options=dict(context=context,started=started,depth=depth,mstatus=mstatus,null=False)
                cases.append(dict(name=f'refs_{refs:x}_{len(cases)}',kind='refs',refs=refs,operations=operations,**options,
                                  expected=references_contract(refs,operations,**options)))
    options=dict(context=0,started=True,depth=0,mstatus=0x1880,null=True)
    cases.append(dict(name='refs_null',kind='refs',refs=1,operations=['retain','release'],**options,
                      expected=references_contract(1,['retain','release'],**options)))
    listeners=[[1,False],[2,True],[3,False],[5,True],[6,False],[15,True],[16,False],[31,False],[36,True],[257,False]]
    for sensor,private in ((1,0),(2,0),(3,0),(6,0),(16,0),(35,0),(0,0),(36,0),(6,1),(6,5),(6,6),(6,256),(6,257)):
        for fusion in ('none','ready','empty'):
            options=dict(source=True,fusion=fusion,thread=True)
            cases.append(dict(name=f'fanout_{sensor}_{private}_{fusion}',kind='fanout',sensor=sensor,private=private,listeners=listeners,
                              **options,expected=fanout_contract(sensor,private,listeners,**options)))
    options=dict(source=False,fusion='none',thread=False)
    cases.append(dict(name='fanout_no_source',kind='fanout',sensor=6,private=0,listeners=listeners,**options,
                      expected=fanout_contract(6,0,listeners,**options)))
    for index,changes in enumerate(({},dict(drain='none'),dict(drain='short'),dict(enabled=False),dict(selected=False),
                                   dict(magic=False),dict(allocated=False),dict(cached=20480),dict(free_memory=102400),
                                   dict(free_memory=102401),dict(cached=0x4fff-68),dict(cached=0x5000-68))):
        options=dict(enabled=True,selected=True,magic=True,allocated=True,drain='take',cached=0,free_memory=200000)|changes
        cases.append(dict(name=f'cache_{index}',kind='cache',**options,expected=cache_contract(**options)))
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    data=archive.read(SENSOR)
    if digest(data)!=SENSOR_HASH:raise ValueError('requires reviewed sensor image')
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from reviewed model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):
        raise ValueError('unexpected native execution report')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected']:raise ValueError('native contract mismatch')
        if not 0<row['steps']<=100000:raise ValueError('invalid execution bound')
    memory=StartupMemory(data)
    return dict(sensor_sha256=SENSOR_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_case_counts={kind:sum(c['kind']==kind for c in expected['cases']) for kind in ('refs','fanout','cache')},
        native_steps=sum(row['steps'] for row in execution['cases']),native_validation=execution,
        limitations=['Allocation/free, OS locks, context predicates and memory-pressure readings are supplied; no concurrent execution or hardware access.',
            'Fanout starts with a supplied read/fusion result and treats cache as a no-op; callback retention policies are synthetic.',
            'Cache cases execute all-selected/none-selected branches and one queue node; filtering/copy, motion triggers and real pressure flush remain open.',
            'Successful dequeue transfers the queued reference to the caller; the harness separately invokes native cleanup after inspecting it.',
            'Reference wrap/underflow cases document instructions and do not establish reachable device misuse or safe ownership guarantees.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive, --vectors, --validation and --decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect delivery contracts: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
