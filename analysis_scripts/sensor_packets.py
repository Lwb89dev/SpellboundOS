#!/usr/bin/env python3
"""Bounded host contracts for sensor flush routing and native sample packets.

The heap, driver table, callbacks, clock and SPI replies are synthetic inputs.
These models neither access hardware nor implement the health algorithms.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import SENSOR, SENSOR_HASH, uint
else:
    from sensorhub_memory import StartupMemory
    from zrpc_packets import SENSOR, SENSOR_HASH, uint

WINDOW=0x80f4fb20
HEAP=0x81020000
RELOCATED=0x81200000
TICK=0x12345678abcdef01
OPTICAL_MASK=0x6de0ffe0
TARGETS=(0x80f632dc,0x80f64216,0x80f64238,0x80f65cd6,0x80f65ce8,
         0x80f65e2e,0x80f66298,0x80f763be,0x80f6453e,0x80f645e2,0x80f747c0)
RANGES=((0x80f632dc,0x24),(0x80f64216,0x328),(0x80f65cd6,0x24),
        (0x80f65e2e,0x1a2),(0x80f66298,0x8e),(0x80f763be,0x8fc),
        (0x80f72e86,0xda),(0x80f738be,0x8a),(0x80f73906,0x42),
        (0x80f6453e,0xe4),(0x80f747c0,0x1436),(0x80f72ea4,0xbc))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(buffer,offset,width,value):
    buffer[offset:offset+width]=(value&((1<<(width*8))-1)).to_bytes(width,'little')


def flush_contract(sensor,flags,*,present=True,callback=True,enabled=True):
    uint(sensor,32);uint(flags,32)
    for value in (present,callback,enabled):
        if type(value) is not bool:raise ValueError('switches must be bool')
    if sensor>257:raise ValueError('sensor outside synthetic table bounds')
    window=bytearray(b'\xa5'*512);put(window,0x1fc,4,flags)
    optical=dict(count=4,write=7,read=3,frame=4,last_tick=10)
    actions=[]
    valid=((sensor-1)&255)<35 and present
    def clear(address,width=4):put(window,address-WINDOW,width,0)
    def deliver(identifier):
        if identifier==sensor and not callback:return
        actions.append(f'callback:{identifier}:129:0:0')
        if identifier==6 and enabled:
            optical.update(count=0,write=0,read=0,frame=3,last_tick=0)
            actions.extend(('read:9','write:9:21','read:13','write:13:18','write:13:16'))
    if valid:
        a=bool(flags&0x38);b=bool(flags&6)
        imu=sensor&31 in (1,2)
        optical_group=bool(OPTICAL_MASK>>(sensor&31)&1)
        coordinated=(a and (imu or optical_group)) or (b and (imu or sensor==3))
        if coordinated:
            deliver(1)
            if a:deliver(6)
            if b:deliver(3)
            for address in (0x80f4fce4,0x80f4fcf0,0x80f4fb34,0x80f4fb48,0x80f4fb64,
                            0x80f4fb78,0x80f4fb94,0x80f4fba8,0x80f4fbc4,0x80f4fbd8,
                            0x80f4fbf4,0x80f4fc08,0x80f4fc24,0x80f4fc38,0x80f4fc54,0x80f4fc68):
                clear(address,2 if address in range(0x80f4fb34,0x80f4fc55,0x30) else 4)
        if coordinated or imu:
            for address in (0x80f4fcd8,0x80f4fc84,0x80f4fca4,0x80f4fc70,0x80f4fc74,
                            0x80f4fc78,0x80f4fc7c,0x80f4fc90,0x80f4fc94,0x80f4fc98,0x80f4fc9c):clear(address)
            for address in (0x80f4fc8a,0x80f4fcaa):clear(address,1)
        if (coordinated and a) or optical_group:
            for address in (0x80f4fcb0,0x80f4fcb4,0x80f4fcb8,0x80f4fcbc,0x80f4fcc4):clear(address)
            clear(0x80f4fcca,1)
        if coordinated:
            for address,active in ((0x80f4fcf8,a),(0x80f4fd08,b)):
                if active:
                    clear(address,16);put(window,address-WINDOW,8,TICK)
                    actions.append('clock')
        else:deliver(sensor)
    return dict(returned=0 if valid else 2,actions=actions,fusion_sha256=digest(window),optical=optical)


def packet_size(count,stride):
    uint(count,32);uint(stride,32)
    return ((stride+40)*count+24)&0xffffffff


def packet_contract(count,stride,*,allocated=True,rebind=False):
    size=packet_size(count,stride);actions=[]
    if type(allocated) is not bool or type(rebind) is not bool:raise ValueError('switches must be bool')
    if not count or not stride:return dict(returned=0,actions=[],heap_sha256=None,relocated_sha256=None)
    actions.append(f'alloc:4:{size}:4')
    if not allocated:
        return dict(returned=0,actions=actions+['allocation_log'],heap_sha256=None,relocated_sha256=None)
    if not 1<=count<=32 or size>262144 or stride>65536:raise ValueError('outside successful host allocation bounds')
    data=bytearray(size)
    put(data,0,2,count);put(data,2,2,stride);put(data,16,4,1);put(data,20,4,HEAP+24)
    actions.extend((f'zero:{size}','clock'))
    for index in range(count):
        put(data,24+40*index+8,8,TICK)
        put(data,24+40*index+32,4,HEAP+24+40*count+stride*index)
    relocated=None
    if rebind:
        moved=bytearray(data);put(moved,16,4,1);put(moved,20,4,RELOCATED+24)
        for index in range(count):put(moved,24+40*index+32,4,RELOCATED+24+40*count+(stride&65535)*index)
        relocated=digest(moved)
    return dict(returned=HEAP,actions=actions,heap_sha256=digest(data),relocated_sha256=relocated)


def consumer_contract(words,*,secondary=0,rate=10,dac=0,read=0,enabled=True,locked=True,allocated=True,tick=TICK):
    """Reviewed mode 1 only: prefilled cache, frame width 2, no concurrent reader."""
    uint(rate,16);uint(dac,32);uint(tick,64)
    if secondary not in (0,1) or not 0<=read<1000 or len(words)>1000:raise ValueError('consumer host bounds')
    for value in (enabled,locked,allocated):
        if type(value) is not bool:raise ValueError('consumer switches must be bool')
    ring=[0xdeadbeef]*1000
    for index,word in enumerate(words):ring[(read+index)%1000]=uint(word,32)
    state=dict(count=len(words),read=read,auxiliary=7,counter=5);actions=[];data=None
    available=len(words)//2;frames=min(available,rate*1200//1000)
    if enabled:
        actions.append('lock:4660')
        if locked:
            if available:
                if frames<available:actions.append('clamp_log')
                streams=1+secondary;stride=frames*4
                if stride:
                    size=packet_size(streams,stride);actions.append(f'alloc:4:{size}:4')
                    if not allocated:actions.append('allocation_log')
                    else:
                        data=bytearray(size);put(data,0,2,streams);put(data,2,2,stride)
                        put(data,16,4,1);put(data,20,4,HEAP+24);actions.extend((f'zero:{size}','clock'))
                        offset=((dac*0x7ffff)&0xffffffff)>>5
                        for stream in range(streams):
                            descriptor=24+40*stream;payload=24+40*streams+stride*stream
                            put(data,descriptor,4,0x8000 if stream==0 else 0x100000)
                            put(data,descriptor+8,8,(tick-(available-frames)*1000//rate)&0xffffffffffffffff)
                            put(data,descriptor+20,2,frames);put(data,descriptor+22,2,rate)
                            put(data,descriptor+24,2,20);put(data,descriptor+32,4,HEAP+payload)
                            for index in range(frames):
                                word=words[2*index+stream]
                                # Actions must follow the native interleaved pop order below.
                                value=word&0xfffff
                                if value&0x80000:value-=0x100000
                                put(data,payload+4*index,4,value+offset)
                        for index in range(frames):
                            for stream in range(streams):
                                tag=(words[2*index+stream]>>24)&31
                                if tag not in (stream+1,21,22):actions.append('sample_tag_log')
                        state.update(count=len(words)-2*frames,read=(read+2*frames)%1000,counter=0)
            actions.append('unlock:4660')
    return dict(returned=HEAP if data is not None else 0,actions=actions,state=state,
                heap_sha256=digest(data) if data is not None else None,
                ring_sha256=digest(struct.pack('<1000I',*ring)))


def native_vectors():
    cases=[]
    def flush(sensor,flags,**options):
        options=dict(present=True,callback=True,enabled=True)|options
        name=f'flush_{sensor}_{flags:x}'+''.join(f'_{k}_off' for k,v in options.items() if not v)
        cases.append(dict(name=name,kind='flush',sensor=sensor,flags=flags,**options,
                          expected=flush_contract(sensor,flags,**options)))
    for flags in range(64):
        for sensor in (1,2,3,4,6,31):flush(sensor,flags)
    for sensor in range(1,36):
        if sensor not in (1,2,3,4,6,31):
            for flags in (0,2,8,10):flush(sensor,flags)
    for sensor in (0,36,256,257):
        for flags in (0,10):flush(sensor,flags)
    for flags in (0,8,10):
        for option in ('present','callback','enabled'):flush(6,flags,**{option:False})
    for count,stride in ((0,4),(2,0),(1,1),(1,4),(2,4),(3,12),(4,24),(5,64),(32,8),(2,65536)):
        for allocated in (False,True):
            options=dict(allocated=allocated,rebind=True)
            cases.append(dict(name=f'packet_{count}_{stride}_{int(allocated)}',kind='packet',count=count,stride=stride,
                              **options,expected=packet_contract(count,stride,**options)))
    for count,stride in ((65536,4),(1,0xffffffff),(0xffffffff,0xffffffff)):
        cases.append(dict(name=f'packet_wrap_{count}_{stride}',kind='packet',count=count,stride=stride,
                          allocated=False,rebind=False,expected=packet_contract(count,stride,allocated=False)))
    def consume(name,words=None,**options):
        options=dict(secondary=0,rate=10,dac=0,read=0,enabled=True,locked=True,allocated=True,tick=TICK)|options
        words=[0x2107ffff,0x22080000,0x210fffff,0x22000001] if words is None else words
        cases.append(dict(name=name,kind='consumer',words=words,**options,expected=consumer_contract(words,**options)))
    consume('consumer_one_stream');consume('consumer_two_streams',secondary=1)
    consume('consumer_offset',secondary=1,dac=32);consume('consumer_offset_wrap',secondary=1,dac=0xffffffff)
    consume('consumer_ring_wrap',secondary=1,read=999)
    consume('consumer_partial_frame',words=[0x21000001,0x22000002,0x21000003])
    consume('consumer_empty',words=[]);consume('consumer_disabled',enabled=False)
    consume('consumer_lock_failure',locked=False);consume('consumer_allocation_failure',allocated=False)
    consume('consumer_zero_rate',rate=0)
    consume('consumer_clamped',words=[0x21000001,0x22000002]*20,secondary=1,rate=10)
    consume('consumer_timestamp_borrow',words=[0x21000001,0x22000002]*20,secondary=1,rate=10,tick=0x1234567800000010)
    consume('consumer_bad_first_tag',words=[0x22000001,0x22000002],secondary=1)
    consume('consumer_bad_discarded_tag',words=[0x21000001,0x23000002])
    consume('consumer_bad_secondary_tag',words=[0x21000001,0x23000002],secondary=1)
    consume('consumer_special_tags',words=[0x55000001,0x56000002],secondary=1)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    data=archive.read(SENSOR)
    if digest(data)!=SENSOR_HASH:raise ValueError('requires reviewed sensor image')
    expected=native_vectors()
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from reviewed host model')
    execution=json.loads(validation.read_bytes())
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']):
        raise ValueError('unexpected native execution report')
    if len(execution['cases'])!=len(expected['cases']):raise ValueError('wrong native case count')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected']:raise ValueError('native contract mismatch')
        if not 0<row['steps']<=100000:raise ValueError('invalid execution bound')
    memory=StartupMemory(data)
    return dict(sensor_sha256=SENSOR_HASH,vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_case_counts={kind:sum(c['kind']==kind for c in expected['cases']) for kind in ('flush','packet','consumer')},
        native_steps=sum(row['steps'] for row in execution['cases']),native_validation=execution,
        limitations=['Driver table, non-optical callbacks, allocation, memset, clock and SPI outcomes are synthetic.',
            'Native flush backend starts after the worker/control transport; no scheduler/IPC or physical reset success is established.',
            'Successful allocation model bounds count to 1..32 and stride to 1..65536; wider malformed values only exercise allocator failure.',
            'Consumer executes only mode 1 with frame width 2 and a prefilled cache; mutex outcomes are synthetic and peripheral acquisition is skipped.',
            'The packet is a native pointer-bearing runtime object, not a portable wire format; other consumer modes, calibration and health algorithms remain open.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:
            args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive, --vectors, --validation and --decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect sensor contracts: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
