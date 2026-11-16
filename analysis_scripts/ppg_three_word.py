#!/usr/bin/env python3
"""Bounded mode-2/3 optical consumer model, with a prefilled three-word ring."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .sensor_packets import HEAP,TICK,packet_size,put
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import SENSOR,SENSOR_HASH,uint
else:
    from sensor_packets import HEAP,TICK,packet_size,put
    from sensorhub_memory import StartupMemory
    from zrpc_packets import SENSOR,SENSOR_HASH,uint


def digest(data):return hashlib.sha256(data).hexdigest()


def signed20(word):
    value=word&0xfffff
    return value-0x100000 if value&0x80000 else value


def contract(words,*,mode=2,frame=3,secondary=0,rate=10,dac=0,read=0,enabled=True,locked=True,
             allocated=True,tick=TICK,clip=0,channel_offset=0,minimum=-1000000,maximum=1000000,
             auxiliary=7,policy=2,counter=5,calibration=0):
    if mode not in (2,3) or frame!=3:raise ValueError('only reviewed three-word modes')
    for value,bits in ((secondary,8),(rate,16),(dac,32),(read,16),(tick,64),(clip,8),(channel_offset,8),
                       (auxiliary,16),(policy,8),(counter,32),(calibration,8)):uint(value,bits)
    if secondary>1 or read>=1000 or len(words)>999:raise ValueError('consumer host bounds')
    if any(type(v) is not bool for v in (enabled,locked,allocated)):raise ValueError('switches must be bool')
    for v in (minimum,maximum):
        if type(v) is not int or not -(1<<31)<=v<(1<<31):raise ValueError('signed threshold range')
    ring=[0xdeadbeef]*1000
    for i,word in enumerate(words):ring[(read+i)%1000]=uint(word,32)
    actions=[];data=None;state=dict(count=len(words),read=read,auxiliary=auxiliary,counter=counter)
    available=len(words)//3;frames=min(available,rate*1200//1000)
    if enabled:
        actions.append('lock:4660')
        if locked:
            if available:
                if frames<available:actions.append('clamp_log')
                streams=2+secondary;stride=frames*4
                if stride:
                    size=packet_size(streams,stride);actions.append(f'alloc:4:{size}:4')
                    if not allocated:actions.append('allocation_log')
                    else:
                        data=bytearray(size);put(data,0,2,streams);put(data,2,2,stride)
                        put(data,16,4,1);put(data,20,4,HEAP+24);actions.extend((f'zero:{size}','clock'))
                        values=[[] for _ in range(streams)];bad=0
                        global_offset=((dac*0x7ffff)&0xffffffff)>>5
                        for index in range(frames):
                            first,second,third=words[3*index:3*index+3]
                            for stream,word in ((1,first),(2,second)):
                                if stream==2 and not secondary:continue
                                if ((word>>24)&31) not in (stream,21,22):actions.append('sample_tag_log')
                                values[stream].append((signed20(word)+global_offset)&0xffffffff)
                            raw=signed20(third);value=raw+(channel_offset*0x7ffff>>5);values[0].append(value&0xffffffff)
                            if clip and (abs(raw)>524286 or value<minimum or value>maximum):bad+=1
                        marked=auxiliary>0
                        for stream,samples in enumerate(values):
                            descriptor=24+40*stream;payload=24+40*streams+stride*stream
                            put(data,descriptor,4,(0x10,0x8000,0x100000)[stream])
                            put(data,descriptor+8,8,(tick-(available-frames)*1000//rate)&0xffffffffffffffff)
                            put(data,descriptor+20,2,frames);put(data,descriptor+22,2,rate);put(data,descriptor+24,2,20)
                            if stream==0:put(data,descriptor+28,2,int(marked) if policy==2 else 1)
                            put(data,descriptor+32,4,HEAP+payload)
                            for i,value in enumerate(samples):put(data,payload+4*i,4,value)
                        new_counter=(counter+frames)&0xffffffff if frames==bad else 0
                        signed_counter=new_counter if new_counter<0x80000000 else new_counter-0x100000000
                        if frames==bad and signed_counter>=2*rate:
                            new_counter=0
                            if calibration==0:actions.append('postprocess_reset')
                        state.update(count=len(words)-3*frames,read=(read+3*frames)%1000,
                                     auxiliary=max(0,auxiliary-3*frames),counter=new_counter)
            actions.append('unlock:4660')
    return dict(returned=HEAP if data is not None else 0,actions=actions,state=state,
                heap_sha256=digest(data) if data is not None else None,ring_sha256=digest(struct.pack('<1000I',*ring)))


def native_vectors():
    cases=[]
    def add(name,words=None,**changes):
        words=[0x2107ffff,0x22080000,0x23000003,0x210fffff,0x22000001,0x230fffff] if words is None else words
        options=dict(mode=2,frame=3,secondary=0,rate=10,dac=0,read=0,enabled=True,locked=True,allocated=True,tick=TICK,
                     clip=0,channel_offset=0,minimum=-1000000,maximum=1000000,auxiliary=7,policy=2,counter=5,calibration=0)|changes
        cases.append(dict(name=name,kind='consumer',words=words,**options,expected=contract(words,**options)))
    add('mode2_two_streams');add('mode2_three_streams',secondary=1);add('mode3_three_streams',mode=3,secondary=1)
    add('mode2_global_offset',secondary=1,dac=32);add('mode2_channel_offset',channel_offset=32)
    add('mode2_ring_wrap',read=999);add('mode2_partial_frame',words=[0x21000001,0x22000002,0x23000003,0x21000004])
    add('mode2_empty',words=[]);add('mode2_disabled',enabled=False);add('mode2_lock_failure',locked=False)
    add('mode2_allocation_failure',allocated=False);add('mode2_zero_rate',rate=0)
    add('mode2_no_auxiliary',auxiliary=0);add('mode2_one_marked_word',auxiliary=1)
    add('mode2_policy_non_two',auxiliary=0,policy=0)
    add('mode2_bad_first_tag',words=[0x22000001,0x22000002,0x23000003])
    add('mode2_discarded_second_tag',words=[0x21000001,0x23000002,0x23000003])
    add('mode2_checked_second_tag',words=[0x21000001,0x23000002,0x23000003],secondary=1)
    add('mode2_ignored_third_tag',words=[0x21000001,0x22000002,0x2f000003],secondary=1)
    for raw in (0x7fffe,0x7ffff,0x80000,0x80001):
        add(f'mode2_clip_raw_{raw:x}',words=[0x21000001,0x22000002,0x23000000|raw],clip=1,rate=2,counter=0)
    add('mode2_clip_at_limits',words=[0x21000001,0x22000002,0x23000064],clip=1,minimum=-100,maximum=100,counter=0)
    add('mode2_clip_past_limit',words=[0x21000001,0x22000002,0x23000065],clip=1,minimum=-100,maximum=100,counter=0)
    add('mode2_all_bad_reset',words=[0x21000001,0x22000002,0x2307ffff]*2,clip=1,rate=2,counter=2)
    add('mode2_calibration_suppresses_reset',words=[0x21000001,0x22000002,0x2307ffff]*2,clip=1,rate=2,counter=2,calibration=1)
    add('mode2_mixed_bad_resets_counter',words=[0x21000001,0x22000002,0x2307ffff,0x21000001,0x22000002,0x23000000],clip=1)
    add('mode2_clamped_timestamp_borrow',words=[0x21000001,0x22000002,0x23000003]*20,rate=10,tick=0x1234567800000010)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    data=archive.read(SENSOR)
    if digest(data)!=SENSOR_HASH:raise ValueError('requires reviewed sensor image')
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from reviewed host model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):
        raise ValueError('unexpected execution report')
    for row,case in zip(execution['cases'],expected['cases']):
        actual=row['observed']
        if row['name']!=case['name'] or actual!=case['expected']:raise ValueError('native consumer mismatch')
        if not 0<row['steps']<=100000:raise ValueError('invalid native execution bound')
    memory=StartupMemory(data)
    return dict(sensor_sha256=SENSOR_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
                export_sha256=digest((decompiled/'80f747c0.c').read_bytes()),
                byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in ((0x80f747c0,0x1436),(0x80f72ea4,0xbc),(0x80f6453e,0xa4))},
                native_validation=execution,native_steps=sum(row['steps'] for row in execution['cases']),
                limitations=['Only modes 2/3, frame width 3, optional-stream byte 0/1, channel-count byte 0 and a prefilled ring are executed.',
                    'Lock, allocation, memset, clock, diagnostics and postprocess-reset helper are intercepted; no peripheral or concurrency execution.',
                    'Values are native sample integers; stream meanings, calibrated units, measurement accuracy and other modes remain open.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive, --vectors, --validation and --decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect three-word consumer: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
