#!/usr/bin/env python3
"""Bounded optical FIFO lifecycle models and synthetic native-execution vectors.

SPI results, tick/context values and event registration are supplied inputs.
No device, FIFO hardware or final health algorithm is accessed or implemented.
"""
import argparse
from dataclasses import asdict, dataclass, replace
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

RING_WORDS=1000
STAGE_SIZE=2052
TARGETS=(0x80f74526,0x80f72e86,0x80f72ea4,0x80f72f18,0x80f738be,0x80f73906,
         0x80f75bf6,0x80f747c0,0x80f7f958,0x80f80aa0,0x80f8263e,0x80f82648,
         0x80fa40b0,0x80fa286a,0x80f63aa6,0x80f63f6c)


@dataclass(frozen=True)
class State:
    count:int=0
    write:int=0
    read:int=0
    frame:int=2
    auxiliary:int=0
    mode:int=2
    policy:int=0
    last_tick:int=0
    limit:int=100
    frame_total:int=9
    enabled:bool=True
    base_frame:int=2

    def __post_init__(self):
        for name in ('count','write','read'):
            value=getattr(self,name);uint(value,16)
            if value>(1000 if name=='count' else 999):raise ValueError('ring metadata outside host bounds')
        for name in ('frame','base_frame'):
            value=getattr(self,name)
            if type(value) is not int or not 0<=value<=32:raise ValueError('frame outside reviewed host range')
        for name,bits in (('auxiliary',16),('mode',16),('policy',8),('last_tick',32),('limit',32),('frame_total',32)):
            uint(getattr(self,name),bits)
        if type(self.enabled) is not bool:raise ValueError('enabled must be bool')


def reset_metadata(state):
    return replace(state,count=0,write=0,read=0,frame=state.base_frame)


def recovery(state,*,notify=True,registers=None,registered=True):
    if type(notify) is not bool or type(registered) is not bool:raise ValueError('recovery switches must be bool')
    if not state.enabled:return state,[]
    registers={9:5,13:16} if registers is None else registers
    actions=[];temporary=0
    for register in (9,13):
        actions.append(f'read:{register}')
        value=registers.get(register)
        if value is not None:temporary=uint(value,8)
        if register==9:actions.append(f'write:9:{temporary|16}')
        else:actions.extend((f'write:13:{temporary|2}',f'write:13:{temporary}'))
    if notify:
        actions.append('event:0206000000000000')
        if registered:actions.append('control:6:129:0:0')
    return replace(reset_metadata(state),last_tick=0),actions


def fifo_read(state,ring,stage,*,now,registers,response=b'',bulk_result=0,registered=True):
    uint(now,32);uint(bulk_result,32)
    if len(ring)!=RING_WORDS or not isinstance(stage,bytes) or len(stage)!=STAGE_SIZE:
        raise ValueError('wrong host cache or staging buffer size')
    if not isinstance(response,bytes):raise ValueError('response must be bytes')
    ring=list(ring);actions=[]
    if state.last_tick and ((now-state.last_tick)&0xffffffff)>state.limit:
        state,actions=recovery(state,registers=registers,registered=registered)
        return state,ring,stage,actions
    state=replace(state,last_tick=now)
    values=[]
    for register in (3,4):
        actions.append(f'read:{register}');value=registers.get(register)
        values.append(0 if value is None else uint(value,8))
    available=((values[0]&0xc0)<<2)|values[1]
    if available>=512 or available+state.count>1000:
        state,more=recovery(state,registers=registers,registered=registered)
        return state,ring,stage,actions+more
    words=state.frame*(available//state.frame) if state.frame else 0
    if not words:return state,ring,stage,actions
    size=2+words*4
    if len(response)>size:raise ValueError('supplied response exceeds native transfer size')
    state=replace(state,frame_total=(state.frame_total+available//state.frame)&0xffffffff)
    merged=bytearray(stage);merged[:2]=b'\x08\x80';merged[:len(response)]=response;stage=bytes(merged)
    actions.append(f'bulk:{size}') # result word is deliberately not inspected by native FIFO code
    for index in range(words):
        word=struct.unpack_from('>I',stage,2+index*4)[0]
        if state.mode and index%state.frame==0 and ((word>>24)&31)!=1 and ((word>>29)&3)!=0:
            state,more=recovery(state,registers=registers,registered=registered)
            return state,ring,stage,actions+more
        ring[state.write]=word
        mark=state.policy!=2 and state.mode!=1
        state=replace(state,count=state.count+1,write=(state.write+1)%1000,
                      auxiliary=(state.auxiliary+int(mark))&65535)
    return state,ring,stage,actions


def pop_word(state,ring,flags=0):
    uint(flags,8)
    if len(ring)!=RING_WORDS:raise ValueError('wrong ring size')
    if not state.count:return state,0,flags
    word=uint(ring[state.read],32)
    mark=state.auxiliary!=0 and state.mode!=1
    return replace(state,count=state.count-1,read=(state.read+1)%1000,
                   auxiliary=state.auxiliary-int(mark)),word,flags|int(mark)


def sample_value(index,word):
    uint(index,32);uint(word,32)
    measurement=(word>>24)&31
    value=word&0xfffff
    signed=value-0x100000 if value&0x80000 else value
    return signed,measurement!=((index+1)&255) and measurement not in (21,22)


def ring_bytes(ring):return struct.pack('<1000I',*ring)


def digest(data):return hashlib.sha256(data).hexdigest()


def response_words(words):return b'\xaa\xbb'+b''.join(struct.pack('>I',word) for word in words)


def native_vectors():
    cases=[]
    def add(name,*,kind='fifo',state=None,registers=None,response=None,now=100,
            initial_words=(0x21000009,0x2100000a),bulk_result=0,registered=True,notify=True,
            ring_overrides=None,flags=160,index=0,word=0):
        state=state or State()
        registers={3:0,4:2,9:5,13:16} if registers is None else registers
        response=response_words((0x21000001,0x21000002)) if response is None else response
        ring=[0xdeadbeef]*1000
        for location,value in (ring_overrides or {}).items():ring[int(location)]=value
        stage=bytearray(b'\xa5'*STAGE_SIZE);stage[:2]=b'\x55\xaa'
        for n,value in enumerate(initial_words):struct.pack_into('>I',stage,2+4*n,value)
        returned=None;out_flags=flags
        if kind=='fifo':out,cache,staged,actions=fifo_read(state,ring,bytes(stage),now=now,registers=registers,
                response=response,bulk_result=bulk_result,registered=registered)
        elif kind=='recovery':
            out,actions=recovery(state,notify=notify,registers=registers,registered=registered);cache=ring;staged=bytes(stage)
        elif kind=='reset':out=reset_metadata(state);cache=ring;staged=bytes(stage);actions=[]
        elif kind=='pop':
            out,returned,out_flags=pop_word(state,ring,flags);cache=ring;staged=bytes(stage);actions=[]
        elif kind=='sample':
            signed,logged=sample_value(index,word);returned=signed&0xffffffff
            out=state;cache=ring;staged=bytes(stage);actions=['sample_tag_log'] if logged else []
        else:raise ValueError('unknown synthetic vector kind')
        cases.append(dict(name=name,kind=kind,state=asdict(state),now=now,context=len(cases)%2,
            registers={str(k):v for k,v in registers.items()},response_hex=response.hex(),
            initial_words=list(initial_words),bulk_result=bulk_result,registered=registered,notify=notify,
            ring_overrides={str(k):v for k,v in (ring_overrides or {}).items()},flags=flags,index=index,word=word,
            expected=dict(state=asdict(out),ring_sha256=digest(ring_bytes(cache)),stage_sha256=digest(staged),
                          returned=returned,flags=out_flags,actions=actions)))
    add('complete_frames')
    add('ring_wrap',state=State(count=10,write=999,read=989))
    add('burst_failure_stale_payload',response=b'',bulk_result=0xfffffff2)
    add('burst_failure_complete_payload',bulk_result=0xfffffff2)
    add('burst_failure_partial_word',response=response_words((0x2100aabb,))[:5],bulk_result=0xfffffff2)
    add('both_status_reads_fail',registers={3:None,4:None,9:5,13:16},response=b'')
    add('high_status_read_fails',registers={3:None,4:2,9:5,13:16})
    add('low_status_read_fails',registers={3:0,4:None,9:5,13:16},response=b'')
    add('no_complete_frame',registers={3:0,4:1,9:5,13:16},response=b'')
    add('zero_frame',state=State(frame=0),response=b'')
    add('round_to_frame',state=State(frame=3),registers={3:0,4:5,9:5,13:16},
        response=response_words((0x21000001,0x22000002,0x23000003)))
    add('fifo_count_512',registers={3:128,4:0,9:5,13:16},response=b'')
    add('overflow_before_rounding',state=State(count=998,write=998),registers={3:0,4:3,9:5,13:16},response=b'')
    add('cache_exactly_full',state=State(count=998,write=998))
    add('maximum_511_words',state=State(frame=1,mode=0),registers={3:64,4:255,9:5,13:16},
        response=response_words(range(511)))
    add('frame_error_after_prefix',state=State(frame=1),response=response_words((0x21000001,0x22000002)))
    add('frame_error_recovery_disabled',state=State(frame=1,enabled=False),response=response_words((0x21000001,0x22000002)))
    add('frame_error_non_start_allowed',response=response_words((0x21000001,0x22000002)))
    add('frame_error_channel_zero_allowed',response=response_words((0x02000001,0x02000002)))
    add('mode_one_does_not_mark',state=State(mode=1,auxiliary=5))
    add('policy_two_does_not_mark',state=State(policy=2,auxiliary=5))
    add('auxiliary_wrap',state=State(auxiliary=65535))
    add('timeout_at_limit',state=State(last_tick=50,limit=50))
    add('timeout_past_limit',state=State(count=3,write=3,last_tick=49,limit=50),response=b'')
    add('timeout_recovery_disabled',state=State(count=3,write=3,last_tick=49,limit=50,enabled=False),response=b'')
    add('tick_rollover_at_limit',state=State(last_tick=0xfffffffe,limit=3),now=1)
    add('tick_rollover_expired',state=State(last_tick=0xfffffffe,limit=2),now=1,response=b'')
    add('zero_timestamp_sentinel',state=State(last_tick=0,limit=0))
    for name,reg9,reg13 in (('normal_recovery',5,16),('recovery_read13_failure',5,None),
                           ('recovery_both_reads_fail',None,None)):
        add(name,kind='recovery',state=State(count=4,write=7,read=3,frame=4,auxiliary=9,last_tick=10,base_frame=3),
            registers={3:0,4:0,9:reg9,13:reg13})
    add('recovery_without_notification',kind='recovery',notify=False)
    add('recovery_without_registered_callback',kind='recovery',registered=False)
    add('inactive_recovery',kind='recovery',state=State(enabled=False,count=2,write=3,read=1))
    add('metadata_only_reset',kind='reset',state=State(count=2,write=3,read=1,auxiliary=7,last_tick=12,frame=4,base_frame=3))
    for name,state,overrides in (
        ('pop_empty',State(),{}),('pop_marked',State(count=2,write=2,auxiliary=2),{0:0x21080000}),
        ('pop_ring_wrap',State(count=1,read=999,auxiliary=1),{999:0x210fffff}),
        ('pop_mode_one',State(count=1,write=1,mode=1,auxiliary=3),{0:0x2107ffff})):
        add(name,kind='pop',state=state,ring_overrides=overrides)
    for name,index,word in (('sample_max',0,0x2107ffff),('sample_min',0,0x21080000),
        ('sample_minus_one',0,0x210fffff),('sample_unexpected_tag_logged',0,0x22000001),
        ('sample_special_tag_21',0,0x55000001),('sample_special_tag_22',0,0x56000001)):
        add(name,kind='sample',index=index,word=word)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    data=archive.read(SENSOR)
    if digest(data)!=SENSOR_HASH:raise ValueError('requires reviewed sensor image')
    supplied=json.loads(vectors.read_bytes());expected=native_vectors()
    if supplied!=expected:raise ValueError('synthetic vectors differ from the reviewed model')
    raw=validation.read_bytes();execution=json.loads(raw)
    if execution['case_count']!=len(expected['cases']) or execution['hardware_execution'] is not False:
        raise ValueError('unexpected native FIFO execution report')
    if [row['name'] for row in execution['cases']]!=[row['name'] for row in expected['cases']]:
        raise ValueError('native FIFO cases differ')
    for row,case in zip(execution['cases'],expected['cases']):
        for field in ('state','actions','ring_sha256','stage_sha256','returned','flags'):
            if row[field]!=case['expected'][field]:raise ValueError(f'native {case["name"]} {field} differs from model')
    m=StartupMemory(data)
    return dict(sensor_sha256=SENSOR_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(raw),
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        byte_range_sha256={f'{a:08x}_{n:x}':digest(m.read(a,n)) for a,n in
            ((0x80f74526,0x272),(0x80f72e86,0xda),(0x80f738be,0x8a),(0x80f7f958,0x1a),
             (0x80f8263e,0x14),(0x80f80aa0,2),(0x80f63aa6,0xc8),(0x80f63f6c,0xe),(0x80fa40b0,0x14))},
        state_addresses=dict(count=0x80f1705c,write=0x80f1705e,read=0x80f17060,frame=0x80f17062,
            auxiliary=0x80f17066,mode=0x80f17070,policy=0x80f1706d,last_tick=0x80f17050,
            frame_total=0x80f17054,limit=0x80f1704c,enabled=0x80f17091,base_frame=0x80f16b30),
        cache=dict(address=0x80f5073c,words=1000,staging=0x80f4ff38,staging_host_bytes=STAGE_SIZE),
        kernel_tick_address=0x80f171a4,native_validation=execution,
        limitations=['SPI outcomes, contexts, ticks and callback-list registration are synthetic; no device/scheduler execution.',
            'Native FIFO ignores supplied burst result and decodes remaining staging bytes; no live fault incidence established.',
            'Event dispatch uses one synthetic registered listener and stops at control request 0x81; worker/IPC effects not executed.',
            'Frame range 0..32 and valid ring metadata are host bounds; corrupted pointers and concurrency are excluded.',
            'Sample helper only sign-extends and logs tags; complete consumer, calibration and health algorithms remain open.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    parser.add_argument('--vectors-output',type=Path);parser.add_argument('--vectors',type=Path)
    parser.add_argument('--validation',type=Path);parser.add_argument('--decompiled',type=Path);args=parser.parse_args()
    try:
        if args.vectors_output:
            args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive, --vectors, --validation and --decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:
        parser.exit(2,f'Cannot inspect FIFO lifecycle: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
