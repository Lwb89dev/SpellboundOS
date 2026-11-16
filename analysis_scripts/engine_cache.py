#!/usr/bin/env python3
"""Main cache listener registration, engine fanout and bounded HR result policy.

Scheduling, allocation and algorithm results are supplied. This does not compute
or validate heart rate, nor run the watch or its full health algorithms.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .cache_receiver import CONFIG as RECEIVER,HEAP,GUARD,snapshot,fixup_backing,native_vectors as receiver_vectors,image_memory
    from .cache_pipeline import MAGIC,put
    from .zrpc_packets import MAIN_HASH,uint
else:
    from cache_receiver import CONFIG as RECEIVER,HEAP,GUARD,snapshot,fixup_backing,native_vectors as receiver_vectors,image_memory
    from cache_pipeline import MAGIC,put
    from zrpc_packets import MAIN_HASH,uint

HEAD=0x70f92920
NODES=0x81008000
CB=0x70000100
REAL_LISTENER=0x704c3ea8
CONFIG=dict(RECEIVER['main'])|dict(reg=0x701e320e,unreg=0x701e328e,event_listener=REAL_LISTENER,event_handler=0x704c3f3a,
    event_destructor=0x704c3340,event_alloc=0x7030425e,event_post=0x70304a62,walk=0x701e53b0,gate=0x704c4148,
    hr_packet=0x703150f4,hr_descriptor=0x70314ba4,algorithm_dispatch=0x704c4d44)
CONFIG['ranges']=RECEIVER['main']['ranges']+((0x701e28d8,0x1a6),(0x701e320e,0x100),(0x701e53b0,0x5e),
    (0x704c3e92,0x32e),(0x704c3340,8),(0x704c3576,0xa8),(0x704c43e6,0x1e),(0x704c31fc,0x1c),
    (0x704c253e,0x20),(0x703150f4,0x38),(0x70314ba4,0x550),(0x704c4d44,0xbc),(0x704c4c0c,0x58),(0x704c586a,0x28))
CONFIG['logs']=RECEIVER['main']['logs']|{0x709d09cc:'reg_duplicate',0x709d09fc:'reg_alloc',0x709d0a20:'unreg_missing',
    0x70c02ac0:'event_alloc',0x70c03094:'algorithm_missing',0x70c030cc:'algorithm_error',0x70a43650:'period_success',0x70a43638:'manual_success'}
TARGETS=(0x701e28d8,0x701e29a4,0x701e320e,0x701e328e,0x704c3ea8,0x704c3576,0x704c3340,0x704c43e6,
         0x704c3f3a,0x701e53b0,0x704c4148,0x704c31fc,0x704c253e,0x704c2556,0x703150f4,0x70314ba4,
         0x704c4d44,0x704c4c0c,0x704c4c3a,0x704c41c0,0x70315634)


def digest(data):return hashlib.sha256(data).hexdigest()
def u32(data,at):return int.from_bytes(data[at:at+4],'little')


def hr_initial(c):
    data=bytearray(0xbc)
    for at,n,value in ((0x75,1,c['features']),(0x74,1,c['control']),(0x5c,4,c['counter']),(0x60,4,c['limit']),
                       (0x64,4,c['aggregate']),(0x69,1,255),(0x6b,1,255)):put(data,at,n,value)
    return data


def hr_result(data,c):
    if not c['ready']:return []
    pulse=c['pulse'];quality=c['quality'];data[0x6a]=1;data[0x69]=pulse;data[0x6b]=quality;logs=[]
    if quality>3 and 30<=pulse<=220:
        count=(u32(data,0x64)>>16)+1;put(data,0x50,4,count)
        value=((count&65535)<<16)|((u32(data,0x64)+pulse)&65535);put(data,0x64,4,value)
        put(data,0x48,2,pulse|(quality<<8))
        if quality<7:data[0x4a]=2 if c['features']&2 and c['counter']>=c['limit'] else 1
        else:
            data[0x4a]=2
            if c['features']&2:logs.append('log:manual_success')
            elif c['features']&1:logs.append('log:period_success')
        if c['control']&6:data[0x76]=1
    return logs


def engine(index,**changes):
    return dict(index=index,enabled=1,callback=True,state=2,cache=1,mask=0xffffffffffffffff,handle=True,hr=False)|changes


def eligible(card,mask):
    return card['index']<39 and card['index']!=30 and card['callback'] and bool(card['enabled']) and card['handle'] and card['state']==2 and bool(card['cache']) and bool(card['mask']&mask)


def registry_contract(c):
    active=[];nodes=[];actions=[];rows=[];attempt=0;data=hr_initial(c)
    for operation in c['operations']:
        op,_,name=operation.partition(':');cb=0 if name=='null' else CB+(4 if name=='b' else 0);returned=None
        if op=='reg':
            if cb==0:returned=0
            elif any(n[1]==cb for n in active):actions.append('log:reg_duplicate');returned=1
            else:
                ok=c['allocations'][attempt] if attempt<len(c['allocations']) else True
                actions.append(('node_alloc:' if ok else 'node_alloc_fail:')+str(attempt));node=NODES+0x100*attempt;attempt+=1
                if not ok:actions.append('log:reg_alloc');returned=0
                else:
                    raw=bytearray(struct.pack('<4I',HEAD,active[-1][0] if active else HEAD,0,cb))
                    if active:put(nodes[active[-1][2]],0,4,node)
                    nodes.append(raw);active.append((node,cb,len(nodes)-1));returned=1
        elif op=='unreg':
            match=next((i for i,n in enumerate(active) if n[1]==cb),None)
            if cb==0 or not active:returned=0
            elif match is None:actions.append('log:unreg_missing');returned=0
            else:
                node,_,index=active[match]
                if match>0:put(nodes[active[match-1][2]],0,4,active[match+1][0] if match+1<len(active) else HEAD)
                if match+1<len(active):put(nodes[active[match+1][2]],4,4,active[match-1][0] if match>0 else HEAD)
                put(nodes[index],0,4,node);put(nodes[index],4,4,node);actions.append('free:node'+str((node-NODES)//0x100));active.pop(match);returned=1
        elif op=='dispatch':actions.extend('listener:'+str((n[1]-CB)//4) for n in active)
        else:raise ValueError('unknown registry operation')
        rows.append(dict(returned=returned,callbacks=[n[1] for n in active]))
    return dict(actions=actions,registry=rows,node_sha256=[digest(n) for n in nodes],registration=None,unregistration=None,
                owner_after=None,final_heap=None,receiver_returned=None,event_returned=None,deliveries=[],algorithm_calls=[],hr_sha256=digest(data))


def contract(c):
    if c['kind']=='registry':return registry_contract(c)
    if c['kind']!='pipeline':raise ValueError('unknown engine-cache scope')
    for field,bits in (('features',8),('control',8),('pulse',8),('quality',8),('counter',32),('limit',32),('aggregate',32),('algorithm_mask',64)):
        uint(c[field],bits)
    wire=bytes.fromhex(c['wire_hex']);length=u32(wire,1);blob=wire[5:5+length]
    if wire[0]!=21 or not length or len(blob)!=length:raise ValueError('only bounded valid envelopes')
    data=hr_initial(c);actions=[];deliveries=[];calls=[];size=16+length
    registered=c['register_allocated'];actions.append('node_alloc:0' if registered else 'node_alloc_fail:0')
    if not registered:actions.append('log:reg_alloc')
    actions.append('buffer_alloc:'+str(size));heap=bytearray(b'\xa5'*(size+GUARD));heap[:size]=bytes(size)
    struct.pack_into('<IIII',heap,0,1,MAGIC,length,HEAP+16);heap[16:size]=blob;fixup_backing(heap,length)
    posted=registered and c['event_allocated']
    if registered:
        actions.append('event_alloc' if posted else 'event_alloc_fail')
        if posted:put(heap,0,4,2);actions.append('post:39')
        else:actions.append('log:event_alloc')
    put(heap,0,4,u32(heap,0)-1)
    if u32(heap,0)==0:put(heap,4,4,0);actions.append('free:buffer')
    owner=snapshot(heap,size);event_result=None
    if posted:
        cursor=0
        while cursor+4<=length:
            n=u32(heap,16+cursor);cursor+=4
            if n==0 or n>length-cursor:break
            packet_at=16+cursor;pointer=HEAP+packet_at;actions.append('packet:'+str(packet_at));mask=int.from_bytes(heap[packet_at+8:packet_at+16],'little')
            for card in sorted(c['engines'],key=lambda e:e['index']):
                if not eligible(card,mask):continue
                actions.append(f'engine:{card["index"]}:{packet_at}');deliveries.append(dict(engine=card['index'],packet=pointer))
                if card['hr']:
                    if card['index']!=7:raise ValueError('only identified engine-7 HR binding')
                    count=int.from_bytes(heap[packet_at:packet_at+2],'little')
                    for i in range(count):
                        at=packet_at+24+40*i;typ=int.from_bytes(heap[at:at+8],'little')
                        if typ==1:raise ValueError('motion descriptor branch excluded')
                        if not c['features'] or not c['algorithm_active']:continue
                        if not c['algorithm_present']:actions.append('log:algorithm_missing');continue
                        if not typ&c['algorithm_mask']:continue
                        actions.append('algorithm:'+str(at))
                        calls.append(dict(descriptor=HEAP+at,type=typ,payload=u32(heap,at+32),tag=0x100d))
                        if c['algorithm_error']:actions.append('log:algorithm_error')
                        actions.extend(hr_result(data,c))
            cursor+=n
        event_result=1
        put(heap,0,4,u32(heap,0)-1);put(heap,4,4,0);actions.append('free:buffer')
    if registered:actions.append('free:node0')
    return dict(actions=actions,registry=[],node_sha256=[],registration=int(registered),unregistration=int(registered),owner_after=owner,
                final_heap=snapshot(heap,size),receiver_returned=0,event_returned=event_result,deliveries=deliveries,algorithm_calls=calls,hr_sha256=digest(data))


def native_vectors():
    cases=[]
    defaults=dict(features=1,control=0,pulse=72,quality=4,counter=0,limit=10,aggregate=0,ready=True,
                  algorithm_active=True,algorithm_present=True,algorithm_mask=0xffffffffffffffff,algorithm_error=0)
    for name,ops,allocations in (
        ('duplicate',['reg:a','reg:a','reg:b','dispatch','unreg:a','dispatch','unreg:b'],[]),
        ('missing',['unreg:a','reg:a','unreg:b','unreg:a'],[]),('null',['reg:null','unreg:null'],[]),
        ('allocation_failure',['reg:a','reg:b','dispatch'],[False,True]),
        ('reinsert',['reg:a','unreg:a','reg:a','dispatch','unreg:a'],[]),
        ('reverse',['reg:a','reg:b','unreg:b','dispatch','unreg:a'],[]),('empty_dispatch',['dispatch'],[])):
        c=dict(name='registry_'+name,kind='registry',operations=ops,allocations=allocations,**defaults);c['expected']=contract(c);cases.append(c)
    fixtures={c['name']:c['wire_hex'] for c in receiver_vectors()['cases'] if c['platform']=='main'}
    high=bytearray.fromhex(fixtures['main_receive_one']);put(high,17,8,1<<32);put(high,33,8,1<<32);fixtures['high_type']=high.hex()
    private=bytearray.fromhex(fixtures['main_receive_one']);put(private,15,2,0x1234);fixtures['private_type']=private.hex()
    def add(name,fixture='main_receive_one',**changes):
        c=dict(name=name,kind='pipeline',wire_hex=fixtures[fixture],register_allocated=True,event_allocated=True,
               engines=[engine(7,hr=True)],**defaults)|changes;c['expected']=contract(c);cases.append(c)
    add('pipeline_hr');add('pipeline_multi',fixture='main_receive_multi');add('pipeline_registration_failure',register_allocated=False)
    add('pipeline_event_allocation_failure',event_allocated=False)
    for field,value in (('enabled',0),('callback',False),('state',1),('state',3),('cache',0),('handle',False),('mask',0x10)):
        add(f'gate_{field}_{value}',engines=[engine(7,**{field:value})])
    add('gate_index_boundaries',engines=[engine(0),engine(7),engine(30),engine(38),engine(39)])
    add('gate_nonboolean_flags',engines=[engine(7,enabled=2,cache=255)])
    add('gate_high_type',fixture='high_type',engines=[engine(7,mask=1<<32)])
    add('gate_private_field',fixture='private_type')
    add('pipeline_zero_record',fixture='main_receive_zero_prefix');add('pipeline_overrun_record',fixture='main_receive_overrun_prefix')
    add('hr_disabled',features=0);add('algorithm_disabled',algorithm_active=False);add('algorithm_missing',algorithm_present=False)
    add('algorithm_mask_mismatch',algorithm_mask=0x10);add('algorithm_result_absent',ready=False)
    add('algorithm_error_ready',algorithm_error=7)
    for pulse in (29,30,220,221):add('hr_pulse_'+str(pulse),pulse=pulse)
    for quality in (3,7):add('hr_quality_'+str(quality),quality=quality)
    add('hr_manual_threshold',features=2,counter=10,limit=10);add('hr_manual_success',features=2,quality=7)
    add('hr_mark_control',control=2);add('hr_aggregate_wrap',aggregate=0xfffffffe)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from reviewed model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('native case count')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected']:raise ValueError('native engine cache mismatch')
        if not 0<row['steps']<=100000:raise ValueError('native execution bound')
    m=image_memory(archive,'main')
    return dict(main_sha256=MAIN_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(m.read(a,n)) for a,n in CONFIG['ranges']},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(row['steps'] for row in execution['cases']),
        limitations=['OS context/critical sections, allocation/free/copies, event queue and scheduling are supplied; no hardware or concurrency execution.',
            'Engine records, handle states and algorithm registration are synthetic; the real engine-7 callback and HR descriptor path execute.',
            'Algorithm math is intercepted with supplied result fields/status, so the checked HR policy is not a sensor measurement or accuracy validation.',
            'HR cases use descriptor types other than 1, inactive auxiliary engine 9 and no wear/reset output; motion/minute/reset paths remain open.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive, --vectors, --validation, --decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect engine cache: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
