#!/usr/bin/env python3
"""Main/sensor cache receiver contracts with borrowed decoding and copied buffers.

Allocation, memory copies, critical-section boundaries and listener registration
are supplied. Decoder, receive dispatch, fixup and reference arithmetic execute
natively in the associated runner. No transport/device execution is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .cache_pipeline import packet,rebase,put,MAGIC,SOURCE,BUFFER as SENDER
    from .sensorhub_memory import StartupMemory
    from .zrpc_packets import MAIN,SENSOR,MAIN_HASH,SENSOR_HASH,uint
else:
    from cache_pipeline import packet,rebase,put,MAGIC,SOURCE,BUFFER as SENDER
    from sensorhub_memory import StartupMemory
    from zrpc_packets import MAIN,SENSOR,MAIN_HASH,SENSOR_HASH,uint

WIRE=0x81010000
HEAP=0x81200000
GUARD=128
CONFIG={
 'main':dict(recv=0x7071fd60,parser=0x70720ac0,handler=0x707200f2,cleanup=0x70722a98,
    init=0x7032db3a,remain=0x7032dbae,byte=0x7032dca6,word=0x7032dd0c,pointer=0x7032ddaa,
    valid=0x701e4ce0,alloc=0x701e4f04,retain=0x701e4f7c,release=0x701e4fa6,fixup=0x701e4ff0,
    reset=0x701e3cb8,dispatch=0x701e330e,bridge=0x7071ed94,initializer=0x707209e4,
    malloc=0x80d3c324,free=0x80d3c35a,copy=0x70947b0c,zero=0x70947ce8,
    increment=0x80d3d5a2,subtract=0x80d3d622,critical_enter=0x80d379ee,critical_exit=0x80d37a1a,
    context=0x80d378d6,logger=0x702b38a2,table=0x70fd600c,callback=0x70fd6004,head=0x70f92920,
    pool=5,tag=0x709d09ec,logs={0x70ca91c8:'parse_cache',0x70ca8da8:'receive_parse',0x709d12a0:'buffer_alloc',0x70ca8e04:'receive_alloc'},
    ranges=((0x7071fd60,0x1ca),(0x70720ac0,0xce0),(0x707200f2,0x74),(0x70722a98,0x8c),
            (0x7032db3a,0x2aa),(0x701e4ce0,0x26),(0x701e4f04,0x146),(0x701e3cb8,0x40),
            (0x701e330e,0xa6),(0x7071ed94,8),(0x704c5872,0x20),(0x80d3d5a2,0xae))),
 'sensor':dict(recv=0x80f993d0,parser=0x80f99ea8,handler=0x80f996e4,cleanup=0x80f9afa0,
    init=0x80fa5ae0,remain=0x80fa5b28,byte=0x80fa5b9a,word=0x80fa5c00,pointer=0x80fa5c96,
    valid=0x80f655d2,alloc=0x80f657ee,retain=0x80f6585e,release=0x80f65884,fixup=0x80f658c6,
    reset=0x80f645e2,dispatch=0x80f63c2e,bridge=0x80f9891c,initializer=0x80f99e0e,
    malloc=0x80f84cee,free=0x80f84d24,copy=0x80fcddf0,zero=0x80fcdfcc,
    increment=0x80f85cbe,subtract=0x80f85d14,critical_enter=0x80f80aa2,critical_exit=0x80f80ace,
    context=0x80f809a0,logger=0x80f86d34,table=0x80f55e54,callback=0x80f55e4c,head=0x80f4fb10,
    pool=4,tag=0x80fd4868,logs={0x80fe1ad0:'parse_cache',0x80fe1798:'receive_parse',0x80fd5134:'buffer_alloc',0x80fe1818:'receive_alloc'},
    ranges=((0x80f993d0,0x122),(0x80f99ea8,0x73e),(0x80f996e4,0x60),(0x80f9afa0,0x15a),
            (0x80fa5ae0,0x1f0),(0x80f655d2,0x26),(0x80f657ee,0x132),(0x80f645e2,0x40),
            (0x80f63c2e,0x86),(0x80f9891c,4),(0x80fa27e2,0x10),(0x80f85cbe,0x84))),
}


def digest(data):return hashlib.sha256(data).hexdigest()
def u32(data,at):return int.from_bytes(data[at:at+4],'little')


def decoder_contract(data,operations):
    if not isinstance(data,bytes) or len(data)>8192 or len(operations)>16:raise ValueError('decoder host bounds')
    cursor=0;error=0 if data else 1;rows=[]
    for op in operations:
        if op in ('byte','word'):size=1 if op=='byte' else 4;pointer=False
        elif op.startswith('data:'):size=int(op.split(':')[1]);uint(size,32);pointer=True
        else:raise ValueError('unknown decoder operation')
        remain=len(data)-cursor if error!=1 else 0;value=0
        if pointer and size==0:pass
        elif size>remain:
            if error==0:error=2
        else:
            value=WIRE+cursor if pointer else int.from_bytes(data[cursor:cursor+size],'little');cursor+=size
        rows.append(dict(operation=op,returned=value,base=WIRE if data else 0,length=len(data),
                         cursor=WIRE+cursor if data else 0,error=error))
    return rows


def parse_contract(data):
    if not isinstance(data,bytes) or not data or data[0]!=21:raise ValueError('only reviewed opcode-21 inputs')
    declared=int.from_bytes(data[1:5],'little') if len(data)>=5 else 0
    pointer=WIRE+5 if declared and len(data)>=5+declared else 0
    return dict(opcode=21,length=declared,pointer=pointer),0 if pointer else 1


def fixup_backing(backing,used):
    cursor=0
    while cursor!=used:
        if cursor+4>used:raise ValueError('unreviewed partial record-prefix read')
        size=u32(backing,16+cursor);end=cursor+4+size
        if size==0 or end>used:break
        at=20+cursor;count,stride=struct.unpack_from('<HH',backing,at)
        if count>8:raise ValueError('bounded malformed-count fixture')
        put(backing,at+16,4,1);put(backing,at+20,4,HEAP+at+24)
        for i in range(count):
            if at+24+40*i+36>len(backing):raise ValueError('host guard bound')
            put(backing,at+24+40*i+32,4,HEAP+at+24+40*count+stride*i)
        cursor=end


def snapshot(backing,size):
    return dict(refs=u32(backing,0),magic=u32(backing,4),sha256=digest(backing[:size]),guard_sha256=digest(backing[size:]))


def contract(case):
    data=bytes.fromhex(case['wire_hex']);kind=case['kind'];actions=[];parsed=None;callbacks=[];rows=[];heap=None;owner=None
    returned=0;ack=165;size=0
    if kind=='decoder':
        rows=decoder_contract(data,case['operations']);returned=rows[-1]['returned'] if rows else 0
    else:
        parsed,returned=parse_contract(data)
        if returned:actions.append('log:parse_cache')
        if kind=='receive':
            ack=0
            if returned:actions.append('log:receive_parse')
            elif case['handler']:
                length=parsed['length'];size=length+16;actions.append(('alloc:' if case['allocated'] else 'alloc_fail:')+str(size))
                if not case['allocated']:
                    actions.extend(('log:buffer_alloc','log:receive_alloc'));returned=8
                else:
                    heap=bytearray(b'\xa5'*(size+GUARD));heap[:size]=bytes(size)
                    struct.pack_into('<IIII',heap,0,1,MAGIC,length,HEAP+16);heap[16:size]=data[5:5+length]
                    fixup_backing(heap,length)
                    for i,retain in enumerate(case['listeners']):
                        if type(retain) is not bool:raise ValueError('listener retention switch')
                        actions.append('callback:'+str(i))
                        callbacks.append(dict(index=i,refs=u32(heap,0),data_sha256=digest(heap[16:size]),guard_sha256=digest(heap[size:])))
                        if retain:actions.append('retain:'+str(i));put(heap,0,4,u32(heap,0)+1)
                    put(heap,0,4,u32(heap,0)-1)
                    if u32(heap,0)==0:put(heap,4,4,0);actions.append('free:buffer')
                    owner=snapshot(heap,size)
                    for i,retain in enumerate(case['listeners']):
                        if retain:
                            actions.append('drop:'+str(i));put(heap,0,4,u32(heap,0)-1)
                            if u32(heap,0)==0:put(heap,4,4,0);actions.append('free:buffer')
        elif kind!='parse':raise ValueError('unknown case kind')
    return dict(actions=actions,returned=returned,parsed=parsed,ack=ack,decoder=rows,callbacks=callbacks,
                owner_after=owner,final_heap=snapshot(heap,size) if heap is not None else None,input_sha256=digest(data))


def envelope(blob,declared=None,trailing=b''):
    return b'\x15'+struct.pack('<I',len(blob) if declared is None else declared)+blob+trailing


def native_vectors():
    packets=[packet(SOURCE,(0x8000,),4),packet(SOURCE,(0x10,0x8000,0x100000),8)]
    blobs=[]
    for p in packets:blobs.append(struct.pack('<I',len(p))+rebase(p,SENDER+20))
    multi=blobs[0]+struct.pack('<I',len(packets[1]))+rebase(packets[1],SENDER+len(blobs[0])+20)
    zero=bytes(4)+blobs[0][4:];overrun=struct.pack('<I',80)+blobs[0][4:]
    malformed=bytearray(blobs[0]);put(malformed,4,2,2)
    cases=[]
    def add(core,name,kind,wire,**changes):
        c=dict(platform=core,name=core+'_'+name,kind=kind,wire_hex=wire.hex())
        if kind=='receive':c.update(handler=True,allocated=True,listeners=[False])
        c.update(changes);c['expected']=contract(c);cases.append(c)
    for core in CONFIG:
        for name,wire in [('one',envelope(blobs[0])),('multi',envelope(multi)),('trailing',envelope(blobs[0],trailing=b'ignored')),
                          ('zero',envelope(b'')),('too_long',envelope(blobs[0],73)),('huge',envelope(blobs[0],0xffffffff)),
                          ('one_byte_payload',envelope(b'\0'))]+[(f'short_{n}',envelope(blobs[0])[:n]) for n in range(1,5)]:
            add(core,'parse_'+name,'parse',wire)
        for name,wire,changes in [('one',envelope(blobs[0]),{}),('multi',envelope(multi),{}),
            ('retained',envelope(blobs[0]),dict(listeners=[True])),('two_listeners',envelope(blobs[0]),dict(listeners=[True,True])),
            ('no_listeners',envelope(blobs[0]),dict(listeners=[])),('no_handler',envelope(blobs[0]),dict(handler=False)),
            ('allocation_failure',envelope(blobs[0]),dict(allocated=False)),('trailing',envelope(blobs[0],trailing=b'ignored'),{}),
            ('zero_prefix',envelope(zero),{}),('overrun_prefix',envelope(overrun),{}),
            ('good_then_bad_record',envelope(blobs[0]+overrun),{}),('inner_count_two',envelope(malformed),{}),
            ('bad_envelope',envelope(blobs[0],73),{}),('zero_envelope',envelope(b''),{})]:
            add(core,'receive_'+name,'receive',wire,**changes)
        for name,wire,ops in [('mixed',bytes.fromhex('010203040506'),['byte','word','data:1','byte']),
                             ('sticky_error',b'ab',['word','byte','data:1']),('empty',b'',['byte','word','data:1','data:0']),
                             ('zero_slice',b'ab',['data:0','byte']),('exact_slice',b'ab',['data:2','data:1']),
                             ('short_word',b'abc',['word']),('little_endian',bytes.fromhex('78563412'),['word']),
                             ('huge_slice',b'ab',['data:4294967295','byte'])]:
            add(core,'decoder_'+name,'decoder',wire,operations=ops)
    return dict(schema=1,cases=cases)


def image_memory(archive,core):
    member,expected=(MAIN,MAIN_HASH) if core=='main' else (SENSOR,SENSOR_HASH);data=archive.read(member)
    if digest(data)!=expected:raise ValueError('requires reviewed image')
    return StartupMemory(data,0x70160000,0x270,4,0x2a0,2) if core=='main' else StartupMemory(data)


def evidence(archive,decompiled,vectors,validations):
    expected=native_vectors()
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from reviewed model')
    reports={};exports={};guards={}
    for core in CONFIG:
        report=json.loads(validations[core].read_bytes());cases=[c for c in expected['cases'] if c['platform']==core]
        if report['hardware_execution'] is not False or report['case_count']!=len(cases) or len(report['cases'])!=len(cases):raise ValueError('unexpected native report')
        for row,case in zip(report['cases'],cases):
            if row['name']!=case['name'] or row['observed']!=case['expected']:raise ValueError('native receiver mismatch')
            if not 0<row['steps']<=100000:raise ValueError('native execution bound')
        reports[core]=report;m=image_memory(archive,core);cfg=CONFIG[core]
        exports[core]={f'{cfg[key]:08x}.c':digest((decompiled/f'runtime-cache-receiver-{core}'/f'{cfg[key]:08x}.c').read_bytes()) for key in
                       ('recv','parser','handler','cleanup','init','remain','byte','word','pointer','valid','alloc','retain','release','fixup','reset','dispatch','bridge','initializer')}
        guards[core]={f'{a:08x}_{n:x}':digest(m.read(a,n)) for a,n in cfg['ranges']}
    return dict(main_sha256=MAIN_HASH,sensor_sha256=SENSOR_HASH,vectors_sha256=digest(vectors.read_bytes()),
        validation_sha256={core:digest(path.read_bytes()) for core,path in validations.items()},export_sha256=exports,byte_range_sha256=guards,
        native_validation=reports,native_steps=sum(r['steps'] for report in reports.values() for r in report['cases']),
        default_main_callbacks=[hex(x) for x in struct.unpack('<4I',image_memory(archive,'main').read(0x709b8898,16))],
        default_main_callback_table_sha256=digest(image_memory(archive,'main').read(0x709b8898,16)),
        default_main_callback_setup_sha256=digest(image_memory(archive,'main').read(0x7071fcb6,0x52)),
        replayed_sender_wire_sha256=digest(bytes.fromhex(next(c['wire_hex'] for c in expected['cases'] if c['name']=='main_parse_one'))),
        limitations=['Context, allocation/free, copy/memset, critical-section helpers and listener registrations are supplied; reference arithmetic executes natively.',
            'Receiving starts with a synthetic message in memory, without zrpc/rpmsg or hardware; initializer/default callback evidence is static.',
            'Malformed record callbacks capture opaque bytes only; inner count is bounded to 2 and a 128-byte synthetic redzone records out-of-allocation fixup writes.',
            'Consumer listeners and deferred release scheduling are synthetic; no full health algorithm or concurrency guarantee is established.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','decompiled','main-validation','sensor-validation'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.decompiled,args.main_validation,args.sensor_validation)):parser.error('need archive, vectors, decompiled and both validation reports')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,dict(main=args.main_validation,sensor=args.sensor_validation))
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect cache receiver: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
