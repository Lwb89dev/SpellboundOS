#!/usr/bin/env python3
"""Native HR workspace ownership, configuration views and unsupported-type reset.

Allocator/copy/zero, numerical workspace setup and internal cleanup are supplied.
No initialized HR numerical processing or physical measurements are validated.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

if __package__:
    from .algorithm_manager import digest,put,word
    from .cache_receiver import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    from algorithm_manager import digest,put,word
    from cache_receiver import image_memory
    from zrpc_packets import MAIN_HASH

GLOBAL=0x80c46100
EXT=0x80c45f50
HEAP=0x81400000
INPUT=0x82000000
ROOT_SIZE=0x9dc4
EXT_SIZE=0x1a1d0
VIEWS=(8,12,0x268c,0x270c,0x2710,0x2890,0x2a10,0x5a10,0x8a10,0x8b48,0x8c80,0xac30,
       0xd330,0xd468,0xd5a0,0xf550,0x11500,0x11638,0x11770,0x13720,0x156d0,0x15850,0x159d0,0x17dd0)
CHILDREN=[(0,0x1000)]+[(i,0xf0) for i in range(1,12)]+[(i,50) for i in range(12,15)]+[(i,200) for i in range(30,34)]+[(i,256) for i in (34,35)]+[(i,1024) for i in (37,38)]+[(40,512),(41,256),(42,256),(100,30),(0xf1f,256),(0xf20,256),(0xae,480),(0xb2,400),(0xb3,960),(0xdc,100)]+[(i+offset,size) for i in range(8) for offset,size in ((0xf88,1000),(0xf90,1000),(0xf80,1000),(0xf98,1024))]+[(4000,1024)]
SCRATCH=(0x78,0x7c,0x80,0x58,0x5c,0x60,0x64,0x68,0x6c,0x70,0x74)
CONFIG=dict(init=0x7089adca,exit=0x7089b360,process=0x7089b82c,extension=0x7089a252,
            alloc=0x80d3c18a,free=0x80d3c1ea,zero=0x70947ce8,copy=0x70947c08,copy2=0x70947b0c,
            setup=0x708a1432,cleanup=0x708a16c4,logger=0x702b38a2)
RANGES=((0x7089a252,0x162),(0x7089adca,0xa62),(0x7089b82c,0x18e4),(0x708a16c8,0xa))
TARGETS=(0x7089a252,0x7089adca,0x7089b360,0x7089b82c,0x708a1432,0x708a16c8)
LOGS={0x70d1ab70:'extension',0x70d13e7c:'init',0x70d1a1d4:'backend_error',0x70d1abec:'ppg_alloc',0x70d1ac04:'ppg_free'}


def contract(case):
    state=bytearray(b'\x5a'*192);state[0x20]=case['mode'];state[0xbe]=int(case['already_initialized'])
    ext=bytearray(b'\x5a'*104);actions=[];allocations=[];rows=[];output=bytes(b'\xa5'*0x520);aux=0xa5
    for op in case['operations']:
        returned=0;kind=op['op']
        if kind=='extension':
            source=op.get('base',INPUT)
            ext[1:4]=bytes([11,22,33]);put(ext,4,4,op['header_size'])
            for i,offset in enumerate(VIEWS):put(ext,8+4*i,4,source+offset)
            actions.append('log:extension');returned=int(op['length']==EXT_SIZE and op['header_size']==EXT_SIZE)
        elif kind=='init' and not state[0xbe]:
            actions.append('log:init')
            for at in (0x94,0x98,0x9c):put(state,at,4,0)
            if case['root_failure']:
                actions.extend(['alloc_fail:40388','log:backend_error']);put(state,0x90,4,0);returned=1
            else:
                def alloc(size):
                    index=len(allocations);ptr=HEAP+0x10000*index;allocations.append(dict(pointer=ptr,size=size,data=bytearray(b'\xa5'*size),freed=False));actions.append('alloc:'+str(size));return ptr
                ptr=alloc(ROOT_SIZE);put(state,0x90,4,ptr);root=allocations[-1]['data'];root[:]=bytes(ROOT_SIZE);put(root,0x15a,2,25)
                for index,size in CHILDREN:
                    put(root,4*index,4,alloc(size))
                    if index==30:actions.append('log:ppg_alloc')
                state[0x58:0x90]=bytes(56)
                for at in SCRATCH:put(state,at,4,alloc(200))
                actions.append('boundary:setup');root[0x76]=14 if case['mode']==4 else 20
                state[0x1b]=0;state[0x19]=0
                for at in (0xb0,0xb8,0xb4,0xac):put(state,at,4,0)
                state[0xbe]=1
        elif kind=='exit' and state[0xbe]:
            for at in (0xa8,0xa4,0xb0,0xac,0xb8,0xb4,0xa0):put(state,at,4,0)
            state[0xbe]=0;aux=1
            ptr=word(state,0x90)
            if ptr:
                root=allocations[(ptr-HEAP)//0x10000]['data'];actions.append('boundary:cleanup')
                def free(ptr):
                    index=(ptr-HEAP)//0x10000
                    if ptr<HEAP or index>=len(allocations) or allocations[index]['freed']:raise ValueError('invalid free')
                    allocations[index]['freed']=True;actions.append('free:'+str(index))
                order=list(range(14))+[30,14]+[i for i,_ in CHILDREN[16:] if i not in range(0xf80,0xfa0) and i!=4000]
                for index in order:
                    if index==30:actions.append('log:ppg_free')
                    free(word(root,4*index));put(root,4*index,4,0)
                for at in SCRATCH:free(word(state,at));put(state,at,4,0)
                for i in range(8):
                    for offset in (0xf88,0xf90,0xf80,0xf98):index=i+offset;free(word(root,4*index));put(root,4*index,4,0)
                free(word(root,4000*4));put(root,4000*4,4,0);free(ptr);put(state,0x90,4,0)
        elif kind=='process':
            if not state[0xbe]:actions.append('log:backend_error');returned=1
            else:
                if op['type'] not in (1,0x8000,1<<32,1<<63):raise ValueError('only unsupported types are modeled')
                for at in (0x84,0x88,0x8c):put(state,at,4,0)
                for at in SCRATCH:
                    ptr=word(state,at);allocations[(ptr-HEAP)//0x10000]['data'][:]=bytes(200)
        elif kind not in ('init','exit'):raise ValueError('unknown workspace operation')
        rows.append(dict(returned=returned,state_sha256=digest(state),extension_sha256=digest(ext),aux=aux,
            output_sha256=digest(output),allocations=[dict(pointer=a['pointer'],size=a['size'],sha256=digest(a['data']),freed=a['freed']) for a in allocations]))
    return dict(actions=actions,rows=rows)


def native_vectors():
    cases=[]
    def add(name,ops,**options):
        c=dict(name=name,operations=ops,mode=0,already_initialized=False,root_failure=False)|options;c['expected']=contract(c);cases.append(c)
    init=dict(op='init');stop=dict(op='exit')
    add('workspace_cycle',[init,stop]);add('workspace_mode4',[init,stop],mode=4)
    add('workspace_repeated',[init,init,stop,stop]);add('workspace_root_failure',[init,stop],root_failure=True)
    add('workspace_restart',[init,stop,init,stop])
    add('workspace_uninitialized_exit',[stop]);add('workspace_initialized_noop',[init],already_initialized=True)
    add('workspace_init_only',[init])
    for typ in (1,0x8000,1<<32,1<<63):add('unsupported_'+hex(typ),[init,dict(op='process',type=typ),stop])
    add('process_uninitialized',[dict(op='process',type=0x8000)])
    for length,header in ((EXT_SIZE,EXT_SIZE),(0,EXT_SIZE),(EXT_SIZE-1,EXT_SIZE),(EXT_SIZE+1,EXT_SIZE),(EXT_SIZE,0),(EXT_SIZE,EXT_SIZE-1),(0,0)):
        add(f'extension_{length}_{header}',[dict(op='extension',length=length,header_size=header)])
    add('extension_rebind',[dict(op='extension',length=EXT_SIZE,header_size=EXT_SIZE),dict(op='extension',length=0,header_size=0,base=INPUT+0x40000)])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive,'main')
    return dict(main_sha256=MAIN_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Allocator/free/copy/zero, numerical setup 708a1432 and internal cleanup 708a16c4 are supplied; no hardware/concurrency.',
            'All successful workspace allocations and primary-root allocation failure execute; secondary allocation failures remain open.',
            'Initialized processing executes only unsupported-type early returns; supported signal normalization, numerical processing and accuracy remain open.',
            'Extension builds borrowed pointers before its size-result check; pointed-to data, ownership and full consumer use remain unexecuted.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect HR workspace: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
