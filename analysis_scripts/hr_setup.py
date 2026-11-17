#!/usr/bin/env python3
"""Actual HR buffer/component initialization and nested cleanup contracts.

Allocation/copy/zero/logging and component 0x708a4818 remain supplied boundaries.
This does not execute initialized signal-processing kernels or validate accuracy.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .hr_workspace import CHILDREN,SCRATCH,GLOBAL,HEAP,ROOT_SIZE
    from .algorithm_manager import digest,put,word
    from .cache_receiver import image_memory
    from .zrpc_packets import MAIN_HASH
else:
    from hr_workspace import CHILDREN,SCRATCH,GLOBAL,HEAP,ROOT_SIZE
    from algorithm_manager import digest,put,word
    from cache_receiver import image_memory
    from zrpc_packets import MAIN_HASH

CONFIG=dict(init=0x7089adca,exit=0x7089b360,setup=0x708a1432,inner=0x70897c46,cleanup=0x70897e1c,
            alloc=0x80d3c18a,free=0x80d3c1ea,zero=0x70947ce8,copy=0x70947b0c,logger=0x702b38a2,component=0x708a4818)
RANGES=((0x7089adca,0xa62),(0x708a1432,0x3b0),(0x70897c46,0x224),
        (0x70897046,0x3c),(0x7089781a,0xc8),(0x708a2cae,0x104),(0x7089fdbe,0xde))
CONSTANTS={0x70d1aa10:struct.pack('<4f',0.96,0.8,1.5,0.95),0x709c4e7c:struct.pack('<f',-1.0),
           0x70d1a984:struct.pack('<I',0x41f2d07f),0x70ad2e80:struct.pack('<f',0.0005)}
TARGETS=(0x70897c46,0x70897e1c,0x708a1782,0x708978ae,0x708a2d62,0x708a1432,0x708a16c4,0x708a16c8,
         0x708a16ce,0x708a4818,0x708a2cae,0x70897046,0x7089781a,0x7089fdbe)
LOGS={0x70d13e7c:'init',0x70d1a1d4:'backend_error',0x70d1abec:'ppg_alloc',0x70d1ac04:'ppg_free',0x70d1a96c:'extra_alloc_failed'}
CLEAN_FIELDS=(0x3da0,0x3da4,0x3da8,0x3dac,0x3c58,0x3c5c,0xd4c,0xd54,0xd50,0xd58,0x9c14)


def clears(rate):
    return [(0,4*((rate*512)//25))]+[(i,2*rate) for i in (12,13,14)]+[(i,4*((rate*60)//25)) for i in range(1,12)]+[(i,8*rate) for i in range(30,34)]+[(i,4*((rate*64)//25)) for i in (34,35)]+[(37,4*((rate*256)//25)),(38,8*((rate*128)//25)),(40,4*((rate*128)//25))]+[(i,4*((rate*64)//25)) for i in (41,42)]+[(100,(rate*30)//25)]


class Model:
    def __init__(self,c):
        self.c=c;self.actions=[];self.blocks=[];self.state=bytearray(b'\x5a'*192);self.state[0xbe]=0;self.state[0x20]=c['mode'];self.aux=165;self.root=None
    def alloc(self,size,supplied=False):
        if not supplied and size==0x1ffc and self.c['extra_failure']:
            self.actions.append('alloc_fail:8188');return 0
        index=len(self.blocks);ptr=HEAP+0x10000*index
        self.blocks.append(dict(pointer=ptr,data=bytearray(b'\xa5'*size),freed=False))
        if not supplied:self.actions.append('alloc:'+str(size))
        return ptr
    def at(self,ptr,n):
        for i,b in enumerate(self.blocks):
            off=ptr-b['pointer']
            if 0<=off<=len(b['data']) and off+n<=len(b['data']):return i,b,off
        raise ValueError('model memory bounds')
    def zero(self,ptr,n):
        if ptr==GLOBAL+0x58 and n==56:self.state[0x58:0x90]=bytes(n)
        else:
            i,b,off=self.at(ptr,n);b['data'][off:off+n]=bytes(n)
        self.actions.append(f'zero:{ptr:x}:{n}')
    def free(self,ptr):
        if not ptr:self.actions.append('free:null');return
        i,b,off=self.at(ptr,0)
        if off or b['freed']:raise ValueError('duplicate/interior free')
        b['freed']=True;self.actions.append('free:'+str(i))
    def fixture(self):
        self.root=self.alloc(ROOT_SIZE,True);root=self.blocks[0]['data'];root[:]=b'\x5a'*ROOT_SIZE
        put(root,0x15a,2,self.c['rate']);put(self.state,0x90,4,self.root)
        if self.c['scope']=='cleanup':
            for i,at in enumerate(CLEAN_FIELDS):put(root,at,4,self.alloc(64,True) if self.c['mask']&(1<<i) else 0)
        else:
            lengths=dict(clears(self.c['rate']))
            for index,n in CHILDREN:
                size=max(n,lengths.get(index,0),4*((self.c['rate']*64)//25) if index in (0xf1f,0xf20) else 0)+16
                put(root,4*index,4,self.alloc(size,True))
    def setup(self):
        root=self.at(self.root,ROOT_SIZE)[1]['data'];rate=word(root,0x15a,2);root[0x76]=20;root[0x75]=1
        for index,n in clears(rate):self.zero(word(root,4*index),n)
        for at in (0x46,0x47,0x48,0x49):root[at]=0
        for at in (0x5c,0x60,0x4c,0x50,0x54,0x58):put(root,at,4,0)
        put(root,0x6624,2,1);self.inner();self.zero(self.root+0x3c,10);root[0x77]=0
    def inner(self):
        root=self.at(self.root,ROOT_SIZE)[1]['data'];rate=word(root,0x15a,2)
        root[0xac:0xbc]=CONSTANTS[0x70d1aa10];self.actions.append('copy:coefficients')
        for at in (0xa8,0x88):self.zero(word(root,at),4*((rate*64)//25))
        put(root,0x138,4,0xbf800000);put(root,0x108,4,0x41f2d07f)
        put(root,0x16e,2,0x101);put(root,0x170,2,0x101);root[0x172]=1
        for at in (0x18a,0x189,0x187,0x180,0x17c,0x17b,0x176,0x174,0x16d):root[at]=0
        for at,n in ((0x17e,2),(0x13c,4),(0x140,4)):put(root,at,n,0)
        first=0x3d04;put(root,first,4,0);count=(rate*18)//25+1;width=count*4;matrix=((rate*9)//25+1)*width
        for at,n in ((0x9c,width),(0xa0,width),(0xa4,width),(0xa8,matrix)):put(root,first+at,4,self.alloc(n))
        for at,n in ((0xa4,width),(0x9c,width),(0xa0,width),(0xa8,matrix)):self.zero(word(root,first+at),n)
        put(root,0x2bc,2,rate);root[0x219]=0;self.actions.append('boundary:component')
        p=0xd0c;root[p]=0;put(root,p+0x10,2,rate)
        for at,n in ((0xc,2),(1,1),(3,1),(8,2),(5,1)):put(root,p+at,n,0)
        self.zero(self.root+p+0x2850,0x6f0);put(root,p+0x2bc2,2,65535);put(root,p+0x2f3a,2,65535)
        for at,n in ((0x40,(rate//25)*256),(0x44,(rate//25)*256),(0x48,(rate//25)*332),(0x4c,(rate//25)*332)):put(root,p+at,4,self.alloc(n))
        root[0x3c65]=0;put(root,0x3c70,2,rate)
        for at in (0x3c80,0x3c7c):self.zero(word(root,at),4*((rate*64)//25))
        root[0x3c8c]=0;p=0x3c4c;put(root,p,2,rate);self.zero(self.root+p,24);put(root,p,2,rate)
        for at in (12,16):put(root,p+at,4,self.alloc((rate*600)//25))
        for at in (12,16):self.zero(word(root,p+at),(rate*600)//25)
        root[p+2]=(rate*3)&255
        for at in (0x9bec,0x9bf0,0x9c0c,0x9c10):put(root,at,4,0)
        for at in (0x9bf4,0x9c00):self.zero(self.root+at,12)
        ptr=self.alloc(0x1ffc);put(root,0x9c14,4,ptr)
        if ptr:
            b=self.at(ptr,0x1ffc)[1]['data'];put(b,0,4,0)
            for at,n in ((0x1580,100),(0xfd4,192),(0x1094,440),(0x1514,96),(0x124c,96),(0x12ac,616),(0x1e7c,384),(0x15e4,640),(0x1864,520),(0x1a6c,520),(0x1c74,520)):self.zero(ptr+at,n)
            for at in (0x1574,0x1578,0x157c):put(b,at,4,0)
        else:self.actions.append('log:extra_alloc_failed')
        for at in (0x9c58,0x9c18,0x9c38):self.zero(self.root+at,32)
        root[0x9dbc]=0;put(root,0x9c78,4,0x3a03126f)
    def cleanup(self):
        root=self.at(self.root,ROOT_SIZE)[1]['data']
        for i,at in enumerate(CLEAN_FIELDS):
            ptr=word(root,at)
            if ptr or 6<=i<10:self.free(ptr)
            if i>=4 and (ptr or 6<=i<10):put(root,at,4,0)
    def owner_init(self):
        if self.state[0xbe]:return 0
        self.actions.append('log:init')
        for at in (0x94,0x98,0x9c):put(self.state,at,4,0)
        self.root=self.alloc(ROOT_SIZE);put(self.state,0x90,4,self.root);self.zero(self.root,ROOT_SIZE)
        root=self.at(self.root,ROOT_SIZE)[1]['data'];put(root,0x15a,2,25)
        for index,n in CHILDREN:
            put(root,4*index,4,self.alloc(n))
            if index==30:self.actions.append('log:ppg_alloc')
        self.zero(GLOBAL+0x58,56)
        for at in SCRATCH:put(self.state,at,4,self.alloc(200))
        self.setup();root[0x76]=14 if self.c['mode']==4 else 20;self.state[0x19]=0;self.state[0x1b]=0
        for at in (0xb0,0xb8,0xb4,0xac):put(self.state,at,4,0)
        self.state[0xbe]=1;return 0
    def owner_exit(self):
        if not self.state[0xbe]:return 0
        self.state[0xbe]=0;self.aux=1
        for at in (0xa8,0xa4,0xb0,0xac,0xb8,0xb4,0xa0):put(self.state,at,4,0)
        root=self.at(self.root,ROOT_SIZE)[1]['data'];self.cleanup()
        order=list(range(14))+[30,14]+[i for i,_ in CHILDREN[16:] if i not in range(0xf80,0xfa0) and i!=4000]
        for index in order:
            if index==30:self.actions.append('log:ppg_free')
            self.free(word(root,4*index));put(root,4*index,4,0)
        for at in SCRATCH:self.free(word(self.state,at));put(self.state,at,4,0)
        for i in range(8):
            for offset in (0xf88,0xf90,0xf80,0xf98):index=i+offset;self.free(word(root,4*index));put(root,4*index,4,0)
        self.free(word(root,4000*4));put(root,4000*4,4,0);self.free(self.root);put(self.state,0x90,4,0);return 0
    def snapshot(self,returned):
        return dict(returned=returned,state_sha256=digest(self.state),aux=self.aux,
                    allocation_sha256=[digest(b['data']) for b in self.blocks],freed=[i for i,b in enumerate(self.blocks) if b['freed']])


def contract(case):
    if not 0<=case['rate']<=100:raise ValueError('rate fixture bound 0..100')
    m=Model(case);rows=[]
    if case['scope']!='owner':m.fixture()
    for op in case['operations']:
        returned=None
        if op=='setup':m.setup()
        elif op=='inner':m.inner()
        elif op=='cleanup':m.cleanup()
        elif op=='init':returned=m.owner_init()
        elif op=='exit':returned=m.owner_exit()
        else:raise ValueError('unknown setup operation')
        rows.append(m.snapshot(returned))
    return dict(actions=m.actions,allocation_sizes=[len(b['data']) for b in m.blocks],rows=rows)


def native_vectors():
    cases=[]
    def add(name,scope,ops,**options):
        c=dict(name=name,scope=scope,operations=ops,rate=25,mode=0,mask=2047,extra_failure=False,component_status=0)|options;c['expected']=contract(c);cases.append(c)
    for rate in (0,1,12,24,25,26,49,50,75,100):add('setup_rate_'+str(rate),'setup',['setup','cleanup'],rate=rate)
    for rate in (0,24,25,26,50):add('inner_rate_'+str(rate),'setup',['inner','cleanup'],rate=rate)
    add('inner_extra_failure','setup',['inner','cleanup'],extra_failure=True)
    add('setup_component_status_ignored','setup',['setup','cleanup'],component_status=7)
    for mask in (0,2047,0x555,0x2aa,*[1<<i for i in range(11)]):add('cleanup_mask_'+str(mask),'cleanup',['cleanup'],mask=mask)
    add('owner_cycle','owner',['init','exit']);add('owner_mode4','owner',['init','exit'],mode=4)
    add('owner_repeated','owner',['init','init','exit','exit']);add('owner_restart','owner',['init','exit','init','exit'])
    add('owner_extra_failure','owner',['init','exit'],extra_failure=True)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ from model')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,case in zip(execution['cases'],expected['cases']):
        if row['name']!=case['name'] or row['observed']!=case['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive,'main')
    if any(memory.read(a,len(data))!=data for a,data in CONSTANTS.items()):raise ValueError('unexpected setup constants')
    return dict(main_sha256=MAIN_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        constant_sha256={f'{a:08x}':digest(data) for a,data in CONSTANTS.items()},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},native_validation=execution,
        native_steps=sum(r['steps'] for r in execution['cases']),
        limitations=['Allocator/free/zero/copy/logger and component 708a4818 are supplied; no hardware or concurrency.',
            'Synthetic standalone rate fixtures resize/pad buffers; real outer initialization fixes rate 25.',
            'Only the nested 8188-byte allocation failure is exercised; other secondary failures remain open.',
            'Setup/cleanup execute, but initialized signal processing, engine activation and measurement accuracy remain unverified.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        if args.vectors_output:args.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((args.archive,args.vectors,args.validation,args.decompiled)):parser.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(args.archive) as archive:report=evidence(archive,args.decompiled,args.vectors,args.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as error:parser.exit(2,f'Cannot inspect HR setup: {error}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
