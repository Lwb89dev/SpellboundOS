#!/usr/bin/env python3
"""Connected EFTL initializer/geometry/scan contracts with supplied services.

Null allocation use and assertions stop before the unsafe operation. NAND,
format/erase/OOB, heap and time services are synthetic; no device is accessed.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH, digest, image_memory
    from .eftl_resume import contract as resume_contract, RANGES as RESUME_RANGES
else:
    from recovery_validator import BOOT_HASH, digest, image_memory
    from eftl_resume import contract as resume_contract, RANGES as RESUME_RANGES

CONTEXT=0x80de5fb8
NAND=0x81230000
OLD=(0x81240000,0x81241000,0x81242000)
HEAP=0x81400000
CONFIG=dict(initialize=0x80c02298,geometry=0x80c02460,resume=0x80c01d8a,
    find=0x80c29478,ioctl=0x80c2964c,format=0x80c0285a,alloc=0x80c1a308,free=0x80c1a312,
    memset=0x80c2e014,clock=0x80c1642e,millis=0x80c171d4,assertion=0x80c16516,
    bad=0x80c028d8,erase=0x80c0282a,oob=0x80c027b0,logger=0x80c1cd7a,lazy=0x80c231d6,lazy_logger=0x80c1cc90)
RANGES=RESUME_RANGES+((0x80c02298,0x1c8),(0x80c02460,0x174),(0x80c0285a,0x7e),(0x80c231d6,0x7c))
TARGETS=(0x80c02298,0x80c02460,0x80c01d8a,0x80c01a0a,0x80c0285a,0x80c231d6)
LOGS={0x80c340b0:'bad_block',0x80c340d0:'oob_read_error',0x80c33f68:'checksum_error',
      0x80c34274:'geometry_summary',0x80c3429c:'format_error',0x80c342b8:'capacity_summary',0x80c342e4:'block_summary',0x80c3ba98:'eftl_ready'}


class Stop(Exception):
    def __init__(self,info):self.info=info


class Model:
    def __init__(self,c):
        self.c=c;self.context=bytearray(64);self.context[4]=c['marker'];self.allocations=[];self.actions=[];self.ordinal=0;self.ticks=0
        self.eftl_ready=c['eftl_ready'];self.capacity_word=0x7fffffff;self.block_word=0x20000
        self.put(0,4,NAND if c['handle_present'] else 0)
        for i,size in enumerate((4,8,48)):
            if c['old_mask']&(1<<i):
                self.allocations.append(dict(pointer=OLD[i],size=size,active=True,data=bytearray(b'\x55'*size)))
                self.put(44+i*4,4,OLD[i])
    def put(self,at,n,value):self.context[at:at+n]=(value&((1<<(8*n))-1)).to_bytes(n,'little')
    def get(self,at,n=4):return int.from_bytes(self.context[at:at+n],'little')
    def allocation(self,p):return next(row for row in self.allocations if row['pointer']==p)
    def fill(self,p,byte,n):
        self.actions.append(f'fill:{p}:{byte}:{n}')
        if not p:raise Stop(dict(kind='null_memset',size=n,fill=byte))
        target=self.context if p==CONTEXT else self.allocation(p)['data']
        target[:n]=bytes((byte,))*n
    def assert_at(self,line):raise Stop(dict(kind='assertion',line=line))
    def geometry(self):
        c=self.c
        if not self.get(0):
            self.actions.append('find:eftl:'+str(int(c['find_ok'])));self.put(0,4,NAND if c['find_ok'] else 0)
            if not c['find_ok']:self.assert_at(0x1a)
        values={1:c['pages'],2:c['page_size'],3:c['pages_per_block'],18:c['spare'],19:c['ecc_total'],20:c['ecc_unit']}
        for query,at in ((1,20),(2,12),(3,8)):
            self.actions.append(f'ioctl:{query}:{c["ioctl_status"]}');self.put(at,4,values[query])
        for at,line in ((12,0x21),(8,0x22),(20,0x23)):
            if not self.get(at):self.assert_at(line)
        self.put(16,4,self.get(20)//self.get(8));self.put(24,4,c['partition_offset']//self.get(12))
        for query in (18,19,20,21):self.actions.append(f'ioctl:{query}:{c["ioctl_status"]}')
        for key,line in (('spare',0x35),('ecc_total',0x36),('ecc_unit',0x37)):
            if not c[key]:self.assert_at(line)
        for i,v in enumerate((c['spare'],c['ecc_total'],c['ecc_unit'],*c['positions'])):self.put(28+2*i,2,v)
        return 0
    def alloc(self,size):
        self.ordinal+=1;p=0 if self.ordinal==self.c['alloc_fail_at'] else HEAP+(self.ordinal-1)*4096
        self.actions.append(f'alloc:{size}:{p}')
        if p:self.allocations.append(dict(pointer=p,size=size,active=True,data=bytearray(b'\xa5'*size)))
        return p
    def scan(self,repair):
        self.actions.append(f'scan:{repair}');n=self.get(16);flags=self.allocation(self.get(44))['data'];mapping=self.allocation(self.get(48))['data']
        c=dict(mode='resume',repeat=1,block_count=n,pages_per_block=self.get(8),repair=repair,marker=self.context[4],
            flags=list(flags)+[0]*(8-n),mapping=list(struct.unpack('<'+'H'*n,mapping))+[0xffff]*(8-n),
            counters=[self.get(56+i*2,2) for i in range(3)],blocks=self.c['blocks'])
        r=resume_contract(c);self.actions.extend(r['actions']);row=r['rows'][0]
        flags[:]=bytes.fromhex(row['flags'])[:n];mapping[:]=struct.pack('<'+'H'*n,*row['mapping'][:n]);self.context[4]=row['marker']
        for i,key in enumerate(('free','used','reserved')):self.put(56+i*2,2,row[key])
        return row['returned']
    def time(self):
        self.ticks+=1;self.actions.extend((f'clock:{self.ticks*1000}',f'millis:{self.ticks*1000}:{self.ticks*10}'))
    def initialize(self):
        c=self.c
        if self.context[4]==0xa5:
            if not c['force']:return 0
            for at in (44,48,52):
                p=self.get(at)
                if p:self.actions.append(f'free:{p}');self.allocation(p)['active']=False
        self.fill(CONTEXT,0,64);self.geometry();self.context[5]=1;self.actions.append('log:geometry_summary')
        if c['force']:
            if c['format_native']:
                self.actions.append(f'format_native:{c["format_kind"]}')
                for i,block in enumerate(c['blocks'][:self.get(16)]):
                    if not c['format_kind']:
                        self.actions.append(f'format_bad:{i}:{block["bad"]}')
                        if block['bad']:continue
                    self.actions.append(f'format_erase:{i}:{block["erase"]}')
            else:
                self.actions.append(f'format:{c["format_kind"]}:{c["format_status"]}')
                if c['format_status']:self.actions.append('log:format_error');return 0xffffffff
        self.time()
        for at,size,byte in ((44,self.get(16),0),(48,self.get(16)*2,255),(52,self.get(12)+self.get(28,2),255)):
            p=self.alloc(size);self.put(at,4,p);self.fill(p,byte,size)
        result=self.scan(0)
        if result!=0xffffffff and result>0:
            self.fill(self.get(44),0,self.get(16));self.fill(self.get(48),255,self.get(16)*2);self.put(56,4,0);self.put(60,2,0);result=self.scan(1)
        if result==0:self.time();self.actions.extend(('log:capacity_summary','log:block_summary'))
        return result
    def run(self):
        rows=[]
        for _ in range(self.c['repeat']):
            stopped=None
            try:
                if self.c['mode']=='geometry':returned=self.geometry()
                elif self.c['mode']=='lazy':
                    if not self.eftl_ready:
                        result=self.initialize()
                        if result<0x80000000:
                            self.block_word=(self.get(8)*self.get(12))&0xffffffff
                            self.capacity_word=((self.get(16)-self.get(60,2))*self.block_word)&0xffffffff
                            self.eftl_ready=True;self.actions.append('log:eftl_ready')
                    returned=None
                else:returned=self.initialize()
            except Stop as stop:returned=None;stopped=stop.info
            rows.append(dict(returned=returned,stopped=stopped,context_sha256=digest(self.context),context_hex=self.context.hex(),
                marker=self.context[4],read_behavior=self.context[5],page_size=self.get(12),pages_per_block=self.get(8),block_count=self.get(16),base_page=self.get(24),
                eftl_ready=int(self.eftl_ready),capacity_word=self.capacity_word,block_word=self.block_word,
                pointers=[self.get(at) for at in (44,48,52)],counters=[self.get(56+i*2,2) for i in range(3)],
                allocations=[{k:v for k,v in a.items() if k!='data'}|dict(sha256=digest(a['data'])) for a in self.allocations]))
            if stopped:break
        return dict(actions=self.actions,rows=rows)


def contract(c):
    if not 1<=c['repeat']<=2 or len(c['blocks'])!=8:raise ValueError('initializer fixture bounds')
    if c['pages_per_block']:
        count=c['pages']//c['pages_per_block']
        if not 0<=count<=8 or (not count and c['mode']!='geometry'):raise ValueError('block backing bound')
    if c['mode']!='geometry' and not 0<=c['page_size']+(c['spare']&0xffff)<=512:raise ValueError('scratch allocation bound')
    return Model(c).run()


def native_vectors():
    cases=[]
    def block(logical=0,tag=0x45,**kw):return dict(logical=logical,tag=tag,corrupt=False,bad=0,erase=0,read=0)|kw
    blocks=[block(2),block(0xffff,tag=255),block(0),block(1,bad=1)]+[block(0xffff,tag=255) for _ in range(4)]
    def add(name,mode='initialize',**changes):
        c=dict(name=name,mode=mode,repeat=1,marker=0,handle_present=False,old_mask=0,force=0,format_kind=0,format_status=0,format_native=False,eftl_ready=False,
            find_ok=True,ioctl_status=0,pages=16,page_size=32,pages_per_block=4,partition_offset=0x100000,
            spare=16,ecc_total=8,ecc_unit=2,positions=[2,4,8,12],alloc_fail_at=0,blocks=blocks)|changes
        c['expected']=contract(c);cases.append(c)
    add('initialize_mixed');add('initialize_repeat',repeat=2)
    add('initialize_marker_guard',marker=0xa5,old_mask=7)
    add('initialize_force_cleanup',marker=0xa5,old_mask=7,force=1)
    add('initialize_force_partial_cleanup',marker=0xa5,old_mask=5,force=1)
    add('initialize_force_format_error',marker=0xa5,old_mask=7,force=1,format_status=-9)
    add('initialize_force_positive_format_error',force=1,format_status=1)
    add('initialize_unmarked_old_buffers',old_mask=7)
    for i in (1,2,3):add(f'initialize_alloc_{i}_error',alloc_fail_at=i)
    add('initialize_oob_error',blocks=[block(0,read=-9)]+blocks[1:])
    add('initialize_error_repeat_leaks',repeat=2,blocks=[block(0,read=-9)]+blocks[1:])
    add('initialize_retry_rebuild',blocks=[block(i,bad=1) for i in range(8)])
    add('initialize_retry_all_reserved',blocks=[block(i,bad=1,erase=-9) for i in range(8)])
    add('initialize_retry_read_error',blocks=[block(i,bad=1,read=-9 if i==1 else 0) for i in range(8)])
    add('initialize_ioctl_status_ignored',ioctl_status=-9)
    add('lazy_connected','lazy');add('lazy_connected_repeat','lazy',repeat=2)
    add('lazy_connected_error','lazy',blocks=[block(0,read=-9)]+blocks[1:])
    add('lazy_already_ready','lazy',eftl_ready=True)
    add('initialize_native_format',force=1,format_native=True)
    add('initialize_native_format_erase_errors',force=1,format_native=True,format_kind=1,
        blocks=[b|dict(erase=-9) for b in blocks])
    add('initialize_native_format_negative_bad',force=1,format_native=True,
        blocks=[blocks[0]|dict(bad=-9)]+blocks[1:])
    add('initialize_native_format_all_reserved',force=1,format_native=True,
        blocks=[block(i,bad=1,erase=-9) for i in range(8)])
    add('geometry_original','geometry');add('geometry_existing_handle','geometry',handle_present=True)
    add('geometry_unaligned_partition','geometry',partition_offset=0x100003)
    add('geometry_page_count_truncation','geometry',pages=19)
    add('geometry_ioctl_status_ignored','geometry',ioctl_status=-9)
    add('geometry_find_error','geometry',find_ok=False)
    add('geometry_zero_pages','geometry',pages=0)
    add('geometry_metadata_u16','geometry',spare=0x10010,ecc_total=0x10008,ecc_unit=0x10002,
        positions=[0x10002,0x10004,0x10008,0x1000c])
    for key in ('page_size','pages_per_block','spare','ecc_total','ecc_unit'):
        add('geometry_zero_'+key,'geometry',**{key:0})
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive)
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual EFTL initializer, geometry collection, OOB scan/checksum, retry/reset and selected generic format loops execute; NAND discovery/ioctl data, erase/OOB, heap and clocks are supplied. Format is supplied in the explicit format-error cases.',
            'Allocation failure stops at the attempted null memset before any address-zero write; assertion cases stop before the assert body without returning ABI claims.',
            'Authored geometry/OOB/heap lifetime fixtures do not establish physical NAND geometry, allocation failure incidence or actual device faults.',
            'Physical NAND/ECC/bus, lower format/OOB transport, other mapping repair/write paths, SFTL and boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect EFTL initialization: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
