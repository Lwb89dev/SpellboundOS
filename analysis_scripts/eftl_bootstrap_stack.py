#!/usr/bin/env python3
"""Original EFTL initializer/geometry/lookup/scan/retry through NAND and QSPI."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import eftl_scan_stack as scan
else:
    import eftl_scan_stack as scan

qspi=scan.qspi
EXTRA_RANGES=((0x80c02298,456),(0x80c02460,372),(0x80c0285a,126),
    (0x80c231d6,124),(0x80c29478,186),(0x80c243d6,112))
RANGES=scan.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
CONTEXT=0x80de5fb8
PART=0x81308000
ROLES=((0x8130c000,8),(0x81309100,16),(0x8130a000,2112))


class Model(scan.Model):
    def __init__(self,c):
        super().__init__(dict(c));self.ctx=scan.repair.rb.context(c);self.ctx[4]=c['init_marker']
        self.put(0,4,PART if c['init_handle_present'] else 0);self.ctx[56:62]=b'\0'*6
        self.heap=[];self.attempts=0;self.frees=0;self.clocks=0
        self.ready=c['init_ready'];self.capacity=0x7fffffff;self.block_size=131072
        for i,(p,n) in enumerate(ROLES):
            old=bool(c['init_old_mask']&(1<<i));self.put(44+i*4,4,p if old else 0)
            if old:self.heap.append(dict(pointer=p,size=n,active=True))
    def put(self,at,n,v):self.ctx[at:at+n]=(v&((1<<(8*n))-1)).to_bytes(n,'little')
    def get(self,at,n=4):return int.from_bytes(self.ctx[at:at+n],'little')
    def body(self,p):
        if p==ROLES[0][0]:return bytes(self.flags)
        if p==ROLES[1][0]:return struct.pack('<8H',*self.mapping)
        if p==ROLES[2][0]:return bytes(self.scratch)
        raise ValueError('initializer heap pointer')
    def fill(self,p,byte,n):
        self.actions.append(f'init_fill:{p}:{byte}:{n}')
        if not p:self.stopped=dict(kind='null_memset',size=n,fill=byte);return
        if p==CONTEXT:
            if (byte,n)!=(0,64):raise ValueError('context fill')
            self.ctx[:]=b'\0'*64;self.c['fast']=False;self.marker=0;self.counters=[0,0,0]
        elif (p,n)==ROLES[0]:self.flags[:]=bytes([byte])*n
        elif (p,n)==ROLES[1]:self.mapping[:]=[byte*257]*8
        elif (p,n)==ROLES[2]:self.scratch[:]=bytes([byte])*n
        else:raise ValueError('initializer fill bound')
    def allocate(self,n):
        self.attempts+=1;p,size=ROLES[self.attempts-1]
        if n!=size:raise ValueError('initializer allocation size')
        if self.attempts==self.c['init_alloc_fail_at']:p=0
        self.actions.append(f'init_alloc:{n}:{p}')
        if p:
            if any(a['pointer']==p and a['active'] for a in self.heap):raise ValueError('overlapping live allocation')
            self.heap.append(dict(pointer=p,size=n,active=True))
        return p
    def free(self,p):
        a=next(a for a in reversed(self.heap) if a['pointer']==p and a['active'])
        a.update(active=False,sha256=qspi.digest(self.body(p)));self.frees+=1;self.actions.append('init_free:'+str(p))
    def partition_ioctl(self,query,arg):
        self.actions.append('init_partition_ioctl:'+str(query));return super().partition_ioctl(query,arg)
    def lookup(self):
        self.actions.extend(('init_lookup:eftl','init_partition_lookup:eftl'))
        if not self.c['init_registry_present']:self.actions.append('init_board:0');return 0
        self.actions.extend(('init_strcmp:eftl:eftl','log:init_partition_found'))
        for query in (2,1,3):
            if self.driver_ioctl(query,bytearray(4)):return 0
            if self.stopped:return 0
        return PART
    def geometry(self):
        if not self.get(0):
            p=self.lookup()
            if self.stopped:return
            self.put(0,4,p)
            if not p:self.stopped=dict(kind='assertion',owner=0x80c34480,line=0x1a);return
        for query,at in ((1,20),(2,12),(3,8)):
            b=bytearray(4);self.partition_ioctl(query,b)
            if self.stopped:return
            self.put(at,4,struct.unpack('<I',b)[0])
        self.put(16,4,self.get(20)//self.get(8));self.put(24,4,self.c['partition_base']//self.get(12))
        values=[]
        for query in (18,19,20,21):
            b=bytearray(16);self.partition_ioctl(query,b)
            if self.stopped:return
            values.extend(struct.unpack('<4I',b) if query==21 else [struct.unpack_from('<I',b)[0]])
        for i,v in enumerate(values):self.put(28+i*2,2,v)
    def time(self):
        self.clocks+=1;v=self.clocks*1000;self.actions.extend((f'init_clock:{v}',f'init_millis:{v}:{self.clocks*10}'))
    def scan(self):
        self.actions.append('init_scan:'+str(self.c['scan_repair']));value=super().scan()
        self.ctx[4]=self.marker;struct.pack_into('<3H',self.ctx,56,*self.counters);return value
    def initialize_eftl(self,force,kind):
        if self.ctx[4]==165:
            if not force:return 0
            for at in (44,48,52):
                if self.get(at):self.free(self.get(at))
        self.fill(CONTEXT,0,64);self.geometry()
        if self.stopped:return None
        self.ctx[5]=1;self.actions.append('log:init_geometry_summary')
        if force:
            for i in range(8):
                if not kind:
                    value=self.partition_ioctl(10,bytearray(struct.pack('<I',i)))
                    if self.stopped:return None
                    if value:continue
                self.partition_ioctl(12,bytearray(struct.pack('<I',i)))
                if self.stopped:return None
        self.time()
        for i,(p,n) in enumerate(ROLES):
            pointer=self.allocate(n);self.put(44+i*4,4,pointer);self.fill(pointer,0 if i==0 else 255,n)
            if self.stopped:return None
        self.c['scan_repair']=0;value=self.scan()
        if self.stopped:return None
        if value>0:
            self.fill(ROLES[0][0],0,8);self.fill(ROLES[1][0],255,16)
            self.counters=[0,0,0];self.ctx[56:62]=b'\0'*6;self.c['scan_repair']=1;value=self.scan()
        if self.stopped:return None
        if value==0:self.time();self.actions.extend(('log:init_capacity_summary','log:init_block_summary'))
        return value
    def storage_mutation(self):
        c=self.c;value=0
        for _ in range(c['init_repeat']):
            if c['init_entry']=='geometry':self.geometry();value=0
            elif c['init_entry']=='lazy':
                if not self.ready:
                    value=self.initialize_eftl(0,0)
                    if self.stopped:return None
                    if value>=0:
                        self.block_size=self.get(8)*self.get(12);self.capacity=(self.get(16)-self.get(60,2))*self.block_size
                        self.ready=True;self.actions.append('log:init_ready')
            else:value=self.initialize_eftl(c['init_force'],c['init_format_kind'])
            if self.stopped:return None
        return value
    def run(self):
        result=super().run();row=result['rows'][0];row['eftl_context_hex']=self.ctx.hex()
        if self.c['init_entry']=='lazy':row['returned']=None
        row.update(init_allocation_attempts=self.attempts,init_frees=self.frees,init_ready=int(self.ready),
            init_capacity=self.capacity,init_block_size=self.block_size,
            init_heap=[a|dict(sha256=qspi.digest(self.body(a['pointer'])) if a['active'] else a['sha256']) for a in self.heap])
        return result


def contract(c):
    if not c['native_initialize'] or c['init_entry'] not in ('initialize','geometry','lazy'):raise ValueError('initializer entry')
    if c['partition_span']!=1048576 or c['scan_count']!=8 or c['ecc_unit']!=4:raise ValueError('fixed original-chip geometry backing')
    if not 0<=c['init_alloc_fail_at']<=3 or not 0<=c['init_marker']<=255 or not 0<=c['init_old_mask']<=7:raise ValueError('initializer heap bounds')
    if c['init_old_mask'] and c['init_marker']!=165:raise ValueError('deferred unmarked old buffers')
    if c['init_force'] not in (0,1) or c['init_format_kind'] not in (0,1) or c['init_repeat'] not in (1,2):raise ValueError('initializer mode bounds')
    if c['init_repeat']>1 and (c['init_force'] or c['init_alloc_fail_at'] or c['responses']!=[0]):raise ValueError('deferred repeated allocations')
    if c['init_entry']!='initialize' and c['init_force']:raise ValueError('selected force entry')
    if not 1<=len(c['cache_payloads'])<=64 or any(len(bytes.fromhex(p)) not in (2,64) for p in c['cache_payloads']):raise ValueError('initializer FIFO backing')
    scan.contract(c|dict(native_initialize=False,cache_payloads=[b'\xff\xff'.hex()]*3+[scan.oob(0,'empty').hex()],init_repeat=1))
    return Model(c).run()


def native_vectors():
    base=scan.native_vectors()['cases'][0];cases=[]
    def block(logical=0,variant='empty'):return [b'\xff\xff']*3+[scan.oob(logical,variant)]
    normal=block(0,'valid')+block(1,'valid')+block()*6
    def add(name,**changes):
        c=base|dict(name=name,native_initialize=True,init_entry='initialize',init_repeat=1,init_marker=0,
            init_old_mask=0,init_handle_present=False,init_ready=False,init_force=0,init_format_kind=0,
            init_alloc_fail_at=0,init_registry_present=True,partition_span=1048576,scan_count=8,
            irq_context=1,cache_payloads=[b.hex() for b in normal])|changes
        c['expected']=contract(c);cases.append(c)
    add('bootstrap_connected');add('bootstrap_repeat',init_repeat=2)
    add('bootstrap_generic_stale',irq_context=0)
    add('bootstrap_lazy',init_entry='lazy');add('bootstrap_lazy_repeat',init_entry='lazy',init_repeat=2)
    add('bootstrap_lazy_ready',init_entry='lazy',init_ready=True)
    add('bootstrap_marker_guard',init_marker=165,init_old_mask=7,init_handle_present=True)
    add('bootstrap_force_cleanup',init_marker=165,init_old_mask=7,init_force=1,init_format_kind=1)
    for i in (1,2,3):add(f'bootstrap_alloc_{i}_failure',init_alloc_fail_at=i)
    add('bootstrap_oob_error',responses=[0,0,0,32,0])
    add('bootstrap_lazy_oob_error',init_entry='lazy',responses=[0,0,0,32,0])
    add('bootstrap_registry_missing',init_registry_present=False)
    add('bootstrap_geometry',init_entry='geometry')
    add('bootstrap_geometry_handle',init_entry='geometry',init_handle_present=True)
    add('bootstrap_duplicate',cache_payloads=[b.hex() for b in block(0,'valid')*2+block()*6])
    reserved=[b'\0\0']*8
    repaired=[v for _ in range(8) for v in (b'\0\0',scan.oob(0,'empty'))]
    add('bootstrap_retry',cache_payloads=[b.hex() for b in reserved+repaired])
    add('bootstrap_retry_all_reserved',init_entry='lazy',responses=[0]*8+[0,4]*8,
        cache_payloads=[b.hex() for b in reserved*2])
    add('bootstrap_lazy_reserved_capacity',init_entry='lazy',cache_payloads=[b.hex() for b in [b'\0\0']+block(0,'valid')+block()*6])
    add('bootstrap_force_format',init_force=1,cache_payloads=[b.hex() for b in [b'\xff\xff']*24+normal])
    add('bootstrap_force_erase_errors',init_force=1,init_format_kind=1,responses=[4])
    add('bootstrap_force_oob_error_ready',init_marker=165,init_old_mask=7,init_force=1,
        init_format_kind=1,init_ready=True,responses=[0]*11+[32,0])
    return dict(schema=1,bound_per_case=scan.repair.read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=scan.repair.read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=scan.repair.read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in scan.repair.mutation.storage.DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original EFTL initialize/lazy/geometry/registry lookup/format/scan/retry and NAND/BBT/QSPI execute together with fixed original-chip geometry and an authored eight-block NAND partition.',
            'Registry binding, guarded fixed heap slots, clock/string/cache/copy/RTOS services, FIFO bytes and status scripts are authored; no DMA movement or physical erase/persistence is modeled.',
            'Ready/capacity publication and cleanup snapshots do not establish physical boot, live heap behavior, persistent recovery, complete concurrency or device-specific restoration.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect connected EFTL bootstrap: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
