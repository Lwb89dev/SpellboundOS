#!/usr/bin/env python3
"""Device registry, environment handle setup and NVMS mirror contracts.

Registry rows, volume bases and driver callbacks are synthetic. Only the small
default table is recovered from the image. No physical flash or boot executes.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .env_initialize import RANGES as INIT_RANGES
    from .recovery_validator import BOOT_HASH,digest,image_memory,table
else:
    from env_initialize import RANGES as INIT_RANGES
    from recovery_validator import BOOT_HASH,digest,image_memory,table

REGISTRY=0x81210000
DEVICE=0x81230000
MUTEX=0x81290000
NAMES=('easyflash','envbak','nvms','env')
BASES=(0,0x6000,0xa000,0xb000)
SIZES=(0x6000,0x4000,0x1000,0x6000)
STOP=0x80c0b7b0
CONFIG=dict(setup=0x80c0be14,bootstrap=0x80c0c27a,caller=0x80c1a022,lookup=0x80c243d6,
    check=0x80c24218,read=0x80c24446,program=0x80c24502,erase=0x80c245be,rewrite=0x80c24652,
    sync=0x80c1c51a,nv_read=0x80c0d736,nv_write=0x80c0d776,retained=0x80c01704,
    strcmp=0x80c2e3d8,memcmp=0x80c2dddc,memset=0x80c2e014,copy=0x80c2de38,
    create_mutex=0x80c16afa,take=0x80c16b86,give=0x80c16c2a,alloc=0x80c1a308,free=0x80c1a312,
    logger=0x80c1cd7a,warn=0x80c0c220,diagnostic=0x80c0c120,
    driver_read=0x70000100,driver_program=0x70000104,driver_erase=0x70000108,driver_rewrite=0x7000010c)
RANGES=INIT_RANGES+((0x80c0be14,0x144),(0x80c0c27a,0x76),(0x80c24218,0x506),
    (0x80c1c51a,0xee),(0x80c0d736,0x126),(0x80c0c06c,0x8a),(0x80c01704,0x36),(0x80c1a022,0x10),(0x80c0c118,8))
TARGETS=(0x80c0be14,0x80c0c27a,0x80c243d6,0x80c24218,0x80c24446,0x80c24502,
    0x80c245be,0x80c24652,0x80c1c51a,0x80c0d736,0x80c0d776,0x80c01704,0x80c1a022)
LOGS={0x80c3c0f8:'registry_unready',0x80c3c068:'no_owner',0x80c3c0b4:'bounds',
      0x80c3c114:'read_error',0x80c3c148:'program_error',0x80c3c180:'erase_error',
      0x80c3c1b8:'rewrite_missing',0x80c3c1f0:'rewrite_error',0x80c36350:'envbak_found',
      0x80c36374:'nvms_found',0x80c36390:'nvms_missing',0x80c363c0:'env_missing',
      0x80c39a8c:'mirrors_equal',0x80c39aa4:'secondary_write_error',0x80c39ab8:'secondary_repaired',
      0x80c39ad0:'primary_write_error',0x80c39ae4:'primary_repaired',0x80c39afc:'no_valid_mirror'}
WARNS={0x80c3652c:'bootstrap_ok',0x80c36554:'bootstrap_error',0x80c36578:'bootstrap_banner'}


def handle(name):return REGISTRY+NAMES.index(name)*60 if name is not None else 0
def nv_record(valid,kind):
    data=bytearray((i*13+kind)&255 for i in range(160));struct.pack_into('<I',data,0,0x55aa55aa if valid else 0);return data
def physical_bytes(c):
    data=bytearray((i*17+3)&255 for i in range(0x12000))
    for i in range(4):
        at=BASES[3]+i*4096;data[at:at+20]=b'\0\xff\xff\0\xff\xff\xff\xffEF40'+b'\xff'*8
    primary=nv_record(c['primary_valid'],1);secondary=primary if c['mirrors_equal'] else nv_record(c['secondary_valid'],2)
    data[(0xa000 if c['primary_special'] else 0x4000):(0xa000 if c['primary_special'] else 0x4000)+160]=primary
    data[0x10000:0x10000+160]=secondary;return data


class Model:
    def __init__(self,c):
        self.c=c;self.data=physical_bytes(c);self.actions=[];self.buffer=bytearray(b'\xa5'*1024)
        self.payload=bytes(range(256))*2;self.mutex=MUTEX if c['mutex_present'] else 0;self.depth=0;self.heap=None
        self.handles={k:handle(v) for k,v in c['initial_handles'].items()};self.counts=dict(read=0,program=0,erase=0,rewrite=0)
        self.outer=c['outer_ready'];self.inner=c['inner_ready'];self.duplicate=0;self.bound_pointer=0;self.bound_count=0
        self.ends=bytearray(b'\xa5'*32);self.index=bytearray(b'\xa5'*128);self.magic=c['retained_magic'];self.retained=c['retained_value']
    def log(self,name):self.actions.append('log:'+name)
    def find(self,name):
        self.actions.append('lookup:'+name)
        if not self.c['registry_ready']:self.log('registry_unready');return 0
        return handle(name) if name in NAMES and name in self.c['available'] else 0
    def call(self,name,op,offset,n,source=None,target=None):
        i=NAMES.index(name);self.actions.append(f'check:{i}:{offset}:{n}')
        if self.c['owner_missing']:self.log('no_owner');return -1
        span=self.c['sizes'][i] or 0x12000-BASES[i]
        if offset>=span:self.log('bounds');return -1
        n=min(n,span-offset)
        if op=='rewrite' and self.c['rewrite_missing']:self.log('rewrite_missing');return -1
        at=BASES[i]+offset;self.counts[op]+=1
        result=-1 if self.counts[op]==self.c[op+'_fail'] else (n if op in ('read','program') else 0)
        if result>=0 and op in ('read','program') and self.c[op+'_short'] is not None:result=min(n,self.c[op+'_short'])
        action=f'{op}:{at}:{n}:{result}'
        if op in ('program','rewrite'):action+=':'+digest(source[:n])
        self.actions.append(action)
        if result<0:self.log(op+'_error');return result
        if op=='read':target[:result]=self.data[at:at+result]
        elif op=='program':
            for j,b in enumerate(source[:result]):self.data[at+j]&=b
        elif op=='rewrite':self.data[at:at+n]=source[:n]
        else:self.data[at:at+n]=b'\xff'*n
        return result
    def route(self,address):
        h=self.handles
        if 0x4000<=address<0x5000:
            if h['special']:return NAMES[(h['special']-REGISTRY)//60],address-0x4000
            if h['fallback']:return NAMES[(h['fallback']-REGISTRY)//60],address
            return None,address
        return NAMES[(h['active']-REGISTRY)//60],address
    def io(self,address,op,n,source=None,target=None):
        name,offset=self.route(address)
        if name is None:self.log('fdb_'+op+'_error');return 2 if op=='read' else 3
        result=self.call(name,op,offset,n,source,target)
        if result<0:self.log('fdb_'+op+'_error');return 2 if op=='read' else 1 if op=='erase' else 3
        return 0
    def lock(self):
        if self.mutex:self.depth+=1;self.actions.append('lock')
    def unlock(self):
        if self.mutex:self.depth-=1;self.actions.append('unlock')
    def nv_read(self,offset,n,target):
        if not n:return 0
        if offset+n>0x2000:return 2
        self.lock();result=self.io(0x4000+offset,'read',n,target=target);self.unlock();return result
    def nv_write(self,offset,source):
        n=len(source)
        if not n:return 0
        if offset+n>0x2000:return 3
        self.lock();result=self.io(0x4000+offset,'rewrite',n,source=source);self.unlock()
        if not result:return 0
        self.lock();ok=not self.c['alloc_fail'];self.actions.append('alloc:4096:'+str(int(ok)))
        if not ok:return 1
        self.heap=bytearray(b'\xa5'*4096);done=0
        while done<n:
            logical=offset+done;within=logical&0xfff;count=min(n-done,4096-within);page=0x4000+(logical&~0xfff)
            result=self.io(page,'read',4096,target=self.heap)
            if result:break
            self.heap[within:within+count]=source[done:done+count]
            self.io(page,'erase',4096);self.io(page,'program',4096,source=self.heap);done+=count
        self.heap=None;self.actions.append('free:4096');self.unlock();return result
    def sync(self):
        primary=bytearray(b'\xa5'*160);secondary=bytearray(b'\xa5'*160)
        if self.nv_read(0,160,primary):return 0xfffffff2
        if self.nv_read(4096,160,secondary):secondary[:]=b'\xff'*160
        if primary[:4]==b'\xaa\x55\xaa\x55':
            if primary==secondary:self.log('mirrors_equal');return 0
            result=self.nv_write(4096,primary);self.log('secondary_write_error' if result else 'secondary_repaired')
        elif secondary[:4]==b'\xaa\x55\xaa\x55':
            result=self.nv_write(0,secondary);self.log('primary_write_error' if result else 'primary_repaired')
        else:self.log('no_valid_mirror');return 0xfffffff2
        return 0xfffffff2 if result else 0
    def setup(self):
        if not self.mutex:
            self.mutex=0 if self.c['mutex_fail'] else MUTEX;self.actions.append('mutex:create:'+str(int(bool(self.mutex))))
            if not self.mutex:return 7
        h=self.handles;h['fallback']=self.find('easyflash')
        if h['fallback']:h['backup']=h['fallback']
        else:
            h['backup']=self.find('envbak')
            if h['backup']:self.log('envbak_found')
            h['special']=self.find('nvms')
            if not h['special']:self.log('nvms_missing');return 7
            self.log('nvms_found')
        h['active']=self.find('env')
        if not h['active']:self.log('env_missing');return 7
        self.sync();return 0
    def bind_clean(self):
        if self.inner:return 0
        for i in range(4):struct.pack_into('<I',self.ends,i*8,0xffffffff)
        for i in range(16):struct.pack_into('<I',self.index,i*8+4,0xffffffff)
        self.bound_pointer=0x80c36518;self.bound_count=1;self.actions.append('diagnostic:8fe');self.duplicate=1
        for at in range(0,0x4000,4096):self.io(at,'read',20,target=bytearray(20))
        self.lock()
        for _ in range(2):
            for at in range(0,0x4000,4096):self.io(at,'read',20,target=bytearray(20))
        self.duplicate=0;self.unlock();self.inner=True;return 0
    def bootstrap(self):
        if self.outer:return 0
        result=self.setup()
        if not result:result=self.bind_clean()
        if not result:self.outer=True;self.log('bootstrap_ok')
        else:self.log('bootstrap_error')
        self.log('bootstrap_banner')
        return result
    def result(self):
        rows=[];mode=self.c['mode']
        for _ in range(self.c['repeat']):
            stopped=None
            if mode=='setup':returned=self.setup()
            elif mode=='sync':returned=self.sync()
            elif mode in ('bootstrap','caller'):
                returned=self.bootstrap()
                if mode=='caller':stopped=dict(pc=STOP,status=returned);returned=None
            elif mode=='lookup':returned=self.find(self.c['query'])
            elif mode=='nv_read':returned=self.nv_read(self.c['offset'],self.c['size'],self.buffer)
            elif mode=='nv_write':returned=self.nv_write(self.c['offset'],self.payload[:self.c['size']])
            elif mode=='retained':
                if self.magic!=0xabcd1234:self.magic=0xabcd1234;self.retained=0;returned=0
                else:returned=self.retained&255
            else:returned=self.call('env',mode,self.c['offset'],self.c['size'],self.payload,self.buffer)&0xffffffff
            rows.append(dict(returned=returned,storage_sha256=digest(self.data),buffer_sha256=digest(self.buffer),mutex=self.mutex,lock_depth=self.depth,
                handles=dict(self.handles),table_output=0x80c36518 if mode=='setup' else None,count_output=1 if mode=='setup' else None,
                outer_ready=int(self.outer),inner_ready=int(self.inner),duplicate_guard=self.duplicate,bound_pointer=self.bound_pointer,bound_count=self.bound_count,
                sector_cache_sha256=digest(self.ends),key_cache_sha256=digest(self.index),heap_active=self.heap is not None,
                retained_magic=self.magic,retained_value=self.retained,stopped=stopped))
        return dict(actions=self.actions,rows=rows)


def contract(c):
    if not 0<=c['size']<=512 or not 0<=c['offset']<=0x7000 or not 1<=c['repeat']<=2:raise ValueError('bounded storage probe')
    if c['mode'] in ('bootstrap','caller') and any(c[k] for k in ('owner_missing','alloc_fail')):raise ValueError('connected binder fixtures require usable storage')
    return Model(c).result()


def native_vectors():
    cases=[]
    def add(name,mode='setup',**changes):
        seeded=mode not in ('setup','bootstrap','caller')
        c=dict(name=name,mode=mode,repeat=1,available=list(NAMES),registry_ready=True,owner_missing=False,sizes=list(SIZES),
            initial_handles=dict(active='env' if seeded else None,backup='easyflash' if seeded else None,special=None,fallback='easyflash' if seeded else None),
            mutex_present=seeded,mutex_fail=False,outer_ready=False,inner_ready=False,primary_special=False,
            primary_valid=True,secondary_valid=True,mirrors_equal=False,read_fail=0,program_fail=0,erase_fail=0,rewrite_fail=0,
            read_short=None,program_short=None,rewrite_missing=False,alloc_fail=False,offset=0,size=32,query='env',
            retained_magic=0xabcd1234,retained_value=0x12345678)|changes
        c['expected']=contract(c);cases.append(c)
    add('setup_preferred');add('setup_fallback',available=['envbak','nvms','env'],primary_special=True)
    add('setup_without_backup',available=['nvms','env'],primary_special=True)
    add('setup_mutex_error',mutex_fail=True);add('setup_existing_mutex',mutex_present=True)
    add('setup_missing_nvms',available=['envbak','env']);add('setup_missing_env',available=['easyflash'])
    add('setup_registry_unready',registry_ready=False);add('setup_ignores_sync_error',read_fail=1)
    add('setup_stale_special',primary_special=True,initial_handles=dict(active=None,backup=None,special='nvms',fallback=None))
    add('sync_equal','sync',mirrors_equal=True);add('sync_primary','sync')
    add('sync_secondary','sync',primary_valid=False);add('sync_invalid','sync',primary_valid=False,secondary_valid=False)
    add('sync_primary_read_error','sync',read_fail=1);add('sync_secondary_read_error','sync',read_fail=2)
    add('sync_fallback','sync',rewrite_fail=1);add('sync_fallback_read_error','sync',rewrite_fail=1,read_fail=3)
    add('sync_fallback_erase_error','sync',rewrite_fail=1,erase_fail=1)
    add('sync_fallback_program_error','sync',rewrite_fail=1,program_fail=1)
    add('sync_fallback_alloc_error','sync',rewrite_fail=1,alloc_fail=True)
    add('nv_write_missing_callback','nv_write',rewrite_missing=True,size=160)
    add('nv_write_two_pages','nv_write',rewrite_fail=1,offset=4080,size=32)
    add('nv_write_cross_fast','nv_write',offset=4080,size=32)
    add('nv_read_zero','nv_read',size=0);add('nv_read_range_error','nv_read',offset=8192,size=1)
    add('nv_write_zero','nv_write',size=0);add('nv_write_range_error','nv_write',offset=8192,size=1)
    for op in ('read','program','erase','rewrite'):
        add(op+'_clip',op,offset=0x5ff0,size=64)
        add(op+'_error',op,**{op+'_fail':1})
    add('rewrite_missing','rewrite',rewrite_missing=True);add('read_owner_missing','read',owner_missing=True)
    add('read_derived_span','read',sizes=[0x6000,0x4000,0x1000,0],offset=0x6000,size=16)
    add('read_at_end','read',offset=0x6000,size=1)
    add('lookup_hit','lookup');add('lookup_missing','lookup',query='missing');add('lookup_unready','lookup',registry_ready=False)
    add('bootstrap','bootstrap');add('bootstrap_setup_error','bootstrap',available=['easyflash'])
    add('bootstrap_fallback','bootstrap',available=['nvms','env'],primary_special=True)
    add('bootstrap_already_outer','bootstrap',outer_ready=True)
    add('bootstrap_already_inner','bootstrap',inner_ready=True)
    add('caller','caller');add('caller_setup_error','caller',mutex_fail=True)
    add('retained_magic_missing','retained',retained_magic=0,repeat=2);add('retained_low_byte','retained')
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=2000000:raise ValueError('native mismatch/bound')
    memory=image_memory(archive);values=struct.unpack('<III',memory.read(0x80c36518,12))
    if values!=(0x80c36510,0x80c385b0,0) or memory.string(values[0])!='boots' or memory.string(values[1])!='0':raise ValueError('default table')
    if memory.read(0x80c32e8c,1024)!=table():raise ValueError('CRC table')
    return dict(boot_sha256=BOOT_HASH,vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},crc_table_sha256=digest(table()),
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        default_table=dict(address=0x80c36518,sha256=digest(memory.read(0x80c36518,12)),key='boots',value='0',length=0),
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Registry rows/owners/device descriptors, partition bases/spans and driver callbacks are synthetic; named lookup/validation/dispatch execute natively.',
            'NVMS mirror copy, fallback read-modify-erase-program and setup/bootstrap execute; connected binding uses clean authored EF40 headers.',
            'Mutex callbacks record depth without blocking. Heap/NOR/erase/rewrite semantics are supplied; no physical flash geometry, atomicity or device boot is proven.',
            'The framework caller stops before its next startup phase at 80c0b7b0; retained-word fixtures do not establish physical reset-state provenance.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for name in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.vectors,a.validation,a.decompiled)):p.error('need archive/vectors/validation/decompiled')
        with zipfile.ZipFile(a.archive) as z:report=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect environment storage: {e}\n')
    print(json.dumps(report,indent=2,sort_keys=True))


if __name__=='__main__':main()
