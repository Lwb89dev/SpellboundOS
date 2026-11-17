#!/usr/bin/env python3
"""NAND read-retry and UID policy over actual command builders, supplied bus."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from .recovery_validator import BOOT_HASH,digest,image_memory
else:
    from recovery_validator import BOOT_HASH,digest,image_memory

ROOT=Path(__file__).resolve().parents[1]
INVENTORY=ROOT/'analysis/nand-identity.json'
CONFIG=dict(compat=0x80c29d4c,set_level=0x80c29d94,retry=0x80c29e6e,check=0x80c29f5c,uid=0x80c28422,
    get=0x80c27ce8,set=0x80c27d48,load=0x80c27e0e,cache=0x80c27e70,reset_enable=0x80c2825a,reset=0x80c282b8,
    busy=0x80c2836e,wait=0x80c102f0,delay_thunk=0x80c0184a,delay=0x80c12154,transfer=0x80c106f0,
    compare=0x80c2e5e8,zero=0x80c2e014,format=0x80c2e1e8,logger=0x80c1cd7a,assertion=0x80c16516,
    ioctl=0x80c292ee,copy=0x80c2de38)
RANGES=((0x80c29d4c,72),(0x80c29d94,218),(0x80c29e6e,238),(0x80c29f5c,234),(0x80c28422,656),
    (0x80c27ce8,96),(0x80c27d48,104),(0x80c27e0e,98),(0x80c27e70,102),(0x80c2825a,94),(0x80c282b8,94),
    (0x80c2836e,180),(0x80c102f0,20),(0x80c0184a,4),(0x80c292ee,394))
TARGETS=tuple(a for a,n in RANGES if a!=CONFIG['delay_thunk'])
LOGS={0x80c3e87c:'feature_error',0x80c3e89c:'level_mismatch',0x80c3e8c0:'retry_valid',
    0x80c3e8dc:'restore_failed',0x80c3e900:'retry_invalid',0x80c3e918:'level_register',
    0x80c3e92c:'check_level',0x80c3e954:'check_failed',0x80c3d6b0:'uid_feature_error',
    0x80c3d6d8:'uid_error',0x80c3d6e4:'uid_ok',0x80c3d6a4:'busy_timeout',0x80c3d688:'busy_feature_error',
    0x80c3db08:'ioctl_error'}


def inventory(memory):
    chips=[]
    for address in struct.unpack('<11I',memory.read(0x80c3dcd0,44)):
        b=memory.read(address,184);word=lambda at:struct.unpack_from('<I',b,at)[0]
        p=word(0xa8);count=b[0xac]
        chips.append(dict(address=address,sha256=digest(b),name=memory.string(word(0x38)),name_pointer=word(0x38),
            uid_flag=b[0xa6],uid_mode=b[0xad],uid_copies=b[0xae],uid_page=word(0xb0),uid_size=word(0xb4),
            sequence_pointer=p,sequence=[list(memory.read(p+i*2,2)) for i in range(count)],ecc_mask=b[0x8e],ecc_bad=b[0x8f]))
    return dict(boot_sha256=BOOT_HASH,hardware_execution=False,chips=chips)


def facts():return json.loads(INVENTORY.read_bytes())['chips']
def descriptor(c):
    p=dict(facts()[c['chip_index']])
    for key,value in c['overrides'].items():p[key]=value
    return p
def uid_bytes(index,good):
    first=bytes((i*7+index*13+1)&255 for i in range(16));second=bytearray(v^255 for v in first)
    if not good:second[-1]^=1
    return first+second


class Stop(Exception):
    def __init__(self,owner,line):self.info=dict(kind='assertion',owner=owner,line=line)


class Model:
    def __init__(self,c):
        self.c=c;self.p=descriptor(c);self.actions=[];self.uid=bytearray(b'\xa5'*128);self.uid_length=c['initial_uid_length']
        self.registers={0xe0:c['e0']};self.gets=0;self.sets=0;self.e0_reads=0;self.c0_reads=0;self.loads=0;self.caches=0;self.transfers=0
    def log(self,tag):self.actions.append('log:'+tag)
    def packet(self,op,address,n,write,ab,dl=1,dummy=0,payload=b''):
        self.transfers+=1;status=-9 if self.transfers==self.c['bus_error_at'] else 0
        self.actions.append(f'packet:{op}:{address}:{n}:{int(write)}:{ab}:{dl}:{dummy}:'+digest(payload)+f':{status}')
        if status:
            owner,line={0x0f:(0x80c3d670,0x37),0x1f:(0x80c3d658,0x4a),0x13:(0x80c3d62c,0x83),
                3:(0x80c3d604,0x96),0x66:(0x80c3d4c0,0x1a5),0x99:(0x80c3d4ac,0x1b8)}[op]
            raise Stop(owner,line)
    def get(self,reg):
        self.gets+=1
        if self.gets in self.c['get_errors']:self.actions.append(f'inject_get:{reg}:-9');return -9,0
        self.packet(0xf,reg,1,False,1)
        if reg==0xe0:
            i=self.e0_reads;self.e0_reads+=1;v=self.c['e0_reads'][i] if i<len(self.c['e0_reads']) else self.registers[reg]
        elif reg==0xc0:
            i=self.c0_reads;self.c0_reads+=1;v=self.c['statuses'][min(i,len(self.c['statuses'])-1)]
        else:v=self.registers.get(reg,0)^int(self.c['uid_mismatch'])
        self.actions.append(f'get:{reg}:{v}');return 0,v
    def set(self,reg,value):
        self.sets+=1;value&=255
        if self.sets in self.c['set_errors']:self.actions.append(f'inject_set:{reg}:{value}:-9');return -9
        self.packet(0x1f,reg,1,True,1,payload=bytes([value]));self.actions.append(f'set:{reg}:{value}')
        if reg!=0xe0 or self.c['apply_writes']:self.registers[reg]=value
        return 0
    def load(self,page):
        self.loads+=1
        if self.loads==self.c['load_error_at']:self.actions.append(f'inject_load:{page}:-9');return -9
        self.packet(0x13,page,0,True,3);return 0
    def busy(self):
        for i in range(2000):
            self.actions.append('delay:5');status,value=self.get(0xc0)
            if status:self.log('busy_feature_error');return status,255
            if i==1999:self.log('busy_timeout');return 0,255
            if not value&1:return 0,value
        raise AssertionError('bounded busy')
    def compat(self):
        if not self.c['present']:return -1
        name=self.p['name'];return 0 if name[:20] in ('Winbond W25N02LWZEIG','Winbond W25N04LWZEIG') else -1
    def set_level(self,level):
        if level==3:return -1
        status,value=self.get(0xe0)
        if status:self.log('feature_error');return status
        if value&7!=level:
            wanted=(value&0xf8)|(level&255)
            for _ in range(5):
                if self.set(0xe0,wanted):continue
                status,got=self.get(0xe0)
                if not status:
                    if got==wanted:return 0
                    self.log('level_mismatch')
        return 0
    def retry(self):
        if self.compat():return -1
        result=-1
        for level in range(3):
            if self.set_level(level) or self.load(self.c['page']):break
            status,value=self.busy()
            if status:break
            if value&self.p['ecc_mask']!=self.p['ecc_bad']:self.log('retry_valid');result=0;break
        if self.set_level(0):self.log('restore_failed')
        if result:self.log('retry_invalid')
        return result
    def check(self):
        if self.compat():return -1
        self.packet(0x66,0,0,True,0);self.actions.append('delay:1000')
        self.packet(0x99,0,0,True,0);self.actions.append('delay:5000')
        status,value=self.get(0xe0)
        if not status:
            self.log('level_register')
            if not value&7:return 0
            self.log('check_level')
        else:self.log('feature_error')
        if not self.set_level(0):return 0
        self.log('check_failed');return -1
    def unique(self):
        p=self.p
        if not p['uid_flag']:return
        def error(code):self.actions.append('log:uid_error:'+str(code))
        if p['uid_size']>128:error(-1);return
        if p['uid_mode']!=1:return
        for reg,value in p['sequence']:
            status=self.set(reg,value)
            if status:self.actions.append('log:uid_feature_error:-5');error(-5);return
            status,got=self.get(reg)
            if status or got!=value:self.actions.append('log:uid_feature_error:'+str(-6 if status else -7));error(-5);return
        if self.load(p['uid_page']):error(-52);return
        status,value=self.busy()
        if status:error(-100);return
        if value&p['ecc_mask']==p['ecc_bad']:error(-101);return
        self.uid_length=0;column=0;text=''
        if p['uid_size']==32:
            for i in range(p['uid_copies']):
                self.uid[:32]=bytes(32);self.caches+=1
                if self.caches==self.c['cache_error_at']:self.actions.append(f'inject_cache:{column}:32:-9');error(-53);return
                self.packet(3,column,32,False,2,dummy=1);self.uid[:32]=uid_bytes(i,i==self.c['first_good'])
                if all(a^b==255 for a,b in zip(self.uid[:16],self.uid[16:32])):
                    self.uid_length=16
                    for value in self.uid[:16]:self.actions.append('format:'+str(value));text+=f'{value:02X}'
                    break
                column+=32
            else:
                if p['uid_copies']:error(-200);return
        self.actions.append(f'log:uid_ok:{column}:{text}')
    def run(self):
        stopped=None;result=None
        try:
            mode=self.c['mode']
            if mode=='compat':result=self.compat()
            elif mode=='set_level':result=self.set_level(self.c['level'])
            elif mode=='retry':result=self.retry()
            elif mode=='check':result=self.check()
            elif mode.startswith('uid'):self.unique()
            else:raise ValueError('identity mode')
        except Stop as stop:stopped=stop.info;result=None
        row=dict(returned=None if result is None else result&0xffffffff,stopped=stopped,
            uid_length=self.uid_length,uid_sha256=digest(self.uid),e0=self.registers[0xe0])
        rows=[row]
        if self.c['mode']=='uid_export' and stopped is None:
            out=bytearray(b'\xa5'*129);status=-201
            if self.p['uid_flag']:
                out[0]=self.uid_length;out[1:1+self.uid_length]=self.uid[:self.uid_length]
                self.actions.append('copy_uid:'+str(self.uid_length));status=0
            else:self.log('ioctl_error')
            rows.append(row|dict(returned=status&0xffffffff,export_sha256=digest(out)))
        return dict(actions=self.actions,rows=rows)


def contract(c):
    p=descriptor(c)
    if not 0<=c['chip_index']<11 or not c['statuses'] or len(c['e0_reads'])>32:raise ValueError('bounded identity input')
    if not 0<=p['uid_size']<=129 or not 0<=p['uid_copies']<=16 or len(p['sequence'])>8:raise ValueError('bounded UID descriptor')
    if not 0<=c['level']<=0xffffffff or any(not 0<=v<=255 for v in c['e0_reads']+c['statuses']):raise ValueError('bounded feature bytes')
    if c['mode'].startswith('uid') and not c['present']:raise ValueError('UID dereferences descriptor before null check')
    if c['mode']=='uid_export' and not 0<=c['initial_uid_length']<=128:raise ValueError('bounded prior UID length')
    return Model(c).run()


def native_vectors():
    cases=[]
    def add(name,mode='retry',**changes):
        c=dict(name=name,mode=mode,chip_index=3,present=True,overrides={},page=600,level=1,e0=0,
            e0_reads=[],statuses=[0],apply_writes=True,get_errors=[],set_errors=[],load_error_at=0,cache_error_at=0,
            bus_error_at=0,first_good=0,uid_mismatch=False,initial_uid_length=165)|changes
        c['descriptor']=descriptor(c);c['expected']=contract(c);cases.append(c)
    for i in range(11):add('compat_candidate_'+str(i),'compat',chip_index=i)
    add('compat_absent','compat',present=False)
    add('compat_02_name','compat',overrides=dict(name='Winbond W25N02LWZEIG'))
    add('compat_suffix','compat',overrides=dict(name='Winbond W25N04LWZEIG-extra'))
    add('level_already_set','set_level',e0=0xa1)
    add('level_write_verify','set_level',e0=0xa0)
    add('level_mismatch_exhausted','set_level',apply_writes=False)
    add('level_write_errors_exhausted','set_level',set_errors=[1,2,3,4,5])
    add('level_verify_errors_exhausted','set_level',get_errors=[2,3,4,5,6])
    add('level_initial_read_error','set_level',get_errors=[1])
    add('level_second_attempt','set_level',e0_reads=[0,0,1])
    for level in (0,2,3,4,8,256,0xffffffff):add('level_'+str(level),'set_level',level=level,e0=0xa0)
    add('retry_first_level');add('retry_second_level',statuses=[0x20,0]);add('retry_third_level',statuses=[0x20,0x20,0])
    add('retry_all_bad',statuses=[0x20]);add('retry_unsupported',chip_index=0);add('retry_absent',present=False)
    add('retry_set_initial_error',get_errors=[1]);add('retry_load_error',load_error_at=1)
    add('retry_busy_feature_error',get_errors=[2]);add('retry_restore_error',get_errors=[3])
    add('retry_unconfirmed_level',e0=1,apply_writes=False)
    add('retry_busy_timeout',statuses=[1])
    add('check_level_zero','check');add('check_level_nonzero','check',e0=2)
    add('check_initial_get_error','check',get_errors=[1]);add('check_fallback_get_error','check',get_errors=[1,2])
    add('check_unconfirmed_level','check',e0=2,apply_writes=False);add('check_unsupported','check',chip_index=0)
    add('check_enable_bus_error','check',bus_error_at=1);add('check_reset_bus_error','check',bus_error_at=2)
    for i in range(11):add('uid_candidate_'+str(i),'uid',chip_index=i)
    add('uid_second_copy','uid',first_good=1);add('uid_last_copy','uid',first_good=15);add('uid_no_valid_copy','uid',first_good=-1)
    add('uid_feature_write_error','uid',set_errors=[1],initial_uid_length=16)
    add('uid_feature_read_error','uid',get_errors=[1],initial_uid_length=16)
    add('uid_feature_mismatch','uid',uid_mismatch=True,initial_uid_length=16)
    add('uid_load_error','uid',load_error_at=1);add('uid_busy_feature_error','uid',get_errors=[2])
    add('uid_ecc_error','uid',statuses=[0x20]);add('uid_cache_error','uid',cache_error_at=1)
    add('uid_get_bus_error','uid',bus_error_at=2);add('uid_cache_bus_error','uid',bus_error_at=5)
    add('uid_busy_timeout','uid',statuses=[1])
    for size in (0,64,128,129):add('uid_size_'+str(size),'uid',overrides=dict(uid_size=size))
    add('uid_mode_zero','uid',overrides=dict(uid_mode=0))
    add('uid_zero_copies','uid',overrides=dict(uid_copies=0))
    add('uid_two_features','uid',overrides=dict(sequence=[[0xb0,0x48],[0xa0,0x80]]))
    add('uid_export_valid','uid_export',initial_uid_length=16)
    add('uid_export_feature_error','uid_export',get_errors=[1],initial_uid_length=16)
    add('uid_export_invalid_copies','uid_export',first_good=-1,initial_uid_length=16)
    add('uid_export_unsupported','uid_export',chip_index=4,initial_uid_length=16)
    add('uid_export_cache_error','uid_export',cache_error_at=1,initial_uid_length=16)
    add('uid_export_non32','uid_export',overrides=dict(uid_size=64),initial_uid_length=16)
    add('uid_export_busy_timeout','uid_export',statuses=[1],initial_uid_length=16)
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=image_memory(archive)
    if json.loads(INVENTORY.read_bytes())!=inventory(memory):raise ValueError('inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=500000:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=BOOT_HASH,inventory_sha256=digest(INVENTORY.read_bytes()),vectors_sha256=digest(vectors.read_bytes()),validation_sha256=digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual compatibility/level/retry/reset-check/UID policy, selected command builders, busy loop and UID ioctl execute with supplied bus packets, copy/format/compare and delays.',
            'Descriptor inventory is original image evidence; response bytes, feature persistence, timeouts and explicit helper-entry errors are authored fixtures.',
            'UID has no returned-status claim; normal return stack/saved registers are checked. Assertion cases stop before the assertion body.',
            'Physical UID uniqueness/provenance, real ECC recovery, lower QSPI/HAL and persistence/standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('inventory-output','vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not a.archive:p.error('need archive')
        with zipfile.ZipFile(a.archive) as z:
            if a.inventory_output:a.inventory_output.write_text(json.dumps(inventory(image_memory(z)),indent=2,sort_keys=True)+'\n');return
            if not all((a.decompiled,a.vectors,a.validation)):p.error('need decompiled/vectors/validation')
            r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND identity/retry: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
