#!/usr/bin/env python3
"""Original NAND retry and UID through platform, bus, QSPI FIFO and DMA."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_maintenance_stack as maintenance
    from . import nand_identity as identity
else:
    import nand_maintenance_stack as maintenance
    import nand_identity as identity

read=maintenance.read
qspi=maintenance.qspi
EXTRA_RANGES=((0x80c29d94,218),(0x80c29f5c,234),(0x80c28422,656),
    (0x80c2825a,94),(0x80c282b8,94),(0x80c292ee,394),(0x80c0184a,4))
RANGES=maintenance.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
UID=0x80df4370


class Model(maintenance.Model):
    def __init__(self,c):
        super().__init__(c);self.p=c['identity_descriptor'];self.feature_regs={224:c['e0']}
        self.e0_reads=0;self.status_reads=0;self.cache_rx=0;self.uid=bytearray(b'\xa5'*128);self.uid_length=c['initial_uid_length']
    def read(self,offset,size=4):
        if offset!=256:return super().read(offset,size)
        op=self.regs[12]>>24
        if op==15:
            if size!=1:raise ValueError('feature width')
            reg=self.regs[0];self.feature_reads+=1
            if reg==192:
                values=self.c['responses'];value=values[min(self.status_reads,len(values)-1)];self.status_reads+=1
            elif reg==224:
                values=self.c['e0_reads'];i=self.e0_reads;self.e0_reads+=1
                value=values[i] if i<len(values) else self.feature_regs[reg]
            else:value=self.feature_regs.get(reg,0)^int(self.c['uid_mismatch'])
        elif op==3:
            index=self.regs[0]//32;payload=identity.uid_bytes(index,index==self.c['first_good'])
            value=int.from_bytes(payload[self.cache_rx:self.cache_rx+size],'little');self.cache_rx+=size
        else:return super().read(offset,size)
        self.rx+=size;self.actions.append(f'r:{offset}:{size}:{value}');return value
    def write(self,offset,value,size=4):
        if offset==12 and value>>24==3:self.cache_rx=0
        if offset==256 and self.regs[12]>>24==31:
            reg=self.regs[0]
            if reg!=224 or self.c['apply_writes']:self.feature_regs[reg]=value&255
        return super().write(offset,value,size)
    def get(self,reg):return self.bus(15,reg,1,1,write=False,status=True)
    def set(self,reg,value):
        saved=self.buffer;self.buffer=bytearray(512);self.buffer[0]=value&255
        result=self.bus(31,reg,1,1)[0];self.buffer=saved;return result
    def compat(self):
        if not self.c['chip']:return False
        left=self.p['name'].encode().ljust(20,b'\0')[:20]
        for name in ('Winbond W25N02LWZEIG','Winbond W25N04LWZEIG'):
            right=name.encode().ljust(20,b'\0')[:20];value=(left>right)-(left<right)
            self.actions.append('compare20:'+str(value))
            if not value:return True
        return False
    def level(self,level):
        if level==3:return -1
        failed,value=self.get(224)
        if failed:return None
        if value&7!=level:
            wanted=(value&248)|(level&255)
            for _ in range(5):
                if self.set(224,wanted):return None
                failed,got=self.get(224)
                if failed:return None
                if got==wanted:return 0
                self.actions.append('log:level_mismatch')
        return 0
    def retry(self,page):
        if not self.compat():return -1
        result=-1
        for level in range(3):
            if self.level(level) is None or self.bus(19,page,3)[0]:return None
            status=self.poll(2000)
            if status is None:return None
            if status&self.p['ecc_mask']!=self.p['ecc_bad']:
                self.actions.append('log:retry_valid');result=0;break
        if self.level(0) is None:return None
        if result:self.actions.append('log:retry_invalid')
        return result
    def check(self):
        if not self.compat():return -1
        if self.bus(0x66)[0]:return None
        self.actions.append('delay:1000')
        if self.bus(0x99)[0]:return None
        self.actions.append('delay:5000');failed,value=self.get(224)
        if failed:return None
        self.actions.append('log:level_register')
        if not value&7:return 0
        self.actions.append('log:check_level');return self.level(0)
    def unique(self):
        p=self.p
        if not p['uid_flag'] or p['uid_mode']!=1 and p['uid_size']<=128:return
        if p['uid_size']>128:self.actions.append('log:uid_error:-1');return
        for reg,value in p['sequence']:
            if self.set(reg,value):return
            failed,got=self.get(reg)
            if failed:return
            if got!=value:self.actions.extend(('log:uid_feature_error:-7','log:uid_error:-5'));return
        if self.bus(19,p['uid_page'],3)[0]:return
        status=self.poll(2000)
        if status is None:return
        if status&p['ecc_mask']==p['ecc_bad']:self.actions.append('log:uid_error:-101');return
        self.uid_length=0;column=0;text=''
        if p['uid_size']==32:
            for _ in range(p['uid_copies']):
                self.uid[:32]=bytes(32);self.actions.append('zero_uid:32')
                saved=self.buffer;self.buffer=bytearray(self.uid)+bytearray(384)
                failed,_=self.bus(3,column,2,32,8,1,False)
                self.uid[:]=self.buffer[:128];self.buffer=saved
                if failed:return
                if all(a^b==255 for a,b in zip(self.uid[:16],self.uid[16:32])):
                    self.uid_length=16
                    for value in self.uid[:16]:self.actions.append('format:'+str(value));text+=f'{value:02X}'
                    break
                column+=32
            else:
                if p['uid_copies']:self.actions.append('log:uid_error:-200');return
        self.actions.append(f'log:uid_ok:{column}:{text}')
    def read_page(self):
        c=self.c
        if not c['chip']:return -2
        page=self.map(c['page'])
        if page is None:return -150
        if self.bus(19,page,3)[0]:return None
        status=self.poll(2000)
        if status is None:return None
        ecc=(status&self.p['ecc_mask'])==self.p['ecc_bad']
        if ecc:
            result=self.retry(page)
            if self.stopped:return None
            if result==0:ecc=False;self.actions.append('log:workaround_ok')
        address=c['column']|(4096 if c['plane'] and page&64 else 0)
        if self.bus(0x6b,address,2,c['count'],8,3,False,not c['blocking'] and c['count']>31)[0]:return None
        if ecc:self.actions.append('log:page_result');return -101
        return 0
    def run(self):
        c=self.c;mode=c['mode'].removeprefix('platform_')
        if not c['defer_reinit']:self.initialize();self.initialized=True
        if mode=='identity_compat':value=0 if self.compat() else -1
        elif mode=='identity_level':value=self.level(c['level'])
        elif mode=='identity_retry':value=self.retry(c['page'])
        elif mode=='identity_check':value=self.check()
        elif mode=='page_read':value=self.read_page()
        else:
            self.unique();value=None
            if mode=='identity_uid_export' and not self.stopped:
                value=-201
                if self.p['uid_flag']:
                    self.buffer[0]=self.uid_length;self.buffer[1:1+self.uid_length]=self.uid[:self.uid_length]
                    self.actions.append('copy_uid:'+str(self.uid_length));value=0
                else:self.actions.append('log:ioctl_error')
        result=self.snapshot(None if self.stopped or value is None else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=int(c['defer_reinit'] and not self.initialized),feature_reads=self.feature_reads,
            status_reads=self.status_reads,e0_reads=self.e0_reads,feature_registers={str(k):v for k,v in sorted(self.feature_regs.items())},
            uid_length=self.uid_length,uid_sha256=qspi.digest(self.uid))
        return result


def descriptor(c):
    return identity.facts()[c['chip_index']]|c['uid_overrides']


def contract(c):
    modes=('identity_compat','identity_level','identity_retry','identity_check','identity_uid','identity_uid_export','page_read')
    if not c['mode'].startswith('platform_') or c['mode'].removeprefix('platform_') not in modes or not all(c[k] for k in ('native_identity','native_page','native_platform','full_platform','native_dma')):raise ValueError('identity entry')
    if not 0<=c['chip_index']<11 or c['identity_descriptor']!=descriptor(c):raise ValueError('original descriptor variant')
    p=c['identity_descriptor']
    if set(c['uid_overrides'])-{'uid_flag','uid_mode','uid_copies','uid_size'}:raise ValueError('UID overrides')
    if not 0<=p['uid_size']<=129 or not 0<=p['uid_copies']<=16 or not 0<=c['initial_uid_length']<=128:raise ValueError('UID backing')
    if not all(0<=p[k]<=255 for k in ('uid_flag','uid_mode')) or not -1<=c['first_good']<=15:raise ValueError('UID byte fields')
    state=bytes.fromhex(c['bbt_hex'])
    if len(state)!=164 or struct.unpack_from('<I',state,4)[0]>64 or struct.unpack_from('<I',state,148)[0]!=64:raise ValueError('bounded BBT')
    if not c['chip'] and 'uid' in c['mode']:raise ValueError('UID null precheck dereference')
    if not 0<=c['level']<=0xffffffff or c['page']!=600 or c['column']!=16 or c['count']!=64 or c['alignment']:raise ValueError('bounded identity root')
    if not c['responses'] or len(c['responses'])>2000 or len(c['e0_reads'])>64 or any(not 0<=v<=255 for v in c['responses']+c['e0_reads']+[c['e0']]):raise ValueError('feature bytes')
    return Model(c).run()


def native_vectors():
    base=maintenance.program.native_vectors()['cases'][0];cases=[]
    def add(name,mode='identity_retry',**changes):
        c=base|dict(name=name,mode='platform_'+mode,native_identity=True,chip_index=3,uid_overrides={},level=1,e0=0,
            e0_reads=[],apply_writes=True,uid_mismatch=False,initial_uid_length=16,first_good=0)|changes
        c['identity_descriptor']=descriptor(c);c['expected']=contract(c);cases.append(c)
    for i in range(11):add('compat_original_'+str(i),'identity_compat',chip_index=i)
    add('compat_absent','identity_compat',chip=False)
    add('level_already_set','identity_level',e0=0xa1);add('level_write_verify','identity_level',e0=0xa0)
    add('level_unconfirmed','identity_level',apply_writes=False)
    add('level_second_attempt','identity_level',e0_reads=[0,0,1])
    for level in (2,3,4,8,256,0xffffffff):add('level_'+str(level),'identity_level',level=level,e0=0xa0)
    add('retry_first');add('retry_second',responses=[0x20,0]);add('retry_third',responses=[0x20,0x20,0])
    add('retry_all_bad',responses=[0x20]);add('retry_unsupported',chip_index=0)
    add('retry_unconfirmed_level',e0=1,apply_writes=False);add('retry_busy_timeout',responses=[1])
    add('check_zero','identity_check');add('check_nonzero','identity_check',e0=2)
    add('check_unconfirmed','identity_check',e0=2,apply_writes=False)
    add('read_retry_success','page_read',responses=[0x20,0])
    add('read_retry_private','page_read',responses=[0x20,0],blocking=False)
    add('read_retry_all_bad','page_read',responses=[0x20]);add('read_retry_last_level','page_read',responses=[0x20,0x20,0x20,0])
    for i in range(11):add('uid_original_'+str(i),'identity_uid',chip_index=i)
    add('uid_second','identity_uid',first_good=1);add('uid_last','identity_uid',first_good=15)
    add('uid_invalid','identity_uid',first_good=-1);add('uid_mismatch','identity_uid',uid_mismatch=True)
    add('uid_ecc_bad','identity_uid',responses=[0x20]);add('uid_busy_timeout','identity_uid',responses=[1])
    add('uid_size_overflow','identity_uid',uid_overrides=dict(uid_size=129))
    add('uid_size_other','identity_uid',uid_overrides=dict(uid_size=16))
    add('uid_zero_copies','identity_uid',uid_overrides=dict(uid_copies=0))
    add('uid_export','identity_uid_export');add('uid_export_stale','identity_uid_export',uid_mismatch=True)
    add('uid_export_disabled','identity_uid_export',chip_index=4)
    add('uid_export_invalid','identity_uid_export',first_good=-1)
    add('uid_mode_other','identity_uid',uid_overrides=dict(uid_mode=0))
    add('retry_get_assertion',ready=[0],ticks=[0,1001])
    add('uid_feature_assertion','identity_uid',ready=[0],ticks=[0,1001])
    add('uid_verify_assertion','identity_uid',ready=[3,0],ticks=[0,0,0,1001])
    add('uid_load_assertion','identity_uid',done=[1,1,0],ticks=[0,0,0,0,0,1001])
    add('uid_cache_assertion','identity_uid',ready=[3,3,3,0],ticks=[0]*8+[1001])
    add('retry_restore_assertion',ready=[3,3,0],ticks=[0]*6+[1001])
    return dict(schema=1,bound_per_case=read.BOUND,cases=cases)


def data_ranges(memory):
    ranges=list(read.DATA_RANGES)+[(0x80c3da18,5)]
    for p in identity.inventory(memory)['chips']:
        ranges.extend(((p['address'],184),(p['name_pointer'],20),(p['sequence_pointer'],len(p['sequence'])*2)))
    return tuple(dict.fromkeys(ranges))


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if json.loads(identity.INVENTORY.read_bytes())!=identity.inventory(memory):raise ValueError('identity inventory differs')
    if json.loads(read.platform.PIN_FACTS.read_bytes())!=read.platform.pin_facts(memory):raise ValueError('pin records differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['bound_per_case']!=read.BOUND or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in data_ranges(memory)},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual supported-family retry/setter/reset check, connected page-read recovery, UID acquisition and selected UID ioctl execute through original bus/QSPI/FIFO; private read also connects DMA.',
            'Original candidate descriptors and explicit UID variants are fixtures; feature-register behavior, status/UID FIFO, peripherals, timestamps and leaf delay/cache/copy/zero/format/compare services are authored.',
            'BBT and adjacent UID backing use combined external guards; no physical ECC correction, UID provenance, page cache or DMA payload movement is established.',
            'Higher storage, physical chip/board/coherency/persistence, backup/restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect NAND identity stack: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
