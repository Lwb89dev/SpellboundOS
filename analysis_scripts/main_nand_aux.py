#!/usr/bin/env python3
"""Actual main NAND workaround and UID acquisition inside the platform/FIFO probe."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_nand_full_probe as joined
    from . import nand_identity as policy
else:
    import main_nand_full_probe as joined
    import nand_identity as policy

base=joined.base
FACTS=Path(__file__).resolve().parents[1]/'analysis/main-nand-identity.json'
UID=0x70f9bc50
UID_LENGTH=0x70f8e6f4
EXTRA=((0x702d7ee6,80),(0x702d7f36,218),(0x702d80fe,242),(0x702d6524,668),(0x702d6470,180),
    (0x702d5f42,106),(0x702d5edc,102),(0x702d6354,98),(0x702d63b6,98),(0x7029681c,20),(0x701648f8,8))


def facts():return json.loads(FACTS.read_bytes())['chips']
def inventory(memory):
    chips=[]
    for chip in joined.probe.facts()['chips']:
        address=chip['address'];b=memory.read(address,184);word=lambda off:struct.unpack_from('<I',b,off)[0];p=word(0xa8)
        chips.append(dict(address=address,sha256=base.digest(b),name=memory.string(word(0x38)),name_pointer=word(0x38),
            uid_flag=b[0xa6],uid_mode=b[0xad],uid_copies=b[0xae],uid_page=word(0xb0),uid_size=word(0xb4),
            sequence_pointer=p,sequence=[list(memory.read(p+i*2,2)) for i in range(b[0xac])],ecc_mask=b[0x8e],ecc_bad=b[0x8f]))
    return dict(main_sha256=base.MAIN_HASH,hardware_execution=False,chips=chips)
def ranges():return tuple(dict.fromkeys(joined.ranges()+EXTRA))
def data_ranges():
    return tuple(dict.fromkeys(joined.data_ranges()+tuple((p['sequence_pointer'],2*len(p['sequence'])) for p in facts())+
        tuple((p['name_pointer'],len(p['name'])+1) for p in facts())+((0x70a323a0,20),(0x70a317c4,20),(0x709d7540,5))))


class Engine(joined.Engine):
    def __init__(self,c,features):super().__init__(c,features);self.features[224]=c['e0']
    def read(self,at,size=4):
        pos=self.payload_at;value=super().read(at,size)
        if at==256 and self.opcode==3:self.uid_target[pos:pos+size]=value.to_bytes(size,'little')
        if at==256 and self.opcode==15:
            if self.reg==224:self.owner.e0_reads+=1
            elif self.reg==192:self.owner.c0_reads+=1
        return value
    def write(self,at,value,size=4):
        prior=self.features.get(224,0);super().write(at,value,size)
        if at==256 and self.opcode==31 and self.reg==224 and not self.full['apply_writes']:self.features[224]=prior


class Model(joined.Model):
    engine_type=Engine
    def __init__(self,c):
        super().__init__(c);self.engine.owner=self;self.uid=bytearray(b'\xa5'*128);self.engine.uid_target=self.uid;self.uid_length=c['initial_uid_length'];self.workaround_result=None
        self.in_uid=False;self.uid_entered=False;self.uid_completed=False;self.caches=0;self.loads=0;self.e0_reads=0;self.c0_reads=0
    def descriptor(self):return next(p for p in facts() if p['address']==self.selected)
    def log(self,tag):self.actions.append('log:'+tag)
    def compat(self):
        name=self.descriptor()['name'].encode()+b'\0'
        for i,wanted in enumerate(('Winbond W25N02LWZEIG','Winbond W25N04LWZEIG')):
            value=0
            for x,y in zip(name,(wanted.encode()+b'\0')):
                value=x-y
                if value or not x:break
            self.actions.append(f'aux_compare:{i}:{value}')
            if not value:return 0
        return -1
    def packet(self,opcode,address,size,write,local,**kw):
        if not isinstance(local,int):return super().packet(opcode,address,size,write,local)
        # The shared UID/check policy supplies address-byte count as its fifth argument.
        if opcode==3:
            payload=bytearray(policy.uid_bytes(address//32,address//32==self.c['first_good']))
        else:payload=bytearray()
        return self.transfer_packet(opcode,address,size,write,payload,local,kw.get('dummy',0))
    def get(self,reg):
        if reg==224:
            i=self.e0_reads;value=self.c['e0_reads'][i] if i<len(self.c['e0_reads']) else self.features[224]
        elif reg==192:
            i=self.c0_reads;value=self.c['statuses'][min(i,len(self.c['statuses'])-1)]
        else:value=self.features.get(reg,0)^int(self.in_uid and self.c['uid_mismatch'])
        self.transfer_packet(15,reg,1,False,bytearray((value,)),1,0);return 0,value
    def set(self,reg,value):self.transfer_packet(31,reg,1,True,bytearray((value&255,)),1,0);return 0
    def load(self,page):self.loads+=1;self.transfer_packet(19,page,0,True,bytearray(),3,0);return 0
    def busy(self):return policy.Model.busy(self)
    def set_level(self,level):return policy.Model.set_level(self,level)
    def run_workaround(self):
        self.actions.append('probe_workaround_native');status=policy.Model.check(self);self.workaround_result=status&0xffffffff
        self.actions.append(f'aux_workaround_return:{status}')
    def run_uid(self):
        if not self.c['native_main_uid']:return super().run_uid()
        self.actions.append('probe_uid_native');self.uid_entered=True;self.in_uid=True;self.p=self.descriptor()
        try:policy.Model.unique(self);self.uid_completed=True
        finally:self.in_uid=False
    def run(self):
        result=super().run()
        for row in result['rows']:row.update(aux_uid_length=self.uid_length,aux_uid_sha256=base.digest(self.uid),aux_workaround_return=self.workaround_result,
            aux_uid_entered=self.uid_entered,aux_uid_completed=self.uid_completed,aux_uid_caches=self.caches,aux_status_reads=self.c0_reads,aux_e0_reads=self.e0_reads)
        return result


def contract(c,scope):
    if scope not in ('workaround','uid') or not c['native_main_aux'] or c['native_main_uid']!=(scope=='uid'):raise ValueError('main auxiliary entry')
    if c['probe_delayed_rounds'] or c['probe_feature_mismatch_at'] or c['bus_disabled']:raise ValueError('auxiliary fixture phase')
    if c['cache_error_at']:raise ValueError('supplied cache-helper results outside native scope')
    if not 0<=c['initial_uid_length']<=128 or not -1<=c['first_good']<16:raise ValueError('UID backing')
    if not c['statuses'] or len(c['statuses'])>16 or c['statuses'][-1]&1 or len(c['e0_reads'])>16 or any(not 0<=v<=255 for v in c['statuses']+c['e0_reads']+[c['e0']]):raise ValueError('auxiliary register inputs')
    joined.contract(c)
    return Model(c).run()


def native_vectors(scope='workaround'):
    cases=[];initial=joined.native_vectors()['cases'][0];chips=joined.probe.facts()['chips']
    def add(name,index=0,**changes):
        c=initial|dict(name='main_aux_'+name,native_main_aux=True,native_main_uid=scope=='uid',probe_id=chips[index]['id'],
            e0=0,e0_reads=[],apply_writes=True,statuses=[0],first_good=0,uid_mismatch=False,initial_uid_length=17,cache_error_at=0)|changes
        c.pop('expected',None);c['expected']=contract(c,scope);cases.append(c)
    if scope=='workaround':
        add('unsupported');add('supported_zero',3);add('supported_level_reset',3,e0=2)
        add('supported_unconfirmed',3,e0=2,apply_writes=False);add('supported_second_write',3,e0=2,e0_reads=[2,2,2,0])
        add('reset_enable_timeout',3,full_done_fail_at=6);add('power_reset_timeout',3,full_done_fail_at=7)
        add('level_read_timeout',3,full_ready_fail_at=8)
    elif scope=='uid':
        add('first_copy');add('second_copy',first_good=1);add('last_copy',first_good=15);add('no_valid_copy',first_good=-1)
        add('feature_mismatch',uid_mismatch=True);add('ecc_reject',statuses=[32]);add('busy_second_read',statuses=[1,0])
        add('cache_timeout',full_ready_fail_at=7);add('feature_read_timeout',full_ready_fail_at=4)
        add('cache_done_timeout',full_done_fail_at=7)
        add('supported_family',3,e0=2);add('uid_not_requested',4)
        add('dosilicon_uid',5);add('esmt_uid',10)
    else:raise ValueError('auxiliary scope')
    return dict(schema=1,scope='nand',bound_per_case=joined.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if inventory(mem)!=json.loads(FACTS.read_bytes()):raise ValueError('original UID inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=joined.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=joined.BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,inventory_sha256=base.digest(FACTS.read_bytes()),vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main workaround/reset/level and optional UID feature/load/busy/cache/complement checks execute inside the original probe/platform/FIFO/root chain, with unchanged descriptors.',
            'FIFO IDs/UID/status/E0, timers, power/pin/BSP/RTOS/heap/PM and bounded library behavior are authored. BBT remains supplied; UID bytes do not establish a physical device identity.',
            'Main BBT/page/media integration, IRQ/cache/coherency, elapsed timing, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('workaround','uid'),default='workaround')
    for key in ('inventory-output','vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.inventory_output:
            if not a.archive:p.error('need archive for inventory')
            with zipfile.ZipFile(a.archive) as z:r=inventory(base.image_memory(z))
            a.inventory_output.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');return
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main auxiliary paths: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
