#!/usr/bin/env python3
"""Original NAND candidate probe through platform, command builders and QSPI FIFO."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import nand_read_stack as lower
    from . import nand_probe as inventory
else:
    import nand_read_stack as lower
    import nand_probe as inventory

qspi=lower.qspi
EXTRA_RANGES=((0x80c2874a,788),(0x80c27aac,70),(0x80c28318,86),(0x80c2819e,94),(0x80c281fc,94))
RANGES=lower.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
BUS_WORDS=(104,104,104,104,104,83,104,83,83,83,83)
CHIPS=inventory.facts()['chips']
DATA_RANGES=tuple(dict.fromkeys(lower.DATA_RANGES+((inventory.TABLE,44),)+
    tuple((c['address'],184) for c in CHIPS)+tuple((c['feature_pointer'],len(c['features'])*2) for c in CHIPS)))


class Model(lower.Model):
    def __init__(self,c):
        super().__init__(dict(c));self.features={};self.id_reads=0;self.id_at=0;self.bus_calls=0
        self.selected=0;self.guard_pages=0;self.guard_blocks=0
        self.mutex=inventory.MUTEX if c['probe_mutex_present'] else 0
        self.regulator=inventory.REGULATOR if c['probe_regulator_present'] else 0
    def write(self,offset,value,size=4):
        if offset==12 and value>>24==0x9f:self.id_reads+=1;self.id_at=0
        if offset==256 and self.regs[12]>>24==0x1f:
            if size!=1:raise ValueError('feature byte width')
            self.features[self.regs[0]]=value
        return super().write(offset,value,size)
    def read(self,offset,size=4):
        if offset!=256:return super().read(offset,size)
        op=self.regs[12]>>24
        if op==0x9f:
            data=bytes([255]*5 if self.id_reads<=self.c['probe_delayed_rounds']*11 else self.c['probe_id'])
            if self.id_at+size>5:raise ValueError('probe ID FIFO bound')
            value=int.from_bytes(data[self.id_at:self.id_at+size],'little');self.id_at+=size
        elif op==0x0f:
            if size!=1:raise ValueError('probe feature FIFO width')
            self.feature_reads+=1;value=self.features.get(self.regs[0],0)
            if self.feature_reads==self.c['probe_feature_mismatch_at']:value^=1
        else:raise ValueError('unexpected probe FIFO opcode')
        self.rx+=size;self.actions.append(f'r:{offset}:{size}:{value}');return value
    def transfer(self,op,address=0,address_bytes=0,count=0,write=True,payload=None,*,dummy=0,lines=1):
        self.actions.append('version:2');self.c['frame']=[2 if write else 0,0,op,1,1,address,1,address_bytes,lines,count,dummy]
        result=self.command();stage='command';saved=self.buffer;self.buffer=bytearray(512)
        if payload is not None:self.buffer[:len(payload)]=payload
        if not result and count:
            stage='transmit_poll' if write else 'receive_poll';result=qspi.Model.data(self,not write,False)
        received=bytes(self.buffer[:count]);self.buffer=saved
        if self.stopped:return None
        if result:
            self.actions.extend(('log:'+stage+'_error','diagnostic'))
            self.stopped=dict(kind='assertion',owner=0x80c37b7c,line={'command':0x11f,'receive_poll':0x12a,'transmit_poll':0x132}[stage]);return None
        return received
    def run_workaround(self):self.actions.append('probe_workaround:'+str(self.c['probe_workaround_status']))
    def run_uid(self):self.actions.append('probe_uid:'+str(self.c['probe_uid_status']))
    def run_probe_bbt(self,chip):self.actions.append(f'probe_bbt:{chip["blocks"]}:{chip["page_size"]}:{chip["pages_per_block"]}:{self.c["probe_bbt_status"]}')
    def probe(self):
        c=self.c;self.actions.append('probe_regulator:'+str(int(bool(self.regulator))))
        if self.regulator:self.actions.extend((f'probe_disable:{c["probe_power_status"]}','probe_delay:20',f'probe_enable:{c["probe_power_status"]}','probe_delay:20'))
        else:self.actions.append('log:regulator_missing')
        for _ in range(3):
            for i,chip in enumerate(CHIPS):
                self.bus_calls+=1;self.actions.append('probe_bus:'+str(i));self.c['bus_word']=BUS_WORDS[i];self.initialize()
                data=self.transfer(0x9f,address_bytes=1,count=5,write=False)
                if self.stopped:return None
                if inventory.match(chip['id'],list(data))==0:self.selected=chip['address'];break
            if self.selected:break
        if not self.selected:self.actions.extend(('log:no_chip_match','log:probe_error'));return -4
        chip=next(c for c in CHIPS if c['address']==self.selected)
        self.transfer(0xff)
        if self.stopped:return None
        self.actions.append(f'probe_delay:{chip["reset_delay_us"]//1000+1}');self.run_workaround()
        if self.stopped:return None
        self.actions.append('log:chip_summary')
        if chip['uid']:self.run_uid()
        if self.stopped:return None
        for reg,value in chip['features']:
            self.transfer(0x1f,reg,1,1,True,bytes([value]))
            if self.stopped:return None
            got=self.transfer(0x0f,reg,1,1,False)
            if self.stopped:return None
            if got[0]!=value:self.actions.extend(('log:feature_mismatch','log:probe_error'));return -7
        self.run_probe_bbt(chip)
        if self.stopped:return None
        self.guard_pages=0x100000//chip['page_size'];self.guard_blocks=self.guard_pages//chip['pages_per_block']
        self.actions.append('log:boot_guard');return 0
    def run_probe_entry(self):
        value=self.probe()
        if not self.stopped and value==0 and self.c['probe_entry']=='wrapper' and not self.mutex:
            ok=not self.c['probe_mutex_fail'];self.actions.append('probe_mutex_create:'+str(int(ok)))
            if ok:self.mutex=inventory.MUTEX
            else:self.stopped=dict(kind='assertion',owner=0x80c3d434,line=0x1e)
        return value
    def run(self):
        self.initialize();self.initialized=True;value=self.run_probe_entry()
        result=self.snapshot(None if self.stopped else value&0xffffffff);row=result['rows'][0]
        row.update(rx_bytes=self.rx,tx_hex=self.tx.hex(),board_mmio={str(k):v for k,v in sorted(self.pins.regs.items())},
            reinit_flag=0,feature_reads=self.feature_reads,probe_selected=self.selected,probe_mutex=self.mutex,
            probe_regulator=self.regulator,probe_guard_pages=self.guard_pages,probe_guard_blocks=self.guard_blocks,
            probe_bus_calls=self.bus_calls,probe_id_reads=self.id_reads,probe_features={str(k):v for k,v in sorted(self.features.items())})
        return result


def contract(c):
    if c['mode']!='platform_probe' or not c['native_probe'] or c['probe_entry'] not in ('probe','wrapper') or c['defer_reinit']:raise ValueError('probe entry')
    if len(c['probe_id'])!=5 or any(not 0<=v<=255 for v in c['probe_id']) or not 0<=c['probe_delayed_rounds']<=2:raise ValueError('probe ID backing')
    if not 0<=c['probe_feature_mismatch_at']<=3 or any(not -100<=c[k]<=100 for k in ('probe_power_status','probe_workaround_status','probe_uid_status','probe_bbt_status')):raise ValueError('probe service bounds')
    lower.contract(c|dict(native_probe=False,mode='platform_page_read',count=0))
    return Model(c).run()


def native_vectors():
    base=lower.native_vectors()['cases'][0];cases=[]
    def add(name,**changes):
        c=base|dict(name=name,mode='platform_probe',native_probe=True,probe_entry='probe',probe_id=CHIPS[0]['id'],
            probe_delayed_rounds=0,probe_feature_mismatch_at=0,probe_regulator_present=True,probe_power_status=0,
            probe_workaround_status=0,probe_uid_status=0,probe_bbt_status=0,probe_mutex_present=False,probe_mutex_fail=False)|changes
        c['expected']=contract(c);cases.append(c)
    for i,chip in enumerate(CHIPS):add('fifo_probe_candidate_'+str(i),probe_id=chip['id'])
    add('fifo_probe_no_match',probe_id=[255]*5)
    add('fifo_probe_second_round',probe_delayed_rounds=1)
    add('fifo_probe_third_round',probe_delayed_rounds=2)
    add('fifo_probe_last_allowed_attempt',probe_delayed_rounds=2,probe_id=CHIPS[10]['id'])
    add('fifo_probe_optional_tail',probe_id=[0xef,0xba,0x21,0x12,0x34])
    add('fifo_probe_no_regulator',probe_regulator_present=False)
    add('fifo_probe_power_error_ignored',probe_power_status=-9)
    add('fifo_probe_aux_errors_ignored',probe_workaround_status=-9,probe_uid_status=-9,probe_bbt_status=-9)
    add('fifo_probe_feature_mismatch',probe_feature_mismatch_at=2)
    add('fifo_probe_wrapper',probe_entry='wrapper')
    add('fifo_probe_wrapper_existing',probe_entry='wrapper',probe_mutex_present=True)
    add('fifo_probe_wrapper_mutex_failure',probe_entry='wrapper',probe_mutex_fail=True)
    add('fifo_probe_id_assertion',ready=[0],ticks=[0,1001])
    actions=cases[0]['expected']['actions'];reset=next(i for i,a in enumerate(actions) if a.startswith('w:12:4:') and int(a.split(':')[-1])>>24==0xff)
    before=actions[:reset];done=sum(a.startswith('r:36:4:') for a in before);ticks=sum(a.startswith('tick:') for a in before)
    add('fifo_probe_reset_assertion',done=[1]*done+[0],ticks=[0]*(ticks+1)+[1001])
    feature=next(i for i,a in enumerate(actions) if a.startswith('w:12:4:') and int(a.split(':')[-1])>>24==0x1f)
    before=actions[:feature];ready=sum(a.startswith('r:24:4:') for a in before);ticks=sum(a.startswith('tick:') for a in before)
    add('fifo_probe_feature_assertion',ready=[3]*ready+[0],ticks=[0]*(ticks+1)+[1001])
    return dict(schema=1,bound_per_case=lower.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if inventory.chip_table(memory)!=inventory.facts():raise ValueError('chip inventory differs')
    for chip,word in zip(CHIPS,BUS_WORDS):
        if struct.unpack('<I',memory.read(chip['address']+12,4))[0]!=word:raise ValueError('candidate bus word')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=lower.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=lower.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,chip_table_sha256=qspi.digest(inventory.TABLE_PATH.read_bytes()),vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original eleven-candidate probe/matcher, per-candidate platform/clock/pin/DMA initialization, ID/reset/feature builders and bus/QSPI FIFO execute together.',
            'ID bytes, feature-register effects, board MMIO/timers/power/mutex and auxiliary workaround/UID/BBT results are authored; auxiliary bodies and physical chip identity are not established.',
            'No physical NAND, electrical operation, BBT initialization, object registry, persistent recovery or standalone boot is established by this connected probe pass.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect connected NAND probe: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
