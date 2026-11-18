#!/usr/bin/env python3
"""Original main NAND candidate probe and ID/reset packets, joined to root consumers."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_nand_stack as stack
    from .nand_probe import match
else:
    import main_nand_stack as stack
    from nand_probe import match

base=stack.base
FACTS=Path(__file__).resolve().parents[1]/'analysis/main-nand-chips.json'
TABLE=0x70a31798
BUS=0x80c007c4
REGULATOR=0x70f8e6e8
GUARD_BLOCKS=0x70f8e6ec
GUARD_PAGES=0x70f8e6f0
POWER=0x81272000
EXTRA=((0x702d685c,804),(0x702d6290,98),(0x702d62f2,98),(0x702d641a,86))


def facts():return json.loads(FACTS.read_bytes())
def inventory(mem):
    rows=[]
    for p in struct.unpack('<11I',mem.read(TABLE,44)):
        raw=mem.read(p,184);w=lambda off:struct.unpack_from('<I',raw,off)[0];pointer=w(0x88);count=raw[0x8c]
        if not 1<=count<=8:raise ValueError('main feature count')
        features=mem.read(pointer,count*2)
        rows.append(dict(address=p,name=mem.string(w(0x38)),name_pointer=w(0x38),sha256=base.digest(raw),id=list(raw[44:49]),reset_delay_us=w(8),
            blocks=w(0x48),pages=w(0x54),pages_per_block=w(0x58),page_size=w(0x5c),feature_pointer=pointer,
            features=[list(features[i:i+2]) for i in range(0,len(features),2)],uid=bool(raw[0xa6]),reset_opcode=raw[0x78]))
    return dict(main_sha256=base.MAIN_HASH,table_address=TABLE,table_sha256=base.digest(mem.read(TABLE,44)),chips=rows,hardware_execution=False)


def ranges(scope):
    if scope not in ('probe','root'):raise ValueError('main probe scope')
    return stack.ranges('root' if scope=='root' else 'geometry')+EXTRA
def data_ranges(scope):
    ranges(scope);chips=facts()['chips']
    return tuple(dict.fromkeys(stack.data_ranges('root' if scope=='root' else 'geometry')+((TABLE,44),(BUS,20))+
        tuple((c['address'],184) for c in chips)+tuple((c['feature_pointer'],2*len(c['features'])) for c in chips)))


class Model(stack.Model):
    def __init__(self,c,scope):
        super().__init__(c,'root' if scope=='root' else 'geometry');self.probe_scope=scope;self.table=facts()['chips']
        self.regulator=0;self.guard_pages=0;self.guard_blocks=0;self.bus_calls=0;self.id_reads=0;self.feature_reads=0;self.feature_writes=0;self.features={}
    def stop_probe(self,owner,line):self.stopped=dict(kind='assertion',owner=owner,line=line)
    def probe(self):
        c=self.c;self.actions.append('main_probe_native');self.regulator=POWER if c['probe_regulator_present'] else 0
        self.actions.append(f'probe_regulator:{int(bool(self.regulator))}')
        if self.regulator:self.actions.extend((f'probe_disable:{c["probe_power_status"]}','probe_delay:20',f'probe_enable:{c["probe_power_status"]}','probe_delay:20'))
        else:self.actions.append('log:probe_regulator_missing')
        self.selected=0
        for _ in range(3):
            for i,chip in enumerate(self.table):
                self.bus_calls+=1;status=-9 if self.bus_calls==c['probe_bus_fail_at'] else 0;self.actions.append(f'probe_bus:{i}:{status}')
                if status:self.stop_probe(0x70a31738,99);return None
                self.id_reads+=1;data=[255]*5 if self.id_reads<=11*c['probe_delayed_rounds'] else c['probe_id'];status=-9 if self.id_reads==c['probe_id_fail_at'] else 0
                self.actions.append(f'probe_id:{i}:{bytes(data).hex()}:{status}')
                if status:self.stop_probe(0x70a30fa4,383);return None
                if match(chip['id'],data)==0:self.selected=chip['address'];break
            if self.selected:break
        if not self.selected:self.actions.extend(('log:probe_no_match','log:probe_error'));return -4
        chip=next(p for p in self.table if p['address']==self.selected)
        self.chip=dict(address=chip['address'],id=chip['id'][0]|chip['id'][1]<<8,pages=chip['pages'],page_size=chip['page_size'])
        status=-9 if c['probe_reset_fail'] else 0;self.actions.append(f'probe_reset:{chip["reset_opcode"]}:{status}')
        if status:self.stop_probe(0x70a30f94,402);return None
        self.actions.extend((f'probe_delay:{chip["reset_delay_us"]//1000+1}',f'probe_workaround:{c["probe_workaround_return"]}','log:probe_chip_summary'))
        if chip['uid']:self.actions.append(f'probe_uid:{c["probe_uid_return"]}')
        for reg,value in chip['features']:
            self.feature_writes+=1;status=-9 if self.feature_writes==c['probe_feature_write_fail_at'] else 0
            self.actions.append(f'probe_set:{reg}:{value}:{status}')
            if status:self.actions.extend(('log:probe_feature_write_error','log:probe_error'));return -5
            self.features[reg]=value;self.feature_reads+=1;status=-9 if self.feature_reads==c['probe_feature_read_fail_at'] else 0
            got=value^int(self.feature_reads==c['probe_feature_mismatch_at']);self.actions.append(f'probe_get:{reg}:{got}:{status}')
            if status:self.actions.extend(('log:probe_feature_read_error','log:probe_error'));return -6
            if got!=value:self.actions.extend(('log:probe_feature_mismatch','log:probe_error'));return -7
        self.actions.append(f'probe_bbt:{chip["blocks"]}:{chip["page_size"]}:{chip["pages_per_block"]}:{c["probe_bbt_return"]}')
        self.guard_pages=0x100000//chip['page_size'];self.guard_blocks=self.guard_pages//chip['pages_per_block'];self.actions.append('log:probe_guard');return 0
    def operation(self,op):
        if op['op']=='probe':return self.probe()
        return super().operation(op)
    def run(self):
        result=super().run()
        for row in result['rows']:row.update(probe_regulator=self.regulator,probe_guard_pages=self.guard_pages,probe_guard_blocks=self.guard_blocks,
            probe_bus_calls=self.bus_calls,probe_id_reads=self.id_reads,probe_features={str(k):v for k,v in sorted(self.features.items())})
        return result


def contract(c,scope):
    ranges(scope)
    if not c['native_main_probe'] or c['native_main_root']!=(scope=='root'):raise ValueError('probe entry')
    if len(c['probe_id'])!=5 or any(not 0<=v<=255 for v in c['probe_id']) or not 0<=c['probe_delayed_rounds']<=2:raise ValueError('probe ID backing')
    if not 0<=c['probe_bus_fail_at']<=33 or not 0<=c['probe_id_fail_at']<=33:raise ValueError('probe call bounds')
    if any(not 0<=c[k]<=3 for k in ('probe_feature_write_fail_at','probe_feature_read_fail_at','probe_feature_mismatch_at')):raise ValueError('feature bounds')
    if any(not -100<=c[k]<=100 for k in ('probe_power_status','probe_workaround_return','probe_uid_return','probe_bbt_return')):raise ValueError('service results')
    ops=c['operations']
    if scope=='probe' and (len(ops)!=1 or ops[0]['op']!='probe'):raise ValueError('direct probe scope')
    common=c|dict(native_main_probe=False)
    if scope=='probe':common=common|dict(operations=[ops[0]|dict(op='active')])
    stack.contract(common,'root' if scope=='root' else 'geometry')
    return Model(c,scope).run()


def native_vectors(scope='probe'):
    ranges(scope);cases=[];chips=facts()['chips'];initial=stack.native_vectors('root')['cases'][0]
    def op(kind):return dict(op=kind,object=True,data=True,output=True,command=0x1001,flags=0x1234,offset=5,size=8)
    def add(name,index=0,**changes):
        c=initial|dict(name=name,native_main_probe=True,native_main_root=scope=='root',operations=[op('probe')] if scope=='probe' else [op('initialize'),op('open'),op('ioctl'),op('close')],
            probe_id=chips[index]['id'],probe_delayed_rounds=0,probe_bus_fail_at=0,probe_id_fail_at=0,probe_reset_fail=False,
            probe_regulator_present=True,probe_power_status=0,probe_workaround_return=0,probe_uid_return=0,probe_bbt_return=0,
            probe_feature_write_fail_at=0,probe_feature_read_fail_at=0,probe_feature_mismatch_at=0)|changes
        c['expected']=contract(c,scope);cases.append(c)
    if scope=='probe':
        for i in range(11):add('main_probe_chip_'+str(i),i)
        add('main_probe_second_round',probe_delayed_rounds=1);add('main_probe_last_33rd',10,probe_delayed_rounds=2)
        add('main_probe_no_match',probe_id=[255]*5);add('main_probe_bus_assert',probe_bus_fail_at=1)
        add('main_probe_id_assert',probe_id_fail_at=1);add('main_probe_reset_assert',probe_reset_fail=True)
        add('main_probe_write_error',probe_feature_write_fail_at=1);add('main_probe_read_error',probe_feature_read_fail_at=1)
        add('main_probe_feature_mismatch',probe_feature_mismatch_at=1);add('main_probe_missing_regulator',probe_regulator_present=False)
        add('main_probe_power_error_ignored',probe_power_status=-9)
        add('main_probe_aux_returns_ignored',probe_workaround_return=-9,probe_uid_return=-9,probe_bbt_return=-9)
        add('main_probe_supplied_no_bbt',probe_bbt_return=1,main_bbt_magic=0)
    else:
        add('main_probe_root_ready');add('main_probe_root_four_kib',3);add('main_probe_root_append',main_seed='other')
        add('main_probe_root_duplicate',main_seed='duplicate');add('main_probe_root_no_match',probe_id=[255]*5)
        add('main_probe_root_feature_error',probe_feature_mismatch_at=1)
        add('main_probe_root_no_bbt',probe_bbt_return=1,main_bbt_magic=0)
        add('main_probe_root_existing_mutexes',main_mutex_present=True,main_reg_mutex_present=True)
        add('main_probe_root_no_pm',main_pm_property=False);add('main_probe_root_alloc_error',main_alloc_fail=True)
    return dict(schema=1,scope='nand',bound_per_case=base.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if inventory(mem)!=facts():raise ValueError('original main inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=base.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=base.BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,inventory_sha256=base.digest(FACTS.read_bytes()),vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges(scope)},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges(scope)},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges(scope)},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main probe/matcher/ID/reset builders execute over all eleven unchanged descriptors; bus initialization/packet responses, power, feature services and auxiliary workaround/UID/BBT bodies remain supplied.',
            'Root scope joins actual root/wrapper/registry/PM publication and original geometry/context/chip/magic consumers; no main FIFO/DMA, real UID/BBT recovery or physical chip identity is established.',
            'Requested delays, supplied auxiliary return-register values and guard counts do not establish elapsed timing, valid media/protection, ownership/reclamation, concurrency or standalone boot.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('probe','root'),default='probe')
    for key in ('vectors-output','vectors','validation','decompiled','inventory-output'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.inventory_output:
            if not a.archive:p.error('need archive for inventory')
            with zipfile.ZipFile(a.archive) as z:r=inventory(base.image_memory(z))
            a.inventory_output.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');return
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main probe: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
