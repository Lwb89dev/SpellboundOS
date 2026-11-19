#!/usr/bin/env python3
"""Actual main UID export through the locked context interface after probe/FIFO acquisition."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_aux as aux
else:
    import main_nand_aux as aux

base=aux.base
OUTPUT=0x8132e000


def ranges():return aux.ranges()
def data_ranges():return aux.data_ranges()


class Model(aux.Model):
    def __init__(self,c):
        super().__init__(c);self.export=bytearray(b'\xa5'*129);self.exports=0;self.export_rows=[]
    def export_uid(self):
        c=self.c;self.exports+=1;self.lower_calls+=1;self.actions.extend(('main_uid_export_native','main_lower_native:24',f'main_irq:{c["main_irq"]}'))
        direct=bool(c['main_irq'])
        if not direct:self.actions.append(f'main_scheduler:{c["main_scheduler"]}');direct=bool(c['main_scheduler'])
        if not direct and self.driver_mutex:
            self.actions.append(f'main_acquire:{c["main_acquire"]}')
            if c['main_acquire']:self.stopped=dict(kind='assertion',owner=0x70a30f20,line=36);return None
        self.actions.append('main_chip_native:24')
        if self.descriptor()['uid_flag']:
            self.export[0]=self.uid_length;self.export[1:1+self.uid_length]=self.uid[:self.uid_length]
            self.actions.append('copy_uid:'+str(self.uid_length));status=0
        else:self.actions.append('log:main_chip_error');status=-201
        if not direct and self.driver_mutex:
            self.actions.append(f'main_release:{c["main_release"]}')
            if c['main_release']:self.stopped=dict(kind='assertion',owner=0x70a30f08,line=42);return None
        return status
    def operation(self,op):
        result=self.export_uid() if op['op']=='uid_export' else super().operation(op)
        self.export_rows.append(dict(export_hex=self.export.hex(),export_calls=self.exports))
        return result
    def run(self):
        result=super().run()
        for row,export in zip(result['rows'],self.export_rows):row.update(export)
        return result


def contract(c):
    ops=c['operations']
    if not c['native_main_uid_export'] or not 2<=len(ops)<=12 or ops[0]['op']!='initialize' or not any(op['op']=='uid_export' for op in ops):raise ValueError('UID export sequence')
    if c['main_alloc_fail'] or c['main_mutex_fail'] or c['main_seed']=='duplicate' or not c['main_pm_property']:raise ValueError('UID export requires published root')
    if c['full_ready_fail_at'] or c['full_done_fail_at']:raise ValueError('transport assertions covered in acquisition scope')
    filtered=[op for op in ops if op['op']!='uid_export']
    aux.contract(c|dict(operations=filtered),'uid')
    for op in ops:
        if op['op']=='uid_export' and (op['command']!=24 or not op['output']):raise ValueError('bounded UID export output')
    return Model(c).run()


def native_vectors():
    cases=[];sources={c['name'].removeprefix('main_aux_'):c for c in aux.native_vectors('uid')['cases']}
    def add(name,source='first_copy',**changes):
        original=sources[source];op=original['operations'][0]|dict(op='uid_export',command=24)
        c=original|dict(name='main_uid_export_'+name,native_main_uid_export=True,operations=[original['operations'][0],op])|changes
        c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    add('first_copy');add('last_copy','last_copy');add('no_valid_copy','no_valid_copy')
    add('stale_mismatch','feature_mismatch');add('stale_ecc','ecc_reject');add('disabled','uid_not_requested')
    add('stale_empty','feature_mismatch',initial_uid_length=0);add('stale_full_backing','feature_mismatch',initial_uid_length=128)
    add('supported_family','supported_family');add('dosilicon','dosilicon_uid');add('esmt','esmt_uid')
    add('irq',main_irq=1);add('scheduler',main_scheduler=1)
    add('acquire_error',main_acquire=-9);add('release_error',main_release=-9)
    original=sources['first_copy'];export=original['operations'][0]|dict(op='uid_export',command=24)
    add('geometry_and_repeat',operations=original['operations']+[export,export])
    return dict(schema=1,scope='nand',bound_per_case=aux.joined.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if aux.inventory(mem)!=json.loads(aux.FACTS.read_bytes()):raise ValueError('original UID inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=aux.joined.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=aux.joined.BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,inventory_sha256=base.digest(aux.FACTS.read_bytes()),vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main probe/platform/FIFO/UID/root acquisition joins actual context locking and chip ioctl 24. The generic NAND geometry ioctl does not forward UID queries.',
            'Bounded memcpy, library, power/pin/RTOS/BSP/heap/PM and BBT services remain supplied; MMIO/status/UID bytes and prior UID state are authored.',
            'Publication and successful export can expose retained state after UID errors. No physical identity, BBT recovery, persistence, concurrency, safe restoration or standalone boot is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main UID export: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
