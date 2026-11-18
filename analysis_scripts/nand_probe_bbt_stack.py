#!/usr/bin/env python3
"""Connected original first-chip probe, unsupported-family workaround and BBT recovery."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import nand_bbt_stack as recovery
    from . import nand_probe_stack as probe
else:
    import nand_bbt_stack as recovery
    import nand_probe_stack as probe

qspi=probe.qspi
EXTRA_RANGES=probe.EXTRA_RANGES+((0x80c29f5c,234),)
RANGES=recovery.RANGES+EXTRA_RANGES
TARGETS=tuple(a for a,n in RANGES)
DATA_RANGES=tuple(dict.fromkeys(recovery.DATA_RANGES+probe.DATA_RANGES))


class Model(recovery.BbtMixin,probe.Model,recovery.scan.Model):
    def __init__(self,c):super().__init__(dict(c));self.bounce=bytearray(b'\xa5'*512);self.init_bbt()
    def run_workaround(self):
        if not self.c['bbt_native_workaround']:return super().run_workaround()
        self.actions.extend(('probe_workaround_native','compare20:-1','compare20:-1'))
    def run_probe_bbt(self,chip):self.resume_bbt()
    def run(self):
        result=probe.Model.run(self);self.bbt_snapshot(result['rows'][0]);return result


def contract(c):
    if c['mode']!='platform_probe' or not c['native_probe'] or not c['native_bbt_stack']:raise ValueError('joined probe entry')
    if c['bbt_entry']!='resume' or c['bbt_follow_read'] or any(c[k] for k in ('native_dispatch','native_eftl','native_storage','native_mutation','native_repair')):raise ValueError('joined direct probe scope')
    if c['probe_id']!=probe.CHIPS[0]['id'] or c['probe_delayed_rounds']!=0:raise ValueError('selected first-chip integration')
    recovery.contract(c|dict(mode='platform_mutation',native_probe=False,native_dispatch=True,native_eftl=True,
        native_storage=True,native_mutation=True,native_repair=True,bbt_entry='resume',bbt_follow_read=False))
    probe.contract(c|dict(native_bbt_stack=False,mode='platform_probe'))
    return Model(c).run()


def native_vectors():
    base=recovery.native_vectors()['cases'][0];p=probe.native_vectors()['cases'][0];cases=[]
    def add(name,records=None,**changes):
        fields={k:v for k,v in p.items() if k.startswith('probe_')}
        c=base|fields|dict(name=name,mode='platform_probe',native_probe=True,bbt_native_workaround=True,
            native_dispatch=False,native_eftl=False,native_storage=False,native_mutation=False,native_repair=False,
            bbt_records={'1023':dict(bad=[1,3,7])} if records is None else records)|changes
        c['bbt_record_hex']={k:recovery.bbt.record(v).hex() for k,v in c['bbt_records'].items()}
        c['expected']=contract(c);cases.append(c)
    add('probe_bbt_primary');add('probe_bbt_wrapper',probe_entry='wrapper')
    backup={'1022':dict(bad=[1,3,7])}
    add('probe_bbt_backup',records=backup)
    add('probe_bbt_no_records',records={})
    add('probe_bbt_no_records_wrapper',records={},probe_entry='wrapper')
    add('probe_bbt_erase_error',records=backup,responses=[0]*9+[4,0])
    add('probe_bbt_program_error',records=backup,responses=[0]*10+[8,0])
    add('probe_bbt_reread_error',records=backup,responses=[0]*8+[32,0])
    add('probe_bbt_no_good',bbt_good_blocks=[],records={},probe_entry='wrapper')
    add('probe_bbt_feature_mismatch',probe_feature_mismatch_at=2)
    add('probe_bbt_uid_error_ignored',probe_uid_status=-9)
    add('probe_bbt_workaround_supplied',bbt_native_workaround=False,probe_workaround_status=-9)
    return dict(schema=1,bound_per_case=probe.lower.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes());memory=qspi.image_memory(archive)
    if probe.inventory.chip_table(memory)!=probe.inventory.facts():raise ValueError('chip inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']) or execution['bound_per_case']!=probe.lower.BOUND:raise ValueError('case count/bound')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=probe.lower.BOUND:raise ValueError('native mismatch/bound')
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        data_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in DATA_RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Original selected first-chip probe, unsupported-family workaround, actual BBT recovery and wrapper mutex ordering execute through original NAND/QSPI.',
            'UID/power/mutex/library/peripheral effects and marker/record/status streams remain authored; no physical NAND contents or persistent repairs are established.',
            'Actual positive no-BBT and zero-after-repair-error results are observed inside the original probe, not substituted auxiliary returns; full UID/registry/hardware boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:result=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect probe/BBT integration: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
