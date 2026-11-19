#!/usr/bin/env python3
"""Actual main BBT block/page remapping after original recovery and publication."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_bbt as recovery
else:
    import main_nand_bbt as recovery

base=recovery.base
OUTPUT=0x8132f000
EXTRA=((0x702d5a32,64),(0x702d5a72,96))


def ranges():return recovery.ranges()+EXTRA
def data_ranges():return recovery.data_ranges()


class Model(recovery.Model):
    def __init__(self,c):super().__init__(c);self.mapped=0xa5a5a5a5;self.map_rows=[]
    def map_value(self,value,page=False):
        self.actions.append(('main_remap_page:' if page else 'main_remap_block:')+str(value))
        helper=recovery.policy.Model(dict(active=False,bad=[],blocks=1024,page_size=2048,ppb=64,reserve=16,primary=0,backup=0,value=value))
        helper.state=bytearray(self.bbt_state);helper.output=self.mapped
        if page and helper.word(0)==recovery.policy.MAGIC:self.actions.append('main_remap_block:'+str(value//helper.word(148)))
        result=helper.map(page)
        return result,helper.output
    def operation(self,op):
        if op['op'] in ('map_block','map_page'):
            result,value=self.map_value(op['offset'],op['op']=='map_page')
            if not result:self.mapped=value
            self.export_rows.append(dict(export_hex=self.export.hex(),export_calls=self.exports))
        else:result=super().operation(op)
        self.map_rows.append(dict(map_output=self.mapped));return result
    def run(self):
        result=super().run()
        for row,mapped in zip(result['rows'],self.map_rows):row.update(mapped)
        return result


def contract(c):
    ops=c['operations'];mapping=[op for op in ops if op['op'] in ('map_block','map_page')]
    if not c['native_main_bbt_mapping'] or not mapping or not 3<=len(ops)<=12:raise ValueError('main mapping sequence')
    if not c['bbt_good_blocks'] or c['main_acquire'] or c['main_release']:raise ValueError('mapping requires completed recovery/publication')
    for op in mapping:
        if not op['output'] or not 0<=op['offset']<=0xffffffff:raise ValueError('bounded mapping output/input')
    recovery.contract(c|dict(operations=[op for op in ops if op not in mapping]))
    return Model(c).run()


def native_vectors():
    sources={c['name'].removeprefix('main_bbt_'):c for c in recovery.native_vectors()['cases']};cases=[]
    def add(name,value=1,page=False,source='primary',sequence=None):
        original=sources[source];template=original['operations'][-1]
        ops=[template|dict(op='map_page' if p else 'map_block',offset=v) for v,p in (sequence or [(value,page)])]
        c=original|dict(name='main_bbt_map_'+name,native_main_bbt_mapping=True,operations=original['operations']+ops)
        c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    for value in (0,1,3,1018,1019,0xffffffff):add('block_'+str(value),value)
    for value in (0,65,193,65215,65216,0xffffffff):add('page_'+str(value),value,True)
    add('inactive_block',0xffffffff,source='both_invalid');add('inactive_page',0xffffffff,True,source='both_invalid')
    add('empty_reserved',1022,source='empty_table');add('repair_error_active',3,source='write_error')
    add('duplicate_entries',1,source='duplicates');add('unsorted_entries',1,source='unsorted')
    add('last_pair_boundary',1008,source='last_reserved_pair')
    add('error_retains_previous_output',sequence=[(3,False),(1019,False),(65,True),(65216,True)])
    return dict(schema=1,scope='nand',bound_per_case=recovery.uid.aux.joined.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if recovery.uid.aux.inventory(mem)!=json.loads(recovery.uid.aux.FACTS.read_bytes()):raise ValueError('original UID inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=recovery.uid.aux.joined.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=recovery.uid.aux.joined.BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main block/page remappers consume BBT state produced by actual main verifier/resume/CRC within original probe/UID/platform/root and later geometry/UID export.',
            'BBT page/marker and library/RTOS/power/heap services remain supplied over authored records and peripherals; no physical NAND table or persistent repair is established.',
            'Wrapping inputs and malformed lists are bounded software counterexamples. Main page/DMA integration, physical provenance, concurrency, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main BBT remapping: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
