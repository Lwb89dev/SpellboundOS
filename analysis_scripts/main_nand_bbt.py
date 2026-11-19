#!/usr/bin/env python3
"""Actual main BBT verify/resume/CRC inside probe with supplied page and marker services."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_uid_export as uid
    from . import nand_bbt as policy
else:
    import main_nand_uid_export as uid
    import nand_bbt as policy

base=uid.base
BBT=0x70f9bbac
EXTRA=((0x702d569c,528),(0x702d58ac,390),(0x70161332,46))


def ranges():return uid.ranges()+EXTRA
def data_ranges():return uid.data_ranges()+((0x709bc4fc,1024),(0x70a4997c,4))


class Model(uid.Model):
    def __init__(self,c):
        super().__init__(dict(c));self.bbt_state=bytearray(b'\xa5'*164);self.bbt_state[:4]=c['main_bbt_magic'].to_bytes(4,'little');self.bbt_result=None;self.bbt_reads=0
    def run_bbt(self,chip):
        c=self.c;self.actions.append(f'main_bbt_native:{chip["blocks"]}:{chip["page_size"]}:{chip["pages_per_block"]}')
        config=dict(active=False,bad=[],blocks=chip['blocks'],page_size=chip['page_size'],ppb=chip['pages_per_block'],reserve=16,
            primary=0,backup=0,good_blocks=c['bbt_good_blocks'],records=c['bbt_records'],reread_status=c['bbt_reread_status'],erase_status=c['bbt_erase_status'],write_status=c['bbt_write_status'])
        helper=policy.Model(config);status,stop=helper.resume();self.bbt_state=helper.state;self.bbt_reads=helper.reads
        for action in helper.actions:self.actions.append('log:bbt_'+action[4:] if action.startswith('log:') else 'bbt_'+action)
        self.c['main_bbt_magic']=helper.word(0)
        if stop:raise uid.aux.joined.prior.bus.boot.Stop(0x70a30e6c,196)
        self.bbt_result=status;self.actions.append('main_bbt_return:'+str(status))
    def run(self):
        result=super().run()
        for row in result['rows']:row.update(bbt_state_hex=self.bbt_state.hex(),bbt_resume_return=self.bbt_result,bbt_reads=self.bbt_reads)
        return result


def contract(c):
    if not c['native_main_bbt'] or c['probe_id']!=uid.aux.joined.probe.facts()['chips'][0]['id']:raise ValueError('selected original BBT integration')
    if c['probe_bbt_return']!=0:raise ValueError('supplied BBT result outside scope')
    if len(c['bbt_good_blocks'])>16 or any(not 1008<=v<1024 for v in c['bbt_good_blocks']):raise ValueError('BBT tail backing')
    for key,spec in c['bbt_records'].items():
        if str(int(key))!=key or not 1008<=int(key)<1024 or len(spec['bad'])>64 or any(not 0<=v<=65535 for v in spec['bad']):raise ValueError('BBT record backing')
        if not 0<=spec.get('magic',policy.MAGIC)<=0xffffffff or not -100<=spec.get('read_status',0)<=100:raise ValueError('BBT record fields')
    if c['bbt_record_hex']!={k:policy.record(v).hex() for k,v in c['bbt_records'].items()}:raise ValueError('BBT encoded records')
    if any(not -100<=c[k]<=100 for k in ('bbt_reread_status','bbt_erase_status','bbt_write_status')):raise ValueError('BBT service result')
    uid.contract(c)
    return Model(c).run()


def native_vectors():
    cases=[];initial=uid.native_vectors()['cases'][0];original=uid.aux.native_vectors('uid')['cases'][0]
    export=initial['operations'][-1];ops=original['operations']+[export]
    def add(name,records=None,**changes):
        c=initial|dict(name='main_bbt_'+name,native_main_bbt=True,operations=ops,bbt_good_blocks=[1023,1022],
            bbt_records={'1023':dict(bad=[1,3,7])} if records is None else records,bbt_reread_status=0,bbt_erase_status=0,bbt_write_status=0)|changes
        c['bbt_record_hex']={k:policy.record(v).hex() for k,v in c['bbt_records'].items()};c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    add('primary');add('empty_table',records={'1023':dict(bad=[])})
    backup={'1022':dict(bad=[1,3,7])}
    add('backup_repair',records=backup);add('reread_error',records=backup,bbt_reread_status=-9)
    add('erase_error',records=backup,bbt_erase_status=-9);add('write_error',records=backup,bbt_write_status=-9)
    add('both_invalid',records={});add('primary_bad_crc',records={'1023':dict(bad=[1],bad_crc=True)}|backup)
    add('primary_read_error',records={'1023':dict(bad=[1],read_status=-9)}|backup)
    add('count_limit',records={'1023':dict(bad=list(range(14)))})
    add('count_exceeds',records={'1023':dict(bad=list(range(15)))})
    add('unsorted',records={'1023':dict(bad=[7,1])});add('duplicates',records={'1023':dict(bad=[1,1])})
    add('skip_bad_tail',bbt_good_blocks=[1022,1020],records={'1022':dict(bad=[1])})
    add('last_reserved_pair',bbt_good_blocks=[1009,1008],records={'1009':dict(bad=[])})
    add('no_good',bbt_good_blocks=[],records={});add('one_good',bbt_good_blocks=[1023],records={})
    add('stale_uid',uid_mismatch=True)
    return dict(schema=1,scope='nand',bound_per_case=uid.aux.joined.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if uid.aux.inventory(mem)!=json.loads(uid.aux.FACTS.read_bytes()):raise ValueError('original UID inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=uid.aux.joined.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=uid.aux.joined.BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,inventory_sha256=base.digest(uid.aux.FACTS.read_bytes()),vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main BBT verifier/resume and CRC join actual first-chip probe/UID/platform/FIFO/root, geometry and UID export; BBT page read/write/erase and bad-marker services remain supplied.',
            'Records/status/UID/peripheral state are authored. Bounded library, power/pin/RTOS/BSP/heap/PM and copy/format services remain supplied; no physical media or persistent repair is established.',
            'Valid RAM BBT and zero recovery status can survive supplied repair failures. Main BBT lower page/DMA integration, remapping consumers, physical provenance, concurrency, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main BBT: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
