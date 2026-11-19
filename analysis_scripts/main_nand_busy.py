#!/usr/bin/env python3
"""Complete original main NAND busy boundaries inside connected BBT recovery/repair."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_bbt_repair as repair
else:
    import main_nand_bbt_repair as repair

base=repair.base
BOUND=4000000
FIFO_BOUND=8192


def ranges():return repair.ranges()
def data_ranges():return repair.data_ranges()


class Trace:
    def __init__(self):self.count=0;self.digest=hashlib.sha256()
    def append(self,value):
        if not isinstance(value,str) or '\n' in value:raise ValueError('canonical busy trace event')
        self.digest.update(value.encode('utf-8')+b'\n');self.count+=1
    def extend(self,values):
        for value in values:self.append(value)


class Model(repair.Model):
    def __init__(self,c):super().__init__(c);self.busy_kind=None;self.busy_ordinal=0;self.busy_polls=0;self.busy_target=False
    def get(self,reg):
        if reg!=192 or not self.busy_target:return super().get(reg)
        poll=self.busy_polls+1;ready=self.c['busy_ready_at'];value=self.c['busy_final_status'] if ready and poll>=ready else 1
        self.transfer_packet(15,reg,1,False,bytearray((value,)),1,0);return 0,value
    def busy(self):
        kind=self.repair_phase or ('read' if self.in_read else 'uid')
        ordinal=self.erase_calls if kind=='erase' else self.program_calls if kind=='program' else self.io_page_calls if kind=='read' else 1
        limit=4000 if kind=='erase' else 2000;self.busy_kind=kind;self.busy_ordinal=ordinal;self.busy_polls=0
        self.busy_target=kind==self.c['busy_stage'] and ordinal==self.c['busy_call']
        previous=self.actions;engine_actions=self.engine.actions;trace=Trace();self.actions=trace;self.engine.actions=trace
        out=255;status=0
        try:
            for poll in range(1,limit+1):
                self.actions.append('delay:5');status,value=self.get(192);self.busy_polls=poll
                if status:self.log('busy_feature_error');break
                if poll==limit:self.log('busy_timeout');break
                if not value&1:out=value;break
        finally:
            self.actions=previous;self.engine.actions=engine_actions;self.busy_target=False
        previous.append(f'busy_window:{kind}:{ordinal}:{limit}:{self.busy_polls}:{out}:{status}:{trace.count}:{trace.digest.hexdigest()}')
        self.busy_kind=None;return status,out


def contract(c,scope):
    if scope not in ('read','repair') or not c['native_main_busy']:raise ValueError('main busy entry')
    if c['busy_stage'] not in (('read',) if scope=='read' else ('erase','program')):raise ValueError('busy selected stage')
    limit=4000 if c['busy_stage']=='erase' else 2000
    if c['busy_call']!=(7 if scope=='read' else 1) or c['busy_ready_at'] not in (0,limit-1,limit):raise ValueError('busy bounded boundary')
    if c['busy_final_status'] not in (0,8,32):raise ValueError('busy final status')
    if c['repair_fault_phase']!='none' or c['recovery_fault_read'] or c['full_ready_fail_at'] or c['full_done_fail_at']:raise ValueError('busy transport remains ready')
    repair.contract(c,'program')
    return Model(c).run()


def native_vectors(scope='read'):
    sources={c['name'].removeprefix('main_bbt_repair_'):c for c in repair.native_vectors('program')['cases']};cases=[]
    def add(name,stage,ready=0,final=0):
        source='program_primary_no_repair' if stage=='read' else 'program_ready'
        c=sources[source]|dict(name='main_busy_'+name,native_main_busy=True,busy_stage=stage,busy_call=7 if stage=='read' else 1,busy_ready_at=ready,busy_final_status=final)
        c.pop('expected',None);c['expected']=contract(c,scope);cases.append(c)
    if scope=='read':
        add('read_exhausted','read');add('read_ready_at_limit','read',2000);add('read_ready_before_limit','read',1999)
        add('read_ecc_at_limit','read',2000,32);add('read_ecc_before_limit','read',1999,32)
    elif scope=='repair':
        for kind,limit in (('erase',4000),('program',2000)):
            add(kind+'_exhausted',kind);add(kind+'_ready_at_limit',kind,limit);add(kind+'_ready_before_limit',kind,limit-1)
    else:raise ValueError('busy scope')
    return dict(schema=1,scope='nand',bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if repair.read.aux.inventory(mem)!=json.loads(repair.read.aux.FACTS.read_bytes()):raise ValueError('original UID inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main busy loops run all 2000/4000 polls through actual feature/bus/QSPI FIFO inside connected BBT read/erase/program/root. Busy-window events are streamed into a counted SHA-256 trace, without skipping loop iterations.',
            'Status streams/timers/peripheral/FIFO inputs and library/pin/power/RTOS/BSP/heap/PM services remain authored or supplied; requested waits do not establish elapsed time or physical readiness.',
            'Late-ready/ECC discard, retained ff status and outer registration are software observations. DMA/asynchronous IO, physical persistence/atomicity/timing/IRQ/cache/coherency, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('read','repair'),default='read')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main busy loops: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
