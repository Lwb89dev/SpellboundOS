#!/usr/bin/env python3
"""Actual main BBT repair erase/program through original direct NAND/QSPI."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_bbt_read as read
else:
    import main_nand_bbt_read as read

base=read.base
EXTRA=((0x702d730c,264),(0x702d6d2c,372),(0x702d5e7a,98),(0x702d6086,102),(0x702d6152,104),(0x702d6224,108))


def ranges():return read.ranges()+EXTRA
def data_ranges():return read.data_ranges()


class Policy(read.Policy):
    def resume(self):
        # Original reserved-tail/recovery policy, now invoking real lower erase/program paths.
        c=self.c;self.state=bytearray(164)
        for at,v in ((140,c['blocks']),(144,c['page_size']),(148,c['ppb']),(152,c['blocks']>>6)):self.put(at,v)
        scan=c['blocks'];primary=0
        while True:
            self.put(156,primary);scan=(scan-1)&0xffffffff;backup=self.word(160)
            if scan<((c['blocks']-self.word(152))&0xffffffff):break
            if self.word(156)==0 and self.bad(scan)==0:primary=scan;continue
            primary=self.word(156)
            if self.word(160)!=0:continue
            backup=scan
            if self.bad(scan)!=0:continue
            break
        self.put(160,backup)
        if not self.word(156) or not self.word(160):self.log('too_many_bad');return None,dict(kind='assertion',owner=0x80c3d3b0,line=172)
        if self.verify(self.word(156)):return 0,None
        if not self.verify(self.word(160)):self.log('no_bbt');return 1,None
        self.put(0,0);status,data=self.read(self.word(160))
        if not status:
            self.sync();status=self.owner.actual_erase(self.word(156))
            if not status:
                if self.owner.c['native_main_bbt_program']:status=self.owner.actual_program(self.word(156)*self.word(148),data)
                else:
                    status=c['write_status'];self.actions.append(f'write:{(self.word(156)*self.word(148))&0xffffffff}:140:{self.word(0)}:{base.digest(data)}:{status}')
        if status:self.log('repair_failed')
        self.put(0,read.recovery.policy.MAGIC);return 0,None


class Engine(read.Engine):
    def packet_fails(self,ready):
        o=self.owner
        if o.repair_phase:return self.full['repair_fault_phase']==o.repair_phase and self.command_index-o.repair_base==self.full['repair_ready_fail_at' if ready else 'repair_done_fail_at']
        return super().packet_fails(ready)
    def read(self,at,size=4):
        value=super().read(at,size);o=self.owner
        if at==256 and self.opcode==15 and self.reg==192 and o.repair_phase:
            if o.repair_phase=='erase':o.erase_status_reads+=1
            else:o.program_status_reads+=1
        return value
    def write(self,at,value,size=4):
        super().write(at,value,size)
        if at==256 and self.opcode==50:self.owner.repair_tx.extend(value.to_bytes(size,'little'))


class Model(read.Model):
    engine_type=Engine
    policy_type=Policy
    def __init__(self,c):
        super().__init__(c);self.repair_phase=None;self.repair_base=0;self.erase_calls=0;self.program_calls=0
        self.erase_status_reads=0;self.program_status_reads=0;self.erase_return=None;self.program_return=None;self.repair_tx=bytearray()
    def get(self,reg):
        if not self.repair_phase or reg!=192:return super().get(reg)
        phase=self.repair_phase;values=self.c[phase+'_statuses'];index=self.erase_status_reads if phase=='erase' else self.program_status_reads
        value=values[min(index,len(values)-1)];self.transfer_packet(15,reg,1,False,bytearray((value,)),1,0);return 0,value
    def actual_erase(self,block):
        self.erase_calls+=1;self.repair_phase='erase';self.repair_base=self.commands;self.actions.append(f'main_repair_erase_native:{block}:{self.c["main_bbt_magic"]}')
        try:
            status,mapped=self.map_value(block)
            if status:result=-151
            else:
                self.transfer_packet(6,0,0,True,bytearray(),0,0)
                self.transfer_packet(216,mapped*64,0,True,bytearray(),3,0)
                _,status=self.busy();result=-104 if status&4 else 0
            if result:self.actions.append('log:main_repair_erase_result:'+str(result))
            self.erase_return=result&0xffffffff;self.actions.append('main_repair_erase_return:'+str(result));return result
        finally:self.repair_phase=None
    def actual_program(self,address,data):
        self.program_calls+=1;self.repair_phase='program';self.repair_base=self.commands
        self.actions.append(f'main_repair_program_native:{address}:140:{self.c["main_bbt_magic"]}:{base.digest(data)}')
        try:
            status,mapped=self.map_value(address,True)
            if status:result=-150
            else:
                self.transfer_packet(6,0,0,True,bytearray(),0,0)
                self.transfer_packet(50,0,140,True,bytearray(data),2,0,lines=3)
                self.transfer_packet(16,mapped,0,True,bytearray(),3,0)
                _,status=self.busy();result=-102 if status&8 else 0
            if result:self.actions.append('log:main_repair_program_result:'+str(result))
            self.program_return=result&0xffffffff;self.actions.append('main_repair_program_return:'+str(result));return result
        finally:self.repair_phase=None
    def run(self):
        result=super().run()
        for row in result['rows']:row.update(repair_erase_calls=self.erase_calls,repair_program_calls=self.program_calls,
            repair_erase_status_reads=self.erase_status_reads,repair_program_status_reads=self.program_status_reads,
            repair_erase_return=self.erase_return,repair_program_return=self.program_return,repair_tx_hex=self.repair_tx.hex())
        return result


def contract(c,scope):
    if scope not in ('erase','program') or not c['native_main_bbt_repair'] or c['native_main_bbt_program']!=(scope=='program'):raise ValueError('main repair entry')
    if c['bbt_erase_status'] or scope=='program' and c['bbt_write_status']:raise ValueError('supplied native repair statuses')
    if c['repair_fault_phase'] not in ('none','erase','program') or scope=='erase' and c['repair_fault_phase']=='program':raise ValueError('repair fault phase')
    if any(not 0<=c[k]<=8 for k in ('repair_ready_fail_at','repair_done_fail_at')):raise ValueError('repair fault command bound')
    if (c['repair_fault_phase']!='none')!=bool(c['repair_ready_fail_at'] or c['repair_done_fail_at']):raise ValueError('repair fault target')
    for key in ('erase_statuses','program_statuses'):
        values=c[key]
        if not values or len(values)>16 or values[-1]&1 or any(not 0<=v<=255 for v in values):raise ValueError('bounded repair status stream')
    read.contract(c,'markers')
    return Model(c).run()


def native_vectors(scope='erase'):
    cases=[];originals={c['name'].removeprefix('main_bbt_io_'):c for c in read.native_vectors('markers')['cases']}
    def add(name,source='markers_backup',**changes):
        c=originals[source]|dict(name='main_bbt_repair_'+name,native_main_bbt_repair=True,native_main_bbt_program=scope=='program',
            erase_statuses=[0],program_statuses=[0],repair_fault_phase='none',repair_ready_fail_at=0,repair_done_fail_at=0)|changes
        c.pop('expected',None);c['expected']=contract(c,scope);cases.append(c)
    if scope=='erase':
        add('erase_ready');add('erase_failed',erase_statuses=[4]);add('erase_busy_ready',erase_statuses=[1,0]);add('erase_other_bits',erase_statuses=[32])
        add('supplied_write_failed',bbt_write_status=-9);add('primary_no_repair',source='markers_primary');add('no_table_no_repair',source='markers_no_records')
        add('erase_enable_timeout',repair_fault_phase='erase',repair_done_fail_at=1)
        add('erase_command_timeout',repair_fault_phase='erase',repair_done_fail_at=2)
        add('erase_status_ready_timeout',repair_fault_phase='erase',repair_ready_fail_at=3)
        add('erase_status_done_timeout',repair_fault_phase='erase',repair_done_fail_at=3)
    elif scope=='program':
        add('program_ready');add('program_failed',program_statuses=[8]);add('program_busy_ready',program_statuses=[1,0]);add('program_other_bits',program_statuses=[32])
        add('program_after_erase_failed',erase_statuses=[4]);add('program_both_busy',erase_statuses=[1,0],program_statuses=[1,0])
        add('program_primary_no_repair',source='markers_primary')
        add('program_enable_timeout',repair_fault_phase='program',repair_done_fail_at=1)
        add('program_cache_ready_timeout',repair_fault_phase='program',repair_ready_fail_at=2)
        add('program_cache_done_timeout',repair_fault_phase='program',repair_done_fail_at=2)
        add('program_execute_timeout',repair_fault_phase='program',repair_done_fail_at=3)
        add('program_status_ready_timeout',repair_fault_phase='program',repair_ready_fail_at=4)
        add('program_status_done_timeout',repair_fault_phase='program',repair_done_fail_at=4)
    else:raise ValueError('repair scope')
    return dict(schema=1,scope='nand',bound_per_case=read.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if read.aux.inventory(mem)!=json.loads(read.aux.FACTS.read_bytes()):raise ValueError('original UID inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=read.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=read.BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main BBT recovery/markers/read/CRC and repair erase plus optional program execute through original remapping, builders, busy loops and direct QSPI FIFO, then root/geometry/UID consumers.',
            'Status/FIFO/record/marker/timer/peripheral inputs and library/pin/power/RTOS/BSP/heap/PM remain authored or supplied. Program remains supplied in erase scope; emitted commands/bytes do not establish physical persistence.',
            'DMA/asynchronous IO, full busy exhaustion, wider geometries/consumers, physical timing/IRQ/cache/coherency/media effects, repair atomicity, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('erase','program'),default='erase')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main BBT repair: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
