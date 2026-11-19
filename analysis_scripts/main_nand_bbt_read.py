#!/usr/bin/env python3
"""Actual main recovery record/marker reads through original NAND and QSPI FIFO."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_page_read as page
else:
    import main_nand_page_read as page

mapping=page.mapping
recovery=mapping.recovery
aux=page.aux
base=page.base
BOUND=200000
EXTRA=((0x702d7168,228),)


def ranges():return page.ranges()+EXTRA
def data_ranges():return page.data_ranges()


class Sink:
    def __init__(self,model):self.model=model
    def append(self,value):self.model.actions.append('log:bbt_'+value[4:] if value.startswith('log:') else 'bbt_'+value)


class Policy(recovery.policy.Model):
    def __init__(self,c,owner):super().__init__(c);self.owner=owner;self.actions=Sink(owner)
    def sync(self):self.owner.bbt_state=self.state;self.owner.c['main_bbt_magic']=self.word(0)
    def read(self,block):
        self.sync();self.reads+=1;self.owner.bbt_reads+=1
        self.owner.actions.append(f'bbt_record_read_native:{block*64}:{self.word(0)}')
        return self.owner.actual_read(block*64,0,140)
    def bad(self,block):
        self.sync()
        if not self.owner.c['native_main_bbt_markers']:return super().bad(block)
        self.owner.io_marker_calls+=1;self.owner.actions.append('main_marker_native:'+str(block))
        status=0
        for offset in range(3):
            status,data=self.owner.actual_read(block*64+offset,2048,2)
            if status:break
            if data[0]&data[1]!=255:status=103;break
        if status:self.owner.actions.append('log:main_marker_bad' if status==103 else 'log:main_marker_error:'+str(status))
        self.owner.actions.append('main_marker_return:'+str(status));return status


class Engine(aux.Engine):
    def packet_fails(self,ready):
        o=self.owner
        if o.in_read:return o.io_page_calls==self.full['recovery_fault_read'] and self.command_index-o.io_base==self.full['recovery_ready_fail_at' if ready else 'recovery_done_fail_at']
        return super().packet_fails(ready)
    def read(self,at,size=4):
        value=super().read(at,size);o=self.owner
        if at==256 and o.in_read:
            if self.opcode==107:o.io_received.extend(value.to_bytes(size,'little'));o.io_cache_bytes+=size
            elif self.opcode==15 and self.reg==192:o.io_status_reads+=1
        return value


class Model(mapping.Model):
    engine_type=Engine
    def __init__(self,c):
        super().__init__(c);self.in_read=False;self.io_page_calls=0;self.io_marker_calls=0;self.io_status_reads=0;self.io_cache_packets=0;self.io_cache_bytes=0
        self.io_received=bytearray();self.io_loaded=0;self.io_base=0
    def get(self,reg):
        if not self.in_read or reg!=192:return super().get(reg)
        values=self.c['recovery_statuses'];value=values[min(self.io_status_reads,len(values)-1)]
        self.transfer_packet(15,reg,1,False,bytearray((value,)),1,0);return 0,value
    def actual_read(self,address,column,size):
        self.io_page_calls+=1;self.io_base=self.commands;self.io_received=bytearray();self.in_read=True
        self.actions.append(f'main_recovery_page_native:{address}:{column}:{size}')
        try:
            status,physical=self.map_value(address,True)
            if status:result=-150
            else:
                self.io_loaded=physical;self.load(physical);_,status=self.busy();ecc=status&48==32
                if ecc:self.actions.append('main_page_retry:'+str(physical));self.compat()
                self.io_cache_packets+=1;block=physical//64
                if column==2048:
                    good=block in self.c['bbt_good_blocks'] and physical%64 not in self.c['marker_bad_pages'].get(str(block),[])
                    data=bytes((255,255)) if good else bytes(2)
                else:data=bytes.fromhex(self.c['bbt_record_hex'].get(str(block),recovery.policy.record(dict(bad=[],magic=0)).hex()))
                self.transfer_packet(107,column,size,False,bytearray(data),2,1,lines=3)
                result=-101 if ecc else 0
                if result:self.actions.append('log:main_page_result:'+str(result))
            self.actions.append('recovery_read_return:'+str(result));return result,bytes(self.io_received)
        finally:self.in_read=False
    def run_bbt(self,chip):
        c=self.c;self.actions.append(f'main_bbt_native:{chip["blocks"]}:{chip["page_size"]}:{chip["pages_per_block"]}')
        helper=Policy(dict(active=False,bad=[],blocks=1024,page_size=2048,ppb=64,reserve=16,primary=0,backup=0,
            good_blocks=c['bbt_good_blocks'],records=c['bbt_records'],reread_status=0,erase_status=c['bbt_erase_status'],write_status=c['bbt_write_status']),self)
        try:
            status,stop=helper.resume()
            if stop:raise aux.joined.prior.bus.boot.Stop(0x70a30e6c,196)
            self.bbt_result=status;self.actions.append('main_bbt_return:'+str(status))
        finally:self.bbt_state=helper.state;self.c['main_bbt_magic']=helper.word(0)
    def run(self):
        result=super().run()
        for row in result['rows']:row.update(io_page_calls=self.io_page_calls,io_marker_calls=self.io_marker_calls,io_status_reads=self.io_status_reads,
            io_cache_packets=self.io_cache_packets,io_cache_bytes=self.io_cache_bytes,io_last_fifo_hex=self.io_received.hex(),io_loaded=self.io_loaded)
        return result


def contract(c,scope):
    if scope not in ('records','markers') or not c['native_main_bbt_read'] or c['native_main_bbt_markers']!=(scope=='markers'):raise ValueError('main recovery IO scope')
    if c['bbt_reread_status'] or any(s.get('read_status',0) for s in c['bbt_records'].values()):raise ValueError('supplied read errors outside native IO scope')
    if not c['recovery_statuses'] or len(c['recovery_statuses'])>16 or c['recovery_statuses'][-1]&1 or any(not 0<=v<=255 for v in c['recovery_statuses']):raise ValueError('bounded recovery status stream')
    if not 0<=c['recovery_fault_read']<=100 or any(not 0<=c[k]<=3 for k in ('recovery_ready_fail_at','recovery_done_fail_at')):raise ValueError('recovery transport fault bound')
    if bool(c['recovery_fault_read'])!=bool(c['recovery_ready_fail_at'] or c['recovery_done_fail_at']):raise ValueError('recovery fault target')
    for block,offsets in c['marker_bad_pages'].items():
        if str(int(block))!=block or not 1008<=int(block)<1024 or any(v not in (0,1,2) for v in offsets):raise ValueError('marker page backing')
    if scope=='records' and c['marker_bad_pages']:raise ValueError('markers remain supplied')
    recovery.contract(c|dict(operations=[op for op in c['operations'] if op['op'] not in ('map_block','map_page')]))
    return Model(c).run()


def native_vectors(scope='records'):
    originals={c['name'].removeprefix('main_bbt_map_'):c for c in mapping.native_vectors()['cases']};cases=[]
    def add(name,source='block_1',**changes):
        c=originals[source]|dict(name='main_bbt_io_'+name,native_main_bbt_read=True,native_main_bbt_markers=scope=='markers',marker_bad_pages={},
            recovery_statuses=[0],recovery_fault_read=0,recovery_ready_fail_at=0,recovery_done_fail_at=0)|changes
        c['bbt_record_hex']={k:recovery.policy.record(v).hex() for k,v in c['bbt_records'].items()};c.pop('expected',None);c['expected']=contract(c,scope);cases.append(c)
    if scope=='records':
        add('primary');add('empty',source='empty_reserved');add('no_records',source='inactive_block')
        add('backup_repair',bbt_records={'1022':dict(bad=[1,3,7])})
        add('erase_error',bbt_records={'1022':dict(bad=[1,3,7])},bbt_erase_status=-9)
        add('write_error',source='repair_error_active')
        add('primary_ecc',bbt_records={'1023':dict(bad=[1]),'1022':dict(bad=[1,3,7])},recovery_statuses=[32,0])
        add('reread_ecc',bbt_records={'1022':dict(bad=[1,3,7])},recovery_statuses=[0,0,32])
        add('busy_ready',recovery_statuses=[1,0]);add('bad_crc',bbt_records={'1023':dict(bad=[1],bad_crc=True)})
        add('load_timeout',recovery_fault_read=1,recovery_done_fail_at=1)
        add('status_timeout',recovery_fault_read=1,recovery_ready_fail_at=2)
        add('cache_ready_timeout',recovery_fault_read=1,recovery_ready_fail_at=3)
        add('cache_done_timeout',recovery_fault_read=1,recovery_done_fail_at=3)
    elif scope=='markers':
        add('markers_primary');add('markers_backup',bbt_records={'1022':dict(bad=[1,3,7])})
        add('third_marker_bad',bbt_good_blocks=[1023,1022,1021],marker_bad_pages={'1023':[2]},bbt_records={'1022':dict(bad=[1])})
        add('second_marker_bad',bbt_good_blocks=[1023,1022,1021],marker_bad_pages={'1023':[1]},bbt_records={'1022':dict(bad=[1])})
        add('marker_ecc',bbt_good_blocks=[1023,1022,1021],bbt_records={'1022':dict(bad=[1])},recovery_statuses=[32,0])
        add('marker_ecc_repeat',bbt_good_blocks=[1023,1022,1021],bbt_records={'1022':dict(bad=[1])},recovery_statuses=[32,32,0])
        add('markers_no_records',source='inactive_block');add('markers_last_pair',source='last_pair_boundary')
        add('markers_no_good',bbt_good_blocks=[],bbt_records={})
        add('markers_one_good',bbt_good_blocks=[1023],bbt_records={})
        add('marker_load_timeout',recovery_fault_read=1,recovery_done_fail_at=1)
        add('marker_cache_done_timeout',recovery_fault_read=1,recovery_done_fail_at=3)
        add('record_after_markers_timeout',recovery_fault_read=7,recovery_ready_fail_at=3)
    else:raise ValueError('recovery IO scope')
    return dict(schema=1,scope='nand',bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if aux.inventory(mem)!=json.loads(aux.FACTS.read_bytes()):raise ValueError('original UID inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main recovery record reader and optional three-page marker checker execute remap/load/busy/direct-x4-cache/QSPI FIFO inside actual probe/UID/root and subsequent consumers.',
            'Record/marker/status/FIFO/timer/peripheral state is authored. Erase/write, bounded library, pin/power/RTOS/BSP/heap/PM and optional marker services remain supplied; no persistent repair or physical table is established.',
            'DMA/asynchronous read, actual repair erase/program, full busy exhaustion, wider chip geometries/consumers, physical IRQ/cache/timing/coherency, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('records','markers'),default='records')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main recovery IO: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
