#!/usr/bin/env python3
"""Actual main page read after recovered BBT through original direct QSPI FIFO."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_bbt_mapping as mapping
else:
    import main_nand_bbt_mapping as mapping

base=mapping.base
aux=mapping.recovery.uid.aux
BUFFER=0x81330000
EXTRA=((0x702d6bbe,366),(0x702d5fac,108),(0x702d8010,238))


def ranges():return mapping.ranges()+EXTRA
def data_ranges():return mapping.data_ranges()
def payload(page,column,size):return bytes((0x5a+page*3+column+i*7)&255 for i in range(size))


class Engine(aux.Engine):
    def packet_fails(self,ready):
        if self.owner.in_page:return self.command_index-self.owner.page_base==self.full['page_ready_fail_at' if ready else 'page_done_fail_at']
        return super().packet_fails(ready)
    def read(self,at,size=4):
        pos=self.payload_at;value=super().read(at,size)
        if at==256 and self.owner.in_page:
            if self.opcode==0x6b:self.owner.page_buffer[pos:pos+size]=value.to_bytes(size,'little')
            elif self.opcode==15 and self.reg==192:self.owner.page_status_reads+=1
        return value


class Model(mapping.Model):
    engine_type=Engine
    def __init__(self,c):
        super().__init__(c);self.in_page=False;self.page_buffer=bytearray(b'\xa5'*128);self.page_rows=[]
        self.page_calls=0;self.page_status_reads=0;self.page_caches=0;self.page_loaded=0;self.page_base=0
    def load(self,page):
        if self.in_page:self.page_loaded=page
        return super().load(page)
    def get(self,reg):
        if not self.in_page or reg!=192:return super().get(reg)
        values=self.c['page_statuses'];value=values[min(self.page_status_reads,len(values)-1)]
        self.transfer_packet(15,reg,1,False,bytearray((value,)),1,0);return 0,value
    def read_page(self,op):
        self.page_calls+=1;self.page_base=self.commands;self.actions.append(f'main_page_read_native:{op["offset"]}:{op["command"]}:{op["size"]}');self.in_page=True
        try:
            result,page=self.map_value(op['offset'],True)
            if result:return -150
            if not op['data'] or not op['size'] or page>=65536 or ((op['command']+op['size'])&0xffffffff)>2112:
                self.actions.append('log:main_page_result:-1');return -1
            self.load(page);_,status=self.busy();ecc=status&48==32
            if ecc:self.actions.append('main_page_retry:'+str(page));self.compat()
            self.page_caches+=1
            data=bytearray(payload(page,op['command'],op['size']))
            self.transfer_packet(0x6b,op['command'],op['size'],False,data,2,1,lines=3)
            if ecc:self.actions.append('log:main_page_result:-101');return -101
            return 0
        except aux.joined.prior.bus.boot.Stop as stop:self.stopped=stop.info;return None
        finally:self.in_page=False
    def operation(self,op):
        if op['op']=='page_read':
            result=self.read_page(op);self.export_rows.append(dict(export_hex=self.export.hex(),export_calls=self.exports));self.map_rows.append(dict(map_output=self.mapped))
        else:result=super().operation(op)
        self.page_rows.append(self.full_snapshot()|self.aux_snapshot()|dict(page_buffer_hex=self.page_buffer.hex(),page_calls=self.page_calls,
            page_status_reads=self.page_status_reads,page_cache_packets=self.page_caches,page_loaded=self.page_loaded))
        return result
    def run(self):
        result=super().run()
        for row,page in zip(result['rows'],self.page_rows):row.update(page)
        return result


def contract(c):
    ops=c['operations'];reads=[op for op in ops if op['op']=='page_read']
    if not c['native_main_page_read'] or not reads or not 4<=len(ops)<=12:raise ValueError('main page read sequence')
    if any(not 0<=c[k]<=20 for k in ('page_ready_fail_at','page_done_fail_at')):raise ValueError('page transport fault bound')
    if not c['page_statuses'] or len(c['page_statuses'])>16 or c['page_statuses'][-1]&1 or any(not 0<=v<=255 for v in c['page_statuses']):raise ValueError('bounded ready page status stream')
    if sum(op['size'] for op in reads)>512:raise ValueError('aggregate page backing')
    for op in reads:
        if not 0<=op['size']<=128 or not 0<=op['offset']<=0xffffffff or not 0<=op['command']<=0xffffffff:raise ValueError('bounded page parameters')
    mapping.contract(c|dict(operations=[op for op in ops if op not in reads]))
    return Model(c).run()


def native_vectors():
    originals={c['name'].removeprefix('main_bbt_map_'):c for c in mapping.native_vectors()['cases']};cases=[]
    def add(name,page=65,column=16,size=32,source='block_1',sequence=None,**changes):
        original=originals[source];template=original['operations'][-1]
        reads=[template|dict(op='page_read',offset=p,command=col,size=n,data=present) for p,col,n,present in (sequence or [(page,column,size,True)])]
        c=original|dict(name='main_page_read_'+name,native_main_page_read=True,operations=original['operations']+reads,page_statuses=[0],page_ready_fail_at=0,page_done_fail_at=0)|changes
        c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    add('mapped');add('one_byte',size=1);add('word_tail',size=13);add('max_backing',size=128)
    add('last_usable',page=65215);add('reserved_limit',page=65216);add('wrap_page',page=0xffffffff)
    add('inactive_bbt',source='inactive_page');add('unsorted',source='unsorted_entries');add('duplicates',source='duplicate_entries')
    add('repair_error',source='repair_error_active');add('ecc_reject',page_statuses=[32]);add('busy_then_ready',page_statuses=[1,0])
    add('zero_length',size=0);add('null_buffer',sequence=[(65,16,32,False)])
    add('exact_end',column=2080);add('past_end',column=2081);add('wrapping_column',column=0xfffffff8,size=16)
    add('load_done_timeout',page_done_fail_at=1);add('status_ready_timeout',page_ready_fail_at=2)
    add('cache_ready_timeout',page_ready_fail_at=3);add('cache_done_timeout',page_done_fail_at=3)
    add('repeated',sequence=[(65,16,32,True),(193,2080,32,True)])
    return dict(schema=1,scope='nand',bound_per_case=aux.joined.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if aux.inventory(mem)!=json.loads(aux.FACTS.read_bytes()):raise ValueError('original UID inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=aux.joined.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=aux.joined.BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main page read/remap/load/busy/direct x4 cache/FIFO consumes the BBT recovered inside actual first-chip probe/UID/root. The original unsupported-family retry branch executes on ECC rejection.',
            'FIFO page/status/ID/UID/peripheral/timer data and BBT page/marker/library/RTOS/power services remain authored or supplied. BBT recovery page callbacks still do not use the connected read transport.',
            'DMA/asynchronous read, full busy exhaustion, program/erase, wider descriptors/consumers, physical timing/coherency/media provenance, persistence, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main page read: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
