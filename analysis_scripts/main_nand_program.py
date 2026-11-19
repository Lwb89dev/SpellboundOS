#!/usr/bin/env python3
"""Original main mode-zero page program through initialized TX DMA after BBT recovery."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_async as app
else:
    import main_nand_async as app

repair=app.repair
base=app.base
BUFFER=app.BUFFER
BOUNCE=app.BOUNCE
GUARD=app.GUARD
BOUND=app.BOUND
EXTRA=((0x702d61ba,106),(0x702d6418,2))


def ranges():return repair.ranges()+EXTRA
def data_ranges():return app.data_ranges()
def source():return bytes((0x96+i*11)&255 for i in range(128))


class Engine(repair.Engine):
    def packet_fails(self,ready):
        o=self.owner
        if o.app_kind:return self.command_index-o.app_base==self.full['app_ready_fail_at' if ready else 'app_done_fail_at']
        return super().packet_fails(ready)
    def read(self,at,size=4):
        value=super().read(at,size)
        if at==256 and self.owner.app_kind and self.opcode==15 and self.reg==192:self.owner.app_status_reads+=1
        return value
    def write(self,at,value,size=4):
        if at==256 and self.owner.app_kind and self.opcode==50:
            repair.read.Engine.write(self,at,value,size);self.owner.app_tx.extend(value.to_bytes(size,'little'))
        else:super().write(at,value,size)


class Model(repair.Model):
    engine_type=Engine
    def __init__(self,c):
        super().__init__(c);self.app_kind=False;self.app_base=0;self.app_calls=0;self.app_status_reads=0;self.app_dma_calls=0
        self.app_page=0;self.app_tx=bytearray();self.app_rows=[];self.engine.bounce=bytearray([c['app_bounce_byte']])*512
        b=self.engine.backends[0];b.c=b.c|dict(status_a=c['app_dma_a'],status_b=c['app_dma_b'],ticks=c['app_dma_ticks'])
    def get(self,reg):
        if not self.app_kind or reg!=192:return super().get(reg)
        values=self.c['app_statuses'];value=values[min(self.app_status_reads,len(values)-1)]
        self.transfer_packet(15,reg,1,False,bytearray((value,)),1,0);return 0,value
    def cache_program(self,column,n):
        self.actions.append(f'probe_packet:50:{column}:{n}:1');e=self.engine;version=e.version();bounce=n>31 and version>1
        if bounce:e.bounce[:n]=source()[:n];self.actions.append('app_copy_to_bounce:'+str(n))
        self.commands+=1;e.command_index=self.commands;e.opcode=50;e.reg=column;e.payload=b'';e.payload_at=0
        e.c['frame']=[2,0,50,1,1,column,1,2,3,n,0];status=e.command();stage='command'
        if not status:
            if bounce:self.app_dma_calls+=1;status=e.data(False,True);stage='transmit_bounce'
            else:
                self.writes+=1;saved=e.buffer;e.buffer=bytearray(512);e.buffer[:n]=source()[:n];e.c['alignment']=0
                status=app.read.aux.joined.hal.boot.Model.data(e,False,False);e.buffer=saved;stage='transmit_poll'
        if status:
            self.actions.extend(('log:'+stage+'_error','diagnostic'))
            raise app.read.aux.joined.prior.bus.boot.Stop(0x70a1bca8 if bounce else 0x70a1bc8c,361 if stage=='command' and bounce else 294 if stage=='command' else 386 if bounce else 313)
    def program(self,op):
        self.actions.append(f'app_program_native:{op["offset"]}:{op["command"]}:{op["size"]}')
        status,physical=self.map_value(op['offset'],True)
        if status:result=-150
        elif not op['data'] or not op['size'] or physical>=65536 or ((op['command']+op['size'])&0xffffffff)>2112:result=-1
        elif physical<self.guard_pages:self.actions.append('log:app_program_guard');result=-250
        else:
            self.transfer_packet(6,0,0,True,bytearray(),0,0);self.cache_program(op['command'],op['size'])
            self.app_page=physical;self.transfer_packet(16,physical,0,True,bytearray(),3,0)
            _,status=self.busy();result=-102 if status&8 else 0
        if result:self.actions.append('log:app_program_result:'+str(result))
        return result
    def operation(self,op):
        if op['op']=='app_program':
            self.app_calls+=1;self.app_kind=True;self.app_base=self.commands
            try:result=self.program(op)
            except app.read.aux.joined.prior.bus.boot.Stop as stop:self.stopped=stop.info;result=None
            finally:self.app_kind=False
            self.export_rows.append(dict(export_hex=self.export.hex(),export_calls=self.exports));self.map_rows.append(dict(map_output=self.mapped))
        else:result=super().operation(op)
        self.app_rows.append(self.full_snapshot()|self.aux_snapshot()|dict(app_buffer_hex=source().hex(),app_calls=self.app_calls,
            app_status_reads=self.app_status_reads,app_page=self.app_page,app_dma_calls=self.app_dma_calls,
            app_tx_hex=self.app_tx.hex(),app_bounce_sha256=base.digest(self.engine.bounce)))
        return result
    def run(self):
        result=super().run()
        for row,app_row in zip(result['rows'],self.app_rows):row.update(app_row)
        return result


def contract(c):
    if not c['native_main_program']:raise ValueError('main mode-zero program entry')
    ops=c['operations'];writes=[op for op in ops if op['op']=='app_program']
    if not writes or len(ops)>12 or any(not 0<=op['offset']<=0xffffffff or not 0<=op['command']<=0xffffffff or not 0<=op['size']<=64 for op in writes):raise ValueError('bounded program operations')
    if not 0<=c['app_bounce_byte']<=255 or any(not 0<=c[k]<=32 for k in ('app_ready_fail_at','app_done_fail_at')):raise ValueError('application peripheral bounds')
    values=c['app_statuses']
    if not values or len(values)>20 or values[-1]&1 or any(not 0<=v<=255 for v in values):raise ValueError('bounded ready program status stream')
    for key in ('app_dma_a','app_dma_b','app_dma_ticks'):
        values=c[key]
        if not values or len(values)>16 or any(not 0<=v<=(0xffffffffffffffff if key.endswith('ticks') else 0xffffffff) for v in values):raise ValueError('DMA input bounds')
    if not (c['app_dma_a'][-1]&32 or c['app_dma_b'][-1]&32 or ((c['app_dma_ticks'][-1]-c['app_dma_ticks'][0])&0xffffffffffffffff)>1000):raise ValueError('TX DMA must finish within supplied stream')
    repair.contract(c|dict(operations=[op for op in ops if op not in writes]),'program')
    return Model(c).run()


def native_vectors():
    cases=[];initial=repair.native_vectors('program')['cases'][0];template=initial['operations'][-1]
    def add(name,page=513,n=32,column=16,sequence=None,**changes):
        ops=[template|dict(op='app_program',offset=p,size=count,command=col,data=present) for p,count,col,present in (sequence or [(page,n,column,True)])]
        c=initial|dict(name='main_program_'+name,native_main_program=True,operations=initial['operations']+ops,app_statuses=[0],app_bounce_byte=60,
            app_ready_fail_at=0,app_done_fail_at=0,app_dma_a=[32],app_dma_b=[0],app_dma_ticks=[0])|changes
        c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    add('dma_ready');add('direct_one',n=1);add('direct_tail',n=13);add('direct_31',n=31);add('dma_64',n=64)
    add('dma_alternate',app_dma_a=[0],app_dma_b=[32]);add('dma_timeout',app_dma_a=[0],app_dma_ticks=[0,1001]);add('dma_qspi_timeout',app_done_fail_at=2)
    add('old_rom_direct',full_rom_version='v1.1.03');add('failed',app_statuses=[8]);add('busy_ready',app_statuses=[1,0]);add('other_bits',app_statuses=[4])
    add('guarded',page=256);add('guard_boundary',page=320);add('reserved',page=65216);add('zero_length',n=0);add('null',sequence=[(513,32,16,False)])
    add('exact_end',column=2080);add('past_end',column=2081);add('wrapping_column',column=0xfffffff8,n=16)
    add('enable_timeout',app_done_fail_at=1);add('direct_cache_ready_timeout',n=31,app_ready_fail_at=2)
    add('execute_timeout',app_done_fail_at=3);add('status_ready_timeout',app_ready_fail_at=4);add('status_done_timeout',app_done_fail_at=4)
    add('repeated_dma',sequence=[(513,32,16,True),(641,64,0,True)])
    return dict(schema=1,scope='nand',bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if repair.read.aux.inventory(mem)!=json.loads(repair.read.aux.FACTS.read_bytes()) or mem.read(GUARD,1)!=b'\1':raise ValueError('original main facts differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(scope='program',main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main mode-zero program follows full actual BBT recovery/root, recovered page remapping and enabled published guard, through original cache builder, bus, QSPI and initialized TX DMA record/setup/wait.',
            'Source/peripheral/status/ticks are authored. Cache/copy/pin/power/RTOS/BSP/heap/PM services remain supplied. TX DMA source staging and software completion are observed; DMA data movement and NAND persistence are not modeled.',
            'The stored no-op callback is not invoked by this bus path. IRQ scheduling, physical cache/coherency/timing, wider geometries/consumers, persistent repair/atomicity, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main mode-zero program: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
