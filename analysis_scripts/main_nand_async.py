#!/usr/bin/env python3
"""Original main mode-zero page read/DMA and sleep-based erase after full BBT recovery."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_bbt_repair as repair
    from . import main_nand_page_read as read
else:
    import main_nand_bbt_repair as repair
    import main_nand_page_read as read

base=repair.base
BUFFER=0x81330000
BOUNCE=0x80d93960
EXTRA=((0x702d6018,110),(0x702d6418,2),(0x702d67c0,156))
GUARD=0x70f87ad0
BOUND=200000


def ranges():return repair.ranges()+EXTRA
def data_ranges():return repair.data_ranges()+((GUARD,1),)


class Engine(repair.Engine):
    def packet_fails(self,ready):
        o=self.owner
        if o.app_kind:return self.command_index-o.app_base==self.full['app_ready_fail_at' if ready else 'app_done_fail_at']
        return super().packet_fails(ready)
    def read(self,at,size=4):
        pos=self.payload_at;value=super().read(at,size);o=self.owner
        if at==256 and o.app_kind:
            if self.opcode==15 and self.reg==192:o.app_status_reads+=1
            elif self.opcode==107:o.app_buffer[pos:pos+size]=value.to_bytes(size,'little')
        return value


class Model(repair.Model):
    engine_type=Engine
    def __init__(self,c):
        super().__init__(c);self.app_kind=None;self.app_base=0;self.app_calls=0;self.app_status_reads=0;self.app_sleep_calls=0
        self.app_loaded=0;self.app_dma_calls=0;self.app_buffer=bytearray(b'\xa5'*128);self.app_rows=[]
        self.engine.bounce=bytearray([c['app_bounce_byte']])*512
        b=self.engine.backends[1];b.c=b.c|dict(status_a=c['app_dma_a'],status_b=c['app_dma_b'],ticks=c['app_dma_ticks'])
    def get(self,reg):
        if not self.app_kind or reg!=192:return super().get(reg)
        values=self.c['app_statuses'];value=values[min(self.app_status_reads,len(values)-1)]
        self.transfer_packet(15,reg,1,False,bytearray((value,)),1,0);return 0,value
    def cache_read(self,column,n,physical):
        self.actions.append(f'probe_packet:107:{column}:{n}:0');e=self.engine;version=e.version();self.commands+=1
        e.command_index=self.commands;e.opcode=107;e.reg=column;e.payload=read.payload(physical,column,n);e.payload_at=0
        e.c['frame']=[0,0,107,1,1,column,1,2,3,n,8];status=e.command();stage='command';bounce=n>31 and version>1
        if not status:
            if bounce:self.app_dma_calls+=1;status=e.data(True,True);stage='receive_bounce'
            else:
                self.reads+=1;saved=e.buffer;e.buffer=bytearray(512);e.c['alignment']=0
                status=read.aux.joined.hal.boot.Model.data(e,True,False);e.buffer=saved;stage='receive_poll'
        if status:
            self.actions.extend(('log:'+stage+'_error','diagnostic'))
            raise read.aux.joined.prior.bus.boot.Stop(0x70a1bca8 if bounce else 0x70a1bc8c,361 if stage=='command' and bounce else 294 if stage=='command' else 374 if bounce else 305)
        if bounce:self.app_buffer[:n]=e.bounce[:n];self.actions.append('app_copy_from_bounce:'+str(n))
    def app_read(self,op):
        self.actions.append(f'app_read_native:{op["offset"]}:{op["command"]}:{op["size"]}')
        status,physical=self.map_value(op['offset'],True)
        if status:return -150
        if not op['data'] or not op['size'] or physical>=65536 or ((op['command']+op['size'])&0xffffffff)>2112:
            self.actions.append('log:app_read_result:-1');return -1
        self.app_loaded=physical;self.load(physical);_,status=self.busy();ecc=status&48==32
        if ecc:self.actions.append('app_page_retry:'+str(physical));self.compat()
        self.cache_read(op['command'],op['size'],physical)
        if ecc:self.actions.append('log:app_read_result:-101');return -101
        return 0
    def app_erase(self,op):
        self.actions.append('app_erase_native:'+str(op['offset']));status,physical=self.map_value(op['offset'])
        if status:result=-151
        elif physical>=1024:result=-1
        elif physical<self.guard_blocks:self.actions.append('log:app_erase_guard');result=-250
        else:
            self.transfer_packet(6,0,0,True,bytearray(),0,0);self.transfer_packet(216,physical*64,0,True,bytearray(),3,0)
            value=255
            for poll in range(20):
                self.actions.append('app_sleep:1');self.app_sleep_calls+=1;_,status=self.get(192)
                if poll==19:self.actions.append('log:busy_timeout');break
                if not status&1:value=status;break
            result=-104 if value&4 else 0
        if result:self.actions.append('log:app_erase_result:'+str(result))
        return result
    def operation(self,op):
        if op['op'] in ('app_read','app_erase'):
            self.app_calls+=1;self.app_kind=op['op'];self.app_base=self.commands
            try:result=self.app_read(op) if op['op']=='app_read' else self.app_erase(op)
            except read.aux.joined.prior.bus.boot.Stop as stop:self.stopped=stop.info;result=None
            finally:self.app_kind=None
            self.export_rows.append(dict(export_hex=self.export.hex(),export_calls=self.exports));self.map_rows.append(dict(map_output=self.mapped))
        else:result=super().operation(op)
        self.app_rows.append(self.full_snapshot()|self.aux_snapshot()|dict(app_buffer_hex=self.app_buffer.hex(),app_calls=self.app_calls,
            app_status_reads=self.app_status_reads,app_sleep_calls=self.app_sleep_calls,app_loaded=self.app_loaded,app_dma_calls=self.app_dma_calls,
            app_bounce_sha256=base.digest(self.engine.bounce)))
        return result
    def run(self):
        result=super().run()
        for row,app in zip(result['rows'],self.app_rows):row.update(app)
        return result


def contract(c,scope):
    if scope not in ('read','erase') or not c['native_main_async']:raise ValueError('main mode-zero entry')
    ops=c['operations'];app=[op for op in ops if op['op'] in ('app_read','app_erase')]
    if not app or len(ops)>12 or any(op['op']!='app_'+scope or not 0<=op['offset']<=0xffffffff or not 0<=op['command']<=0xffffffff or not 0<=op['size']<=64 for op in app):raise ValueError('bounded application operations')
    if not 0<=c['app_bounce_byte']<=255 or any(not 0<=c[k]<=32 for k in ('app_ready_fail_at','app_done_fail_at')):raise ValueError('application peripheral bounds')
    values=c['app_statuses']
    if not values or len(values)>20 or any(not 0<=v<=255 for v in values) or scope=='read' and values[-1]&1:raise ValueError('application status stream')
    for key in ('app_dma_a','app_dma_b','app_dma_ticks'):
        values=c[key]
        if not values or len(values)>16 or any(not 0<=v<=(0xffffffffffffffff if key.endswith('ticks') else 0xffffffff) for v in values):raise ValueError('DMA input bounds')
    if not (c['app_dma_a'][-1]&64 or c['app_dma_b'][-1]&64 or ((c['app_dma_ticks'][-1]-c['app_dma_ticks'][0])&0xffffffffffffffff)>1000):raise ValueError('DMA must finish within supplied stream')
    repair.contract(c|dict(operations=[op for op in ops if op not in app]),'program')
    return Model(c).run()


def native_vectors(scope='read'):
    cases=[];source=repair.native_vectors('program')['cases'][0];template=source['operations'][-1]
    def add(name,value=65,n=32,column=16,sequence=None,**changes):
        ops=[template|dict(op='app_'+scope,offset=v,size=count,command=col,data=present) for v,count,col,present in (sequence or [(value,n,column,True)])]
        c=source|dict(name='main_async_'+name,native_main_async=True,operations=source['operations']+ops,app_statuses=[0],app_bounce_byte=60,
            app_ready_fail_at=0,app_done_fail_at=0,app_dma_a=[64],app_dma_b=[0],app_dma_ticks=[0])|changes
        c.pop('expected',None);c['expected']=contract(c,scope);cases.append(c)
    if scope=='read':
        add('dma_ready');add('direct_one',n=1);add('direct_tail',n=13);add('direct_31',n=31);add('dma_64',n=64)
        add('dma_alternate',app_dma_a=[0],app_dma_b=[64]);add('dma_timeout',app_dma_a=[0],app_dma_ticks=[0,1001])
        add('dma_qspi_timeout',app_done_fail_at=3);add('old_rom_direct',full_rom_version='v1.1.03')
        add('ecc_after_dma',app_statuses=[32]);add('reserved',value=65216);add('null',sequence=[(65,32,16,False)])
        add('busy_ready',app_statuses=[1,0]);add('status_ready_timeout',app_ready_fail_at=2)
        add('direct_cache_ready_timeout',n=31,app_ready_fail_at=3)
        add('repeated_dma',sequence=[(65,32,16,True),(193,64,0,True)])
    elif scope=='erase':
        add('erase_ready',value=12);add('erase_busy_ready',value=12,app_statuses=[1,0]);add('erase_failed',value=12,app_statuses=[4])
        add('erase_exhausted',value=12,app_statuses=[1]);add('erase_ready_at_limit',value=12,app_statuses=[1]*19+[0])
        add('erase_ready_before_limit',value=12,app_statuses=[1]*18+[0]);add('erase_other_bits',value=12,app_statuses=[32])
        add('erase_guarded',value=4);add('erase_guard_boundary',value=5);add('erase_reserved',value=1019)
        add('erase_enable_timeout',value=12,app_done_fail_at=1);add('erase_command_timeout',value=12,app_done_fail_at=2)
        add('erase_status_ready_timeout',value=12,app_ready_fail_at=3);add('erase_status_done_timeout',value=12,app_done_fail_at=3)
    else:raise ValueError('mode-zero scope')
    return dict(schema=1,scope='nand',bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if repair.read.aux.inventory(mem)!=json.loads(repair.read.aux.FACTS.read_bytes()) or mem.read(GUARD,1)!=b'\1':raise ValueError('original main facts differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main mode-zero page read/private DMA or erase/sleep-poll follows actual BBT marker/read/CRC/erase/program/root. Original platform DMA records and setup/wait execute for large mode-zero reads.',
            'MMIO/status/ticks, initial bounce bytes and FIFO page inputs are authored. Cache/copy/sleep/pin/power/RTOS/BSP/heap/PM services remain supplied; DMA movement is not modeled and success can copy authored retained bounce bytes.',
            'Callback address is stored by the builder but not invoked by this bus path. IRQ-driven scheduling, physical data movement/coherency/timing/persistence, broader consumers, safe restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('read','erase'),default='read')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main mode-zero paths: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
