#!/usr/bin/env python3
"""Original main NAND platform, adjacent DMA records and reinitialized transfers."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_qspi_dma as integrated
else:
    import main_qspi_dma as integrated

hal=integrated.hal
base=hal.base
DMA=(0x80c10df4,0x80c10db0)
DESC=0x81307000
FACTS=Path(__file__).resolve().parents[1]/'analysis/main-nand-platform-facts.json'
BOARD=(0x9a000004,0x9a00000c)


def ranges():return integrated.ranges()
def data_ranges():return integrated.data_ranges()
def facts(memory):
    zero=next(r for r in memory.regions if r['kind']=='zero' and r['destination']<=DMA[1] and DMA[0]+68<=r['destination']+r['size'])
    return dict(main_sha256=base.MAIN_HASH,hardware_execution=False,dma_addresses=list(DMA),observed_record_bytes=68,
        startup_zero_region=zero,startup_sha256=[base.digest(memory.read(p,68)) for p in DMA],controller=hal.CTRL,
        reinit=0x80c10e38,disabled=0x80c10e39,board_addresses=list(BOARD))


class Model(integrated.Model):
    def __init__(self,c):
        super().__init__(c|dict(mode='bus'));self.context=bytearray(64);struct.pack_into('<I',self.context,16,c['controller_mode'])
        self.board=dict(zip(BOARD,c['board_initial']));self.reinit=int(c['defer_reinit']);self.disabled=int(c['platform_disabled'])
        for i,b in enumerate(self.backends):b.address=DMA[i];b.contexts[0]=bytearray([c['initial_dma_byte']])*68
    def board_read(self,p):
        value=self.board[p];self.actions.append(f'board_r:{p}:{value}');return value
    def board_write(self,p,v):
        self.board[p]=v&0xffffffff;self.actions.append(f'board_w:{p}:{v&0xffffffff}')
    def initialize(self):
        c=self.c;selector=2 if c['bus_word']<100 else 1;old=self.clock;self.actions.append('clock_read:'+str(old))
        self.shadow=(old&0xffff0fff)|(selector<<12)
        if selector!=((old>>12)&15):self.clock=self.shadow;self.actions.append('clock_write:'+str(self.clock))
        struct.pack_into('<I',self.context,0,0x93240000);struct.pack_into('<II',self.context,8,0,0)
        self.board_write(BOARD[1],self.board_read(BOARD[1])&~0x200);self.board_write(BOARD[1],self.board_read(BOARD[1])|0x200)
        self.actions.extend((f'platform_pinmux:{c["pin_status"]}',f'platform_gpio:{c["pin_status"]}','fence'))
        self.board_write(BOARD[0],self.board_read(BOARD[0])|0x200);self.init();self.actions.append('fence')
        self.board_write(BOARD[0],self.board_read(BOARD[0])|8)
        for i,b in enumerate(self.backends):
            words=[b.c[k] for k in ('request','direction','source_increment','dest_increment','source_width','dest_width','burst','priority','base','channel')]
            struct.pack_into('<10I',b.contexts[0],0,*words);b.init();self.drain()
            struct.pack_into('<I',self.context,32+i*4,DMA[i]);b.put(44,hal.CTRL)
    def snapshot(self,result):
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=self.stopped,context_hex=self.context.hex(),buffer_sha256=base.digest(self.buffer),
            tx_hex=self.tx.hex(),rx_bytes=self.rx,mmio={str(k):v for k,v in sorted(self.regs.items())},clock_word=self.clock,clock_shadow=self.shadow,
            dma_contexts_hex=[b.contexts[0].hex() for b in self.backends],dma_registry=self.backends[0].registry,
            dma_mmio={str(k):v for k,v in sorted(self.backends[0].regs.items())},bounce_sha256=base.digest(self.bounce),
            board_mmio={str(k):v for k,v in sorted(self.board.items())},reinit_flag=self.reinit,disabled_flag=self.disabled)])
    def run(self):
        c=self.c
        if c['platform_operation']=='init':self.initialize();return self.snapshot(0)
        if not c['defer_reinit'] or c['initialize_before_defer']:self.initialize()
        if self.disabled:return self.snapshot(0xffffffff)
        if self.reinit:self.reinit=0;self.initialize()
        result=integrated.bus.Model.run(self)
        return self.snapshot(result['rows'][0]['returned'])


def contract(c,scope):
    if scope not in ('init','transfer') or c['mode']!='platform' or c['platform_operation']!=scope:raise ValueError('main platform entry')
    if c['initial_dma_byte'] not in (0,165) or not 0<=c['bus_word']<=0xffffffff or not -100<=c['pin_status']<=100:raise ValueError('platform fields')
    if len(c['board_initial'])!=2 or any(not 0<=v<=0xffffffff for v in c['board_initial']):raise ValueError('board backing')
    if c['controller_mode'] not in (0,1) or c['alignment'] or not 0<=c['bus']['size']<=64:raise ValueError('platform controller/payload')
    hal.contract(c|dict(mode='command'))
    if c['bus']['mode']!='transfer' or c['bus']['reinit'] or c['bus']['disabled'] or any(c['bus'][key] for key in ('command_status','read_status','write_status')):raise ValueError('actual platform bus scope')
    for i,label in enumerate(('tx','rx')):
        p=c['dma_'+label];integrated.dma.contract(p)
        if p['descriptor_address']!=DMA[i] or p['channel']!=5+i or p['base']!=0x93080000 or p['direction']!=2-i:raise ValueError('original DMA bindings')
        if tuple(p[key] for key in ('request','source_increment','dest_increment','source_width','dest_width','burst','priority'))!=(12,0 if i==0 else 2,2 if i==0 else 0,0,0,6,1):raise ValueError('original DMA public fields')
        if p['timeout']!=c['timeout'] or p['callback_a'] or p['callback_b']:raise ValueError('platform DMA calls')
    if scope=='transfer':
        if c['bus']['force_block'] or c['bus']['size']<=31 or c['rom_version']!='v1.1.16':raise ValueError('platform bounce fixture')
    return Model(c).run()


def native_vectors(scope='init'):
    cases=[];profiles={c['name']:c for c in integrated.native_vectors()['cases']}
    initial=profiles['main_qspi_dma_cache_read_bounce_ready']
    def add(name,source=initial,**changes):
        c=source|dict(name='main_platform_'+name,mode='platform',platform_operation=scope,bus_word=104,initial_dma_byte=0,
            defer_reinit=False,initialize_before_defer=False,platform_disabled=False,pin_status=0,board_initial=[0x1000001,0x20000001])|changes
        for i,label in enumerate(('tx','rx')):c['dma_'+label]=c['dma_'+label]|dict(descriptor_address=DMA[i])
        c.pop('expected',None);c['expected']=contract(c,scope);cases.append(c)
    if scope=='init':
        add('init');add('clock_83',bus_word=83);add('clock_99',bus_word=99);add('clock_100',bus_word=100)
        add('poisoned_private_fields',initial_dma_byte=165);add('controller_mode_one',controller_mode=1)
        add('pin_status_ignored',pin_status=-9);add('init_retains_flags',defer_reinit=True,platform_disabled=True)
    elif scope=='transfer':
        for label in ('cache_read_bounce','cache_write_bounce'):
            for ending in ('ready','alternate','dma_timeout','qspi_timeout'):
                add(label+'_'+ending,profiles['main_qspi_dma_'+label+'_'+ending])
        add('deferred_reinit_read',defer_reinit=True,bus_word=83)
        add('deferred_reinit_write',profiles['main_qspi_dma_cache_write_bounce_ready'],defer_reinit=True)
        add('poisoned_transfer',initial_dma_byte=165);add('disabled_keeps_reinit',defer_reinit=True,platform_disabled=True)
        add('reinit_after_initialized',defer_reinit=True,initialize_before_defer=True,initial_dma_byte=165)
        add('disabled_after_initialized',defer_reinit=True,initialize_before_defer=True,platform_disabled=True)
    else:raise ValueError('platform scope')
    return dict(schema=1,bound_per_case=hal.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if facts(mem)!=json.loads(FACTS.read_bytes()):raise ValueError('startup facts differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=hal.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=hal.BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,startup_facts_sha256=base.digest(FACTS.read_bytes()),vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main platform/clock/QSPI/DMA initialization uses original adjacent 68-byte records and publishes reciprocal links; selected NAND bounce transfers join actual backend and revision bodies.',
            'The first original chip descriptor is cloned only to vary its bus word. Controller mode, private poison, MMIO/reset/status/timestamps and ROM string are authored; pin/GPIO/cache/copy services remain supplied.',
            'Observed record extents and startup zeroing do not establish complete object allocation, physical pin mapping, DMA movement/coherency, IRQ delivery, full probe/root/media operation, restoration or standalone boot.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('init','transfer'),default='init')
    for key in ('facts-output','vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not a.archive:p.error('need archive')
        with zipfile.ZipFile(a.archive) as z:
            if a.facts_output:a.facts_output.write_text(json.dumps(facts(base.image_memory(z)),indent=2,sort_keys=True)+'\n');return
            if not all((a.decompiled,a.vectors,a.validation)):p.error('need decompiled/vectors/validation')
            result=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main platform: {e}\n')
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
