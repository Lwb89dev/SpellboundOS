#!/usr/bin/env python3
"""Original main probe/root through actual platform, ID/feature QSPI FIFO and DMA init."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_nand_bus_probe as prior
    from . import main_nand_platform as platform
else:
    import main_nand_bus_probe as prior
    import main_nand_platform as platform

probe=prior.probe
hal=platform.hal
base=probe.base
BOUND=30000


def ranges():return tuple(dict.fromkeys(probe.ranges('root')+platform.ranges()))
def data_ranges():return tuple(dict.fromkeys(probe.data_ranges('root')+hal.DATA_RANGES))


class Engine(platform.Model):
    def __init__(self,c,features):
        config=platform.native_vectors('init')['cases'][0]|dict(clock_word=c['full_clock_word'],pin_status=c['full_pin_status'],rom_version=c['full_rom_version'])
        super().__init__(config);self.full=c;self.features=features;self.command_index=0;self.opcode=0;self.reg=0;self.payload=b'';self.payload_at=0
    def tick(self):
        value=self.ticks*1001;self.ticks+=1;self.actions.append('tick:'+str(value));return value
    def read(self,at,size=4):
        if at==0x100:
            if self.payload_at+size>len(self.payload):raise ValueError('probe FIFO response bound')
            value=int.from_bytes(self.payload[self.payload_at:self.payload_at+size],'little');self.payload_at+=size;self.rx+=size
        elif at in (24,36):
            fail=self.full['full_ready_fail_at' if at==24 else 'full_done_fail_at']
            value=0 if self.command_index==fail else (3 if at==24 else 1);self.regs[at]=value
        else:return super().read(at,size)
        self.actions.append(f'r:{at}:{size}:{value}');return value
    def write(self,at,value,size=4):
        super().write(at,value,size)
        if at==0x100 and self.opcode==0x1f:self.features[self.reg]=value&255


class Model(prior.Model):
    engine_type=Engine
    def __init__(self,c):
        super().__init__(c);self.engine=self.engine_type(c,self.features);self.engine.actions=self.actions
    def initialize_bus(self,index):
        self.bus_calls+=1;self.actions.append(f'probe_bus_native:{index}');self.engine.c['bus_word']=prior.BUS_WORDS[index];self.engine.initialize()
    def packet(self,opcode,address,size,write,local):
        return self.transfer_packet(opcode,address,size,write,local,int(bool(size)),0)
    def transfer_packet(self,opcode,address,size,write,local,address_bytes,dummy):
        self.actions.append(f'probe_packet:{opcode}:{address}:{size}:{int(write)}')
        if self.c['bus_disabled']:
            owner,line={0x9f:(0x70a30fa4,383),0xff:(0x70a30f94,402),0x1f:(0x70a31114,74),0x0f:(0x70a3112c,55)}[opcode]
            raise prior.bus.boot.Stop(owner,line)
        self.commands+=1;e=self.engine;e.command_index=self.commands;e.opcode=opcode;e.reg=address;e.payload=bytes(local);e.payload_at=0
        e.version();e.c['frame']=[2 if write else 0,0,opcode,1,1,address,1,address_bytes,1,size,8 if dummy else 0]
        status=e.command();stage='command'
        if not status and size:
            if write:self.writes+=1
            else:self.reads+=1
            saved=e.buffer;e.buffer=bytearray(512);e.buffer[:len(local)]=local;e.c['alignment']=0
            status=hal.boot.Model.data(e,not write,False);e.buffer=saved;stage='transmit_poll' if write else 'receive_poll'
        if status:
            self.actions.extend(('log:'+stage+'_error','diagnostic'))
            raise prior.bus.boot.Stop(0x70a1bc8c,{'command':294,'receive_poll':305,'transmit_poll':313}[stage])
    def run(self):
        result=probe.Model.run(self);e=self.engine
        for row in result['rows']:row.update(full_controller_hex=e.context.hex(),full_dma_contexts_hex=[b.contexts[0].hex() for b in e.backends],
            full_dma_registry=e.backends[0].registry,full_dma_mmio={str(k):v for k,v in sorted(e.backends[0].regs.items())},
            full_mmio={str(k):v for k,v in sorted(e.regs.items())},full_board_mmio={str(k):v for k,v in sorted(e.board.items())},
            full_clock_word=e.clock,full_clock_shadow=e.shadow,full_commands=self.commands,full_reads=self.reads,full_writes=self.writes,
            full_rx_bytes=e.rx,full_tx_hex=e.tx.hex())
        return result


def contract(c):
    if not c['native_main_full_probe']:raise ValueError('full probe entry')
    if any(c[k] for k in ('bus_command_fail_at','bus_read_fail_at','bus_write_fail_at','bus_disable_after','bus_init_status')):raise ValueError('supplied HAL faults outside full scope')
    if any(not 0<=c[k]<=100 for k in ('full_ready_fail_at','full_done_fail_at')):raise ValueError('full probe failure bound')
    if not 0<=c['full_clock_word']<=0xffffffff or not -100<=c['full_pin_status']<=100:raise ValueError('full platform inputs')
    if c['full_rom_version'] not in ('v1.1.03','v1.1.16','unknown'):raise ValueError('full ROM fixture')
    prior.contract(c)
    return Model(c).run()


def native_vectors(scope='root'):
    cases=[];initial=prior.native_vectors()['cases'][0];chips=probe.facts()['chips']
    def add(name,index=0,**changes):
        c=initial|dict(name='main_full_'+name,probe_id=chips[index]['id'],native_main_full_probe=True,full_clock_word=0xa5a5b5a5,
            full_pin_status=0,full_rom_version='v1.1.16',full_ready_fail_at=0,full_done_fail_at=0)|changes
        c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    if scope=='root':
        for i in range(11):add('chip_'+str(i),i)
        add('append',main_seed='other');add('duplicate',main_seed='duplicate');add('no_pm',main_pm_property=False)
        add('no_bbt',probe_bbt_return=1,main_bbt_magic=0)
    elif scope=='faults':
        add('second_round',probe_delayed_rounds=1);add('last_33rd',10,probe_delayed_rounds=2);add('no_match',probe_id=[255]*5)
        add('disabled',bus_disabled=True);add('id_ready_timeout',full_ready_fail_at=1);add('reset_done_timeout',full_done_fail_at=2)
        add('feature_write_done_timeout',full_done_fail_at=3);add('feature_read_ready_timeout',full_ready_fail_at=4)
        add('feature_mismatch',probe_feature_mismatch_at=1);add('missing_regulator',probe_regulator_present=False)
        add('pin_status_ignored',full_pin_status=-9);add('allocation_error',main_alloc_fail=True)
    else:raise ValueError('full probe scope')
    return dict(schema=1,scope='nand',bound_per_case=BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation,scope):
    expected=native_vectors(scope);report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if probe.inventory(mem)!=probe.facts() or platform.facts(mem)!=json.loads(platform.FACTS.read_bytes()):raise ValueError('original main facts differ')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=BOUND:raise ValueError('native mismatch')
    return dict(scope=scope,main_sha256=base.MAIN_HASH,inventory_sha256=base.digest(probe.FACTS.read_bytes()),startup_facts_sha256=base.digest(platform.FACTS.read_bytes()),
        vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main root/probe/matcher/ID/reset/feature/platform/clock/QSPI FIFO/revision/DMA-init and registry/PM/geometry consumers execute together with all original descriptors and bindings unchanged.',
            'MMIO/reset/status/ticks, FIFO IDs/features and ROM string are authored. Power/pin/GPIO/workaround/UID/BBT/BSP/RTOS/heap/PM bodies remain supplied; these short packets do not execute DMA setup/wait or establish media recovery.',
            'Single-thread ordering, software geometry and publication do not establish physical chip identity, IRQ/cache/coherency, elapsed timing, persistence, safe restoration or standalone boot.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?');p.add_argument('--scope',choices=('root','faults'),default='root')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(a.scope),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation,a.scope)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect full main probe: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
