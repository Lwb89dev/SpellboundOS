#!/usr/bin/env python3
"""Original main DMA backend joined to QSPI wrappers and NAND bounce packets."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_dma_backend as dma
    from . import main_qspi_bus as bus
    from . import qspi_dma as prior
else:
    import main_dma_backend as dma
    import main_qspi_bus as bus
    import qspi_dma as prior

hal=bus.hal
base=hal.base
DMA_RANGES=tuple(row for row in dma.RANGES if row[0] in (dma.CONFIG['init'],dma.CONFIG['setup'],dma.CONFIG['wait']))


def ranges():return bus.ranges()+DMA_RANGES
def data_ranges():return bus.data_ranges()


class Model(bus.Model):
    def __init__(self,c):
        super().__init__(c);self.backends=[dma.Model(c['dma_tx']),dma.Model(c['dma_rx'])]
        self.backends[1].regs=self.backends[0].regs;self.backends[1].registry=self.backends[0].registry
        self.backends[1].actions=self.backends[0].actions;self.drained=0
    def drain(self):
        actions=self.backends[0].actions;self.actions.extend('dma_'+a for a in actions[self.drained:]);self.drained=len(actions)
    def data(self,receive,dma_mode):
        if not dma_mode:raise ValueError('main integration requires DMA wrapper')
        c=self.c;backend=self.backends[int(receive)];data=bus.BOUNCE if c['mode']=='bus' else hal.boot.BUFFER+c['alignment']
        if not receive:self.write(32,self.read(32)|1)
        backend.setup(source=c['base']+0x100 if receive else data,dest=data if receive else c['base']+0x100,size=self.count());self.drain()
        if receive:self.write(32,self.read(32)|1)
        result=backend.wait();self.drain();self.write(32,self.read(32)&~1)
        return result if result else self.wait(36,1)
    def run(self):
        for backend in self.backends:
            if backend.init()!=0:raise ValueError('main DMA initializer fixture')
            self.drain()
        result=bus.Model.run(self) if self.c['mode']=='bus' else hal.Model.run(self)
        row=result['rows'][0];row.update(dma_contexts_hex=[b.contexts[0].hex() for b in self.backends],dma_registry=self.backends[0].registry,
            dma_mmio={str(k):v for k,v in sorted(self.backends[0].regs.items())},bounce_sha256=base.digest(self.bounce))
        return result


def contract(c):
    if c['mode']=='bus':bus.contract(c)
    elif c['mode'] in ('receive_dma','transmit_dma','command_receive_dma','command_transmit_dma'):hal.contract(c)
    else:raise ValueError('connected main DMA entry')
    for i,label in enumerate(('tx','rx')):
        p=c['dma_'+label];dma.contract(p)
        if p['base']!=0x93080000 or p['channel']!=5+i or p['direction']!=2-i or p['descriptor_address']!=hal.boot.DMA[i]:raise ValueError('main DMA binding fixture')
        if p['callback_a'] or p['callback_b'] or p['timeout']!=c['timeout']:raise ValueError('main DMA call fixture')
        if c['dma_'+label+'_hex']!=dma.boot.context(p,p['channel']).hex():raise ValueError('main DMA descriptor bytes')
    if c['mode']=='bus' and (c['bus']['force_block'] or c['bus']['size']<=31 or c['alignment'] or c['rom_version']!='v1.1.16'):raise ValueError('main bounce fixture')
    return Model(c).run()


def native_vectors():
    cases=[]
    for original in prior.native_vectors()['cases']:
        c=original|dict(name='main_qspi_dma_'+original['name'],rom_version='v1.1.16')
        frame=c['frame'];c['bus']=bus.bus.DEFAULT|dict(force_block=0,size=c['count'],opcode=frame[2],write_byte=int(bool(frame[0])),dummy_byte=int(bool(frame[10])),data_lines=frame[8])
        if c['mode'].endswith('_bounce'):c['mode']='bus'
        c.pop('expected');c['expected']=contract(c);cases.append(c)
    return dict(schema=1,bound_per_case=hal.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=hal.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=hal.BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main DMA init/setup/wait, QSPI command/completion/DMA wrappers and selected NAND bounce packets execute together over authored controller/descriptor/MMIO/timer/ROM inputs.',
            'Cache/copy services and physical DMA movement remain outside execution. Successful status may leave unchanged/sentinel receive bytes; this fixture does not model data delivery.',
            'Main IRQ dispatch, full original platform/probe/root DMA bindings, real cache coherency/peripheral timing, UID/BBT/media, persistence, restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main QSPI/DMA: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
