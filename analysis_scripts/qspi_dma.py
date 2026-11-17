#!/usr/bin/env python3
"""Connected actual QSPI/DMA software and NAND private-buffer paths."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import dma_backend as dma
    from . import qspi_hal as qspi
else:
    import dma_backend as dma
    import qspi_hal as qspi

BOUNCE=0x80dfb8c0
DMA_RANGES=((0x80c123ac,0x198),(0x80c12628,0x96),(0x80c126e0,0xba))
BOUNCE_RANGES=((0x80c27f3e,0x6a),(0x80c280d0,0x66))
RANGES=qspi.RANGES+DMA_RANGES+BOUNCE_RANGES
TARGETS=tuple(a for a,n in RANGES)
EXTRA_CONFIG=dict(dma_init=dma.CONFIG['init'],dma_tick=dma.CONFIG['tick'],dma_prepare=dma.CONFIG['prepare'],
    dma_finish=dma.CONFIG['finish'],cache_read_bounce=0x80c27f3e,cache_write_bounce=0x80c280d0,copy=0x80c2de38)


class Model(qspi.Model):
    def __init__(self,c):
        super().__init__(c);self.backends=[dma.Model(c['dma_tx']),dma.Model(c['dma_rx'])]
        self.backends[1].regs=self.backends[0].regs;self.backends[1].registry=self.backends[0].registry
        self.backends[1].actions=self.backends[0].actions;self.drained=0;self.bounce=bytearray(b'\xa5'*512)
    def drain(self):
        actions=self.backends[0].actions
        self.actions.extend('dma_'+a for a in actions[self.drained:]);self.drained=len(actions)
    def data(self,receive,dma_mode):
        if not dma_mode:raise ValueError('connected fixture requires DMA')
        c=self.c;backend=self.backends[int(receive)]
        data=BOUNCE if c['mode'].endswith('_bounce') else qspi.BUFFER+c['alignment']
        if not receive:self.write(32,self.read(32)|1)
        backend.setup(source=c['base']+0x100 if receive else data,dest=data if receive else c['base']+0x100,size=self.count());self.drain()
        if receive:self.write(32,self.read(32)|1)
        result=backend.wait();self.drain();self.write(32,self.read(32)&~1)
        return result if result else self.wait(36,1)
    def run(self):
        for backend in self.backends:
            if backend.init()!=0:raise ValueError('bounded DMA initializer')
            self.drain()
        return self.transfer()
    def transfer(self):
        c=self.c;mode=c['mode']
        receive='receive' in mode or 'read' in mode
        if mode.endswith('_bounce'):
            self.actions.append('version:2')
            if not receive:
                self.actions.append('copy_to_bounce:'+str(c['count']));self.bounce[:c['count']]=self.buffer[:c['count']]
            result=self.command()
        else:result=self.command() if mode.startswith('command_') else 0
        if not result:result=self.data(receive,True)
        if mode.endswith('_bounce'):
            if result:
                stage='receive_bounce_error' if receive else 'transmit_bounce_error'
                self.actions.extend(('log:'+stage,'diagnostic'));self.stopped=dict(kind='assertion',owner=0x80c37b98,line=0x16f if receive else 0x17b);result=None
            elif receive:
                self.actions.append('copy_from_bounce:'+str(c['count']));self.buffer[:c['count']]=self.bounce[:c['count']]
        return self.snapshot(result)
    def snapshot(self,result):
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=self.stopped,context_hex=self.context.hex(),
            buffer_sha256=qspi.digest(self.buffer),tx_hex='',rx_bytes=0,mmio={str(k):v for k,v in sorted(self.regs.items())},
            clock_word=self.clock,clock_shadow=self.shadow,dma_contexts_hex=[b.contexts[0].hex() for b in self.backends],
            dma_registry=self.backends[0].registry,dma_mmio={str(k):v for k,v in sorted(self.backends[0].regs.items())},
            bounce_sha256=qspi.digest(self.bounce))])


def contract(c):
    if not 0<=c['count']<=64 or c['alignment'] not in (0,1) or not c['done'] or not c['ticks']:raise ValueError('bounded connected QSPI fixture')
    if c['mode'].endswith('_bounce') and (c['count']<=31 or c['alignment']):raise ValueError('private-buffer fixture preconditions')
    return Model(c).run()


def native_vectors():
    cases=[];qbase=qspi.native_vectors()['cases'][0]
    profiles={c['name']:c for c in dma.native_vectors()['cases']}
    def add(name,mode='receive_dma',status='a',**changes):
        c=qbase|dict(name=name,mode=mode,native_dma=True,count=13,alignment=0)|changes
        receive='receive' in mode or 'read' in mode
        c['frame']=[0 if receive else 2,0,0x6b if receive else 0x32,1,1,c['address'],1,2,3,c['count'],8 if receive else 0]
        for is_rx,label in ((False,'tx'),(True,'rx')):
            profile=profiles['init_nand_'+label]
            p={k:v for k,v in profile.items() if k not in ('expected','context_hex')}
            p.update(descriptor_address=qspi.DMA[int(is_rx)],callback_a=False,callback_b=False,tracked_address=0,tracked_size=0,
                timeout=c['timeout'],ticks=[0],status_a=[1<<p['channel']],status_b=[0])
            if is_rx==receive:
                if status!='a':p['status_a']=[0]
                if status in ('b','both'):p['status_b']=[1<<p['channel']]
                if status=='both':p['status_a']=[1<<p['channel']]
                if status=='timeout':p['ticks']=[0,c['timeout']+1]
                if status=='wrap':p['ticks']=[0xfffffffffffffffe,1];p['timeout']=3;p['status_a']=[0,1<<p['channel']]
                if status=='at_limit':p['ticks']=[0,c['timeout']];p['status_a']=[0,1<<p['channel']]
            c['dma_'+label]=p;c['dma_'+label+'_hex']=dma.context(p,p['channel']).hex()
        c['expected']=contract(c);cases.append(c)
    for mode in ('receive_dma','transmit_dma'):
        add(mode+'_ready',mode);add('command_'+mode,'command_'+mode)
        add(mode+'_alternate',mode,status='b');add(mode+'_both',mode,status='both')
        add(mode+'_timeout',mode,status='timeout');add(mode+'_qspi_timeout',mode,done=[0],ticks=[0,1001])
        add(mode+'_zero',mode,count=0);add(mode+'_unaligned',mode,alignment=1)
        add(mode+'_counter_wrap',mode,status='wrap',timeout=3)
    for mode in ('cache_read_bounce','cache_write_bounce'):
        add(mode+'_ready',mode,count=64);add(mode+'_alternate',mode,status='b',count=64)
        add(mode+'_dma_timeout',mode,status='timeout',count=64)
        add(mode+'_qspi_timeout',mode,count=64,done=[0],ticks=[0,1001])
    for mode in ('receive_dma','transmit_dma'):
        add(mode+'_two_wait_budgets',mode,status='at_limit',done=[0,1],ticks=[1000,2000])
    return dict(schema=1,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();execution=json.loads(validation.read_bytes())
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if execution['hardware_execution'] is not False or execution['case_count']!=len(expected['cases']) or len(execution['cases'])!=len(expected['cases']):raise ValueError('case count')
    for row,c in zip(execution['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=100000:raise ValueError('native mismatch/bound')
    memory=qspi.image_memory(archive)
    return dict(boot_sha256=qspi.BOOT_HASH,vectors_sha256=qspi.digest(vectors.read_bytes()),validation_sha256=qspi.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':qspi.digest(memory.read(a,n)) for a,n in RANGES},
        export_sha256={f'{a:08x}.c':qspi.digest((decompiled/f'{a:08x}.c').read_bytes()) for a in TARGETS},
        native_validation=execution,native_steps=sum(r['steps'] for r in execution['cases']),limitations=[
            'Actual QSPI DMA wrappers, command completion and DMA init/setup/wait execute together; selected NAND private-buffer builders also connect through actual bus/HAL/backend.',
            'Peripheral status, timestamps, cache/copy services, ROM version and descriptor backing are authored. Physical DMA data movement is intentionally not simulated.',
            'Successful control-path return does not establish delivered data; unchanged/sentinel receive buffers are fixture outcomes.',
            'IRQ entry/delivery, real cache coherency, board wiring/timing, physical persistence and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect connected QSPI DMA: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
