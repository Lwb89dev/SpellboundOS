#!/usr/bin/env python3
"""Main NAND bus/feature packets through original QSPI HAL/FIFO and DMA wrappers."""
import argparse
import json
from pathlib import Path
import zipfile

if __package__:
    from . import main_qspi_hal as hal
    from . import main_nand_bus as bus
else:
    import main_qspi_hal as hal
    import main_nand_bus as bus

base=hal.base
BOUNCE=bus.BOUNCE
PACKET=0x81306000


def ranges():return tuple(dict.fromkeys(hal.RANGES+bus.RANGES))
def data_ranges():return hal.DATA_RANGES+bus.DATA_RANGES


class Model(hal.Model):
    def __init__(self,c):
        super().__init__(c);self.c=c.copy();self.bounce=bytearray(b'\xa5'*512)
    def run(self):
        c=self.c;p=bus.Model(c['bus']).packet(c['bus']['mode']);n=p['size'];write=bool(p['write'])
        revision=self.version();bounce=not p['force'] and n>31 and revision>1
        original=self.buffer;offset=c['alignment'];source=bytearray((c['bus']['feature_value']&255,)) if c['bus']['mode']=='write_feature' else original
        if bounce and write and n:self.actions.append(f'copy_to_bounce:{n}');self.bounce[:n]=source[offset:offset+n]
        c['frame']=[2 if write else 0,0,p['opcode'],1,p['command_lines'],p['address'],1,p['address_bytes'],p['data_lines'],n,8 if p['dummy'] else 0]
        result=self.command();stage='command'
        if not result and n:
            self.buffer=self.bounce if bounce else source;c['alignment']=0 if bounce or c['bus']['mode']=='write_feature' else offset
            stage=('transmit_' if write else 'receive_')+('bounce' if bounce else 'poll')
            result=self.data(not write,bounce);self.buffer=original
            if bounce and not write and not result:self.actions.append(f'copy_from_bounce:{n}');original[offset:offset+n]=self.bounce[:n]
        if result:
            self.actions.extend(('log:'+stage+'_error','diagnostic'))
            self.stopped=dict(kind='assertion',owner=0x70a1bca8 if bounce else 0x70a1bc8c,
                line={'command':361 if bounce else 294,'receive_bounce':374,'receive_poll':305,'transmit_bounce':386,'transmit_poll':313}[stage])
            result=None
        return dict(actions=self.actions,rows=[dict(returned=result,stopped=self.stopped,context_hex=self.context.hex(),
            buffer_sha256=base.digest(self.buffer),tx_hex=self.tx.hex(),rx_bytes=self.rx,mmio={str(k):v for k,v in sorted(self.regs.items())},
            clock_word=self.clock,clock_shadow=self.shadow,bounce_sha256=base.digest(self.bounce))])


def contract(c):
    if c['mode']!='bus' or c['bus']['mode'] not in ('transfer','read_feature','write_feature'):raise ValueError('main bus/HAL entry')
    if c['bus']['reinit'] or c['bus']['disabled'] or any(c['bus'][k] for k in ('command_status','read_status','write_status')):raise ValueError('supplied bus state outside connected HAL scope')
    if not c['context_present'] or not c['base_present'] or not c['frame_present']:raise ValueError('initialized controller fixture')
    if c['bus']['size']>64 or c['bus']['mode']!='transfer' and c['alignment']!=0:raise ValueError('bounded connected packet')
    bus.contract(c['bus']);hal.contract(c|dict(mode='command'))
    return Model(c).run()


def native_vectors():
    cases=[];initial=next(c for c in hal.native_vectors()['cases'] if c['name']=='main_hal_command_read')
    def add(name,packet=None,**changes):
        c=initial|dict(name='main_qspi_bus_'+name,mode='bus',bus=bus.DEFAULT|(packet or {}))|changes
        c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    add('read');add('write',dict(write_byte=1));add('unaligned',alignment=1)
    add('bounce_read',dict(force_block=0));add('bounce_write',dict(force_block=0,write_byte=1))
    add('threshold_31',dict(force_block=0,size=31));add('threshold_32',dict(force_block=0,size=32))
    add('old_revision_direct',dict(force_block=0),rom_version='v1.1.03');add('unknown_revision_direct',dict(force_block=0),rom_version='unknown')
    add('empty',dict(size=0));add('empty_timeout',dict(size=0),done=[0],ticks=[0,1001])
    add('receive_timeout',ready=[0],ticks=[0,1001]);add('transmit_timeout',dict(write_byte=1),ready=[0],ticks=[0,1001])
    add('receive_completion_timeout',dict(size=1),done=[0],ticks=[0,0,1001]);add('transmit_completion_timeout',dict(write_byte=1,size=1),done=[0],ticks=[0,0,1001])
    add('bounce_receive_wait_error',dict(force_block=0),dma_wait_status=-9);add('bounce_transmit_wait_error',dict(force_block=0,write_byte=1),dma_wait_status=-9)
    add('bounce_receive_setup_ignored',dict(force_block=0),dma_setup_status=-9);add('bounce_transmit_setup_ignored',dict(force_block=0,write_byte=1),dma_setup_status=-9)
    add('feature_read',dict(mode='read_feature'));add('feature_write',dict(mode='write_feature'));add('feature_truncates',dict(mode='write_feature',feature_value=0x1a5))
    add('feature_read_timeout',dict(mode='read_feature'),done=[0],ticks=[0,0,1001]);add('feature_write_timeout',dict(mode='write_feature'),done=[0],ticks=[0,0,1001])
    return dict(schema=1,bound_per_case=hal.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if bus.probe.inventory(mem)!=bus.probe.facts():raise ValueError('original main inventory differs')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=hal.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=hal.BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main bus/feature builders, revision policy and QSPI HAL/FIFO/DMA wrappers execute over an authored initialized controller, MMIO/timer/ROM string and DMA/copy/diagnostic services.',
            'This scope does not execute platform/probe/root initialization. The original bus binding and first selected descriptor are immutable; physical chip identity and DMA completion are not established.',
            'Actual DMA backend/cache coherency, peripheral timing, UID/BBT/media, persistence, restoration and standalone boot remain open.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect main bus/HAL: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
