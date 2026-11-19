#!/usr/bin/env python3
"""Actual main candidate probe and feature packets joined to original bus/platform."""
import argparse
import json
from pathlib import Path
import struct
import zipfile

if __package__:
    from . import main_nand_bus as bus
else:
    import main_nand_bus as bus

probe=bus.probe
base=probe.base
BUS_WORDS=(104,104,104,104,104,83,104,83,83,83,83)


def ranges():return tuple(dict.fromkeys(probe.ranges('root')+bus.RANGES))
def data_ranges():return probe.data_ranges('root')


class Model(probe.Model):
    def __init__(self,c):
        super().__init__(c,'root')
        config=bus.DEFAULT|dict(rom_revision=c['bus_revision'],disabled=c['bus_disabled'],reinit=False,
            init_status=c['bus_init_status'],command_status=0,read_status=0,write_status=0,mmio=[0x1000001,0x20000001])
        self.bus=bus.Model(config);self.bus.actions=self.actions;self.commands=0;self.reads=0;self.writes=0
    def initialize_bus(self,index):
        self.bus_calls+=1;self.actions.append(f'probe_bus_native:{index}');self.bus.c['bus_word']=BUS_WORDS[index];self.bus.init()
    def run_workaround(self):self.actions.append(f'probe_workaround:{self.c["probe_workaround_return"]}')
    def run_uid(self):self.actions.append(f'probe_uid:{self.c["probe_uid_return"]}')
    def run_bbt(self,chip):self.actions.append(f'probe_bbt:{chip["blocks"]}:{chip["page_size"]}:{chip["pages_per_block"]}:{self.c["probe_bbt_return"]}')
    def packet(self,opcode,address,size,write,local):
        self.actions.append(f'probe_packet:{opcode}:{address}:{size}:{int(write)}')
        if self.bus.c['disabled']:
            owner,line={0x9f:(0x70a30fa4,383),0xff:(0x70a30f94,402),0x1f:(0x70a31114,74),0x0f:(0x70a3112c,55)}[opcode]
            raise bus.boot.Stop(owner,line)
        self.commands+=1;self.bus.c['command_status']=-9 if self.commands==self.c['bus_command_fail_at'] else 0
        # Command failure precedes the corresponding data call.
        data_call=not self.bus.c['command_status'] and bool(size)
        if data_call:
            if write:self.writes+=1
            else:self.reads+=1
        self.bus.c['read_status']=-9 if data_call and not write and self.reads==self.c['bus_read_fail_at'] else 0
        self.bus.c['write_status']=-9 if data_call and write and self.writes==self.c['bus_write_fail_at'] else 0
        self.bus.c['responses']=[local[0] if local else 0]
        packet=dict(write=int(write),dummy=0,force=1,opcode=opcode,command_lines=1,address=address,address_bytes=int(bool(size)),data_lines=1,size=size)
        # ID returns exact authored bytes. Read traces contain status/count, not bytes.
        response=bytes(local);self.bus.transfer(packet,local)
        if not write and size:local[:]=response
        if self.commands==self.c['bus_disable_after']:self.bus.c['disabled']=True
    def probe(self):
        c=self.c;self.actions.append('main_probe_native');self.regulator=probe.POWER if c['probe_regulator_present'] else 0
        self.actions.append(f'probe_regulator:{int(bool(self.regulator))}')
        if self.regulator:self.actions.extend((f'probe_disable:{c["probe_power_status"]}','probe_delay:20',f'probe_enable:{c["probe_power_status"]}','probe_delay:20'))
        else:self.actions.append('log:probe_regulator_missing')
        self.selected=0
        try:
            for _ in range(3):
                for i,chip in enumerate(self.table):
                    self.initialize_bus(i)
                    self.id_reads+=1;data=[255]*5 if self.id_reads<=11*c['probe_delayed_rounds'] else c['probe_id']
                    self.packet(0x9f,0,5,False,bytearray(data))
                    if probe.match(chip['id'],data)==0:self.selected=chip['address'];break
                if self.selected:break
            if not self.selected:self.actions.extend(('log:probe_no_match','log:probe_error'));return -4
            chip=next(p for p in self.table if p['address']==self.selected)
            self.chip=dict(address=chip['address'],id=chip['id'][0]|chip['id'][1]<<8,pages=chip['pages'],page_size=chip['page_size'])
            self.packet(chip['reset_opcode'],0,0,True,bytearray())
            self.actions.append(f'probe_delay:{chip["reset_delay_us"]//1000+1}');self.run_workaround();self.actions.append('log:probe_chip_summary')
            if chip['uid']:self.run_uid()
            for reg,value in chip['features']:
                self.packet(0x1f,reg,1,True,bytearray((value,)));self.features[reg]=value;self.feature_reads+=1
                got=value^int(self.feature_reads==c['probe_feature_mismatch_at'])
                self.packet(0x0f,reg,1,False,bytearray((got,)))
                if got!=value:self.actions.extend(('log:probe_feature_mismatch','log:probe_error'));return -7
            self.run_bbt(chip)
            self.guard_pages=0x100000//chip['page_size'];self.guard_blocks=self.guard_pages//chip['pages_per_block'];self.actions.append('log:probe_guard');return 0
        except bus.boot.Stop as stop:self.stopped=stop.info;return None
    def run(self):
        result=super().run()
        for row in result['rows']:row.update(bus_reinit=self.bus.reinit,bus_disabled=int(self.bus.c['disabled']),bus_commands=self.commands,
            bus_reads=self.reads,bus_writes=self.writes,bus_controller_hex=self.bus.controller.hex(),
            bus_dma_sha256=[base.digest(d) for d in self.bus.dma],bus_mmio=self.bus.mmio)
        return result


def contract(c):
    if not c['native_main_bus'] or not c['native_main_root']:raise ValueError('connected bus entry')
    if any(not 0<=c[k]<=100 for k in ('bus_command_fail_at','bus_read_fail_at','bus_write_fail_at','bus_disable_after')):raise ValueError('bus call bounds')
    if not 0<=c['bus_revision']<=0xffffffff or not -100<=c['bus_init_status']<=100:raise ValueError('bus services')
    if any(c[k] for k in ('probe_bus_fail_at','probe_id_fail_at','probe_reset_fail','probe_feature_write_fail_at','probe_feature_read_fail_at')):raise ValueError('supplied probe faults are outside native bus scope')
    probe.contract(c,'root')
    return Model(c).run()


def native_vectors():
    cases=[];initial=probe.native_vectors('root')['cases'][0];chips=probe.facts()['chips']
    def add(name,index=0,**changes):
        c=initial|dict(name='main_bus_probe_'+name,native_main_bus=True,probe_id=chips[index]['id'],bus_revision=2,bus_disabled=False,
            bus_init_status=0,bus_command_fail_at=0,bus_read_fail_at=0,bus_write_fail_at=0,bus_disable_after=0)|changes
        c.pop('expected',None);c['expected']=contract(c);cases.append(c)
    for i in range(11):add('chip_'+str(i),i)
    add('disabled',bus_disabled=True);add('id_command_error',bus_command_fail_at=1);add('id_receive_error',bus_read_fail_at=1)
    add('reset_command_error',bus_command_fail_at=2);add('feature_command_error',bus_command_fail_at=3)
    add('feature_transmit_error',bus_write_fail_at=1);add('feature_receive_error',bus_read_fail_at=2)
    add('feature_write_disabled',bus_disable_after=2);add('feature_read_disabled',bus_disable_after=3)
    add('feature_mismatch',probe_feature_mismatch_at=1);add('init_status_ignored',bus_init_status=-9)
    add('no_bbt',probe_bbt_return=1,main_bbt_magic=0);add('duplicate',main_seed='duplicate');add('no_pm',main_pm_property=False)
    return dict(schema=1,scope='nand',bound_per_case=base.BOUND,cases=cases)


def evidence(archive,decompiled,vectors,validation):
    expected=native_vectors();report=json.loads(validation.read_bytes());mem=base.image_memory(archive)
    if probe.inventory(mem)!=probe.facts():raise ValueError('original main inventory differs')
    if tuple(struct.unpack('<I',mem.read(c['address']+12,4))[0] for c in probe.facts()['chips'])!=BUS_WORDS:raise ValueError('original bus words')
    if json.loads(vectors.read_bytes())!=expected:raise ValueError('vectors differ')
    if report['hardware_execution'] is not False or report['case_count']!=len(expected['cases']) or len(report['cases'])!=len(expected['cases']) or report['bound_per_case']!=base.BOUND:raise ValueError('case count/bound')
    for row,c in zip(report['cases'],expected['cases']):
        if row['name']!=c['name'] or row['observed']!=c['expected'] or not 0<row['steps']<=base.BOUND:raise ValueError('native mismatch')
    return dict(main_sha256=base.MAIN_HASH,inventory_sha256=base.digest(probe.FACTS.read_bytes()),vectors_sha256=base.digest(vectors.read_bytes()),validation_sha256=base.digest(validation.read_bytes()),
        byte_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in ranges()},
        data_range_sha256={f'{a:08x}_{n:x}':base.digest(mem.read(a,n)) for a,n in data_ranges()},
        export_sha256={f'{a:08x}.c':base.digest((decompiled/f'{a:08x}.c').read_bytes()) for a,n in ranges()},
        native_validation=report,native_steps=sum(r['steps'] for r in report['cases']),limitations=[
            'Original main eleven-candidate probe, ID/reset/feature packets, platform/bus conversion and root/registry/PM/geometry consumers execute with unchanged descriptors and bindings.',
            'HAL/FIFO/DMA bodies, revision return, MMIO backing, power, UID/workaround/BBT and BSP/RTOS/heap/PM services remain supplied. Disabled-flag transitions are explicitly authored after selected completed commands.',
            'No physical chip identity, elapsed timing, UID/BBT recovery, coherency/concurrency, persistence, safe restoration or standalone boot is established.'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',nargs='?')
    for key in ('vectors-output','vectors','validation','decompiled'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    try:
        if a.vectors_output:a.vectors_output.write_text(json.dumps(native_vectors(),indent=2,sort_keys=True)+'\n');return
        if not all((a.archive,a.decompiled,a.vectors,a.validation)):p.error('need archive/decompiled/vectors/validation')
        with zipfile.ZipFile(a.archive) as z:r=evidence(z,a.decompiled,a.vectors,a.validation)
    except (ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile) as e:p.exit(2,f'Cannot inspect connected main NAND bus: {e}\n')
    print(json.dumps(r,indent=2,sort_keys=True))


if __name__=='__main__':main()
